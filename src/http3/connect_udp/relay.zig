//! Policy-neutral RFC 9298 Session to UDP socket relay.
//!
//! The caller resolves and authorizes `target`, creates/binds `socket`, and
//! owns all three resources. The relay preserves UDP message boundaries and
//! filters packets from any source other than the authorized target. It uses
//! one cancel-safe select per turn so HTTP/2 flow-control writes never race a
//! second owner of the connection reader.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

const net = std.Io.net;

pub fn Relay(comptime ConnectUdp: type) type {
    return struct {
        pub const Options = struct {
            /// Absolute awake-clock budget for the complete relay lifetime.
            deadline: ?std.Io.Clock.Timestamp = null,
            /// Cooperative application cancellation. The Event is borrowed.
            cancel: ?*std.Io.Event = null,
            /// Stop after a completed select turn reaches this bidirectional
            /// total. Simultaneous natural completions are both preserved, so
            /// the final count can exceed the threshold by one.
            max_forwarded_datagrams: ?u64 = null,
            /// Drop a kernel-truncated UDP datagram instead of failing.
            drop_truncated: bool = true,
        };

        pub const EndReason = enum {
            session_closed,
            canceled,
            deadline,
            datagram_limit,
        };

        pub const Stats = struct {
            session_to_udp_datagrams: u64 = 0,
            session_to_udp_bytes: u64 = 0,
            udp_to_session_datagrams: u64 = 0,
            udp_to_session_bytes: u64 = 0,
            dropped_unexpected_source: u64 = 0,
            dropped_truncated: u64 = 0,

            pub fn forwardedDatagrams(self: Stats) u64 {
                return self.session_to_udp_datagrams +|
                    self.udp_to_session_datagrams;
            }
        };

        pub const Result = struct {
            reason: EndReason,
            stats: Stats,
        };

        const SendOutcome = struct {
            sent: bool,
            terminal: ?EndReason = null,
        };

        /// Relay between one accepted CONNECT-UDP Session and one caller-owned
        /// UDP socket. The Session buffer must cover the RFC 9298 maximum so a
        /// legal Capsule is never consumed partially. A smaller UDP buffer is
        /// an explicit target-side MTU cap; truncated packets follow
        /// `drop_truncated`. The socket remains open and the Session remains
        /// owned by the caller on every return path.
        pub fn run(
            comptime Session: type,
            io: std.Io,
            session: *Session,
            socket: *net.Socket,
            target: *const net.IpAddress,
            session_receive_buffer: []u8,
            udp_receive_buffer: []u8,
            options: Options,
        ) anyerror!Result {
            const maximum_payload = session.maxPayloadSize() orelse
                return error.DatagramUnavailable;
            if (session_receive_buffer.len < maximum_payload) {
                return error.BufferTooShort;
            }
            if (options.deadline) |deadline| {
                _ = try deadline_policy.usableAwake(io, deadline);
            }
            var stats: Stats = .{};
            if (options.max_forwarded_datagrams == 0) {
                return .{ .reason = .datagram_limit, .stats = stats };
            }

            while (true) {
                const ReceiveWake = union(enum) {
                    session: anyerror!ConnectUdp.ReceivedUdpPayload,
                    udp: anyerror!net.IncomingMessage,
                    cancel: anyerror!void,
                    deadline: anyerror!void,
                };
                const Task = struct {
                    fn sessionReceive(
                        active: *Session,
                        out: []u8,
                    ) anyerror!ConnectUdp.ReceivedUdpPayload {
                        return active.receiveInto(out);
                    }

                    fn udpReceive(
                        udp_socket: *net.Socket,
                        active_io: std.Io,
                        out: []u8,
                    ) anyerror!net.IncomingMessage {
                        return udp_socket.receive(active_io, out);
                    }

                    fn waitEvent(
                        event: *std.Io.Event,
                        active_io: std.Io,
                    ) anyerror!void {
                        return event.wait(active_io);
                    }

                    fn waitDeadline(
                        deadline: std.Io.Clock.Timestamp,
                        active_io: std.Io,
                    ) anyerror!void {
                        return deadline.wait(active_io);
                    }
                };
                var queue_storage: [4]ReceiveWake = undefined;
                var completed: [4]ReceiveWake = undefined;
                var select: std.Io.Select(ReceiveWake) = .init(
                    io,
                    &queue_storage,
                );
                var drained = false;
                defer if (!drained) select.cancelDiscard();
                select.async(
                    .session,
                    Task.sessionReceive,
                    .{ session, session_receive_buffer },
                );
                select.async(
                    .udp,
                    Task.udpReceive,
                    .{ socket, io, udp_receive_buffer },
                );
                if (options.cancel) |event| {
                    select.async(.cancel, Task.waitEvent, .{ event, io });
                }
                if (options.deadline) |deadline| {
                    select.async(
                        .deadline,
                        Task.waitDeadline,
                        .{ deadline, io },
                    );
                }

                var completed_count: usize = 1;
                completed[0] = try select.await();
                while (select.cancel()) |late| {
                    completed[completed_count] = late;
                    completed_count += 1;
                }
                drained = true;

                var terminal: ?EndReason = null;
                for (completed[0..completed_count]) |wake| switch (wake) {
                    .session => |result| if (result) |received| {
                        const outcome = try sendUdpBefore(
                            io,
                            socket,
                            target,
                            received.payload,
                            options,
                        );
                        if (outcome.sent) {
                            stats.session_to_udp_datagrams +|= 1;
                            stats.session_to_udp_bytes +|= @intCast(
                                received.payload.len,
                            );
                        }
                        if (outcome.terminal) |reason| {
                            terminal = terminal orelse reason;
                        }
                    } else |err| switch (err) {
                        error.Canceled => {},
                        error.ConnectionClosed => {
                            terminal = terminal orelse .session_closed;
                        },
                        else => return err,
                    },
                    .udp => |result| if (result) |message| {
                        if (message.flags.trunc) {
                            if (!options.drop_truncated) {
                                return error.DatagramTruncated;
                            }
                            stats.dropped_truncated +|= 1;
                            continue;
                        }
                        if (!net.IpAddress.eql(&message.from, target)) {
                            stats.dropped_unexpected_source +|= 1;
                            continue;
                        }
                        const outcome = try sendSessionBefore(
                            Session,
                            io,
                            session,
                            message.data,
                            options,
                        );
                        if (outcome.sent) {
                            stats.udp_to_session_datagrams +|= 1;
                            stats.udp_to_session_bytes +|= @intCast(
                                message.data.len,
                            );
                        }
                        if (outcome.terminal) |reason| {
                            terminal = terminal orelse reason;
                        }
                    } else |err| switch (err) {
                        error.Canceled => {},
                        else => return err,
                    },
                    .cancel => |result| if (result) |_| {
                        terminal = terminal orelse .canceled;
                    } else |err| switch (err) {
                        error.Canceled => {},
                        else => return err,
                    },
                    .deadline => |result| if (result) |_| {
                        terminal = terminal orelse .deadline;
                    } else |err| switch (err) {
                        error.Canceled => {},
                        else => return err,
                    },
                };

                if (terminal) |reason| {
                    return .{ .reason = reason, .stats = stats };
                }
                if (options.max_forwarded_datagrams) |maximum| {
                    if (stats.forwardedDatagrams() >= maximum) {
                        return .{
                            .reason = .datagram_limit,
                            .stats = stats,
                        };
                    }
                }
            }
        }

        fn sendUdpBefore(
            io: std.Io,
            socket: *net.Socket,
            target: *const net.IpAddress,
            payload: []const u8,
            options: Options,
        ) anyerror!SendOutcome {
            const Wake = union(enum) {
                sent: anyerror!void,
                cancel: anyerror!void,
                deadline: anyerror!void,
            };
            const Task = struct {
                fn send(
                    udp_socket: *net.Socket,
                    active_io: std.Io,
                    destination: *const net.IpAddress,
                    bytes: []const u8,
                ) anyerror!void {
                    return udp_socket.send(active_io, destination, bytes);
                }

                fn waitEvent(
                    event: *std.Io.Event,
                    active_io: std.Io,
                ) anyerror!void {
                    return event.wait(active_io);
                }

                fn waitDeadline(
                    deadline: std.Io.Clock.Timestamp,
                    active_io: std.Io,
                ) anyerror!void {
                    return deadline.wait(active_io);
                }
            };
            var queue_storage: [3]Wake = undefined;
            var completed: [3]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(io, &queue_storage);
            var drained = false;
            defer if (!drained) select.cancelDiscard();
            select.async(.sent, Task.send, .{ socket, io, target, payload });
            if (options.cancel) |event| {
                select.async(.cancel, Task.waitEvent, .{ event, io });
            }
            if (options.deadline) |deadline| {
                select.async(
                    .deadline,
                    Task.waitDeadline,
                    .{ deadline, io },
                );
            }
            var completed_count: usize = 1;
            completed[0] = try select.await();
            while (select.cancel()) |late| {
                completed[completed_count] = late;
                completed_count += 1;
            }
            drained = true;
            var sent = false;
            var terminal: ?EndReason = null;
            for (completed[0..completed_count]) |wake| switch (wake) {
                .sent => |result| if (result) |_| {
                    sent = true;
                } else |err| switch (err) {
                    error.Canceled => {},
                    else => return err,
                },
                .cancel => |result| if (result) |_| {
                    terminal = terminal orelse .canceled;
                } else |err| switch (err) {
                    error.Canceled => {},
                    else => return err,
                },
                .deadline => |result| if (result) |_| {
                    terminal = terminal orelse .deadline;
                } else |err| switch (err) {
                    error.Canceled => {},
                    else => return err,
                },
            };
            if (!sent and terminal == null) return error.Canceled;
            return .{ .sent = sent, .terminal = terminal };
        }

        fn sendSessionBefore(
            comptime Session: type,
            io: std.Io,
            session: *Session,
            payload: []const u8,
            options: Options,
        ) anyerror!SendOutcome {
            const Wake = union(enum) {
                sent: anyerror!void,
                cancel: anyerror!void,
                deadline: anyerror!void,
            };
            const Task = struct {
                fn send(active: *Session, bytes: []const u8) anyerror!void {
                    return active.send(bytes);
                }

                fn waitEvent(
                    event: *std.Io.Event,
                    active_io: std.Io,
                ) anyerror!void {
                    return event.wait(active_io);
                }

                fn waitDeadline(
                    deadline: std.Io.Clock.Timestamp,
                    active_io: std.Io,
                ) anyerror!void {
                    return deadline.wait(active_io);
                }
            };
            var queue_storage: [3]Wake = undefined;
            var completed: [3]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(io, &queue_storage);
            var drained = false;
            defer if (!drained) select.cancelDiscard();
            select.async(.sent, Task.send, .{ session, payload });
            if (options.cancel) |event| {
                select.async(.cancel, Task.waitEvent, .{ event, io });
            }
            if (options.deadline) |deadline| {
                select.async(
                    .deadline,
                    Task.waitDeadline,
                    .{ deadline, io },
                );
            }
            var completed_count: usize = 1;
            completed[0] = try select.await();
            while (select.cancel()) |late| {
                completed[completed_count] = late;
                completed_count += 1;
            }
            drained = true;
            var sent = false;
            var terminal: ?EndReason = null;
            for (completed[0..completed_count]) |wake| switch (wake) {
                .sent => |result| if (result) |_| {
                    sent = true;
                } else |err| switch (err) {
                    error.Canceled => {},
                    error.ConnectionClosed => {
                        terminal = terminal orelse .session_closed;
                    },
                    else => return err,
                },
                .cancel => |result| if (result) |_| {
                    terminal = terminal orelse .canceled;
                } else |err| switch (err) {
                    error.Canceled => {},
                    else => return err,
                },
                .deadline => |result| if (result) |_| {
                    terminal = terminal orelse .deadline;
                } else |err| switch (err) {
                    error.Canceled => {},
                    else => return err,
                },
            };
            if (!sent and terminal == null) return error.Canceled;
            return .{ .sent = sent, .terminal = terminal };
        }
    };
}
