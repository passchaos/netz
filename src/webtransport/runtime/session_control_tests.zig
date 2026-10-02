const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

test "WebTransport classifies terminal close send failures" {
    inline for (&.{
        error.RequestCancelled,
        error.RequestRejected,
        error.StreamStopped,
        error.StreamStateError,
        error.UnexpectedStream,
        error.ConnectionClosed,
        error.ConnectionUnusable,
    }) |err| {
        try std.testing.expect(
            runtime.testing.classifyTerminalSessionBodySendError(err),
        );
    }
    inline for (&.{
        error.Timeout,
        error.Canceled,
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        error.DatagramTooLarge,
    }) |err| {
        try std.testing.expect(
            !runtime.testing.classifyTerminalSessionBodySendError(err),
        );
    }
}

test "WebTransport control records permanent local close failure" {
    var control = try @import("session_control.zig").Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer control.deinit();
    try control.beginLocalClose();
    control.recordLocalCloseFailure(0x10203040);
    try std.testing.expect(!control.local_close_started);
    try std.testing.expect(control.local_close_failed);
    try std.testing.expect(!control.local_close_sent);
    try std.testing.expect(control.state.closed);
    try std.testing.expectEqual(
        @as(?u32, 0x10203040),
        control.state.close_code,
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        control.ensureOpen(),
    );
}

test "WebTransport permanent CLOSE send failure becomes terminal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x11, 0x57, 0x54, 0x46, 0x12 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x13 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x14 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try self.release.wait(self.server.h3.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-terminal-close-send",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb5} ** 32,
                .x25519_secret_key = [_]u8{0xb6} ** 32,
            } },
        },
    );
    defer client.deinit();

    client.h3.abandonExtendedConnect(client.session_id.value);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.closeWithTimeout(401, "retired", .fromSeconds(1)),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(runtime.testing.localCloseFailed(&client));
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expect(client.control.state.closed);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.openBidirectionalStream(),
    );
    // The CONNECT direction is terminal, so a later close only resumes
    // associated-stream cleanup and never rebuilds the discarded capsule.
    try client.closeWithTimeout(999, "ignored", .fromSeconds(1));
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport server permanent CLOSE send failure becomes terminal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x21, 0x57, 0x54, 0x46, 0x22 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x23 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x24 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc7} ** 32,
            .x25519_secret_key = [_]u8{0xc8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        ready: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        failed: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.h3.finishRequest(session.session_id.value);
            try std.testing.expectError(
                error.UnexpectedStream,
                session.closeWithTimeout(402, "retired", .fromSeconds(1)),
            );
            try std.testing.expect(
                runtime.testing.pendingCloseProgress(&session) == null,
            );
            try std.testing.expect(runtime.testing.localCloseFailed(&session));
            try std.testing.expect(!runtime.testing.localCloseSent(&session));
            try std.testing.expect(session.control.state.closed);
            try std.testing.expectError(
                error.InvalidSessionState,
                session.sendDatagram("late"),
            );
            try session.closeWithTimeout(999, "ignored", .fromSeconds(1));
            self.failed = true;
            self.ready.set(self.server.h3.quic_server.endpoint.io);
            try self.release.wait(self.server.h3.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-server-terminal-close-send",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            } },
        },
    );
    defer client.deinit();
    try shared.ready.wait(io);
    try std.testing.expect(shared.failed);
    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake sessions exchange drain and close capsules" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x43, 0x01, 0x57, 0x54, 0x43, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x43, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x43, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings(
                "/wt-control",
                session.request.request.path,
            );

            try session.drain();
            // DRAIN is advisory: opening and using streams remains legal.
            const stream_id = try session.openUnidirectionalStream();
            try session.sendStream(stream_id, "after drain", true);

            const event = try session.receiveSessionEvent();
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 77), event.closed.code);
            try std.testing.expectEqualStrings("client done", event.closed.reason);
            try std.testing.expectError(
                error.InvalidSessionState,
                session.openBidirectionalStream(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-control",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xd1} ** 32,
                    .x25519_secret_key = [_]u8{0xd2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    const drain = try client.receiveSessionEvent();
    try std.testing.expect(drain == .draining);

    var stream_buffer: [32]u8 = undefined;
    const stream = try client.readStream(&stream_buffer);
    try std.testing.expect(stream == .data);
    try std.testing.expectEqualStrings(
        "after drain",
        stream_buffer[0..stream.data.bytes],
    );
    if (!stream.data.fin) {
        const fin = try client.readStream(&stream_buffer);
        try std.testing.expect(fin == .data);
        try std.testing.expectEqual(stream.data.stream_id, fin.data.stream_id);
        try std.testing.expectEqual(@as(usize, 0), fin.data.bytes);
        try std.testing.expect(fin.data.fin);
    }

    try client.close(77, "client done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("late"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport authenticated close deadline resumes capsule and stream cleanup" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,
        expire_after_send_call: ?usize = null,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (self.expire_after_send_call == self.send_calls and
                result[0] == null and result[1] != 0)
            {
                self.now_ns += 2;
            }
            return result;
        }
    };

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x44, 0x01, 0x57, 0x54, 0x44, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x44, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x44, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd7} ** 32,
                .x25519_secret_key = [_]u8{0xd8} ** 32,
            },
            .session = h3_session,
        },
    );
    defer server.deinit();

    const reason = "0123456789" ** 12;
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const event = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 117), event.closed.code);
            try std.testing.expectEqualStrings(reason, event.closed.reason);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-close-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .initial_one_rtt_config = .{
                        .max_datagram_size = 1400,
                        .enable_pacing = true,
                    },
                    .random = [_]u8{0xd5} ** 32,
                    .x25519_secret_key = [_]u8{0xd6} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    const packets_before_invalid_deadline = client.getStats().packets_sent;
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expectEqual(
        packets_before_invalid_deadline,
        client.getStats().packets_sent,
    );

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, "bidi", false);
    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, "uni", false);

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const progress = runtime.testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(!runtime.testing.localCloseSent(&client));
    try std.testing.expect(fixed.send_calls > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendStream(bidi, "must-not-interleave", false),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        client.closeWithDeadline(118, "different", .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const remaining = progress.total - progress.committed;
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        100_000,
        @intCast(fixed.now_ns),
    );
    fixed.expire_after_send_call = fixed.send_calls + remaining + 1;
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(117, reason, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );
    try std.testing.expect(runtime.testing.localCloseSent(&client));
    const bidi_state = client.streams.get(bidi) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(bidi_state.send_reset != null);
    try std.testing.expect(bidi_state.stop_sent == null);
    const uni_state_before_resume = client.streams.get(uni) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(uni_state_before_resume.send_reset == null);

    client.h3.endpoint.io = fixed.delegate;
    try client.closeWithTimeout(117, reason, .fromSeconds(5));
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        bidi_state.send_reset.?.http3_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        bidi_state.stop_sent.?.http3_code,
    );
    const uni_state = client.streams.get(uni) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        uni_state.send_reset.?.http3_code,
    );
    try std.testing.expect(uni_state.stop_sent == null);
    const packets_after_close = client.getStats().packets_sent;
    try client.closeWithTimeout(999, "already closed", .fromSeconds(1));
    try std.testing.expectEqual(
        packets_after_close,
        client.getStats().packets_sent,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport authenticated drain deadline resumes exact capsule" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x49, 0x01, 0x57, 0x54, 0x49, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x49, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x49, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
        .paced_body_chunk_bytes = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xdb} ** 32,
                .x25519_secret_key = [_]u8{0xdc} ** 32,
            },
            .session = h3_session,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const drain = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(drain == .draining);
            const close = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(close == .closed);
            try std.testing.expectEqual(@as(u32, 0), close.closed.code);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-drain-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .initial_one_rtt_config = .{
                        .max_datagram_size = 1400,
                        .enable_pacing = true,
                    },
                    .random = [_]u8{0xd9} ** 32,
                    .x25519_secret_key = [_]u8{0xda} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.drainWithDeadline(.{ .clock = .real, .raw = .zero }),
    );
    try std.testing.expect(
        runtime.testing.pendingDrainProgress(&client) == null,
    );

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.drainWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const progress = runtime.testing.pendingDrainProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendStream(try client.streams.prepareLocal(.bidirectional), "must-not-interleave", false),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        client.close(9, "must-not-interleave"),
    );

    client.h3.endpoint.io = fixed.delegate;
    try client.drainWithTimeout(.fromSeconds(5));
    try std.testing.expect(
        runtime.testing.pendingDrainProgress(&client) == null,
    );
    try std.testing.expect(client.control.local_drain_sent);
    const stream_id = try client.openBidirectionalStream();
    try client.sendStream(stream_id, "after drain", true);
    try client.closeWithTimeout(0, "", .fromSeconds(5));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport server close deadline resumes one exact capsule" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x45, 0x01, 0x57, 0x54, 0x45, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x45, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x45, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    const h3_session: http3.runtime.HandshakeSessionOptions = .{
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 1,
    };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe7} ** 32,
                .x25519_secret_key = [_]u8{0xe8} ** 32,
            },
            .session = h3_session,
        },
    );
    defer server.deinit();

    const reason = "server-close-" ** 10;
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var fixed = FixedSendIo{
                .delegate = session.h3.established.connection.endpoint.io,
            };
            var vtable = fixed.delegate.vtable.*;
            vtable.now = FixedSendIo.now;
            vtable.sleep = FixedSendIo.sleep;
            vtable.netSend = FixedSendIo.netSend;
            session.h3.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.setPacingBudgetAt(
                &session.h3.established.connection,
                64,
                @intCast(fixed.now_ns),
            );
            try std.testing.expectError(
                error.Timeout,
                session.closeWithDeadline(211, reason, .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.now_ns + 1),
                }),
            );
            const progress = runtime.testing.pendingCloseProgress(&session) orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(progress.committed > 0);
            try std.testing.expect(progress.committed < progress.total);
            try std.testing.expect(!runtime.testing.localCloseSent(&session));
            try std.testing.expect(fixed.send_calls > 0);
            try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);

            session.h3.established.connection.endpoint.io = fixed.delegate;
            try session.closeWithTimeout(211, reason, .fromSeconds(5));
            try std.testing.expect(
                runtime.testing.pendingCloseProgress(&session) == null,
            );
            try std.testing.expect(runtime.testing.localCloseSent(&session));
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-server-close-deadline",
            .limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xe5} ** 32,
                    .x25519_secret_key = [_]u8{0xe6} ** 32,
                },
                .session = h3_session,
            },
        },
    );
    defer client.deinit();

    const event = try client.receiveSessionEventWithTimeout(.fromSeconds(5));
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 211), event.closed.code);
    try std.testing.expectEqualStrings(reason, event.closed.reason);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport terminal event survives cleanup timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedDeadlineIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    const Stage = enum { connect, await_peer_fin, force_cleanup_timeout, resume_cleanup, join };
    var stage: Stage = .connect;
    errdefer std.debug.print(
        "WebTransport terminal cleanup test failed during {s}\n",
        .{@tagName(stage)},
    );

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x4f, 0x01, 0x57, 0x54, 0x4f, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x4f, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x4f, 0x04 };
    const limits: runtime.Limits = .{ .http3 = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xf7} ** 32,
            .x25519_secret_key = [_]u8{0xf8} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.close(313, "peer terminal retained");
            // Keep the QUIC owner alive to service ACK/PTO recovery until the
            // client resumes cleanup and closes its CONNECT send direction.
            // Returning immediately after the first UDP submission would make
            // this reliability test depend on that datagram never being lost.
            const event = try session.receiveSessionEventWithTimeout(
                .fromSeconds(5),
            );
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 0), event.closed.code);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-terminal-event-timeout",
            .limits = limits,
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{ .enable_pacing = true },
                .random = [_]u8{0xf5} ** 32,
                .x25519_secret_key = [_]u8{0xf6} ** 32,
            } },
        },
    );
    defer client.deinit();

    stage = .await_peer_fin;
    while ((client.h3.established.connection.recvStreamStats(
        client.session_id.value,
    ) orelse return error.TestUnexpectedResult).final_size == null) {
        var packet = try client.h3.established.connection
            .receivePacketServicingTimersTimeout(.{
            .duration = .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            },
        });
        defer packet.deinit(allocator);
        try client.processPacket(&packet);
    }

    var fixed = FixedDeadlineIo{
        .delegate = client.h3.established.connection.endpoint.io,
    };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedDeadlineIo.now;
    vtable.sleep = FixedDeadlineIo.sleep;
    vtable.netSend = FixedDeadlineIo.netSend;
    client.h3.established.connection.endpoint.io = .{
        .userdata = &fixed,
        .vtable = &vtable,
    };
    defer client.h3.established.connection.endpoint.io = fixed.delegate;
    quic.one_rtt.testing.exhaustPacingAt(
        &client.h3.established.connection,
        @intCast(fixed.now_ns),
    );
    stage = .force_cleanup_timeout;
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionEventWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(runtime.testing.hasPendingSessionEvent(&client));
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        100_000,
        @intCast(fixed.now_ns),
    );
    stage = .resume_cleanup;
    const event = try client.receiveSessionEventWithTimeout(.fromSeconds(5));
    try std.testing.expect(fixed.send_calls > 0);
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 313), event.closed.code);
    try std.testing.expectEqualStrings(
        "peer terminal retained",
        event.closed.reason,
    );

    stage = .join;
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake clean CONNECT FIN is normal close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x46, 0x01, 0x57, 0x54, 0x46, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x46, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x46, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            // A zero-length DATA frame followed by FIN carries no close capsule
            // and is therefore semantically equivalent to close(0, "").
            try session.h3.sendResponseBodyPaced(
                session.session_id.value,
                &.{},
                true,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-fin",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xe1} ** 32,
                    .x25519_secret_key = [_]u8{0xe2} ** 32,
                },
            },
        },
    );
    defer client.deinit();
    const event = try client.receiveSessionEvent();
    try std.testing.expect(event == .closed);
    try std.testing.expectEqual(@as(u32, 0), event.closed.code);
    try std.testing.expectEqualStrings("", event.closed.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake rejects FIN during Capsule type varint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const server_cid = [_]u8{ 0x57, 0x54, 0x56, 0x00 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
        } },
    );
    defer server.deinit();

    // Each value is one byte short of the length selected by its first two
    // bits. The enclosing HTTP/3 DATA frame is complete; only the Capsule type
    // varint is truncated when the CONNECT response direction reaches FIN.
    const truncated_types = [_][]const u8{
        &.{0x40},
        &.{ 0x80, 0x00, 0x00 },
        &.{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            for (truncated_types) |truncated| {
                var session = try server_ptr.accept();
                defer session.deinit();
                try session.h3.sendResponseBodyPaced(
                    session.session_id.value,
                    truncated,
                    true,
                );

                const event = try session.receiveSessionEvent();
                try std.testing.expect(event == .reset);
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    event.reset.http3_code,
                );
                try std.testing.expect(event.reset.application_code == null);
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (truncated_types, 0..) |_, index| {
        const marker: u8 = @intCast(index + 1);
        const original_dcid =
            [_]u8{ 0x57, 0x54, 0x56, marker, 0x57, 0x54, 0x56, marker };
        const client_cid = [_]u8{ 0x57, 0x54, 0x57, marker };
        {
            var client = try runtime.HandshakeClientSession.connect(
                allocator,
                io,
                .{ .ip4 = .loopback(0) },
                server.address(),
                .{
                    .authority = "localhost",
                    .path = "/wt-truncated-capsule-type",
                    .h3 = .{ .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0xa1} ** 32,
                        .x25519_secret_key = [_]u8{0xa2} ** 32,
                    } },
                },
            );
            defer client.deinit();
            try std.testing.expectError(
                error.InvalidCapsule,
                client.receiveSessionEvent(),
            );
        }
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives peer QUIC close details" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x51, 0x01, 0x57, 0x54, 0x51, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x51, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x51, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try session.h3.established.connection.closeApplication(
                0,
                "interop complete",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-quic-close",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xf1} ** 32,
                    .x25519_secret_key = [_]u8{0xf2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    switch (try client.receivePeerConnectionClose()) {
        .application => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqualStrings(
                "interop complete",
                close.reason_phrase,
            );
        },
        .transport => return error.TestUnexpectedResult,
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport session control encodes bounds and rejects malformed close" {
    const control = @import("session_control.zig");
    var buffer: [4 + control.max_close_reason + 16]u8 = undefined;
    const close = try control.writeCloseInto(&buffer, 9, "done");
    const parsed = try webtransport.Capsule.parse(close);
    try std.testing.expectEqual(@as(u32, 9), parsed.capsule.close_session.code);
    try std.testing.expectEqualStrings("done", parsed.capsule.close_session.reason);

    var oversized: [control.max_close_reason + 1]u8 = undefined;
    @memset(&oversized, 'x');
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, &oversized),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        control.writeCloseInto(&buffer, 1, "\xff"),
    );

    // Keep the protocol code visible at the public boundary.
    try std.testing.expectEqual(
        @as(u64, 0x170d7b68),
        webtransport.ApplicationErrorCode.session_gone,
    );
    try std.testing.expectEqual(
        @as(u64, 0x10e),
        @import("../../http3/mod.zig").ApplicationErrorCode.message_error,
    );
    _ = quic;
}

test "WebTransport terminal sweep discovers buffered associated streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-sweep-server",
        .peer_connection_id = "wt-sweep-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 0, .max_peer_uni = 0 },
    );
    defer registry.deinit();

    var bidi_storage: [16]u8 = undefined;
    const bidi = try webtransport.BidirectionalStreamHeader.writeInto(
        &bidi_storage,
        session_id,
    );
    var uni: std.ArrayList(u8) = .empty;
    defer uni.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &uni,
        allocator,
        session_id,
    );
    var other_session: std.ArrayList(u8) = .empty;
    defer other_session.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &other_session,
        allocator,
        .init(4),
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 4, .data = bidi } },
            .{ .stream = .{ .stream_id = 2, .data = uni.items } },
            .{ .stream = .{ .stream_id = 6, .data = other_session.items } },
            .{ .stream = .{ .stream_id = 8, .data = &.{0x41} } },
            .{ .stream = .{ .stream_id = 10, .data = &.{0x00} } },
        },
        null,
        .not_ect,
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);

    try std.testing.expectEqual(
        @import("session_control.zig").TerminateProgress.submitted,
        try @import("session_control.zig").terminateStreamsOnce(
            &connection,
            &registry,
        ),
    );
    try std.testing.expect(registry.get(4) == null);
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expect(registry.get(6) == null);
    try std.testing.expect(registry.get(8) == null);
    try std.testing.expect(registry.get(10) == null);

    while (try @import("session_control.zig").terminateStreamsOnce(
        &connection,
        &registry,
    ) == .submitted) {}

    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(4).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(4).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(2).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expect(connection.recvStreamStats(6).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(8).?.stop_sending_sent == null);
    try std.testing.expect(connection.recvStreamStats(10).?.stop_sending_sent == null);
    try std.testing.expectEqual(bidi.len, connection.availableReceivedStream(4).?.len);
    try std.testing.expectEqual(uni.items.len, connection.availableReceivedStream(2).?.len);

    // The blocking cleanup path uses the same discovery without relying on
    // registry capacity or consuming the association prefix.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{ .stream_id = 12, .data = bidi } }},
        null,
        .not_ect,
    );
    try @import("session_control.zig").terminateStreams(
        &connection,
        &registry,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.sendStreamStats(12).?.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        connection.recvStreamStats(12).?.stop_sending_sent.?
            .application_error_code,
    );
    try std.testing.expectEqual(
        bidi.len,
        connection.availableReceivedStream(12).?.len,
    );
}

test "WebTransport deadline cleanup retains completed stream prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-dl-srv",
        .peer_connection_id = "wt-dl-cli",
        .local_endpoint = .client,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{ .max_local_bidi = 2 },
    );
    defer registry.deinit();
    _ = try registry.registerLocal(4, .bidirectional);
    _ = try registry.registerLocal(8, .bidirectional);
    try connection.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = "first",
    } }});
    try connection.send(&.{.{ .stream = .{
        .stream_id = 8,
        .data = "second",
    } }});

    const ExpiringSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (self.send_calls == 1 and result[0] == null and result[1] != 0) {
                self.now_ns += 2;
            }
            return result;
        }
    };
    var fixed = ExpiringSendIo{ .delegate = endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = ExpiringSendIo.now;
    vtable.netSend = ExpiringSendIo.netSend;
    endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    try std.testing.expectError(
        error.Timeout,
        @import("session_control.zig").terminateStreamsWithDeadline(
            &connection,
            &registry,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(registry.get(4).?.send_reset != null);
    try std.testing.expect(registry.get(8).?.send_reset == null);

    endpoint.io = fixed.delegate;
    try @import("session_control.zig").terminateStreamsWithDeadline(
        &connection,
        &registry,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        registry.get(4).?.send_reset.?.http3_code,
    );
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.session_gone,
        registry.get(8).?.send_reset.?.http3_code,
    );
    try std.testing.expect(quic.one_rtt.testing.localStreamReleaseRequested(
        &connection,
        4,
    ));
    try std.testing.expect(quic.one_rtt.testing.localStreamReleaseRequested(
        &connection,
        8,
    ));
}

test "WebTransport session control parses split framed capsules and skips unknown" {
    const control_module = @import("session_control.zig");

    var unknown_capsule: [64]u8 = undefined;
    const unknown = try @import("../../http3/capsule.zig").writeInto(
        &unknown_capsule,
        0x1234,
        "ignored",
    );
    var drain_capsule: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_capsule);
    var payload: [96]u8 = undefined;
    @memcpy(payload[0..unknown.len], unknown);
    @memcpy(payload[unknown.len..][0..drain.len], drain);

    var frame: [128]u8 = undefined;
    const frame_type = try quic.varint.encodeInto(
        &frame,
        @import("../../http3/mod.zig").FrameType.data,
    );
    const frame_length = try quic.varint.encodeInto(
        frame[frame_type.len..],
        unknown.len + drain.len,
    );
    const header_len = frame_type.len + frame_length.len;
    @memcpy(
        frame[header_len..][0 .. unknown.len + drain.len],
        payload[0 .. unknown.len + drain.len],
    );
    const bytes = frame[0 .. header_len + unknown.len + drain.len];

    // Feed every split point through the parser using a local helper that
    // mirrors transport availability. No complete value is buffered by the
    // state machine while the unknown capsule is skipped.
    for (1..bytes.len) |split| {
        var candidate = try control_module.Control.init(
            std.testing.allocator,
            .init(0),
        );
        defer candidate.deinit();
        const first = try candidate.feed(bytes[0..split]);
        try std.testing.expect(first == null);
        const second = try candidate.feed(bytes[split..]);
        try std.testing.expect(second.? == .draining);
    }
}

test "WebTransport CONNECT control accepts DATA and skips unknown HTTP/3 frames" {
    const control_module = @import("session_control.zig");
    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var encoded: [64]u8 = undefined;
    var len: usize = 0;

    const extension_type = try quic.varint.encodeInto(encoded[len..], 0x21);
    len += extension_type.len;
    const extension_length = try quic.varint.encodeInto(encoded[len..], 2);
    len += extension_length.len;
    encoded[len..][0..2].* = .{ 0xff, 0xff };
    len += 2;
    const data_type = try quic.varint.encodeInto(
        encoded[len..],
        http3.FrameType.data,
    );
    len += data_type.len;
    const data_length = try quic.varint.encodeInto(encoded[len..], drain.len);
    len += data_length.len;
    @memcpy(encoded[len..][0..drain.len], drain);
    len += drain.len;

    var control = try control_module.Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer control.deinit();
    const event = (try control.feed(encoded[0..len])).?;
    try std.testing.expect(event == .draining);
}

test "WebTransport CONNECT control rejects forbidden HTTP/3 frame types" {
    const control_module = @import("session_control.zig");
    const forbidden = [_]u64{
        http3.FrameType.headers,
        http3.FrameType.cancel_push,
        http3.FrameType.settings,
        http3.FrameType.push_promise,
        http3.FrameType.goaway,
        http3.FrameType.origin,
        http3.FrameType.max_push_id,
        http3.FrameType.priority_update_request,
        http3.FrameType.priority_update_push,
        http3.FrameType.webtransport_stream,
        0x02,
        0x06,
        0x08,
        0x09,
    };

    for (forbidden) |frame_type| {
        var encoded: [8]u8 = undefined;
        const frame = try quic.varint.encodeInto(&encoded, frame_type);
        var control = try control_module.Control.init(
            std.testing.allocator,
            .init(0),
        );
        defer control.deinit();
        if (frame.len > 1) {
            try std.testing.expect(
                (try control.feed(frame[0 .. frame.len - 1])) == null,
            );
        }
        try std.testing.expectError(
            error.UnexpectedFrame,
            control.feed(frame[frame.len - 1 ..]),
        );
    }
}

test "Protected session control retains close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        17,
        "after drain",
    );
    var joined: [80]u8 = undefined;
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var reader = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer reader.deinit();
    const first = (try reader.consume(
        joined[0 .. drain.len + close.len],
    )).?;
    try std.testing.expect(first == .draining);
    const second = (try reader.pollPending()).?;
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 17), second.closed.code);
    try std.testing.expectEqualStrings(
        "after drain",
        second.closed.reason,
    );
}

test "Protected session control retains maximum close after drain event" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var reason: [control_module.max_close_reason]u8 = undefined;
    @memset(&reason, 'x');
    var drain_storage: [16]u8 = undefined;
    const drain = try control_module.writeDrainInto(&drain_storage);
    var close_storage: [4 + control_module.max_close_reason + 16]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        29,
        &reason,
    );
    var joined: [protected.buffer_capacity]u8 = undefined;
    try std.testing.expect(drain.len + close.len <= joined.len);
    @memcpy(joined[0..drain.len], drain);
    @memcpy(joined[drain.len..][0..close.len], close);

    var reader = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer reader.deinit();
    const first = (try reader.consume(
        joined[0 .. drain.len + close.len],
    )).?;
    try std.testing.expect(first == .draining);
    const second = (try reader.pollPending()).?;
    try std.testing.expect(second == .closed);
    try std.testing.expectEqual(@as(u32, 29), second.closed.code);
    try std.testing.expectEqualSlices(u8, &reason, second.closed.reason);
}

test "WebTransport session control uses bounded close reason storage" {
    const control_module = @import("session_control.zig");

    const inline_reason = [_]u8{'s'} ** 128;
    var inline_capsule_storage: [4 + control_module.max_close_reason + 16]u8 =
        undefined;
    const inline_capsule = try control_module.writeCloseInto(
        &inline_capsule_storage,
        31,
        &inline_reason,
    );
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var inline_control = try control_module.Control.init(
        no_alloc.allocator(),
        .init(0),
    );
    defer inline_control.deinit();
    const inline_result = try inline_control.feedCapsulePayload(inline_capsule);
    try std.testing.expect(inline_result.event.? == .closed);
    try std.testing.expectEqualSlices(
        u8,
        &inline_reason,
        inline_result.event.?.closed.reason,
    );
    try std.testing.expect(inline_control.close_reason_heap == null);

    const heap_reason = [_]u8{'h'} ** 129;
    var heap_capsule_storage: [4 + control_module.max_close_reason + 16]u8 =
        undefined;
    const heap_capsule = try control_module.writeCloseInto(
        &heap_capsule_storage,
        32,
        &heap_reason,
    );
    var heap_control = try control_module.Control.init(
        no_alloc.allocator(),
        .init(0),
    );
    defer heap_control.deinit();
    try std.testing.expectError(
        error.OutOfMemory,
        heap_control.feedCapsulePayload(heap_capsule),
    );
    try std.testing.expect(heap_control.close_reason_heap == null);
    heap_control.allocator = std.testing.allocator;
    const heap_result = try heap_control.feedCapsulePayload(heap_capsule);
    try std.testing.expect(heap_result.event.? == .closed);
    try std.testing.expectEqualSlices(
        u8,
        &heap_reason,
        heap_result.event.?.closed.reason,
    );
    try std.testing.expectEqual(
        heap_reason.len,
        heap_control.close_reason_heap.?.len,
    );

    const invalid_reason = [_]u8{'i'} ** 129;
    const invalid_capsule = try control_module.writeCloseInto(
        &heap_capsule_storage,
        33,
        &invalid_reason,
    );
    invalid_capsule[invalid_capsule.len - 1] = 0xff;
    var invalid_control = try control_module.Control.init(
        std.testing.allocator,
        .init(0),
    );
    defer invalid_control.deinit();
    try std.testing.expectError(
        error.InvalidCapsule,
        invalid_control.feedCapsulePayload(invalid_capsule),
    );
    try std.testing.expect(invalid_control.close_reason_heap == null);
}

test "Protected session control clean FIN closes only at capsule boundary" {
    const protected =
        @import("protected_session_control.zig");
    const control_module = @import("session_control.zig");

    var clean = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer clean.deinit();
    const closed = (try clean.finish()).?;
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 0), closed.closed.code);
    try std.testing.expectEqualStrings("", closed.closed.reason);

    var partial = protected.Reader.init(
        try control_module.Control.init(std.testing.allocator, .init(0)),
    );
    defer partial.deinit();
    var close_storage: [64]u8 = undefined;
    const close = try control_module.writeCloseInto(
        &close_storage,
        31,
        "partial",
    );
    try std.testing.expect((try partial.consume(close[0..3])) == null);
    try std.testing.expectError(error.InvalidCapsule, partial.finish());
}
