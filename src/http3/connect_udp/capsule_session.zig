//! RFC 9298 Context ID 0 data plane carried by RFC 9297 DATAGRAM capsules.
//!
//! HTTP/1.1 and HTTP/2 lack QUIC DATAGRAM framing, so capsule bytes form one
//! continuous stream. This adapter retains split capsule prefixes/values,
//! skips unknown capsules and Context IDs, and resumes partially committed
//! writes without duplicating a byte prefix.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const quic = @import("../../quic/mod.zig");

pub const Options = struct {
    max_incomplete_capsule_bytes: usize = 65_560,
};

pub fn Session(
    comptime ResetCode: type,
    comptime Capsule: type,
    comptime ConnectUdp: type,
    comptime Tunnel: type,
    comptime WriteProgress: type,
) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        tunnel: Tunnel,
        options: Options,
        receive_buffer: std.ArrayList(u8) = .empty,
        receive_offset: usize = 0,
        peer_finished: bool = false,
        pending_send: ?PendingSend = null,

        const Self = @This();

        const PendingSend = struct {
            header: [24]u8 = undefined,
            header_len: usize,
            payload: []const u8,
            committed: usize = 0,

            fn totalLen(self: *const PendingSend) usize {
                return self.header_len + self.payload.len;
            }

            fn matches(self: *const PendingSend, payload: []const u8) bool {
                return self.payload.len == payload.len and
                    (payload.len == 0 or self.payload.ptr == payload.ptr);
            }

            fn remainingSlices(
                self: *const PendingSend,
                storage: *[2][]const u8,
            ) []const []const u8 {
                if (self.committed < self.header_len) {
                    storage[0] = self.header[self.committed..self.header_len];
                    storage[1] = self.payload;
                    return storage;
                }
                storage[0] = self.payload[self.committed - self.header_len ..];
                return storage[0..1];
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            tunnel: Tunnel,
            options: Options,
        ) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .tunnel = tunnel,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.receive_buffer.deinit(self.allocator);
            if (@hasDecl(Tunnel, "deinit")) self.tunnel.deinit();
            self.* = undefined;
        }

        pub fn streamId(self: *const Self) u31 {
            return self.tunnel.stream_id;
        }

        pub fn writeInProgress(self: *const Self) bool {
            return self.pending_send != null;
        }

        pub fn committedBytes(self: *const Self) usize {
            return if (self.pending_send) |pending| pending.committed else 0;
        }

        pub fn send(self: *Self, payload: []const u8) !void {
            try self.prepareSend(payload);
            var slices_storage: [2][]const u8 = undefined;
            const slices = self.pending_send.?.remainingSlices(
                &slices_storage,
            );
            self.tunnel.writeSlices(slices, false) catch |err| {
                self.pending_send = null;
                return err;
            };
            self.pending_send = null;
        }

        pub fn sendWithTimeout(
            self: *Self,
            payload: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendWithDeadline(payload, .fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn sendWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            try self.prepareSend(payload);
            var slices_storage: [2][]const u8 = undefined;
            const slices = self.pending_send.?.remainingSlices(
                &slices_storage,
            );
            var progress: WriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                slices,
                false,
                &progress,
                deadline,
            ) catch |err| {
                self.pending_send.?.committed += progress.committed_bytes;
                if (err != error.Timeout) self.pending_send = null;
                return err;
            };
            self.pending_send.?.committed += progress.committed_bytes;
            std.debug.assert(
                self.pending_send.?.committed ==
                    self.pending_send.?.totalLen(),
            );
            self.pending_send = null;
        }

        pub fn closeWrite(self: *Self) !void {
            if (self.pending_send != null) return error.WriteInProgress;
            try self.tunnel.closeWrite();
        }

        pub fn receive(self: *Self) !ConnectUdp.OwnedUdpPayload {
            return self.receiveUntil(null);
        }

        pub fn receiveWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !ConnectUdp.OwnedUdpPayload {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn receiveWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !ConnectUdp.OwnedUdpPayload {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveUntil(deadline);
        }

        /// Receive one Context ID 0 UDP payload into caller storage. A short
        /// output returns BufferTooShort without consuming the parsed capsule,
        /// so the caller can retry with a larger buffer.
        pub fn receiveInto(
            self: *Self,
            out: []u8,
        ) !ConnectUdp.ReceivedUdpPayload {
            return self.receiveIntoUntil(out, null);
        }

        /// Relative-timeout caller-buffer receive. Incomplete Capsule bytes
        /// and a complete payload rejected for short output remain resumable.
        pub fn receiveIntoWithTimeout(
            self: *Self,
            out: []u8,
            timeout: std.Io.Duration,
        ) !ConnectUdp.ReceivedUdpPayload {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveIntoWithDeadline(out, .fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        /// Absolute awake-clock counterpart to `receiveIntoWithTimeout`.
        pub fn receiveIntoWithDeadline(
            self: *Self,
            out: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) !ConnectUdp.ReceivedUdpPayload {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveIntoUntil(out, deadline);
        }

        fn prepareSend(self: *Self, payload: []const u8) !void {
            if (self.pending_send) |*pending| {
                if (!pending.matches(payload)) return error.WriteInProgress;
                return;
            }
            if (payload.len > ConnectUdp.max_udp_payload_size) {
                return error.PayloadTooLarge;
            }
            var pending = PendingSend{
                .header_len = 0,
                .payload = payload,
            };
            var offset: usize = 0;
            const capsule_type = try quic.varint.encodeInto(
                pending.header[offset..],
                Capsule.CapsuleType.datagram,
            );
            offset += capsule_type.len;
            const value_len = std.math.add(usize, payload.len, 1) catch
                return error.IntegerOverflow;
            const length = try quic.varint.encodeInto(
                pending.header[offset..],
                @intCast(value_len),
            );
            offset += length.len;
            pending.header[offset] = 0;
            offset += 1;
            pending.header_len = offset;
            self.pending_send = pending;
        }

        fn receiveUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !ConnectUdp.OwnedUdpPayload {
            const buffered = try self.nextDatagramUntil(deadline);
            const owned = try self.allocator.dupe(u8, buffered.payload);
            self.receive_offset += buffered.consumed;
            return .{
                .stream_id = @intCast(self.tunnel.stream_id),
                .storage = owned,
                .payload = owned,
            };
        }

        fn receiveIntoUntil(
            self: *Self,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) !ConnectUdp.ReceivedUdpPayload {
            const buffered = try self.nextDatagramUntil(deadline);
            if (out.len < buffered.payload.len) return error.BufferTooShort;
            @memcpy(out[0..buffered.payload.len], buffered.payload);
            self.receive_offset += buffered.consumed;
            return .{
                .stream_id = @intCast(self.tunnel.stream_id),
                .payload = out[0..buffered.payload.len],
            };
        }

        fn nextDatagramUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !BufferedUdpPayload {
            while (true) {
                if (try self.pollBuffered()) |payload| return payload;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    return self.abortExcessiveLoad();
                }
                if (self.peer_finished) {
                    if (self.bufferedLen() != 0) {
                        return self.abortMalformed(error.BufferTooShort);
                    }
                    return error.ConnectionClosed;
                }
                self.compactReceiveBuffer();
                var data = if (deadline) |absolute|
                    try self.tunnel.readWithDeadline(absolute)
                else
                    try self.tunnel.read();
                defer data.deinit(self.allocator);
                try self.receive_buffer.appendSlice(
                    self.allocator,
                    data.data,
                );
                self.peer_finished = data.end_stream;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    // Complete capsules are drained before another read. A
                    // suffix beyond this bound is therefore one incomplete
                    // capsule, not a batch of ready application messages.
                    if (try self.pollBuffered()) |payload| return payload;
                    if (self.bufferedLen() >
                        self.options.max_incomplete_capsule_bytes)
                    {
                        return self.abortExcessiveLoad();
                    }
                }
            }
        }

        const BufferedUdpPayload = struct {
            payload: []const u8,
            consumed: usize,
        };

        fn pollBuffered(self: *Self) !?BufferedUdpPayload {
            while (self.receive_offset < self.receive_buffer.items.len) {
                const remaining = self.receive_buffer.items[self.receive_offset..];
                const parsed = Capsule.parse(remaining) catch |err| switch (err) {
                    error.BufferTooShort => return null,
                    else => |other| return self.abortMalformed(other),
                };
                if (parsed.capsule.capsule_type !=
                    Capsule.CapsuleType.datagram)
                {
                    self.receive_offset += parsed.consumed;
                    continue;
                }
                const datagram = ConnectUdp.ContextDatagram.parse(
                    parsed.capsule.value,
                ) catch |err| return self.abortMalformed(err);
                if (datagram.context_id != ConnectUdp.udp_context_id) {
                    self.receive_offset += parsed.consumed;
                    continue;
                }
                return .{
                    .payload = datagram.payload,
                    .consumed = parsed.consumed,
                };
            }
            self.receive_buffer.clearRetainingCapacity();
            self.receive_offset = 0;
            return null;
        }

        fn bufferedLen(self: *const Self) usize {
            return self.receive_buffer.items.len - self.receive_offset;
        }

        fn compactReceiveBuffer(self: *Self) void {
            if (self.receive_offset == 0) return;
            const remaining = self.bufferedLen();
            if (remaining != 0) {
                @memmove(
                    self.receive_buffer.items[0..remaining],
                    self.receive_buffer.items[self.receive_offset..],
                );
            }
            self.receive_buffer.items.len = remaining;
            self.receive_offset = 0;
        }

        fn abortMalformed(self: *Self, err: anyerror) anyerror {
            self.tunnel.reset(ResetCode.protocol_error) catch |reset_err| {
                return reset_err;
            };
            return err;
        }

        fn abortExcessiveLoad(self: *Self) anyerror {
            self.tunnel.reset(ResetCode.enhance_your_calm) catch |err| {
                return err;
            };
            return error.ExcessiveLoad;
        }
    };
}
