//! Typed RFC 9298 Context ID 0 data plane over a detached HTTP Datagram
//! association.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn Session(
    comptime Http3: type,
    comptime ConnectUdp: type,
    comptime Transport: type,
) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: *Transport,
        stream_id: u62,
        send_scratch: std.ArrayList(u8) = .empty,
        receive_scratch: std.ArrayList(u8) = .empty,
        pending_receive: ?PendingReceive = null,

        const Self = @This();
        pub const supports_blocking_relay = false;

        const PendingReceive = struct {
            offset: usize,
            len: usize,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            transport: *Transport,
            stream_id: u62,
        ) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .transport = transport,
                .stream_id = stream_id,
            };
        }

        pub fn deinit(self: *Self) void {
            self.send_scratch.deinit(self.allocator);
            self.receive_scratch.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn maxPayloadSize(self: *const Self) ?usize {
            const maximum = self.transport.maxConnectDatagramPayloadSize(
                self.stream_id,
            ) orelse return null;
            return ConnectUdp.maxUdpPayloadForHttpDatagram(maximum);
        }

        fn encode(self: *Self, payload: []const u8) ![]const u8 {
            const value = ConnectUdp.ContextDatagram{
                .context_id = ConnectUdp.udp_context_id,
                .payload = payload,
            };
            try self.send_scratch.resize(
                self.allocator,
                try value.encodedLen(),
            );
            return try value.writeInto(self.send_scratch.items);
        }

        pub fn send(self: *Self, payload: []const u8) !void {
            try self.transport.sendConnectDatagram(
                self.stream_id,
                try self.encode(payload),
            );
        }

        pub fn trySend(self: *Self, payload: []const u8) !void {
            try self.transport.trySendConnectDatagram(
                self.stream_id,
                try self.encode(payload),
            );
        }

        pub fn sendWithTimeout(
            self: *Self,
            payload: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            try self.transport.sendConnectDatagramWithTimeout(
                self.stream_id,
                try self.encode(payload),
                timeout,
            );
        }

        pub fn sendWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            try self.transport.sendConnectDatagramWithDeadline(
                self.stream_id,
                try self.encode(payload),
                deadline,
            );
        }

        fn adopt(
            self: *Self,
            raw: anytype,
        ) !?ConnectUdp.OwnedUdpPayload {
            var owned = raw;
            const datagram = ConnectUdp.ContextDatagram.parse(
                owned.payload,
            ) catch |err| {
                owned.deinit(self.allocator);
                try self.transport.cancelRequest(
                    self.stream_id,
                    Http3.ApplicationErrorCode.message_error,
                );
                return err;
            };
            if (datagram.context_id != ConnectUdp.udp_context_id) {
                owned.deinit(self.allocator);
                return null;
            }
            return .{
                .stream_id = owned.stream_id,
                .storage = owned.payload,
                .payload = datagram.payload,
            };
        }

        pub fn receive(self: *Self) !ConnectUdp.OwnedUdpPayload {
            if (try self.takePendingOwned()) |payload| return payload;
            while (true) {
                const raw = try self.transport.receiveConnectDatagram(
                    self.stream_id,
                );
                if (try self.adopt(raw)) |payload| return payload;
            }
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
            if (try self.takePendingOwned()) |payload| return payload;
            while (true) {
                const raw = try self.transport
                    .receiveConnectDatagramWithDeadline(
                    self.stream_id,
                    deadline,
                );
                if (try self.adopt(raw)) |payload| return payload;
            }
        }

        /// Receive one Context ID 0 UDP payload into caller storage. A short
        /// output retains the complete datagram for a later owning or
        /// caller-buffer retry.
        pub fn receiveInto(
            self: *Self,
            out: []u8,
        ) !ConnectUdp.ReceivedUdpPayload {
            return self.receiveIntoUntil(out, null);
        }

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

        pub fn receiveIntoWithDeadline(
            self: *Self,
            out: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) !ConnectUdp.ReceivedUdpPayload {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveIntoUntil(out, deadline);
        }

        fn receiveIntoUntil(
            self: *Self,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) !ConnectUdp.ReceivedUdpPayload {
            if (try self.copyPendingInto(out)) |payload| return payload;
            const maximum = self.transport.maxConnectDatagramPayloadSize(
                self.stream_id,
            ) orelse return error.DatagramUnavailable;
            try self.receive_scratch.resize(self.allocator, maximum);
            while (true) {
                const raw = if (deadline) |absolute|
                    try self.transport.receiveConnectDatagramIntoWithDeadline(
                        self.stream_id,
                        self.receive_scratch.items,
                        absolute,
                    )
                else
                    try self.transport.receiveConnectDatagramInto(
                        self.stream_id,
                        self.receive_scratch.items,
                    );
                const datagram = ConnectUdp.ContextDatagram.parse(raw) catch |err| {
                    try self.transport.cancelRequest(
                        self.stream_id,
                        Http3.ApplicationErrorCode.message_error,
                    );
                    return err;
                };
                if (datagram.context_id != ConnectUdp.udp_context_id) continue;
                const offset = @intFromPtr(datagram.payload.ptr) -
                    @intFromPtr(self.receive_scratch.items.ptr);
                self.pending_receive = .{
                    .offset = offset,
                    .len = datagram.payload.len,
                };
                return (try self.copyPendingInto(out)).?;
            }
        }

        fn copyPendingInto(
            self: *Self,
            out: []u8,
        ) !?ConnectUdp.ReceivedUdpPayload {
            const pending = self.pending_receive orelse return null;
            if (out.len < pending.len) return error.BufferTooShort;
            @memcpy(
                out[0..pending.len],
                self.receive_scratch.items[pending.offset..][0..pending.len],
            );
            self.pending_receive = null;
            return .{
                .stream_id = self.stream_id,
                .payload = out[0..pending.len],
            };
        }

        fn takePendingOwned(
            self: *Self,
        ) !?ConnectUdp.OwnedUdpPayload {
            const pending = self.pending_receive orelse return null;
            const owned = try self.allocator.dupe(
                u8,
                self.receive_scratch.items[pending.offset..][0..pending.len],
            );
            self.pending_receive = null;
            return .{
                .stream_id = self.stream_id,
                .storage = owned,
                .payload = owned,
            };
        }
    };
}
