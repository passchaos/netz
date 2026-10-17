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

        const Self = @This();

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
            while (true) {
                const raw = try self.transport
                    .receiveConnectDatagramWithDeadline(
                    self.stream_id,
                    deadline,
                );
                if (try self.adopt(raw)) |payload| return payload;
            }
        }
    };
}
