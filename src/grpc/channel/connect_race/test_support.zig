const std = @import("std");
pub const grpc = @import("../../mod.zig");
pub const allocator = std.testing.allocator;
pub const wait = @import("../shared/resolution/test_support.zig").wait;

pub const Stalled = struct {
    listener: std.Io.net.Server,
    started: std.Io.Event = .unset,
    closed: std.Io.Event = .unset,

    pub fn init(io: std.Io, ipv6: bool) !Stalled {
        const bind_address: std.Io.net.IpAddress = if (ipv6) .{ .ip6 = .loopback(0) } else .{ .ip4 = .loopback(0) };
        return .{ .listener = try bind_address.listen(io, .{ .reuse_address = true }) };
    }
    pub fn deinit(self: *Stalled, io: std.Io) void {
        self.listener.deinit(io);
    }
    pub fn address(self: *const Stalled) std.Io.net.IpAddress {
        return self.listener.socket.address;
    }
    pub fn run(self: *Stalled, io: std.Io) !void {
        const stream = try self.listener.accept(io);
        defer stream.close(io);
        defer self.closed.set(io);
        self.started.set(io);
        var storage: [4096]u8 = undefined;
        var output: [4096]u8 = undefined;
        var reader = stream.reader(io, &storage);
        while (try reader.interface.readSliceShort(&output) != 0) {}
    }
};

pub const Echo = struct {
    server: union(enum) { tcp: *grpc.runtime.Server, tls: *grpc.runtime.TlsServer },
    requests: usize = 2,
    pub fn run(self: *Echo) !void {
        var connection = switch (self.server) {
            .tcp => |server| try server.acceptWithTimeout(.fromSeconds(3)),
            .tls => |server| try server.acceptWithTimeout(.fromSeconds(3)),
        };
        defer connection.deinit();
        for (0..self.requests) |_| {
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try connection.writeUnary(request.request.stream_id, .{ .message = "pong" });
        }
    }
};

pub fn unary(channel: *grpc.Channel) !grpc.UnaryResponse {
    return channel.unary(.{ .path = "/fixture.Race/Unary", .authority = "fixture.test", .message = "ping", .wait_for_ready = true, .timeout = .{ .value = 1500, .unit = .millisecond } });
}
