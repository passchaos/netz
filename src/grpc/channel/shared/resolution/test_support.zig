const std = @import("std");
pub const grpc = @import("../../../mod.zig");
pub const shared = @import("../../shared.zig");
pub const allocator = std.testing.allocator;
pub const Address = std.Io.net.IpAddress;

pub const Resolver = struct {
    mutex: std.Io.Mutex = .init,
    addresses: []const Address,
    failure: ?grpc.ChannelAddressResolver.ResolveError = null,
    calls: std.atomic.Value(usize) = .init(0),

    pub fn interface(self: *Resolver) grpc.ChannelAddressResolver {
        return .{ .context = self, .resolve = resolve };
    }
    pub fn set(self: *Resolver, io: std.Io, addresses: []const Address, failure: ?grpc.ChannelAddressResolver.ResolveError) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.addresses = addresses;
        self.failure = failure;
    }
    fn resolve(context: *anyopaque, gpa: std.mem.Allocator, io: std.Io, host: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) grpc.ChannelAddressResolver.ResolveError![]Address {
        const self: *Resolver = @ptrCast(@alignCast(context));
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        _ = self.calls.fetchAdd(1, .monotonic);
        std.debug.assert(std.mem.eql(u8, host, "resolve.test"));
        if (self.failure) |err| return err;
        return gpa.dupe(Address, self.addresses);
    }
};

pub fn options(resolver: *Resolver) shared.Options {
    return .{ .channel = .{
        .address_resolver = resolver.interface(),
        .resolver_min_refresh_interval = .zero,
        .backoff = .{ .initial_backoff = .fromMilliseconds(50), .max_backoff = .fromMilliseconds(50), .multiplier = 1, .jitter = 0, .min_connect_timeout = .fromSeconds(2) },
    } };
}
pub fn wait(event: *std.Io.Event, io: std.Io) !void {
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    while (true) {
        event.waitTimeout(io, .{ .deadline = until }) catch |err| {
            if (err == error.Timeout and until.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}
pub fn ready(watch: *grpc.ChannelConnectivityWatch) !void {
    try watch.waitForReadyWithTimeout(.fromSeconds(5));
}
pub fn unary(sender: shared.Sender, message: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Shared/Unary", .message = message, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}
pub fn healthRequest(_: void, message: grpc.StreamingMessage) !void {
    _ = try grpc.health.decodeRequest(message.payload);
}
pub fn serving(writer: *grpc.stream.ServerWriter) !void {
    const bytes = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
    defer allocator.free(bytes);
    try writer.writeMessage(bytes);
}
pub fn closed(connection: *grpc.runtime.ServerConnection) !void {
    var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
        error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
        else => return err,
    };
    defer reset.deinit(allocator);
    return error.UnexpectedReset;
}
pub fn healthClosed(connection: *grpc.runtime.ServerConnection, writer: *grpc.stream.ServerWriter, id: u31) !void {
    var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
        error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => {
            writer.transport.finished = true;
            return;
        },
        else => return err,
    };
    defer reset.deinit(allocator);
    try std.testing.expectEqual(id, reset.reset.stream_id);
    try std.testing.expectEqual(@import("../../../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
    writer.transport.finished = true;
}

pub const Peer = struct {
    server: *grpc.runtime.Server,
    authority: []const u8,
    reply: []const u8,
    requests: usize,
    admitted: ?*std.Io.Event = null,
    release: ?*std.Io.Event = null,

    pub fn run(self: *Peer) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        for (0..self.requests) |index| {
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try std.testing.expectEqualStrings(self.authority, grpc.call.headerValue(request.request.headers, ":authority").?);
            if (index + 1 == self.requests) {
                if (self.admitted) |event| event.set(connection.connection.io);
                if (self.release) |event| try wait(event, connection.connection.io);
            }
            try connection.writeUnary(request.request.stream_id, .{ .message = self.reply });
        }
        try closed(&connection);
    }
};
