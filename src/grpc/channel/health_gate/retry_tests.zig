const std = @import("std");
const grpc = @import("../../mod.zig");
const allocator = std.testing.allocator;

test "ordinary Channel health gate rejects retrying Watch and restores wait-for-ready calls" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var retry_ready: std.Io.Event = .unset;
    const RetrySleep = struct {
        base: std.Io,
        permitted: *std.Io.Event,
        var active: ?*@This() = null;
        fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            // Hold the retry timer until all fail-fast checks finish. The
            // server's blocked read alone cannot stop a new Watch starting.
            try self.permitted.wait(self.base);
            return self.base.vtable.sleep(userdata, timeout);
        }
    };
    var retry_sleep = RetrySleep{ .base = base, .permitted = &retry_ready };
    RetrySleep.active = &retry_sleep;
    defer RetrySleep.active = null;
    var table = base.vtable.*;
    table.sleep = RetrySleep.sleep;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn run(listener: *grpc.runtime.Server, run_io: std.Io, ready: *std.Io.Event) !void {
            var watch_connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer watch_connection.deinit();
            var first = try watch_connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer first.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, first.path);
            try watch_connection.writeUnary(first.transport.stream_id, .{ .status = .unavailable, .trailers_only = true });
            try ready.wait(run_io);

            var second = try watch_connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer second.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, second.path);
            var writer = try watch_connection.startStreamingResponse(second.transport.stream_id, .{});
            defer writer.deinit();
            const status = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(status);
            try writer.writeMessage(status);

            var application = try listener.acceptWithTimeout(.fromSeconds(3));
            defer application.deinit();
            var request = try application.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            try writer.finishWithOptions(.{ .status = .unimplemented });
        }
    };
    var peer = try base.concurrent(Peer.run, .{ &server, base, &retry_ready });
    defer _ = peer.cancel(base) catch {};
    var channel = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();

    const sync = channel.health_sync.?;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    while (true) {
        const generation = sync.snapshot();
        if (channel.healthServingAt(0) == false) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try sync.wait(io, generation, until);
    }
    try std.testing.expectEqual(@as(?bool, false), channel.healthServing());
    try std.testing.expectError(error.ConnectionUnavailable, channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .timeout = .{ .value = 1, .unit = .second } }));
    try std.testing.expectError(error.ConnectionUnavailable, channel.startStreaming(.{ .path = "/demo.Echo/Stream", .timeout = .{ .value = 1, .unit = .second } }));
    try std.testing.expectError(error.ConnectionUnavailable, channel.startDuplex(.{ .path = "/demo.Echo/Duplex", .timeout = .{ .value = 1, .unit = .second } }));

    retry_ready.set(io);
    var recovered = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer recovered.deinit();
    try std.testing.expectEqual(grpc.Status.ok, recovered.status);
    try std.testing.expectEqualStrings("pong", recovered.message.?.payload);
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    try peer.await(io);
}
