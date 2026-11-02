const std = @import("std");
const grpc = @import("../../mod.zig");
const allocator = std.testing.allocator;

test "ordinary Channel health gate restarted Watch returns to CONNECTING before SERVING" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var started: std.Io.Event = .unset;
    var serve: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {}
        fn run(listener: *grpc.runtime.Server, run_io: std.Io, established: *std.Io.Event, serving: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer first.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, first.path);
            try connection.writeUnary(first.transport.stream_id, .{ .status = .unavailable, .trailers_only = true });
            var second = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer second.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, second.path);
            established.set(run_io);
            try serving.wait(run_io);
            var writer = try connection.startStreamingResponse(second.transport.stream_id, .{});
            defer writer.deinit();
            const message = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(message);
            try writer.writeMessage(message);
            var application = try listener.acceptWithTimeout(.fromSeconds(3));
            defer application.deinit();
            var request = try application.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            try writer.finishWithOptions(.{ .status = .unimplemented });
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io, &started, &serve });
    defer _ = peer.cancel(io) catch {};
    var channel = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();
    try started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    const sync = channel.health_sync.?;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    while (true) {
        const generation = sync.snapshot();
        if (channel.healthServingAt(0) == null) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try sync.wait(io, generation, until);
    }
    // A pending fresh Watch queues both modes. These fail-fast calls exhaust
    // their own budgets without opening an application connection.
    try std.testing.expectError(error.Timeout, channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .timeout = .{ .value = 20, .unit = .millisecond } }));
    try std.testing.expectError(error.Timeout, channel.startStreaming(.{ .path = "/demo.Echo/Stream", .timeout = .{ .value = 20, .unit = .millisecond } }));
    try std.testing.expectError(error.Timeout, channel.startDuplex(.{ .path = "/demo.Echo/Duplex", .timeout = .{ .value = 20, .unit = .millisecond } }));
    try std.testing.expectEqual(@as(?bool, null), channel.healthServingAt(0));
    serve.set(io);
    var response = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .timeout = .{ .value = 3, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    try peer.await(io);
}
