const std = @import("std");
const grpc = @import("../../mod.zig");
const gate_module = @import("../health_gate.zig");
const allocator = std.testing.allocator;

test "ordinary Channel health gate keeps UNIMPLEMENTED disabled and ends its worker" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();

    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var watch_connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer watch_connection.deinit();
            const Collector = struct {
                count: usize = 0,
                fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                    try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
                    self.count += 1;
                }
            };
            var collector: Collector = .{};
            var watch = try watch_connection.readStreamingWithTimeout(.fromSeconds(3), &collector, Collector.consume);
            defer watch.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, watch.path);
            try std.testing.expectEqual(@as(usize, 1), collector.count);
            try watch_connection.writeUnary(watch.transport.stream_id, .{ .status = .unimplemented, .trailers_only = true });

            var application = try listener.acceptWithTimeout(.fromSeconds(3));
            defer application.deinit();
            for (0..2) |_| {
                var request = try application.readUnaryWithTimeout(.fromSeconds(3));
                defer request.deinit();
                try std.testing.expectEqualStrings("/demo.Echo/Unary", request.request.path);
                try std.testing.expectEqualStrings("ping", request.request.message.payload);
                try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            }
        }
    };
    var peer = try io.concurrent(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};

    var channel = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();
    const gate = channel.slots[0].health_gate.?;
    const Completion = struct {
        gate: *gate_module.Gate,
        io: std.Io,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            self.gate.task.?.await(self.io);
            self.done.set(self.io);
        }
    };
    var completion = Completion{ .gate = gate, .io = io };
    var joined = try io.concurrent(Completion.run, .{&completion});
    defer {
        // Bound cleanup even if a regression spins on HealthWatchDisabled.
        gate.stopped.store(true, .release);
        joined.cancel(io);
    }
    try completion.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    joined.await(io);
    try std.testing.expectEqual(@as(?bool, true), channel.healthServing());
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));

    for (0..2) |_| {
        var response = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .timeout = .{ .value = 1, .unit = .second } });
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.ok, response.status);
        try std.testing.expectEqualStrings("pong", response.message.?.payload);
        try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    }
    try peer.await(io);
}
