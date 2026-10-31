const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const allocator = std.testing.allocator;

fn unary(sender: shared.Sender, message: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Update/Unary", .authority = "localhost", .message = message, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}

test "gRPC shared update gates new RPCs on changed health service without canceling active RPC" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var active: std.Io.Event = .unset;
    var health_entered: std.Io.Event = .unset;
    var serving: std.Io.Event = .unset;
    const Peer = struct {
        fn health(_: void, message: grpc.StreamingMessage) !void {
            const request = try grpc.health.decodeRequest(message.payload);
            try std.testing.expectEqualStrings("updated-service", request.service);
        }
        fn run(listener: *grpc.runtime.Server, admitted: *std.Io.Event, health_seen: *std.Io.Event, release_health: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer first.deinit();
            admitted.set(connection.connection.io);
            var watch = try connection.readStreamingWithTimeout(.fromSeconds(5), {}, health);
            defer watch.deinit();
            health_seen.set(connection.connection.io);
            try connection.writeUnary(first.request.stream_id, .{ .message = "active-finished" });
            try support.wait(release_health, connection.connection.io);
            var writer = try connection.startStreamingResponse(watch.transport.stream_id, .{});
            defer writer.deinit();
            try support.serving(&writer);
            var second = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer second.deinit();
            try connection.writeUnary(second.request.stream_id, .{ .message = "health-ready" });
            try support.healthClosed(&connection, &writer, watch.transport.stream_id);
            var third = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer third.deinit();
            try connection.writeUnary(third.request.stream_id, .{ .message = "checking-cleared" });
            try support.closed(&connection);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &active, &health_entered, &serving });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(unary, .{ sender, "active" });
    defer _ = pending.cancel(io) catch {};
    try support.wait(&active, io);
    const source = client.state.sources[0];
    _ = try client.updateWithTimeout(.{ .service_config = .{ .replace = "{\"healthCheckConfig\":{\"serviceName\":\"updated-service\"}}" } }, .fromSeconds(3));
    try support.wait(&health_entered, io);
    var first = try pending.await(io);
    defer first.deinit();
    try std.testing.expectEqualStrings("active-finished", first.message.?.payload);
    try std.testing.expectEqual(grpc.ChannelConnectivityState.connecting, client.connectivityState());
    serving.set(io);
    var second = try unary(sender, "after-health");
    defer second.deinit();
    try std.testing.expectEqualStrings("health-ready", second.message.?.payload);
    _ = try client.update(.{ .service_config = .{ .replace = null } });
    var third = try unary(sender, "after-clear");
    defer third.deinit();
    try std.testing.expectEqualStrings("checking-cleared", third.message.?.payload);
    try std.testing.expect(client.state.sources[0] == source);
    client.deinit();
    live = false;
    try peer.await(io);
}
