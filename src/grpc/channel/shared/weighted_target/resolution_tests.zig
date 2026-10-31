const std = @import("std");
const support = @import("../resolution/test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC weighted target ring rebuilds after resolver promotion and drains old worker" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    const port = a_server.address().getPort();
    const authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{port});
    defer allocator.free(authority);
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var a_peer = support.Peer{
        .server = &a_server,
        .authority = authority,
        .reply = "A",
        .requests = 2,
        .admitted = &admitted,
        .release = &release,
    };
    var b_peer = support.Peer{
        .server = &b_server,
        .authority = authority,
        .reply = "B",
        .requests = 1,
    };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const first = [_]support.Address{a_server.address()};
    const second = [_]support.Address{b_server.address()};
    var resolver = support.Resolver{ .addresses = &first };
    const path = [_][]const u8{"ring"};
    var options = support.options(&resolver);
    options.service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"ring":{"weight":1,"childPolicy":[
        \\  {"ring_hash_experimental":{"minRingSize":8,"maxRingSize":8,
        \\   "requestHashHeader":"x-route"}}]}}
        \\ }}]}
    ;
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_host = .{
            .host = "resolve.test",
            .port = port,
            .ring_hash_key = "logical-ring-source",
            .hierarchical_path = &path,
        } },
        options,
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        try client.refreshNameResolutionWithTimeout(.fromSeconds(5)),
    );
    var old_watch = client.watchEndpointConnectivity(0).?;
    defer old_watch.deinit();
    try support.ready(&old_watch);
    var sender = client.sender();
    defer sender.deinit();
    var warm = try call(sender, "warm");
    defer warm.deinit();
    try std.testing.expectEqualStrings("A", warm.message.?.payload);
    var active = try io.concurrent(call, .{ sender, "active" });
    defer _ = active.cancel(io) catch {};
    try support.wait(&admitted, io);

    resolver.set(io, &second, null);
    try std.testing.expectEqual(
        @as(usize, 1),
        try client.refreshNameResolutionWithTimeout(.fromSeconds(5)),
    );
    var new_watch = client.watchEndpointConnectivity(0).?;
    defer new_watch.deinit();
    try support.ready(&new_watch);
    while ((try old_watch.nextWithTimeout(.fromSeconds(5))).state != .shutdown) {}
    var promoted = try call(sender, "promoted");
    defer promoted.deinit();
    try std.testing.expectEqualStrings("B", promoted.message.?.payload);

    release.set(io);
    var drained = try active.await(io);
    defer drained.deinit();
    try std.testing.expectEqualStrings("A", drained.message.?.payload);
    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
}

fn call(sender: shared.Sender, message: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .message = message,
        .metadata = &.{.{ .name = "x-route", .value = "stable" }},
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}
