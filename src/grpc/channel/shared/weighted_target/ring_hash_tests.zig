const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const Peer = @import("test_support.zig").Peer;

const allocator = std.testing.allocator;

test "gRPC SharedChannel weighted target ring hash owns hash and fallback" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a_peer = io.async(Peer.run, .{ &a_server, &stop, "a", null });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &stop, "b", null });
    defer _ = b_peer.cancel(io) catch {};
    const path = [_][]const u8{"ring"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address(), .ring_hash_key = "a", .ring_hash_weight = 1, .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = a_server.address(), .ring_hash_key = "a", .ring_hash_weight = 2, .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = b_server.address(), .ring_hash_key = "b", .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .ring_hash_key = "c", .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .channel = .{ .backoff = .{
            .initial_backoff = .fromMilliseconds(20),
            .max_backoff = .fromMilliseconds(20),
            .multiplier = 1,
            .jitter = 0,
            .min_connect_timeout = .fromMilliseconds(50),
        } },
        .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"ring":{"weight":1,"childPolicy":[
        \\  {"ring_hash_experimental":{"minRingSize":16,
        \\   "maxRingSize":16,"requestHashHeader":"x-shard"}}]}}
        \\ }}]}
        ,
    });
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(@as(usize, 3), client.endpointCount());
    try std.testing.expectEqual(
        @as(usize, 4),
        client.configuredEndpointCount(),
    );
    try client.connectWithTimeout(.fromSeconds(5));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try a_watch.waitForReadyWithTimeout(.fromSeconds(5));
    try b_watch.waitForReadyWithTimeout(.fromSeconds(5));
    var sender = client.sender();
    defer sender.deinit();
    var a = try ringCall(sender, "a_0", grpc.ringHash("b_0"));
    defer a.deinit();
    try std.testing.expectEqualStrings("a", a.message.?.payload);
    var b = try ringCall(sender, "b_0", grpc.ringHash("a_0"));
    defer b.deinit();
    try std.testing.expectEqualStrings("b", b.message.?.payload);
    var fallback = try ringCall(sender, "c_0", null);
    defer fallback.deinit();
    const fallback_label = fallback.message.?.payload;
    try std.testing.expect(std.mem.eql(u8, fallback_label, "a") or std.mem.eql(u8, fallback_label, "b"));
    var stream = try sender.startDuplex(.{
        .path = "/demo.WeightedTarget/Duplex",
        .authority = "localhost",
        .metadata = &.{.{ .name = "x-shard", .value = "b_0" }},
        .request_hash = grpc.ringHash("a_0"),
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
    defer stream.deinit();
    var writer = stream.writer();
    defer writer.deinit();
    var reader = stream.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("request");
    var stream_messages: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings("b", message.payload);
                stream_messages += 1;
            },
            .terminal => |response| {
                try std.testing.expectEqual(grpc.Status.ok, response.status);
                try std.testing.expectEqual(@as(usize, 1), stream_messages);
                break;
            },
            else => {},
        }
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}

fn ringCall(sender: shared.Sender, shard: []const u8, explicit: ?u64) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .authority = "localhost",
        .message = "request",
        .metadata = &.{.{ .name = "x-shard", .value = shard }},
        .request_hash = explicit,
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}
