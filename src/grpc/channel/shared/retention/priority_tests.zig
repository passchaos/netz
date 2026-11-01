const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

const cfg_both =
    \\{"loadBalancingConfig":[{"priority_experimental":{
    \\ "children":{
    \\  "high":{"config":[{"round_robin":{}}]},
    \\  "low":{"config":[{"round_robin":{}}]}},
    \\ "priorities":["high","low"]}}]}
;
const cfg_high =
    \\{"loadBalancingConfig":[{"priority_experimental":{
    \\ "children":{"high":{"config":[{"round_robin":{}}]}},
    \\ "priorities":["high"]}}]}
;

test "gRPC retained priority child reactivates its transport" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var low_peer = support.Peer{ .server = &low_server, .authority = "localhost", .reply = "low", .requests = 1 };
    var low_task = io.async(support.Peer.run, .{&low_peer});
    defer _ = low_task.cancel(io) catch {};
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    // The high priority is unreachable so the lower child becomes active and
    // owns the transport that retention must preserve.
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &high_path), support.endpoint(low_server.address(), &low_path) };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = cfg_both });
    defer client.deinit();
    client.connect();
    var low_watch = client.watchEndpointConnectivity(1).?;
    defer low_watch.deinit();
    while ((try low_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    const original_high = client.state.sources[0];
    const original_low = client.state.sources[1];
    _ = try client.update(.{ .service_config = .{ .replace = cfg_high } });
    try std.testing.expectEqual(@as(usize, 1), client.retainedChildCount());
    try std.testing.expect(!original_high.suspended and !original_high.retired);
    try std.testing.expect(original_low.suspended and !original_low.retired);
    _ = try client.update(.{ .service_config = .{ .replace = cfg_both } });
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(client.state.sources[1] == original_low);
    try std.testing.expect(!original_low.suspended and !original_low.retired);
}

test "gRPC retained nested priority child reactivates inside a retained parent" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const nested_both =
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{
        \\  "high":{"config":[{"priority_experimental":{
        \\   "children":{
        \\    "high1":{"config":[{"round_robin":{}}]},
        \\    "high2":{"config":[{"round_robin":{}}]}},
        \\   "priorities":["high1","high2"]}}]},
        \\  "low":{"config":[{"round_robin":{}}]}},
        \\ "priorities":["high","low"]}}]}
    ;
    const nested_only_high1 =
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{
        \\  "high":{"config":[{"priority_experimental":{
        \\   "children":{"high1":{"config":[{"round_robin":{}}]}},
        \\   "priorities":["high1"]}}]},
        \\  "low":{"config":[{"round_robin":{}}]}},
        \\ "priorities":["high","low"]}}]}
    ;
    var high2_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer high2_server.deinit();
    var low_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer low_server.deinit();
    var high2_peer = support.Peer{ .server = &high2_server, .authority = "localhost", .reply = "high2", .requests = 1 };
    var low_peer = support.Peer{ .server = &low_server, .authority = "localhost", .reply = "low", .requests = 1 };
    var high2_task = io.async(support.Peer.run, .{&high2_peer});
    defer _ = high2_task.cancel(io) catch {};
    var low_task = io.async(support.Peer.run, .{&low_peer});
    defer _ = low_task.cancel(io) catch {};
    const high1_path = [_][]const u8{ "high", "high1" };
    const high2_path = [_][]const u8{ "high", "high2" };
    const low_path = [_][]const u8{"low"};
    // The nested high1 child is unreachable, so high2 becomes the active
    // nested priority whose transport retention must preserve.
    const endpoints = [_]grpc.ChannelEndpoint{
        support.endpoint(.{ .ip4 = .loopback(1) }, &high1_path),
        support.endpoint(high2_server.address(), &high2_path),
        support.endpoint(low_server.address(), &low_path),
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = nested_both });
    defer client.deinit();
    client.connect();
    var high2_watch = client.watchEndpointConnectivity(1).?;
    defer high2_watch.deinit();
    while ((try high2_watch.nextWithTimeout(.fromSeconds(3))).state != .ready) {}
    const original_high1 = client.state.sources[0];
    const original_high2 = client.state.sources[1];
    _ = try client.update(.{ .service_config = .{ .replace = nested_only_high1 } });
    try std.testing.expectEqual(@as(usize, 1), client.retainedChildCount());
    try std.testing.expect(!original_high1.suspended and !original_high1.retired);
    try std.testing.expect(original_high2.suspended and !original_high2.retired);
    _ = try client.update(.{ .service_config = .{ .replace = nested_both } });
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(client.state.sources[1] == original_high2);
    try std.testing.expect(!original_high2.suspended and !original_high2.retired);
}

test "gRPC retained priority child zero duration retires immediately" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const high_path = [_][]const u8{"high"};
    const low_path = [_][]const u8{"low"};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &high_path), support.endpoint(.{ .ip4 = .loopback(2) }, &low_path) };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = cfg_both, .removed_child_retention = .zero });
    defer client.deinit();
    _ = try client.update(.{ .service_config = .{ .replace = cfg_high } });
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(client.state.sources[1].retired);
}
