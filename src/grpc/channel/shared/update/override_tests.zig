const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const allocator = std.testing.allocator;

test "gRPC shared update preserves actual explicit round robin over JSON weighted targets" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var a_peer = support.Peer{ .server = &a, .authority = "localhost", .reply = "A", .requests = 2 };
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 2 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const path = [_][]const u8{"a"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &path } },
    };
    const weighted = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"pick_first\":{}}]}}}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .channel = .{ .selection_policy = .round_robin }, .service_config_json = weighted });
    var live = true;
    defer if (live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(5));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try support.ready(&a_watch);
    try support.ready(&b_watch);
    var sender = client.sender();
    defer sender.deinit();
    for (0..2) |phase| {
        if (phase != 0) _ = try client.update(.{ .service_config = .{ .replace = weighted } });
        try std.testing.expectEqual(grpc.ChannelSelectionPolicy.round_robin, client.selectionPolicy());
        for ([_][]const u8{ "A", "B" }) |expected| {
            var response = try sender.unary(.{ .path = "/demo.Update/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
            defer response.deinit();
            try std.testing.expectEqualStrings(expected, response.message.?.payload);
        }
    }
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared update rejects an unusable custom ring before publication" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Connector = struct {
        fn connect(_: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../../../http2/mod.zig").runtime.Error!@import("../../../../http2/mod.zig").runtime.Connection {
            return error.ConnectionRefused;
        }
    };
    var client = try shared.SharedChannel.init(allocator, threaded.io(), .{ .custom = .{ .context = null, .connect_fn = Connector.connect } }, .{});
    defer client.deinit();
    try std.testing.expectError(error.InvalidSharedOptions, client.update(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"ring_hash_experimental\":{}}]}" } }));
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expectEqual(grpc.ChannelSelectionPolicy.pick_first, client.selectionPolicy());
    try std.testing.expect(!client.state.demand);
    try std.testing.expectError(error.InvalidSharedOptions, shared.SharedChannel.init(allocator, threaded.io(), .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .channel = .{ .selection_policy = .weighted_target } }));
}
