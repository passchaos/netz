const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const Peer = @import("../weighted_target/test_support.zig").Peer;
const allocator = std.testing.allocator;

test "gRPC shared child state safely replaces a populated ring cache on config update" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Peer{ .server = &server, .authority = "localhost", .reply = "ring", .requests = 2 };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"child"};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .ring_hash_key = "a", .hierarchical_path = &path } }, .{ .service_config_json = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":1,\"childPolicy\":[{\"ring_hash_experimental\":{\"minRingSize\":16,\"maxRingSize\":16}}]}}}}]}" });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const request: grpc.UnaryCallOptions = .{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request", .request_hash = grpc.ringHash("request"), .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } };
    var first = try sender.unary(request);
    defer first.deinit();
    try std.testing.expectEqualStrings("ring", first.message.?.payload);
    _ = try client.update(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":2,\"childPolicy\":[{\"ring_hash_experimental\":{\"minRingSize\":32,\"maxRingSize\":32}}]}}}}]}" } });
    var second = try sender.unary(request);
    defer second.deinit();
    try std.testing.expectEqualStrings("ring", second.message.?.payload);
    {
        client.state.lock();
        defer client.state.unlock();
        const leaf = &client.state.weighted_target.?.root.kind.weighted.children[0].node.kind.leaf;
        try std.testing.expectEqual(@as(usize, 32), leaf.ring.entries.len);
    }
    client.deinit();
    live = false;
    try task.await(io);
}

test "gRPC shared child state keeps round robin position when target weight and methods change" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var a_peer = support.Peer{ .server = &a, .authority = "localhost", .reply = "A", .requests = 1 };
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 1 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const path = [_][]const u8{"child"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}" });
    var live = true;
    defer if (live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try support.ready(&a_watch);
    try support.ready(&b_watch);
    var sender = client.sender();
    defer sender.deinit();
    var first = try sender.unary(.{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer first.deinit();
    try std.testing.expectEqualStrings("A", first.message.?.payload);
    _ = try client.update(.{ .service_config = .{ .replace = "{\"methodConfig\":[{\"name\":[{}],\"timeout\":\"3s\"}],\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":2,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}" } });
    var second = try sender.unary(.{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request" });
    defer second.deinit();
    try std.testing.expectEqualStrings("B", second.message.?.payload);
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared child state remaps outlier buckets and preserves ejection across sibling insertion" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var stop: std.Io.Event = .unset;
    var a_task = io.async(Peer.run, .{ &a, &stop, "bad", @as(?std.Io.Duration, null) });
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "good", .requests = 2 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const path = [_][]const u8{"kept"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{
        \\ "kept":{"weight":1,"childPolicy":[{"outlier_detection_experimental":{
        \\ "interval":"60s","baseEjectionTime":"60s","failurePercentageEjection":{},"childPolicy":[{"round_robin":{}}]}}]}
        \\}}}]}
    });
    var live = true;
    defer if (live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try support.ready(&a_watch);
    try support.ready(&b_watch);
    client.state.lock();
    const bad = client.state.sources[0].current[0];
    const ejected = std.Io.Clock.awake.now(io).nanoseconds;
    bad.weighted_outliers[0].ejected_at_ns = ejected;
    bad.weighted_outliers[0].multiplier = 2;
    bad.weighted_outliers[0].failures.store(7, .monotonic);
    client.state.unlock();
    var sender = client.sender();
    defer sender.deinit();
    var first = try sender.unary(.{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer first.deinit();
    try std.testing.expectEqualStrings("good", first.message.?.payload);
    _ = try client.update(.{ .service_config = .{ .replace =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{
        \\ "added":{"weight":1,"childPolicy":[{"outlier_detection_experimental":{
        \\ "childPolicy":[{"round_robin":{}}]}}]},
        \\ "kept":{"weight":2,"childPolicy":[{"outlier_detection_experimental":{
        \\ "interval":"60s","baseEjectionTime":"60s","failurePercentageEjection":{},"childPolicy":[{"round_robin":{}}]}}]}
        \\}}}]}
    } });
    {
        client.state.lock();
        defer client.state.unlock();
        try std.testing.expectEqual(@as(usize, 2), bad.weighted_outliers.len);
        try std.testing.expectEqual(@as(?i96, ejected), bad.weighted_outliers[1].ejected_at_ns);
        try std.testing.expectEqual(@as(u32, 2), bad.weighted_outliers[1].multiplier);
        try std.testing.expectEqual(@as(u64, 7), bad.weighted_outliers[1].failures.load(.monotonic));
        try std.testing.expect(!bad.weighted_outliers[0].isEjected());
    }
    var second = try sender.unary(.{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer second.deinit();
    try std.testing.expectEqualStrings("good", second.message.?.payload);
    _ = try client.update(.{ .service_config = .{ .replace =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{
        \\ "kept":{"weight":2,"childPolicy":[{"outlier_detection_experimental":{
        \\ "interval":"60s","baseEjectionTime":"60s","childPolicy":[{"round_robin":{}}]}}]}
        \\}}}]}
    } });
    {
        client.state.lock();
        defer client.state.unlock();
        try std.testing.expect(!bad.weighted_outliers[0].isEjected());
        try std.testing.expectEqual(@as(u32, 0), bad.weighted_outliers[0].multiplier);
    }
    var resumed = try sender.unary(.{ .path = "/demo.State/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer resumed.deinit();
    try std.testing.expectEqualStrings("bad", resumed.message.?.payload);
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared child state preserves original snapshot on migration allocation failure" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            const path = [_][]const u8{"child"};
            var client = try shared.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &path } }, .{ .service_config_json = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}" });
            defer client.deinit();
            const root = client.state.weighted_target.?.root;
            const source = client.state.sources[0];
            _ = client.update(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":2,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}" } }) catch |err| {
                try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
                try std.testing.expect(client.state.weighted_target.?.root == root);
                try std.testing.expect(client.state.sources[0] == source);
                return err;
            };
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}
