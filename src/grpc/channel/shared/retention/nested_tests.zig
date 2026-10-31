const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC retained child splits a reactivated parent into retained nested children" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const path_a = [_][]const u8{ "region", "a" };
    const path_b = [_][]const u8{ "region", "b" };
    const other = [_][]const u8{"other"};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &path_b), support.endpoint(.{ .ip4 = .loopback(3) }, &other) };
    const both = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"region\":{\"weight\":1,\"childPolicy\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]},\"b\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}}}}]}";
    const only_a = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"region\":{\"weight\":1,\"childPolicy\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}}}}]}";
    const outside = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"other\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = both });
    defer client.deinit();
    const original_a = client.state.sources[0];
    const original_b = client.state.sources[1];
    _ = try client.update(.{ .service_config = .{ .replace = outside } });
    try std.testing.expectEqual(@as(usize, 1), client.retainedChildCount());
    _ = try client.update(.{ .service_config = .{ .replace = only_a } });
    {
        client.state.lock();
        defer client.state.unlock();
        const now = std.Io.Clock.awake.now(io).nanoseconds;
        try std.testing.expect(client.state.retention.lookup(&path_b, now) != null);
        try std.testing.expect(client.state.retention.lookup(&.{"region"}, now) == null);
        try std.testing.expect(!original_a.suspended and original_b.suspended);
    }
    _ = try client.update(.{ .service_config = .{ .replace = both } });
    try std.testing.expect(!original_b.suspended and !original_b.retired);
    try std.testing.expect(client.state.sources[1] == original_b);
}

test "gRPC retained child zero duration disables caching and closes admission immediately" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(2) });
    defer threaded.deinit();
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &support.path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &support.path_b) };
    var client = try shared.SharedChannel.init(allocator, threaded.io(), .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = support.cfg_a, .removed_child_retention = .zero });
    defer client.deinit();
    _ = try client.update(.{ .service_config = .{ .replace = support.cfg_b } });
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(client.state.sources[0].retired);
    try std.testing.expectEqual(@as(usize, 0), client.state.sources[0].current.len);
}
