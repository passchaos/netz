const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC retained child rolls back when manager task cannot be admitted" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(2) });
    defer threaded.deinit();
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &support.path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &support.path_b) };
    var client = try shared.SharedChannel.init(allocator, threaded.io(), .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = support.cfg_a });
    defer client.deinit();
    try std.testing.expectError(error.ConcurrencyUnavailable, client.update(.{ .service_config = .{ .replace = support.cfg_b } }));
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(!client.state.sources[0].suspended);
}

test "gRPC retained child allocation failure preserves active configuration" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &support.path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &support.path_b) };
            var client = try shared.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = support.cfg_a });
            defer client.deinit();
            _ = client.update(.{ .service_config = .{ .replace = support.cfg_b } }) catch |err| {
                try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
                try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
                try std.testing.expect(!client.state.sources[0].suspended);
                return err;
            };
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}

test "gRPC retained child capacity rejects another removal without extending the first deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const path_c = [_][]const u8{"c"};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &support.path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &support.path_b), support.endpoint(.{ .ip4 = .loopback(3) }, &path_c) };
    const abc = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]},\"b\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]},\"c\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
    const bc = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"b\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]},\"c\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = abc, .max_retained_children = 1 });
    defer client.deinit();
    _ = try client.update(.{ .service_config = .{ .replace = bc } });
    client.state.lock();
    const expires = client.state.retention.head.?.expires_ns;
    client.state.unlock();
    _ = try client.update(.{ .service_config = .{ .replace = bc } });
    try std.testing.expectError(error.SharedRetentionFull, client.update(.{ .service_config = .{ .replace = support.cfg_b } }));
    {
        client.state.lock();
        defer client.state.unlock();
        try std.testing.expectEqual(expires, client.state.retention.head.?.expires_ns);
        try std.testing.expectEqual(@as(usize, 1), client.state.retention.count);
        try std.testing.expectEqual(@as(u64, 3), client.state.config_revision);
        try std.testing.expect(!client.state.sources[2].suspended);
    }
}
