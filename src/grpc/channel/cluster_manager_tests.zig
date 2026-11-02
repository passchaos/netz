//! Cluster configuration, route lifetime and live transport isolation.
const std = @import("std");
const grpc = @import("../mod.zig");
const shared = @import("shared.zig");
const service = @import("../service_config.zig");
const route = @import("cluster_route.zig");
const allocator = std.testing.allocator;
const Peer = @import("shared/weighted_target/test_support.zig").Peer;

pub const json =
    \\{"loadBalancingConfig":[{"xds_cluster_manager_experimental":{"children":{
    \\ "a":{"childPolicy":[{"round_robin":{}}]},
    \\ "b":{"childPolicy":[{"pick_first":{}}]},
    \\ "failed":{"childPolicy":[{"round_robin":{}}]}
    \\ }}}]}
;
const without_a =
    \\{"loadBalancingConfig":[{"xds_cluster_manager_experimental":{"children":{
    \\ "b":{"childPolicy":[{"pick_first":{}}]},
    \\ "failed":{"childPolicy":[{"round_robin":{}}]}
    \\ }}}]}
;

fn unary(client: anytype, cluster: ?[]const u8) !grpc.UnaryResponse {
    return client.unary(.{ .path = "/demo.Cluster/Unary", .message = "request", .xds_cluster = cluster, .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
fn blocked(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Cluster/Unary", .message = "request", .xds_cluster = "failed", .wait_for_ready = true, .timeout = .{ .value = 200, .unit = .millisecond } });
}

test "gRPC cluster manager parses child policies and empty maps with bounded recursion" {
    var config = try service.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    const root = config.loadBalancingConfig().root.?;
    try std.testing.expect(root.* == .cluster_manager);
    try std.testing.expectEqual(@as(usize, 3), root.cluster_manager.targets.len);
    try std.testing.expectEqualStrings("a", root.cluster_manager.targets[0].name);
    const Runtime = @import("shared/state.zig").State.WeightedTarget;
    var runtime = try Runtime.init(allocator, root);
    defer runtime.deinit();
    try route.validate(runtime.root, "a");
    try route.validate(runtime.root, "b");
    try std.testing.expectError(error.UnknownCluster, route.validate(runtime.root, "missing"));
    try std.testing.expectError(error.UnknownCluster, route.validate(runtime.root, null));
    var empty = try service.ServiceConfig.parse(allocator, "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{}}}]}");
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.loadBalancingConfig().root.?.cluster_manager.targets.len);
    for ([_][]const u8{
        "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{}}]}",
        "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":[]}}]}",
        "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{}}}}]}",
        "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":[{\"unknown\":{}}]}}}}]}",
    }) |invalid| try std.testing.expectError(error.InvalidServiceConfig, service.ServiceConfig.parse(allocator, invalid));
    var recursive: std.ArrayList(u8) = .empty;
    defer recursive.deinit(allocator);
    try recursive.appendSlice(allocator, "{\"loadBalancingConfig\":");
    for (0..service.max_load_balancing_depth + 2) |_| try recursive.appendSlice(allocator, "[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":");
    try recursive.appendSlice(allocator, "[{\"round_robin\":{}}]");
    for (0..service.max_load_balancing_depth + 2) |_| try recursive.appendSlice(allocator, "}}}}]");
    try recursive.appendSlice(allocator, "}");
    try std.testing.expectError(error.InvalidServiceConfig, service.ServiceConfig.parse(allocator, recursive.items));
}

test "gRPC cluster manager request ownership retains the RPC-local selector" {
    const inputs = @import("shared/request_inputs.zig");
    var selector = [_]u8{ 'a', 'b' };
    var owned = try inputs.clone(allocator, grpc.call.UnaryCallOptions{ .path = "/demo.Cluster/Unary", .message = "request", .xds_cluster = &selector });
    defer owned.inputs.deinit();
    @memset(&selector, 'x');
    try std.testing.expectEqualStrings("ab", owned.options.xds_cluster.?);
    try std.testing.expectEqual(@as(usize, 0), owned.options.metadata.len);
    var stream = try inputs.clone(allocator, grpc.StreamingRequestOptions{ .path = "/demo.Cluster/Stream", .xds_cluster = &selector });
    defer stream.inputs.deinit();
    @memset(&selector, 'y');
    try std.testing.expectEqualStrings("xx", stream.options.xds_cluster.?);
}

fn exercise(comptime is_shared: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a1 = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a1.deinit();
    var a2 = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a2.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var stop: std.Io.Event = .unset;
    var a1_task = io.async(Peer.run, .{ &a1, &stop, "a1", null });
    defer _ = a1_task.cancel(io) catch {};
    var a2_task = io.async(Peer.run, .{ &a2, &stop, "a2", null });
    defer _ = a2_task.cancel(io) catch {};
    var b_task = io.async(Peer.run, .{ &b, &stop, "b", null });
    defer _ = b_task.cancel(io) catch {};
    const Refused = struct {
        attempts: std.atomic.Value(usize) = .init(0),
        fn connect(context: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../http2/mod.zig").runtime.Error!@import("../../http2/mod.zig").runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            _ = self.attempts.fetchAdd(1, .monotonic);
            return error.ConnectionRefused;
        }
    };
    var refused: Refused = .{};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a1.address(), .hierarchical_path = &.{"a"} } },
        .{ .cleartext_ip = .{ .address = a2.address(), .hierarchical_path = &.{"a"} } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"b"} } },
        .{ .custom = .{ .context = &refused, .connect_fn = Refused.connect, .hierarchical_path = &.{"failed"} } },
    };
    var config = try grpc.ServiceConfig.parse(allocator, json);
    var config_live = true;
    defer if (config_live) config.deinit();
    var client = if (is_shared) try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = json }) else try grpc.Channel.initWithServiceConfig(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{}, &config);
    var live = true;
    defer if (live) client.deinit();
    config.deinit();
    config_live = false;
    var sender = if (is_shared) client.sender() else {};
    defer if (is_shared) sender.deinit();
    try std.testing.expectError(error.UnknownCluster, unary(if (is_shared) sender else &client, null));
    try std.testing.expectError(error.UnknownCluster, unary(if (is_shared) sender else &client, "missing"));
    if (is_shared) {
        client.connect();
        for (0..3) |index| {
            var watch = client.watchEndpointConnectivity(index).?;
            defer watch.deinit();
            while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
        }
    }
    var counts = [_]usize{ 0, 0 };
    for (0..20) |index| {
        var a_response = try unary(if (is_shared) sender else &client, "a");
        defer a_response.deinit();
        const payload = a_response.message.?.payload;
        if (std.mem.eql(u8, payload, "a1")) counts[0] += 1 else if (std.mem.eql(u8, payload, "a2")) counts[1] += 1 else return error.CrossClusterDelivery;
        if (index % 2 == 0) {
            var b_response = try unary(if (is_shared) sender else &client, "b");
            defer b_response.deinit();
            try std.testing.expectEqualStrings("b", b_response.message.?.payload);
        }
    }
    try std.testing.expectEqual(@as(usize, 10), counts[0]);
    try std.testing.expectEqual(@as(usize, 10), counts[1]);
    // Streaming uses the same RPC-local selector as unary calls.
    if (is_shared) {
        var duplex = try sender.startDuplex(.{ .path = "/demo.Cluster/Duplex", .xds_cluster = "b", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
        defer duplex.deinit();
        var writer = duplex.writer();
        defer writer.deinit();
        var reader = duplex.reader();
        defer reader.deinit();
        try writer.writeFinalMessage("request");
        try @import("shared/stream/testing.zig").readReply(reader, "b");
    } else {
        var duplex = try client.startDuplex(.{ .path = "/demo.Cluster/Duplex", .xds_cluster = "b", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
        defer duplex.deinit();
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try duplex.writeFinalMessage("request"));
        const Consumer = struct {
            count: usize = 0,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expectEqualStrings("b", message.payload);
                self.count += 1;
            }
        };
        var consumer: Consumer = .{};
        while (true) {
            var event = try duplex.readResponseEventWithTimeout(.fromSeconds(3), &consumer, Consumer.consume);
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                try std.testing.expectEqual(@as(usize, 1), consumer.count);
                break;
            }
        }
    }
    if (is_shared) {
        // A queued wait-for-ready call to the failed child cannot hold the
        // later healthy-cluster request at the global queue head.
        var blocked_call = try io.concurrent(blocked, .{sender});
        defer _ = blocked_call.cancel(io) catch {};
        const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            client.state.mutex.lockUncancelable(io);
            const queued = client.state.head != null;
            client.state.mutex.unlock(io);
            if (queued) break;
            if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
            try std.Io.sleep(io, .fromMilliseconds(1), .awake);
        }
        var healthy = try unary(sender, "b");
        defer healthy.deinit();
        try std.testing.expectEqualStrings("b", healthy.message.?.payload);
        try std.testing.expectError(error.Timeout, blocked_call.await(io));
        try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/demo.Cluster/Unary", .message = "request", .xds_cluster = "failed", .wait_for_ready = false, .timeout = .{ .value = 1, .unit = .second } }));
        const b_worker = client.state.sources[2].current[0];
        _ = try client.updateWithTimeout(.{ .service_config = .{ .replace = without_a } }, .fromSeconds(2));
        try std.testing.expectError(error.UnknownCluster, unary(sender, "a"));
        var surviving = try unary(sender, "b");
        defer surviving.deinit();
        try std.testing.expectEqualStrings("b", surviving.message.?.payload);
        try std.testing.expect(client.state.sources[2].current[0] == b_worker);
        _ = try client.updateWithTimeout(.{ .service_config = .{ .replace = json } }, .fromSeconds(2));
        var restored = try unary(sender, "a");
        defer restored.deinit();
        try std.testing.expect(std.mem.startsWith(u8, restored.message.?.payload, "a"));
    }
    if (!is_shared) try std.testing.expectEqual(@as(usize, 0), refused.attempts.load(.acquire));
    client.deinit();
    live = false;
    stop.set(io);
    try a1_task.await(io);
    try a2_task.await(io);
    try b_task.await(io);
}

test "gRPC cluster manager ordinary routes each RPC to its configured child" {
    try exercise(false);
}
test "gRPC cluster manager shared isolates failed queues and supports removal restoration" {
    try exercise(true);
}

test "gRPC cluster manager construction retains nested locality and cleans allocation failures" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io) !void {
            const nested = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":[{\"round_robin\":{}}]}}]}}}}]}";
            var config = try grpc.ServiceConfig.parse(gpa, nested);
            defer config.deinit();
            const target: grpc.ChannelTarget = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{ "a", "locality" }, .locality_weight = 1 } };
            var ordinary = try grpc.Channel.initWithServiceConfig(gpa, io, target, .{}, &config);
            defer ordinary.deinit();
            try route.validate(ordinary.weighted_target_runtime.?.root, "a");
            var client = try shared.SharedChannel.init(gpa, io, target, .{ .service_config_json = nested });
            defer client.deinit();
            try route.validate(client.state.weighted_target.?.root, "a");
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{threaded.io()});
}
