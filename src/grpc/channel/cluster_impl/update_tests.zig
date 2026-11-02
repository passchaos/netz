//! Pending discovery stays queued; category changes re-evaluate exactly once.
const std = @import("std");
const grpc = @import("../../mod.zig");
const gpa = std.testing.allocator;
fn config(allocator: std.mem.Allocator, full: bool) ![]u8 {
    return std.fmt.allocPrint(allocator, "{{\"loadBalancingConfig\":[{{\"xds_cluster_manager_experimental\":{{\"children\":{{\"a\":{{\"childPolicy\":[{{\"xds_cluster_impl_experimental\":{{\"clusterName\":\"queued-impl\",\"discoveryPending\":{},\"dropCategories\":[{{\"category\":\"policy\",\"requestsPerMillion\":{d}}}],\"childPolicy\":[{{\"round_robin\":{{}}}}]}}}}]}},\"b\":{{\"childPolicy\":[{{\"round_robin\":{{}}}}]}}}}}}}}]}}", .{ !full, @as(u32, if (full) 1000000 else 0) });
}
fn waiting(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Impl/Unary", .message = "request", .xds_cluster = "a", .wait_for_ready = false, .timeout = .{ .value = 3, .unit = .second } });
}
test "gRPC cluster impl preserves queued discovery and unchanged drop draws then rejects a replaced category" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const initial = try config(gpa, false);
    defer gpa.free(initial);
    const replaced = try config(gpa, true);
    defer gpa.free(replaced);
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"b"} } }} } }, .{ .service_config_json = initial });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var pending = try io.concurrent(waiting, .{sender});
    defer _ = pending.cancel(io) catch {};
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        channel.state.lock();
        const queued = channel.state.head != null;
        channel.state.unlock();
        if (queued) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u64, 1), (try channel.clusterDropStats("a")).evaluated);
    try std.testing.expectEqual(@as(u32, 0), (try channel.clusterCircuitStats("a")).active);
    _ = try channel.updateWithTimeout(.{ .service_config = .{ .replace = initial } }, .fromSeconds(1));
    try std.testing.expectEqual(@as(u64, 1), (try channel.clusterDropStats("a")).evaluated);
    _ = try channel.updateWithTimeout(.{ .service_config = .{ .replace = replaced } }, .fromSeconds(1));
    var result = try pending.await(io);
    defer result.deinit();
    try std.testing.expect(result.was_dropped and result.transport == null);
    const stats = try channel.clusterDropStats("a");
    try std.testing.expectEqual(@as(u64, 2), stats.evaluated);
    try std.testing.expectEqual(@as(u64, 1), stats.dropped);
}
