//! Native drop behavior against independent ADS/grpc-js peers.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const eds = grpc.xds.eds;
const ads = grpc.xds.ads;
const drop = grpc.drop_policy;
const allocator = std.heap.c_allocator;
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}
fn retry() grpc.RetryPolicy {
    return .{ .max_attempts = 5, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(1), .backoff_multiplier = 1, .retryable_status_codes = &.{.unavailable} };
}
const Counts = struct { accepted: usize, dropped: usize };
fn calls(client: anytype, count: usize) !Counts {
    var result: Counts = .{ .accepted = 0, .dropped = 0 };
    for (0..count) |_| {
        var response = try client.unaryWithRetry(.{ .path = "/fixture.Drop/Unary", .authority = "backend.test", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 2, .unit = .second } }, retry());
        defer response.deinit();
        if (response.was_dropped) {
            try std.testing.expectEqual(grpc.Status.unavailable, response.status);
            try std.testing.expect(response.transport == null);
            result.dropped += 1;
        } else {
            try std.testing.expectEqual(grpc.Status.ok, response.status);
            try std.testing.expectEqualStrings("reply", response.message.?.payload);
            result.accepted += 1;
        }
    }
    return result;
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    const ordinary_mode = std.mem.eql(u8, args[1], "ordinary");
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const app_port = try std.fmt.parseInt(u16, args[2], 10);
    if (ordinary_mode) {
        var client = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(app_port) } } }, .{ .drop_categories = &.{.{ .category = "half", .requests_per_million = 500000 }} });
        defer client.deinit();
        const result = try calls(&client, 500);
        try std.testing.expect(result.dropped > 150 and result.dropped < 350);
        const stats = client.dropStats();
        try std.testing.expectEqual(@as(u64, 500), stats.evaluated);
        try std.testing.expectEqual(@as(u64, result.dropped), stats.dropped);
        std.debug.print("DROP_RESULT {{\"mode\":\"ordinary\",\"accepted\":{d},\"dropped\":{d},\"evaluated\":{d}}}\n", .{ result.accepted, result.dropped, stats.evaluated });
        return;
    }
    var control = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[3], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var discovery = try ads.Client.init(allocator, control_sender, .{ .node = .{ .id = "netz-eds-drop" } });
    defer discovery.deinit();
    try discovery.setSubscription(eds.type_url, &.{"backend"});
    try discovery.connectWithDeadline(until(io));
    var client = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(app_port) } } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const options: eds.TargetOptions = .{ .authority = "backend.test" };
    var first = try discovery.nextWithDeadline(until(io));
    defer first.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, first.update, "backend", client, options, .{}, until(io));
    const half = try calls(sender, 500);
    try std.testing.expect(half.dropped > 150 and half.dropped < 350);
    try discovery.setSubscription(eds.type_url, &.{ "backend", "all" });
    _ = try discovery.flushWithDeadline(until(io));
    var all = try discovery.nextWithDeadline(until(io));
    defer all.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, all.update, "backend", client, options, .{}, until(io));
    const rejected = try calls(sender, 10);
    try std.testing.expectEqual(@as(usize, 10), rejected.dropped);
    var hedged = try sender.unaryWithHedging(.{ .path = "/fixture.Drop/Unary", .message = "request" }, .{ .max_attempts = 5, .hedging_delay = .fromSeconds(1), .non_fatal_status_codes = &.{.unavailable} });
    defer hedged.deinit();
    try std.testing.expect(hedged.was_dropped);
    try std.testing.expectEqual(@as(u64, 1), client.hedgingStats().attempts_started);
    try std.testing.expectError(error.CallDropped, sender.startDuplex(.{ .path = "/fixture.Drop/Duplex" }));
    try discovery.setSubscription(eds.type_url, &.{ "backend", "off" });
    _ = try discovery.flushWithDeadline(until(io));
    var off = try discovery.nextWithDeadline(until(io));
    defer off.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, off.update, "backend", client, options, .{}, until(io));
    const resumed = try calls(sender, 10);
    try std.testing.expectEqual(@as(usize, 10), resumed.accepted);
    try discovery.setSubscription(eds.type_url, &.{ "backend", "empty" });
    _ = try discovery.flushWithDeadline(until(io));
    var empty = try discovery.nextWithDeadline(until(io));
    defer empty.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, empty.update, "backend", client, options, .{}, until(io));
    const no_endpoint = try calls(sender, 10);
    try std.testing.expectEqual(@as(usize, 10), no_endpoint.dropped);
    try std.testing.expectEqual(@as(usize, 0), client.configuredEndpointCount());
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, client.connectivityState());
    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    const stats = client.dropStats();
    try std.testing.expectEqual(@as(u64, 522), stats.evaluated);
    try std.testing.expectEqual(@as(u64, half.dropped + 22), stats.dropped);
    std.debug.print("DROP_RESULT {{\"mode\":\"shared\",\"accepted\":{d},\"dropped\":{d},\"evaluated\":{d},\"all\":10,\"resumed\":10,\"empty\":10,\"hedging_attempts\":1,\"stream_rejected\":true}}\n", .{ half.accepted + resumed.accepted, stats.dropped, stats.evaluated });
}
