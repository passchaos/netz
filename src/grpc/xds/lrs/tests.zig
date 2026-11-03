const std = @import("std");
const codec = @import("codec.zig");
const integration = @import("integration.zig");
const channel = @import("../../channel/shared.zig");
const lrs_stats = @import("../../channel/shared/lrs_stats.zig");
const ads = @import("../ads.zig");
const allocator = std.testing.allocator;

test "gRPC LRS envelopes round-trip node, clusters, localities and dropped stats" {
    const node = try ads.codec.encodeNode(allocator, .{ .id = "node-1", .client_features = &.{"envoy.lrs.supports_send_all_clusters"} });
    defer allocator.free(node);
    const endpoints = [_]codec.EndpointStats{.{
        .host = "127.0.0.1",
        .port = 1001,
        .successful = 2,
        .in_progress = 1,
        .error_requests = 1,
        .issued = 3,
    }};
    const localities = [_]codec.LocalityStats{.{
        .locality = .{ .region = "r", .zone = "z", .sub_zone = "s" },
        .successful = 2,
        .in_progress = 1,
        .error_requests = 1,
        .issued = 3,
        .endpoints = &endpoints,
    }};
    const dropped = [_]codec.Dropped{.{ .category = "throttle", .count = 1 }};
    const clusters = [_]codec.ClusterStats{.{
        .name = "a",
        .service_name = "eds-a",
        .localities = &localities,
        .total_dropped = 1,
        .dropped = &dropped,
        .interval_ns = 100 * std.time.ns_per_ms,
    }};
    const encoded = try codec.encodeRequest(allocator, .{ .node = node, .clusters = &clusters }, .{});
    defer allocator.free(encoded);
    var decoded = try codec.decodeRequest(allocator, encoded, .{});
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, node, decoded.value.node.?);
    try std.testing.expectEqual(@as(usize, 1), decoded.value.clusters.len);
    const cluster = decoded.value.clusters[0];
    try std.testing.expectEqualStrings("a", cluster.name);
    try std.testing.expectEqualStrings("eds-a", cluster.service_name);
    try std.testing.expectEqual(@as(u64, 1), cluster.total_dropped);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), cluster.interval_ns);
    try std.testing.expectEqual(@as(usize, 1), cluster.localities.len);
    try std.testing.expectEqualStrings("r", cluster.localities[0].locality.region);
    try std.testing.expectEqual(@as(u64, 2), cluster.localities[0].successful);
    try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].in_progress);
    try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].error_requests);
    try std.testing.expectEqual(@as(u64, 3), cluster.localities[0].issued);
    try std.testing.expectEqual(@as(usize, 1), cluster.localities[0].endpoints.len);
    try std.testing.expectEqualStrings("127.0.0.1", cluster.localities[0].endpoints[0].host);
    try std.testing.expectEqual(@as(u16, 1001), cluster.localities[0].endpoints[0].port);
    try std.testing.expectEqual(@as(u64, 3), cluster.localities[0].endpoints[0].issued);
    try std.testing.expectEqual(@as(usize, 1), cluster.dropped.len);
    try std.testing.expectEqualStrings("throttle", cluster.dropped[0].category);
    try std.testing.expectEqual(@as(u64, 1), cluster.dropped[0].count);

    const response = try codec.encodeResponse(allocator, .{
        .clusters = &.{ "a", "b" },
        .interval_ns = 250 * std.time.ns_per_ms,
        .report_endpoint_granularity = true,
        .send_all_clusters = false,
    }, .{});
    defer allocator.free(response);
    var owned = try codec.decodeResponse(allocator, response, .{});
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 2), owned.value.clusters.len);
    try std.testing.expectEqualStrings("b", owned.value.clusters[1]);
    try std.testing.expectEqual(@as(u64, 250 * std.time.ns_per_ms), owned.value.interval_ns.?);
    try std.testing.expect(owned.value.report_endpoint_granularity);
    try std.testing.expect(!owned.value.send_all_clusters);
}

test "gRPC LRS envelopes reject malformed, duplicate and over-limit input" {
    const response = try codec.encodeResponse(allocator, .{ .clusters = &.{ "a", "a" } }, .{});
    defer allocator.free(response);
    try std.testing.expectError(error.InvalidLoadReport, codec.decodeResponse(allocator, response, .{}));
    try std.testing.expectError(error.LoadReportLimitExceeded, codec.decodeResponse(allocator, response, .{ .max_clusters = 1 }));
    var empty = try codec.decodeResponse(allocator, "", .{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.value.clusters.len);
    try std.testing.expect(empty.value.interval_ns == null);
    try std.testing.expectError(error.TruncatedMessage, codec.decodeResponse(allocator, "\x0a\x03a", .{}));
    try std.testing.expectError(error.InvalidUtf8, codec.decodeResponse(allocator, "\x0a\x01\xff", .{}));

    try std.testing.expectError(error.InvalidLoadReport, codec.decodeRequest(allocator, "\x12\x00", .{}));

    const duplicate = try codec.encodeRequest(allocator, .{ .clusters = &.{ .{ .name = "a" }, .{ .name = "a" } } }, .{});
    defer allocator.free(duplicate);
    try std.testing.expectError(error.InvalidLoadReport, codec.decodeRequest(allocator, duplicate, .{}));

    // Negative protobuf int64 durations encode as a huge varint.
    try std.testing.expectError(error.InvalidLoadReport, codec.decodeResponse(allocator, "\x12\x0b\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", .{}));
}

test "gRPC LRS integration converts channel counters into cluster reports" {
    const storage = try allocator.alloc(u8, 24);
    const entries = try allocator.alloc(lrs_stats.Entry, 2);
    const categories = try allocator.alloc(lrs_stats.CategoryCount, 1);
    categories[0] = .{ .category = storage[2..10], .count = 1 };
    const endpoints = try allocator.alloc(lrs_stats.EndpointEntry, 1);
    endpoints[0] = .{ .host = storage[10..19], .port = 1001, .ipv6 = false, .issued = 2, .successful = 1, .error_requests = 1 };
    @memcpy(storage[10..19], "127.0.0.1");
    entries[0] = .{ .cluster = storage[0..1], .service_name = storage[19..24], .issued = 2, .successful = 1, .error_requests = 1, .dropped = 1, .in_progress = 1, .cpu_utilization = .{ .sum = 0.5, .count = 1 }, .load_metrics = &.{.{ .name = storage[19..24], .sum = 2.0, .count = 2 }}, .categories = categories[0..1], .endpoints = endpoints[0..1] };
    entries[1] = .{ .cluster = storage[1..2], .issued = 1, .successful = 1, .error_requests = 0 };
    @memcpy(storage[0..1], "a");
    @memcpy(storage[1..2], "b");
    @memcpy(storage[2..10], "throttle");
    @memcpy(storage[19..24], "eds-a");
    var snapshot: channel.LrsStatsSnapshot = .{ .allocator = allocator, .storage = storage, .entries = entries, .categories = categories, .endpoints = endpoints };
    defer snapshot.deinit();
    var reports = try integration.buildWithOptions(allocator, &snapshot, .{ .region = "r", .zone = "z" }, 100 * std.time.ns_per_ms, null, true);
    defer reports.deinit();
    try std.testing.expectEqual(@as(usize, 2), reports.clusters.len);
    for (reports.clusters) |cluster| {
        try std.testing.expectEqual(@as(usize, 1), cluster.localities.len);
        try std.testing.expectEqualStrings("r", cluster.localities[0].locality.region);
        try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), cluster.interval_ns);
        if (std.mem.eql(u8, cluster.name, "a")) {
            try std.testing.expectEqualStrings("eds-a", cluster.service_name);
            try std.testing.expectEqual(@as(u64, 2), cluster.localities[0].issued);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].successful);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].error_requests);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].in_progress);
            try std.testing.expectEqual(@as(f64, 0.5), cluster.localities[0].cpu_utilization.?.value);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].cpu_utilization.?.count);
            try std.testing.expectEqual(@as(usize, 1), cluster.localities[0].load_metrics.len);
            try std.testing.expectEqualStrings("eds-a", cluster.localities[0].load_metrics[0].name);
            try std.testing.expectEqual(@as(f64, 2.0), cluster.localities[0].load_metrics[0].value);
            try std.testing.expectEqual(@as(u64, 2), cluster.localities[0].load_metrics[0].count);
            try std.testing.expectEqual(@as(usize, 1), cluster.localities[0].endpoints.len);
            try std.testing.expectEqualStrings("127.0.0.1", cluster.localities[0].endpoints[0].host);
            try std.testing.expectEqual(@as(u16, 1001), cluster.localities[0].endpoints[0].port);
            try std.testing.expectEqual(@as(u64, 2), cluster.localities[0].endpoints[0].issued);
            try std.testing.expectEqual(@as(u64, 1), cluster.total_dropped);
            try std.testing.expectEqual(@as(usize, 1), cluster.dropped.len);
            try std.testing.expectEqualStrings("throttle", cluster.dropped[0].category);
            try std.testing.expectEqual(@as(u64, 1), cluster.dropped[0].count);
        } else {
            try std.testing.expectEqualStrings("b", cluster.name);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].successful);
        }
    }
}

test "gRPC LRS reporter requires the node feature for send_all_clusters" {
    const grpc = @import("../../mod.zig");
    var source = try grpc.SharedChannel.init(allocator, std.testing.io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer source.deinit();
    var sender = source.sender();
    defer sender.deinit();
    var client = try @import("client.zig").Client.init(allocator, sender, .{ .node = .{ .id = "node" } });
    defer client.deinit();
    var reporter = @import("reporter.zig").Reporter.init(allocator, &client, source, .{});
    defer reporter.deinit();
    try reporter.onResponse(.{ .clusters = &.{"a"}, .send_all_clusters = true });
    try std.testing.expectEqual(@as(usize, 1), reporter.filter.?.len);
    try std.testing.expectEqualStrings("a", reporter.filter.?[0]);
}

test "gRPC LRS reporter applies response interval and cluster filter" {
    const grpc = @import("../../mod.zig");
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer first.deinit();
    var first_sender = first.sender();
    defer first_sender.deinit();
    var second = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer second.deinit();
    var client = try @import("client.zig").Client.init(allocator, first_sender, .{ .node = .{ .id = "node", .client_features = &.{"envoy.lrs.supports_send_all_clusters"} } });
    defer client.deinit();
    var reporter = @import("reporter.zig").Reporter.init(allocator, &client, first, .{ .interval_ns = std.time.ns_per_s });
    defer reporter.deinit();
    try reporter.onResponse(.{ .clusters = &.{"a"}, .interval_ns = 50 * std.time.ns_per_ms, .send_all_clusters = false, .report_endpoint_granularity = true });
    try std.testing.expectEqual(@as(u64, 50 * std.time.ns_per_ms), reporter.interval_ns);
    try std.testing.expect(reporter.endpoint_granularity);
    try std.testing.expectEqual(@as(usize, 1), reporter.filter.?.len);
    try std.testing.expectEqualStrings("a", reporter.filter.?[0]);
    try reporter.onResponse(.{ .clusters = &.{}, .send_all_clusters = true });
    try std.testing.expect(reporter.filter == null);
    const now = std.Io.Clock.Timestamp.now(io, .awake);
    reporter.last_report_ns = now.raw.nanoseconds - 100 * std.time.ns_per_ms;
    const next = reporter.nextDeadline();
    try std.testing.expectEqual(now.raw.nanoseconds - 50 * std.time.ns_per_ms, next.raw.nanoseconds);

    const second_sender = second.sender();
    try client.rebind(second_sender, .{ .path = @import("client.zig").path });
    try std.testing.expect(client.stream == null);
    try std.testing.expect(client.sender.state == second.state);
    try std.testing.expect(!client.node_sent);
}
