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
    const localities = [_]codec.LocalityStats{.{
        .locality = .{ .region = "r", .zone = "z", .sub_zone = "s" },
        .successful = 2,
        .in_progress = 1,
        .error_requests = 1,
        .issued = 3,
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
    const storage = try allocator.alloc(u8, 2);
    const entries = try allocator.alloc(lrs_stats.Entry, 2);
    entries[0] = .{ .cluster = storage[0..1], .issued = 2, .successful = 1, .error_requests = 1 };
    entries[1] = .{ .cluster = storage[1..2], .issued = 1, .successful = 1, .error_requests = 0 };
    @memcpy(storage[0..1], "a");
    @memcpy(storage[1..2], "b");
    var snapshot: channel.LrsStatsSnapshot = .{ .allocator = allocator, .storage = storage, .entries = entries };
    defer snapshot.deinit();
    var reports = try integration.build(allocator, &snapshot, .{ .region = "r", .zone = "z" }, 100 * std.time.ns_per_ms);
    defer reports.deinit();
    try std.testing.expectEqual(@as(usize, 2), reports.clusters.len);
    for (reports.clusters) |cluster| {
        try std.testing.expectEqual(@as(usize, 1), cluster.localities.len);
        try std.testing.expectEqualStrings("r", cluster.localities[0].locality.region);
        try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), cluster.interval_ns);
        if (std.mem.eql(u8, cluster.name, "a")) {
            try std.testing.expectEqual(@as(u64, 2), cluster.localities[0].issued);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].successful);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].error_requests);
        } else {
            try std.testing.expectEqualStrings("b", cluster.name);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].successful);
        }
    }
}
