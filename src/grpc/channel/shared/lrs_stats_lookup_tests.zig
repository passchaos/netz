//! Warmed reporting registrations must remain usable under allocator pressure.
const std = @import("std");
const stats = @import("lrs_stats.zig");
const keys = @import("lrs_stats_key.zig");
const allocator = std.testing.allocator;

test "gRPC LRS borrowed identity hash matches stored keys across split boundaries" {
    const inputs = [_]keys.Borrowed{
        .{ .cluster = "a", .service_name = "bc" },
        .{ .cluster = "ab", .service_name = "c" },
        .{ .cluster = "a\x00b", .service_name = "c" },
        .{ .cluster = "a", .service_name = "b\x00c" },
        .{ .cluster = "long-cluster-with-more-than-48-bytes-to-cross-wyhash-block", .service_name = "another-long-service-name-to-cross-a-second-wyhash-block" },
    };
    const context: keys.Adapted = .{};
    for (inputs, 0..) |input, index| {
        const owned = try allocator.alloc(u8, 8 + input.cluster.len + input.service_name.len);
        defer allocator.free(owned);
        std.mem.writeInt(u64, owned[0..8], @intCast(input.cluster.len), .little);
        @memcpy(owned[8..][0..input.cluster.len], input.cluster);
        @memcpy(owned[8 + input.cluster.len ..], input.service_name);
        try std.testing.expectEqual(std.hash.Wyhash.hash(0, owned), context.hash(input));
        try std.testing.expect(context.eql(input, owned));
        for (inputs[0..index]) |previous| try std.testing.expect(!context.eql(previous, owned));
    }
}

test "gRPC LRS warmed identity endpoint and metric lookups survive allocation failure" {
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var counters: stats.Stats = .{ .allocator = failing.allocator() };
    defer counters.deinit();
    const identities = [_]stats.Identity{
        .{ .cluster = "ab", .service_name = "c", .propagation = .{ .cpu_utilization = true, .named_metrics_all = true } },
        .{ .cluster = "a\x00b", .service_name = "c" },
        .{ .cluster = "a", .service_name = "b\x00c" },
        .{ .cluster = "a", .service_name = "bc" },
    };
    const selection = try stats.Selection.create(allocator, &identities);
    try std.testing.expect(counters.swapSelection(std.testing.io, selection) == null);
    const endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(1001) };
    for (identities) |identity| {
        const registration = counters.begin(std.testing.io, identity.cluster, identity.service_name, endpoint) orelse return error.MissingRegistration;
        defer registration.release();
        counters.complete(std.testing.io, registration, endpoint, true);
        counters.recordRegisteredOrca(std.testing.io, registration, .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "load", .value = 0.25 }} });
        counters.recordDropped(std.testing.io, identity.cluster, identity.service_name, "quota");
    }
    var baseline = try counters.snapshotDelta(allocator, std.testing.io);
    defer baseline.deinit();
    const previous_allocations = failing.alloc_index;
    failing.fail_index = previous_allocations;
    for (identities, 0..) |identity, index| {
        for (0..index + 1) |_| {
            const registration = counters.begin(std.testing.io, identity.cluster, identity.service_name, endpoint) orelse return error.WarmedRegistrationLost;
            defer registration.release();
            counters.complete(std.testing.io, registration, endpoint, false);
            counters.recordRegisteredOrca(std.testing.io, registration, .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "load", .value = 0.25 }} });
            counters.recordDropped(std.testing.io, identity.cluster, identity.service_name, "quota");
        }
    }
    try std.testing.expectEqual(previous_allocations, failing.alloc_index);
    var snapshot = try counters.snapshotDelta(allocator, std.testing.io);
    defer snapshot.deinit();
    try std.testing.expectEqual(identities.len, snapshot.entries.len);
    for (identities, 0..) |identity, index| {
        const entry = for (snapshot.entries) |candidate| {
            if (std.mem.eql(u8, candidate.cluster, identity.cluster) and std.mem.eql(u8, candidate.service_name, identity.service_name)) break candidate;
        } else return error.MissingIdentity;
        const expected: u64 = @intCast(index + 1);
        try std.testing.expectEqual(expected, entry.issued);
        try std.testing.expectEqual(expected, entry.error_requests);
        try std.testing.expectEqual(@as(u64, 0), entry.successful);
        try std.testing.expectEqual(expected, entry.dropped);
        try std.testing.expectEqual(expected, entry.categories[0].count);
        try std.testing.expectEqual(expected, entry.endpoints[0].issued);
        try std.testing.expectEqual(expected, entry.endpoints[0].error_requests);
        if (index == 0) {
            try std.testing.expectEqual(expected, entry.cpu_utilization.count);
            try std.testing.expectEqual(expected, entry.load_metrics[0].count);
        }
        try std.testing.expect(selection.find(identity.cluster, identity.service_name) != null);
    }
    try std.testing.expect(selection.find("a", "c") == null);
}

test "gRPC LRS opening captures publish no phantom issued count or lost later delta" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    const selected = try stats.Selection.create(allocator, &.{.{ .cluster = "a", .service_name = "eds" }});
    try std.testing.expect(counters.swapSelection(std.testing.io, selected) == null);
    const endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(1001) };
    const failed_open = counters.capture(std.testing.io, "a", "eds") orelse return error.MissingCapture;
    var failed_live = true;
    defer if (failed_live) failed_open.release();
    {
        var during_open = try counters.snapshotDelta(allocator, std.testing.io);
        defer during_open.deinit();
        try std.testing.expectEqual(@as(usize, 1), during_open.entries.len);
        try std.testing.expectEqual(@as(u64, 0), during_open.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 0), during_open.entries[0].in_progress);
        try std.testing.expectEqual(@as(usize, 0), during_open.entries[0].endpoints.len);
    }
    // Opening failed: release the pin without decrementing monotonic counters.
    failed_open.release();
    failed_live = false;
    const opened = counters.capture(std.testing.io, "a", "eds") orelse return error.MissingCapture;
    defer opened.release();
    {
        var before_success = try counters.snapshotDelta(allocator, std.testing.io);
        defer before_success.deinit();
        try std.testing.expectEqual(@as(u64, 0), before_success.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 0), before_success.entries[0].in_progress);
    }
    const disabled = try stats.Selection.create(allocator, &.{});
    counters.swapSelection(std.testing.io, disabled).?.release();
    try std.testing.expect(counters.capture(std.testing.io, "a", "eds") == null);
    counters.start(std.testing.io, opened, endpoint);
    counters.complete(std.testing.io, opened, endpoint, true);
    {
        var succeeded = try counters.snapshotDelta(allocator, std.testing.io);
        defer succeeded.deinit();
        try std.testing.expectEqual(@as(usize, 1), succeeded.entries.len);
        try std.testing.expectEqual(@as(u64, 1), succeeded.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 1), succeeded.entries[0].successful);
        try std.testing.expectEqual(@as(u64, 0), succeeded.entries[0].in_progress);
        try std.testing.expectEqual(@as(u64, 1), succeeded.entries[0].endpoints[0].issued);
    }
    var consumed = try counters.snapshotDelta(allocator, std.testing.io);
    defer consumed.deinit();
    try std.testing.expectEqual(@as(u64, 0), consumed.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), consumed.entries[0].successful);
}
