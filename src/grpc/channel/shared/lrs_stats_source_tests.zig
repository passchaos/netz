//! Source ownership and interval baselines survive discovery-source replacement.
const std = @import("std");
const stats = @import("lrs_stats.zig");
const Source = @import("../../xds/discovery_source.zig").Source;
const bootstrap = @import("../../xds/bootstrap.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;

fn select(counters: *stats.Stats, source_key: []const u8) !void {
    const selection = try stats.Selection.create(allocator, &.{.{
        .cluster = "a",
        .service_name = "eds",
        .source_key = source_key,
        .propagation = .{ .cpu_utilization = true, .named_metrics_all = true },
    }});
    if (counters.swapSelection(io, selection)) |previous| previous.release();
}

test "gRPC LRS source replacement keeps held calls and independent interval baselines" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    const endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(1001) };
    try select(&counters, "old");
    const old = counters.begin(io, "a", "eds", endpoint) orelse return error.MissingRegistration;
    var old_live = true;
    defer if (old_live) old.release();
    {
        var admitted = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer admitted.deinit();
        try std.testing.expectEqual(@as(usize, 1), admitted.entries.len);
        try std.testing.expectEqualStrings("old", admitted.entries[0].source_key);
        try std.testing.expectEqual(@as(u64, 1), admitted.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 1), admitted.entries[0].in_progress);
    }
    try select(&counters, "new");
    try std.testing.expect(counters.sourceActive(io, "old"));
    try std.testing.expect(counters.sourceActive(io, "new"));
    const new = counters.begin(io, "a", "eds", endpoint) orelse return error.MissingRegistration;
    counters.complete(io, new, endpoint, false);
    counters.recordRegisteredOrca(io, new, .{ .cpu_utilization = 0.75, .named_metrics = &.{.{ .name = "load", .value = 2.0 }} });
    new.release();
    counters.recordDropped(io, "a", "eds", "quota");
    {
        var old_pending = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer old_pending.deinit();
        try std.testing.expectEqual(@as(u64, 0), old_pending.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 1), old_pending.entries[0].in_progress);
        try std.testing.expectEqual(@as(u64, 0), old_pending.entries[0].cpu_utilization.count);
    }
    {
        var new_completed = try counters.snapshotDeltaForSource(allocator, io, "new");
        defer new_completed.deinit();
        try std.testing.expectEqual(@as(usize, 1), new_completed.entries.len);
        const entry = new_completed.entries[0];
        try std.testing.expectEqualStrings("new", entry.source_key);
        try std.testing.expectEqualStrings("a", entry.cluster);
        try std.testing.expectEqualStrings("eds", entry.service_name);
        try std.testing.expectEqual(@as(u64, 1), entry.issued);
        try std.testing.expectEqual(@as(u64, 1), entry.error_requests);
        try std.testing.expectEqual(@as(u64, 1), entry.dropped);
        try std.testing.expectEqual(@as(u64, 1), entry.categories[0].count);
        try std.testing.expectEqual(@as(u64, 1), entry.endpoints[0].error_requests);
        try std.testing.expectEqual(@as(f64, 0.75), entry.cpu_utilization.sum);
        try std.testing.expectEqual(@as(f64, 2.0), entry.load_metrics[0].sum);
    }
    counters.complete(io, old, endpoint, true);
    counters.recordRegisteredOrca(io, old, .{ .cpu_utilization = 0.25, .named_metrics = &.{.{ .name = "load", .value = 1.0 }} });
    old.release();
    old_live = false;
    try std.testing.expect(counters.sourceActive(io, "old"));
    {
        var new_next = try counters.snapshotDeltaForSource(allocator, io, "new");
        defer new_next.deinit();
        try std.testing.expectEqual(@as(usize, 1), new_next.entries.len);
        try std.testing.expectEqual(@as(u64, 0), new_next.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 0), new_next.entries[0].successful);
        try std.testing.expectEqual(@as(u64, 0), new_next.entries[0].cpu_utilization.count);
        try std.testing.expect(counters.sourceActive(io, "old"));
    }
    var old_final = try counters.snapshotDeltaForSource(allocator, io, "old");
    defer old_final.deinit();
    try std.testing.expectEqual(@as(u64, 0), old_final.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), old_final.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), old_final.entries[0].endpoints[0].successful);
    try std.testing.expectEqual(@as(f64, 0.25), old_final.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(f64, 1.0), old_final.entries[0].load_metrics[0].sum);
    try std.testing.expect(!counters.sourceActive(io, "old"));
    var retired = try counters.snapshotDeltaForSource(allocator, io, "old");
    defer retired.deinit();
    try std.testing.expectEqual(@as(usize, 0), retired.entries.len);
    try std.testing.expectEqualStrings("old", old_final.entries[0].source_key);
    try std.testing.expect(counters.sourceActive(io, "new"));
}

test "gRPC LRS disabled source membership preserves later call completion and metrics" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    try select(&counters, "old");
    const admitted = counters.capture(io, "a", "eds") orelse return error.MissingRegistration;
    var admitted_live = true;
    defer if (admitted_live) admitted.release();
    const disabled = try stats.Selection.create(allocator, &.{});
    counters.swapSelection(io, disabled).?.release();
    try std.testing.expect(counters.capture(io, "a", "eds") == null);
    try std.testing.expect(counters.sourceActive(io, "old"));
    {
        var opening = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer opening.deinit();
        try std.testing.expectEqual(@as(u64, 0), opening.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 0), opening.entries[0].in_progress);
    }
    counters.start(io, admitted, null);
    counters.complete(io, admitted, null, true);
    counters.recordRegisteredOrca(io, admitted, .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "load", .value = 3.0 }} });
    admitted.release();
    admitted_live = false;
    try std.testing.expect(counters.sourceActive(io, "old"));
    {
        var final = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer final.deinit();
        try std.testing.expectEqual(@as(usize, 1), final.entries.len);
        try std.testing.expectEqual(@as(u64, 1), final.entries[0].issued);
        try std.testing.expectEqual(@as(u64, 1), final.entries[0].successful);
        try std.testing.expectEqual(@as(f64, 0.5), final.entries[0].cpu_utilization.sum);
        try std.testing.expectEqual(@as(f64, 3.0), final.entries[0].load_metrics[0].sum);
    }
    try std.testing.expect(!counters.sourceActive(io, "old"));
    var retired = try counters.snapshotDeltaForSource(allocator, io, "old");
    defer retired.deinit();
    try std.testing.expectEqual(@as(usize, 0), retired.entries.len);
}

test "gRPC LRS source selection and snapshot own source key strings" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    var key: [3]u8 = "old".*;
    try select(&counters, &key);
    @memset(&key, 'x');
    try std.testing.expect(counters.sourceActive(io, "old"));
    try std.testing.expect(!counters.sourceActive(io, "xxx"));
    counters.record(io, "a", "eds", true);
    var snapshot = try counters.snapshot(allocator, io);
    defer snapshot.deinit();
    try std.testing.expectEqualStrings("old", snapshot.entries[0].source_key);
    const disabled = try stats.Selection.create(allocator, &.{});
    counters.swapSelection(io, disabled).?.release();
    {
        var final = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer final.deinit();
    }
    {
        var retired = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer retired.deinit();
        try std.testing.expectEqual(@as(usize, 0), retired.entries.len);
    }
    try std.testing.expectEqualStrings("old", snapshot.entries[0].source_key);
}

test "gRPC LRS enabling allocator-null stats preserves committed selection and existing allocator" {
    var counters: stats.Stats = .{};
    defer counters.deinit();
    try select(&counters, "source");
    try std.testing.expect(counters.capture(io, "a", "eds") == null);
    try std.testing.expect(counters.sourceActive(io, "source"));
    var disabled = try counters.snapshotDeltaForSource(allocator, io, "source");
    defer disabled.deinit();
    try std.testing.expectEqual(@as(usize, 0), disabled.entries.len);
    counters.enable(allocator, io);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    counters.enable(failing.allocator(), io);
    const admitted = counters.begin(io, "a", "eds", null) orelse return error.MissingRegistration;
    counters.complete(io, admitted, null, true);
    admitted.release();
    var enabled = try counters.snapshotDeltaForSource(allocator, io, "source");
    defer enabled.deinit();
    try std.testing.expectEqual(@as(usize, 1), enabled.entries.len);
    try std.testing.expectEqual(@as(u64, 1), enabled.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), enabled.entries[0].successful);
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

test "gRPC LRS copied identities retain sources and release them across allocation failures" {
    const configuration = try bootstrap.parse(allocator, "{\"xds_servers\":[{\"server_uri\":\"http://xds.test:80\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .{});
    defer configuration.deinit();
    const source = try Source.create(allocator, configuration, configuration.servers[0], .{ .id = "node" }, .{ .path = "/discovery" });
    defer source.release();
    const Scenario = struct {
        fn run(gpa: std.mem.Allocator, owner: *Source) !void {
            const selection = stats.Selection.create(gpa, &.{
                .{ .cluster = "a", .service_name = "eds", .source = owner, .source_key = owner.key, .propagation = .{ .named_metrics = &.{"load"} } },
                .{ .cluster = "b", .service_name = "eds", .source = owner, .source_key = owner.key },
            }) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), owner.refs.load(.acquire));
                return err;
            };
            var selection_live = true;
            defer if (selection_live) selection.release();
            try std.testing.expectEqual(@as(usize, 3), owner.refs.load(.acquire));
            const identity = selection.find("a", "eds").?;
            try std.testing.expect(identity.source.? == owner);
            try std.testing.expectEqualStrings(owner.key, identity.source_key);
            try std.testing.expect(identity.source_key.ptr != owner.key.ptr);
            selection.release();
            selection_live = false;
            try std.testing.expectEqual(@as(usize, 1), owner.refs.load(.acquire));
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Scenario.run, .{source});
}

test "gRPC LRS retired source activity includes metrics after call deltas drain" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    try select(&counters, "old");
    const admitted = counters.begin(io, "a", "eds", null) orelse return error.MissingRegistration;
    var admitted_live = true;
    defer if (admitted_live) admitted.release();
    counters.complete(io, admitted, null, true);
    {
        var calls = try counters.snapshotDeltaForSource(allocator, io, "old");
        defer calls.deinit();
    }
    try select(&counters, "new");
    counters.recordRegisteredOrca(io, admitted, .{ .named_metrics = &.{.{ .name = "load", .value = 3.0 }} });
    admitted.release();
    admitted_live = false;
    try std.testing.expect(counters.sourceActive(io, "old"));
    var metrics = try counters.snapshotDeltaForSource(allocator, io, "old");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u64, 0), metrics.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), metrics.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), metrics.entries[0].load_metrics[0].count);
    try std.testing.expect(!counters.sourceActive(io, "old"));
}

test "gRPC LRS ordinary delta snapshots include all source buckets and retired drops" {
    var counters: stats.Stats = .{ .allocator = allocator };
    defer counters.deinit();
    try select(&counters, "old");
    counters.recordDropped(io, "a", "eds", "quota");
    try select(&counters, "new");
    counters.record(io, "a", "eds", true);
    try std.testing.expect(counters.sourceActive(io, "old"));
    var all = try counters.snapshotDelta(allocator, io);
    defer all.deinit();
    try std.testing.expectEqual(@as(usize, 2), all.entries.len);
    for (all.entries) |entry| {
        if (std.mem.eql(u8, entry.source_key, "old")) {
            try std.testing.expectEqual(@as(u64, 1), entry.dropped);
            try std.testing.expectEqual(@as(u64, 1), entry.categories[0].count);
        } else {
            try std.testing.expectEqualStrings("new", entry.source_key);
            try std.testing.expectEqual(@as(u64, 1), entry.issued);
            try std.testing.expectEqual(@as(u64, 1), entry.successful);
        }
    }
    try std.testing.expect(!counters.sourceActive(io, "old"));
    var new = try counters.snapshotDeltaForSource(allocator, io, "new");
    defer new.deinit();
    try std.testing.expectEqual(@as(usize, 1), counters.map.count());
    try std.testing.expectEqual(@as(u64, 0), new.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), new.entries[0].successful);
}
