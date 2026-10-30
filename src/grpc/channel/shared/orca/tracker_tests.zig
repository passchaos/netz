const std = @import("std");
const tracker_mod = @import("tracker.zig");
const orca = @import("../../../orca.zig");

test "gRPC shared ORCA tracker fans out latest reports and lifecycle" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const tracker = try tracker_mod.Tracker.create(
        std.testing.allocator,
        threaded.io(),
    );
    var first = tracker_mod.Watch.init(tracker);
    defer first.deinit();
    var second = tracker_mod.Watch.init(tracker);
    defer second.deinit();

    var report_one = try ownedReport(0.25, "first");
    tracker.publish(&report_one);
    var first_update = try first.nextWithTimeout(.fromSeconds(1));
    defer first_update.deinit();
    var second_update = try second.nextWithTimeout(.fromSeconds(1));
    defer second_update.deinit();
    try expectReport(first_update, 0.25, "first");
    try expectReport(second_update, 0.25, "first");
    try std.testing.expect(
        first_update.report.?.bytes.ptr != second_update.report.?.bytes.ptr,
    );

    var skipped = try ownedReport(0.5, "skipped");
    tracker.publish(&skipped);
    var latest = try ownedReport(0.75, "latest");
    tracker.publish(&latest);
    var coalesced = try first.nextWithTimeout(.fromSeconds(1));
    defer coalesced.deinit();
    try expectReport(coalesced, 0.75, "latest");

    tracker.setStatus(.unavailable);
    var unavailable = try first.nextWithTimeout(.fromSeconds(1));
    defer unavailable.deinit();
    try std.testing.expectEqual(
        tracker_mod.Status.unavailable,
        unavailable.header.status,
    );
    try std.testing.expect(unavailable.report == null);

    tracker.shutdown();
    tracker.release();
    var terminal = try second.nextWithTimeout(.fromSeconds(1));
    defer terminal.deinit();
    try std.testing.expectEqual(
        tracker_mod.Status.shutdown,
        terminal.header.status,
    );
    try std.testing.expect(terminal.report == null);
}

test "gRPC shared ORCA tracker preserves cursor on clone allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const tracker = try tracker_mod.Tracker.create(
        failing.allocator(),
        threaded.io(),
    );
    defer tracker.release();
    var watch = tracker_mod.Watch.init(tracker);
    defer watch.deinit();
    var report = try ownedReportWithAllocator(
        failing.allocator(),
        0.5,
        "metric",
    );
    tracker.publish(&report);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        watch.nextWithTimeout(.fromSeconds(1)),
    );
    failing.fail_index = std.math.maxInt(usize);
    var update = try watch.nextWithTimeout(.fromSeconds(1));
    defer update.deinit();
    try expectReport(update, 0.5, "metric");
    tracker.shutdown();
}

fn ownedReport(cpu: f64, name: []const u8) !orca.OwnedLoadReport {
    return ownedReportWithAllocator(std.testing.allocator, cpu, name);
}

fn ownedReportWithAllocator(
    allocator: std.mem.Allocator,
    cpu: f64,
    name: []const u8,
) !orca.OwnedLoadReport {
    const encoded = try orca.encodeAlloc(allocator, .{
        .cpu_utilization = cpu,
        .named_metrics = &.{.{ .name = name, .value = cpu * 10 }},
    });
    defer allocator.free(encoded);
    return orca.decodeAlloc(allocator, encoded);
}

fn expectReport(
    update: tracker_mod.Update,
    cpu: f64,
    name: []const u8,
) !void {
    try std.testing.expectEqual(tracker_mod.Status.ready, update.header.status);
    const report = update.report.?.report;
    try std.testing.expectEqual(cpu, report.cpu_utilization);
    try std.testing.expectEqual(@as(usize, 1), report.named_metrics.len);
    try std.testing.expectEqualStrings(name, report.named_metrics[0].name);
    try std.testing.expectEqual(cpu * 10, report.named_metrics[0].value);
}
