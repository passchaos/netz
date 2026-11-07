//! CDS selects raw ORCA keys but retains the named_metrics namespace in LRS.
const std = @import("std");
const bootstrap = @import("../bootstrap.zig");
const control_plane = @import("../control_plane.zig");
const cds = @import("../cds.zig");
const lrs = @import("../lrs.zig");
const orca = @import("../../orca.zig");
const stats = @import("../../channel/shared/lrs_stats.zig");
const fixture = @import("../cds/testing.zig");
const support = @import("lrs_automatic/testing.zig");
const gpa = std.testing.allocator;

fn namedCds(selector: []const u8) ![]u8 {
    var extra: fixture.Builder = .{ .allocator = gpa };
    defer extra.deinit();
    try extra.data.appendSlice(gpa, support.self_lrs);
    try extra.bytes(57, selector);
    return fixture.cluster(gpa, "a", "eds-a", extra.data.items);
}

fn metric(request: lrs.codec.Request, name: []const u8) !lrs.codec.NamedMetric {
    try std.testing.expectEqual(@as(usize, 1), request.clusters.len);
    try std.testing.expectEqual(@as(usize, 1), request.clusters[0].localities.len);
    for (request.clusters[0].localities[0].load_metrics) |value| {
        if (std.mem.eql(u8, value.name, name)) return value;
    }
    return error.MissingNamedMetric;
}

fn encodeSnapshot(snapshot: *const stats.Snapshot) !lrs.codec.OwnedRequest {
    var reports = try lrs.integration.build(gpa, snapshot, .{}, std.time.ns_per_s);
    defer reports.deinit();
    const bytes = try lrs.codec.encodeRequest(gpa, .{ .clusters = reports.clusters }, .{});
    defer gpa.free(bytes);
    return lrs.codec.decodeRequest(gpa, bytes, .{});
}

fn runNames(comptime mode: support.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://127.0.0.1:1\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"node\":{\"id\":\"node\"}}", .{});
    defer configuration.deinit();
    const plane = try control_plane.ControlPlane.init(gpa, io, configuration, .{});
    defer plane.deinit();
    var h = try support.Harness(mode).init(io, plane, gpa, true, false);
    defer h.deinit();
    h.channel.state.lrs_stats.enable(gpa, io); // Local collector; no LRS transport.
    try h.discover();
    const selected = try namedCds("named_metrics.load");
    defer gpa.free(selected);
    try h.accept(cds.type_url, "a", "selected", selected);
    const admitted = try h.begin();
    defer admitted.release();
    const admitted_policy = admitted.propagation orelse return error.MissingAdmittedMetricPolicy;
    try std.testing.expect(admitted_policy.prefix_named_metrics);
    try std.testing.expectEqual(@as(usize, 1), admitted_policy.named_metrics.len);
    try std.testing.expectEqualStrings("load", admitted_policy.named_metrics[0]);
    const wildcard = try namedCds("named_metrics.*");
    defer gpa.free(wildcard);
    try h.accept(cds.type_url, "a", "wildcard", wildcard);
    const current = try h.begin();
    defer current.release();
    const current_policy = current.propagation orelse return error.MissingCurrentMetricPolicy;
    try std.testing.expect(current_policy.named_metrics_all and current_policy.prefix_named_metrics);
    const bytes = try orca.encodeAlloc(gpa, .{ .named_metrics = &.{
        .{ .name = "load", .value = 2.0 },
        .{ .name = "other", .value = 3.0 },
        .{ .name = "named_metrics.load", .value = 4.0 },
    } });
    defer gpa.free(bytes);
    var report = try orca.decodeAlloc(gpa, bytes);
    defer report.deinit();
    try std.testing.expectEqualStrings("load", report.report.named_metrics[0].name);
    h.channel.state.lrs_stats.recordRegisteredOrca(io, admitted, report.report);
    h.channel.state.lrs_stats.recordRegisteredOrca(io, current, report.report);
    h.complete(admitted, true);
    h.complete(current, true);
    var snapshot = try h.channel.lrsStatsDeltaSnapshot(gpa);
    defer snapshot.deinit();
    var wire = try encodeSnapshot(&snapshot);
    defer wire.deinit();
    try std.testing.expectEqual(@as(usize, 3), wire.value.clusters[0].localities[0].load_metrics.len);
    const selected_metric = try metric(wire.value, "named_metrics.load");
    try std.testing.expectEqual(@as(u64, 2), selected_metric.count);
    try std.testing.expectEqual(@as(f64, 4.0), selected_metric.value);
    try std.testing.expectEqual(@as(u64, 1), (try metric(wire.value, "named_metrics.other")).count);
    try std.testing.expectEqual(@as(f64, 3.0), (try metric(wire.value, "named_metrics.other")).value);
    try std.testing.expectEqual(@as(u64, 1), (try metric(wire.value, "named_metrics.named_metrics.load")).count);
    try std.testing.expectEqual(@as(f64, 4.0), (try metric(wire.value, "named_metrics.named_metrics.load")).value);
}

test "gRPC CDS named metric selectors retain LRS names and admitted policy" {
    try runNames(.sotw);
    try runNames(.delta);
}

test "gRPC manual ORCA reports keep raw named metric names in LRS" {
    var counters: stats.Stats = .{ .allocator = gpa };
    defer counters.deinit();
    counters.setPropagation(std.testing.io, "a", .{ .named_metrics_all = true });
    counters.recordOrca(std.testing.io, "a", .{ .named_metrics = &.{.{ .name = "load", .value = 2.0 }} });
    var snapshot = try counters.snapshotDelta(gpa, std.testing.io);
    defer snapshot.deinit();
    var wire = try encodeSnapshot(&snapshot);
    defer wire.deinit();
    try std.testing.expectEqual(@as(u64, 1), (try metric(wire.value, "load")).count);
    try std.testing.expectEqual(@as(f64, 2.0), (try metric(wire.value, "load")).value);
}
