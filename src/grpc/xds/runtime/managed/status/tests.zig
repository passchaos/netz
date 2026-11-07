//! Resource histories stay independent across authorities and publication failure.
const std = @import("std");
const grpc = @import("../../../../mod.zig");
const managed = @import("../../managed.zig");
const csds = @import("../../../csds.zig");
const t = @import("testing.zig");
const gpa = t.gpa;

fn expectResource(dump: t.Dump, url: []const u8, name: []const u8, version: []const u8, status: csds.ClientStatus) !csds.Resource {
    const value = dump.find(url, name) orelse return error.MissingResource;
    try std.testing.expectEqualStrings(version, value.version);
    try std.testing.expectEqual(status, value.status);
    return value;
}

fn history(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(mode).init(threaded.io());
    defer h.deinit();
    try h.graph();
    const encoded = try h.snapshot("");
    defer gpa.free(encoded);
    const initial = try t.decode(encoded);
    defer initial.deinit();
    try std.testing.expectEqual(@as(usize, 6), initial.resources.len);
    try std.testing.expectEqualStrings("grpc", initial.scope);
    const node = try @import("../../../ads.zig").codec.encodeNode(gpa, h.config.adsNode().?);
    defer gpa.free(node);
    try std.testing.expectEqualSlices(u8, node, initial.node);
    inline for (.{
        .{ t.lds.type_url, t.names.listener, "l1" },
        .{ t.rds.type_url, t.names.routes, "r1" },
        .{ t.cds.type_url, t.names.cluster_a, "ca1" },
        .{ t.cds.type_url, t.names.cluster_b, "cb1" },
        .{ t.eds.type_url, t.names.endpoint_a, "ea1" },
        .{ t.eds.type_url, t.names.endpoint_b, "eb1" },
    }) |item| {
        const value = try expectResource(initial, item[0], item[1], item[2], .acked);
        try std.testing.expect(value.wire.len != 0 and value.last_updated_seconds != null and value.last_updated_nanos != null);
        try std.testing.expect(value.error_state == null);
    }
    const old_a = initial.find(t.cds.type_url, t.names.cluster_a).?;
    const revision = h.data.configurationRevision();
    const invalid = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "\xd2\x02\x02\x1a\x00");
    defer gpa.free(invalid);
    var bad = try h.event(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "bad-a", .bytes = invalid });
    defer bad.deinit();
    try std.testing.expectError(error.UnsupportedCdsFeature, h.facade.applyWithDeadline(&bad, t.names.deadline(h.io)));
    try std.testing.expectEqual(revision, h.data.configurationRevision());
    try std.testing.expectError(error.AdsNotConnected, h.facade.rejectWithDeadline(&bad, "invalid source A", t.names.deadline(h.io)));
    const rejected = try h.snapshot("");
    defer gpa.free(rejected);
    const rejected_dump = try t.decode(rejected);
    defer rejected_dump.deinit();
    const failed = try expectResource(rejected_dump, t.cds.type_url, t.names.cluster_a, "ca1", .nacked);
    try std.testing.expectEqualSlices(u8, old_a.wire, failed.wire);
    try std.testing.expectEqual(old_a.last_updated_seconds, failed.last_updated_seconds);
    try std.testing.expectEqual(old_a.last_updated_nanos, failed.last_updated_nanos);
    try std.testing.expectEqualStrings("bad-a", failed.error_state.?.version_info);
    try std.testing.expectEqualStrings("invalid source A", failed.error_state.?.details);
    try std.testing.expect(failed.error_state.?.last_update_attempt != null);
    _ = try expectResource(rejected_dump, t.cds.type_url, t.names.cluster_b, "cb1", .acked);
    bad.session.client.disconnect();
    try std.testing.expect(@import("../status.zig").rejected(mode, &bad));
    const excluded = try h.snapshot("\x18\x01");
    defer gpa.free(excluded);
    const excluded_dump = try t.decode(excluded);
    defer excluded_dump.deinit();
    try std.testing.expectEqual(@as(usize, 6), excluded_dump.resources.len);
    for (excluded_dump.resources) |value| try std.testing.expectEqual(@as(usize, 0), value.wire.len);
    const excluded_a = try expectResource(excluded_dump, t.cds.type_url, t.names.cluster_a, "ca1", .nacked);
    try std.testing.expectEqualStrings("bad-a", excluded_a.error_state.?.version_info);
    const valid = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "");
    defer gpa.free(valid);
    try h.accept(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "ca2", .bytes = valid });
    const restored = try h.snapshot("");
    defer gpa.free(restored);
    const restored_dump = try t.decode(restored);
    defer restored_dump.deinit();
    const current = try expectResource(restored_dump, t.cds.type_url, t.names.cluster_a, "ca2", .acked);
    try std.testing.expect(current.error_state == null);
    // An already returned response owns its prior version and resource bytes.
    _ = try expectResource(initial, t.cds.type_url, t.names.cluster_a, "ca1", .acked);
    _ = try expectResource(rejected_dump, t.cds.type_url, t.names.cluster_a, "ca1", .nacked);
}

fn handoff(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(mode).init(threaded.io());
    defer h.deinit();
    try h.graph();
    const next_routes = "xdstp://B/envoy.config.route.v3.RouteConfiguration/next";
    const listener = try t.lds_fixture.encode(gpa, .{ .name = t.names.listener, .route_name = next_routes });
    defer gpa.free(listener);
    try h.accept(.{ .url = t.lds.type_url, .name = t.names.listener, .version = "l2", .bytes = listener });
    const routes = try t.rds_fixture.encode(gpa, next_routes, &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = t.names.cluster_b2 }}, null);
    defer gpa.free(routes);
    try h.accept(.{ .url = t.rds.type_url, .name = next_routes, .version = "r2", .bytes = routes });
    const pending = try h.snapshot("");
    defer gpa.free(pending);
    const pending_dump = try t.decode(pending);
    defer pending_dump.deinit();
    _ = try expectResource(pending_dump, t.rds.type_url, t.names.routes, "r1", .acked);
    _ = try expectResource(pending_dump, t.rds.type_url, next_routes, "r2", .acked);
    const child = try expectResource(pending_dump, t.cds.type_url, t.names.cluster_b2, "", .requested);
    try std.testing.expect(child.wire.len == 0 and child.last_updated_seconds == null);
    try std.testing.expectEqual(@as(usize, 2), h.data.configuredEndpointCount());
    const cluster = try t.cds_fixture.cluster(gpa, t.names.cluster_b2, t.names.endpoint_b2, "");
    defer gpa.free(cluster);
    try h.accept(.{ .url = t.cds.type_url, .name = t.names.cluster_b2, .version = "cb2", .bytes = cluster });
    const assignment = try t.cds_fixture.assignment(gpa, t.names.endpoint_b2, "127.0.0.1", 1001);
    defer gpa.free(assignment);
    try h.accept(.{ .url = t.eds.type_url, .name = t.names.endpoint_b2, .version = "eb2", .bytes = assignment });
    // A subsequent accepted LDS delivery reconciles now-retired route watches.
    try h.accept(.{ .url = t.lds.type_url, .name = t.names.listener, .version = "l3", .bytes = listener });
    const completed = try h.snapshot("");
    defer gpa.free(completed);
    const completed_dump = try t.decode(completed);
    defer completed_dump.deinit();
    try std.testing.expectEqual(@as(usize, 4), completed_dump.resources.len);
    try std.testing.expect(completed_dump.find(t.rds.type_url, t.names.routes) == null);
    try std.testing.expect(completed_dump.find(t.cds.type_url, t.names.cluster_a) == null);
    _ = try expectResource(completed_dump, t.rds.type_url, next_routes, "r2", .acked);
    _ = try expectResource(completed_dump, t.cds.type_url, t.names.cluster_b2, "cb2", .acked);
    try std.testing.expect((try h.facade.nextResourceTimerExpiry()) == null);
    try std.testing.expectEqual(@as(usize, 0), h.facade.controller.resource_timers.items.len);
    _ = try expectResource(pending_dump, t.rds.type_url, t.names.routes, "r1", .acked);
}

fn rollback(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(mode).init(threaded.io());
    defer h.deinit();
    try h.graph();
    const before = try h.snapshot("");
    defer gpa.free(before);
    const revision = h.data.configurationRevision();
    const cluster = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "");
    defer gpa.free(cluster);
    var update = try h.event(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "ca2", .bytes = cluster });
    defer update.deinit();
    const budget = h.facade.status_history.options.max_storage_bytes;
    h.facade.status_history.options.max_storage_bytes = 1;
    try std.testing.expectError(error.XdsLimitExceeded, h.facade.applyWithDeadline(&update, t.names.deadline(h.io)));
    h.facade.status_history.options.max_storage_bytes = budget;
    const bounded = try h.snapshot("");
    defer gpa.free(bounded);
    try std.testing.expectEqualSlices(u8, before, bounded);
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    h.facade.status_history.allocator = failing.allocator();
    defer h.facade.status_history.allocator = gpa;
    var exhausted = false;
    var failures: usize = 0;
    for (0..32) |index| {
        failing.fail_index = failing.alloc_index + index;
        const result = h.facade.applyWithDeadline(&update, t.names.deadline(h.io));
        failing.fail_index = std.math.maxInt(usize);
        if (result) |_| return error.ExpectedOfflineTransport else |err| {
            if (err == error.AdsNotConnected) {
                exhausted = true;
                break;
            }
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
        }
        try std.testing.expectEqual(revision, h.data.configurationRevision());
        const unchanged = try h.snapshot("");
        defer gpa.free(unchanged);
        try std.testing.expectEqualSlices(u8, before, unchanged);
    }
    try std.testing.expect(exhausted and failures != 0);
    try std.testing.expectError(error.StaleDiscoveryResponse, h.facade.applyWithDeadline(&update, t.names.deadline(h.io)));
    const after = try h.snapshot("");
    defer gpa.free(after);
    const after_dump = try t.decode(after);
    defer after_dump.deinit();
    _ = try expectResource(after_dump, t.cds.type_url, t.names.cluster_a, "ca2", .acked);
    _ = try expectResource(after_dump, t.cds.type_url, t.names.cluster_b, "cb1", .acked);
    try std.testing.expectError(error.InvalidRequest, h.facade.fetchClientStatus(gpa, "\x0f", .{}));
}

test "gRPC federated CSDS SotW owns accepted history and source-specific NACKs" {
    try history(.sotw);
}
test "gRPC federated CSDS delta owns accepted history and source-specific NACKs" {
    try history(.delta);
}
test "gRPC federated CSDS SotW retains per-resource versions through pending handoff" {
    try handoff(.sotw);
}
test "gRPC federated CSDS delta retains per-resource versions through pending handoff" {
    try handoff(.delta);
}
test "gRPC federated CSDS SotW allocation and budget rollback preserve publication" {
    try rollback(.sotw);
}
test "gRPC federated CSDS delta allocation and budget rollback preserve publication" {
    try rollback(.delta);
}

test "gRPC federated CSDS timer refresh preserves both authorities and source features" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(.sotw).init(threaded.io());
    defer h.deinit();
    try h.routes();
    _ = try h.facade.nextResourceTimerExpiry();
    try std.testing.expectEqual(@as(usize, 2), h.facade.controller.resource_timers.items.len);
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(std.Io.Clock.Timestamp.now(h.io, .awake).raw.nanoseconds - 1) };
    for (h.facade.controller.resource_timers.items) |*timer| timer.deadline = expired;
    const encoded = try h.snapshot("");
    defer gpa.free(encoded);
    const dump = try t.decode(encoded);
    defer dump.deinit();
    const timed_out = try expectResource(dump, t.cds.type_url, t.names.cluster_a, "", .timeout);
    try std.testing.expectEqualStrings("initial resource fetch timed out", timed_out.error_state.?.details);
    _ = try expectResource(dump, t.cds.type_url, t.names.cluster_b, "", .does_not_exist);
    try h.facade.pollResourceTimers();
    try std.testing.expectEqual(managed.ResourceStatus.timeout, (try h.facade.resourceStatus(t.cds.type_url, t.names.cluster_a)).?);
    try std.testing.expectEqual(managed.ResourceStatus.does_not_exist, (try h.facade.resourceStatus(t.cds.type_url, t.names.cluster_b)).?);
    try std.testing.expectEqual(@as(usize, 2), h.facade.controller.resource_timers.items.len);
    for (h.facade.controller.resource_timers.items) |timer| try std.testing.expectEqual(expired.raw.nanoseconds, timer.deadline.raw.nanoseconds);
    try std.testing.expect(h.facade.controller.response_authority == null);
    try std.testing.expect(!h.facade.controller.options.resource_timer_is_transient_error);
}

test "gRPC federated CSDS delta expiry and failed publication preserve source histories" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(.delta).init(threaded.io());
    defer h.deinit();
    try h.graph();
    const before = try h.snapshot("");
    defer gpa.free(before);
    const revision = h.data.configurationRevision();
    for (h.facade.controller.entries.items) |*entry| {
        if (!std.mem.eql(u8, entry.identity.name, t.names.cluster_a)) continue;
        entry.cds_deadline = .{ .clock = .awake, .raw = .fromNanoseconds(std.Io.Clock.Timestamp.now(h.io, .awake).raw.nanoseconds - 1) };
    }
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    h.facade.controller.allocator = failing.allocator();
    defer h.facade.controller.allocator = gpa;
    failing.fail_index = failing.alloc_index;
    const result = h.facade.expireDeltaWithDeadline(t.names.deadline(h.io));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(revision, h.data.configurationRevision());
    const unchanged = try h.snapshot("");
    defer gpa.free(unchanged);
    try std.testing.expectEqualSlices(u8, before, unchanged);
    try std.testing.expectError(error.AdsNotConnected, h.facade.expireDeltaWithDeadline(t.names.deadline(h.io)));
    const after = try h.snapshot("");
    defer gpa.free(after);
    const dump = try t.decode(after);
    defer dump.deinit();
    const deleted = try expectResource(dump, t.cds.type_url, t.names.cluster_a, "", .does_not_exist);
    try std.testing.expect(deleted.wire.len == 0);
    _ = try expectResource(dump, t.cds.type_url, t.names.cluster_b, "cb1", .acked);
}
