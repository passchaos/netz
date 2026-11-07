//! A partial data-error publication and its wire NACK have distinct histories.
const std = @import("std");
const managed = @import("../../managed.zig");
const t = @import("testing.zig");
const gpa = t.gpa;
const sibling = "xdstp://A/envoy.config.cluster.v3.Cluster/a2";
const old_eds = "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/a2";
const next_eds = "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/a2-next";

fn partial(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(mode).initWithDataErrors(threaded.io(), true);
    defer h.deinit();
    const listener = try t.lds_fixture.encode(gpa, .{ .name = t.names.listener, .route_name = t.names.routes });
    defer gpa.free(listener);
    try h.accept(.{ .url = t.lds.type_url, .name = t.names.listener, .version = "l1", .bytes = listener });
    const routes = try t.rds_fixture.encode(gpa, t.names.routes, &.{"backend.test"}, &.{
        .{ .exact = "/demo.Service/Alpha", .cluster = t.names.cluster_a },
        .{ .exact = "/demo.Service/Alternate", .cluster = sibling },
        .{ .prefix = "/", .cluster = t.names.cluster_b },
    }, null);
    defer gpa.free(routes);
    try h.accept(.{ .url = t.rds.type_url, .name = t.names.routes, .version = "r1", .bytes = routes });
    const a = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "");
    defer gpa.free(a);
    const a2 = try t.cds_fixture.cluster(gpa, sibling, old_eds, "");
    defer gpa.free(a2);
    try h.accept(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "ca1", .bytes = a, .extra = .{ .name = sibling, .bytes = a2 } });
    const ea = try t.cds_fixture.assignment(gpa, t.names.endpoint_a, "127.0.0.1", 1001);
    defer gpa.free(ea);
    const ea2 = try t.cds_fixture.assignment(gpa, old_eds, "127.0.0.1", 1001);
    defer gpa.free(ea2);
    try h.accept(.{ .url = t.eds.type_url, .name = t.names.endpoint_a, .version = "ea1", .bytes = ea, .extra = .{ .name = old_eds, .bytes = ea2 } });
    const b = try t.cds_fixture.cluster(gpa, t.names.cluster_b, t.names.endpoint_b, "");
    defer gpa.free(b);
    try h.accept(.{ .url = t.cds.type_url, .name = t.names.cluster_b, .version = "cb1", .bytes = b });
    const eb = try t.cds_fixture.assignment(gpa, t.names.endpoint_b, "127.0.0.1", 1001);
    defer gpa.free(eb);
    try h.accept(.{ .url = t.eds.type_url, .name = t.names.endpoint_b, .version = "eb1", .bytes = eb });
    try std.testing.expectEqual(@as(usize, 3), h.data.configuredEndpointCount());
    const bad = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "\xd2\x02\x02\x1a\x00");
    defer gpa.free(bad);
    const replacement = try t.cds_fixture.cluster(gpa, sibling, next_eds, "");
    defer gpa.free(replacement);
    var event = try h.event(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "partial-a", .bytes = bad, .extra = .{ .name = sibling, .bytes = replacement } });
    defer event.deinit();
    try std.testing.expectError(error.UnsupportedCdsFeature, h.facade.applyWithDeadline(&event, t.names.deadline(h.io)));
    const before_nack = try h.snapshot("");
    defer gpa.free(before_nack);
    const accepted_dump = try t.decode(before_nack);
    defer accepted_dump.deinit();
    const accepted = accepted_dump.find(t.cds.type_url, sibling) orelse return error.MissingValidSibling;
    try std.testing.expectEqualStrings("partial-a", accepted.version);
    try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.acked, accepted.status);
    try std.testing.expectEqualSlices(u8, replacement, accepted.wire);
    const failed = accepted_dump.find(t.cds.type_url, t.names.cluster_a) orelse return error.MissingFailedSibling;
    try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.nacked, failed.status);
    try std.testing.expect(failed.wire.len == 0 and failed.version.len == 0 and failed.last_updated_seconds == null);
    try std.testing.expectEqualStrings("partial-a", failed.error_state.?.version_info);
    if (mode == .delta) {
        const session = try h.facade.registry.forName(sibling);
        try std.testing.expectEqualStrings("partial-a", session.client.acceptedVersion(t.cds.type_url, sibling).?);
        try std.testing.expect(session.client.acceptedVersion(t.cds.type_url, t.names.cluster_a) == null);
        const versions = session.client.subscriptions.find(t.cds.type_url).?.versions;
        for (versions) |value| {
            if (!std.mem.eql(u8, value.name, sibling)) continue;
            try std.testing.expectEqual(@as(i64, @intCast(@divFloor(value.accepted_ns, std.time.ns_per_s))), accepted.last_updated_seconds.?);
            try std.testing.expectEqual(@as(u32, @intCast(@mod(value.accepted_ns, std.time.ns_per_s))), accepted.last_updated_nanos.?);
        }
    }
    const identity = @intFromPtr(h.facade.status_history.find(t.cds.type_url, sibling).?);
    try std.testing.expectError(error.AdsNotConnected, h.facade.rejectWithDeadline(&event, "invalid source A", t.names.deadline(h.io)));
    try std.testing.expectEqual(identity, @intFromPtr(h.facade.status_history.find(t.cds.type_url, sibling).?));
    const after_nack = try h.snapshot("");
    defer gpa.free(after_nack);
    const rejected_dump = try t.decode(after_nack);
    defer rejected_dump.deinit();
    const stable = rejected_dump.find(t.cds.type_url, sibling).?;
    try std.testing.expectEqualStrings("partial-a", stable.version);
    try std.testing.expectEqual(accepted.last_updated_seconds, stable.last_updated_seconds);
    try std.testing.expectEqual(accepted.last_updated_nanos, stable.last_updated_nanos);
    try std.testing.expect(stable.error_state == null);
    const foreign = rejected_dump.find(t.cds.type_url, t.names.cluster_b).?;
    try std.testing.expectEqualStrings("cb1", foreign.version);
    try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.acked, foreign.status);
    // A later rejection of the same valid wire/version is a new attempt.
    var again = try h.event(.{ .url = t.cds.type_url, .name = sibling, .version = "partial-a", .bytes = replacement });
    defer again.deinit();
    try std.testing.expectError(error.AdsNotConnected, h.facade.rejectWithDeadline(&again, "new rejected attempt", t.names.deadline(h.io)));
    const distinct = try h.snapshot("");
    defer gpa.free(distinct);
    const distinct_dump = try t.decode(distinct);
    defer distinct_dump.deinit();
    const new_rejection = distinct_dump.find(t.cds.type_url, sibling).?;
    try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.nacked, new_rejection.status);
    try std.testing.expectEqualStrings("new rejected attempt", new_rejection.error_state.?.details);
    try std.testing.expectEqualSlices(u8, replacement, new_rejection.wire);
}

test "gRPC federated CSDS SotW partial publication preserves valid sibling acceptance" {
    try partial(.sotw);
}
test "gRPC federated CSDS delta partial publication preserves valid sibling acceptance" {
    try partial(.delta);
}
