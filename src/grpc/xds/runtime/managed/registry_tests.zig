//! Failed multi-authority preparation must release provisional quota slots.
const std = @import("std");
const bootstrap = @import("../../bootstrap.zig");
const cds = @import("../../cds.zig");
const rds = @import("../../rds.zig");
const registry_mod = @import("registry.zig");
const gpa = std.testing.allocator;
const a = "xdstp://A/envoy.config.cluster.v3.Cluster/a";
const b = "xdstp://B/envoy.config.cluster.v3.Cluster/b";

fn configuration() !*bootstrap.Bootstrap {
    return bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"127.0.0.1:1\",\"channel_creds\":[{\"type\":\"insecure\"}]}],\"authorities\":{\"A\":{},\"B\":{}},\"node\":{\"id\":\"registry\"}}", .{});
}
fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

fn rollback(comptime mode: registry_mod.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const config = try configuration();
    defer config.deinit();
    const io = threaded.io();
    var registry = registry_mod.Registry(mode).init(gpa, io, config, .{ .max_sessions = 2 });
    defer registry.deinit();
    _ = try registry.forAuthority("");
    try std.testing.expectError(error.InvalidControlPlaneOptions, registry.router().prepare(&.{.{ .type_url = cds.type_url, .names = &.{ a, "xdstp://missing/envoy.config.cluster.v3.Cluster/bad" } }}, deadline(io)));
    try std.testing.expectEqual(@as(usize, 1), registry.sessions.items.len);
    try std.testing.expectEqual(@as(usize, 0), registry.desired.items.len);
    try std.testing.expectEqual(@as(usize, 0), registry.pending_types);
    {
        var staged = try registry.router().prepare(&.{.{ .type_url = cds.type_url, .names = &.{b} }}, deadline(io));
        try std.testing.expectEqual(@as(usize, 2), registry.sessions.items.len);
        try std.testing.expect(registry.sessions.items[1].provisional);
        const retained = registry.sessions.items[1].retain();
        defer retained.release();
        staged.deinit(); // A failed target publication rolls back the prepared batch.
        try std.testing.expectEqualStrings("B", retained.authority);
    }
    try std.testing.expectEqual(@as(usize, 1), registry.sessions.items.len);
    var valid = try registry.router().prepare(&.{.{ .type_url = cds.type_url, .names = &.{b} }}, deadline(io));
    defer valid.deinit();
    valid.commit();
    try std.testing.expectEqual(@as(usize, 2), registry.sessions.items.len);
    const session = registry.sessions.items[1];
    try std.testing.expect(!session.provisional);
    try std.testing.expectEqualStrings("B", session.authority);
    try std.testing.expectEqualStrings(b, session.client.subscriptions.find(cds.type_url).?.names[0]);
}

fn nested(comptime mode: registry_mod.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const config = try configuration();
    defer config.deinit();
    const io = threaded.io();
    var registry = registry_mod.Registry(mode).init(gpa, io, config, .{ .max_sessions = 1 });
    defer registry.deinit();
    var outer = try registry.router().prepare(&.{.{ .type_url = rds.type_url, .names = &.{"xdstp://A/envoy.config.route.v3.RouteConfiguration/r"} }}, deadline(io));
    var inner = registry.router().prepare(&.{.{ .type_url = cds.type_url, .names = &.{a} }}, deadline(io)) catch |err| {
        outer.deinit();
        return err;
    };
    defer inner.deinit();
    outer.deinit();
    try std.testing.expectEqual(@as(usize, 1), registry.sessions.items.len);
    try std.testing.expectEqual(@as(usize, 1), registry.sessions.items[0].pending_prepares);
    inner.commit();
    try std.testing.expect(!registry.sessions.items[0].provisional);
    try std.testing.expect(registry.sessions.items[0].client.subscriptions.find(rds.type_url) == null);
    try std.testing.expectEqualStrings(a, registry.sessions.items[0].client.subscriptions.find(cds.type_url).?.names[0]);
}

test "gRPC federated registry failed preparations release authority quota" {
    try rollback(.sotw);
    try rollback(.delta);
}
test "gRPC federated registry nested preparation reserves a provisional session" {
    try nested(.sotw);
    try nested(.delta);
}

test "gRPC federated registry discards inactive authority errors without a stream" {
    inline for (.{ registry_mod.Mode.sotw, registry_mod.Mode.delta }) |mode| {
        var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const config = try configuration();
        defer config.deinit();
        const io = threaded.io();
        var registry = registry_mod.Registry(mode).init(gpa, io, config, .{});
        defer registry.deinit();
        const session = try registry.forAuthority("B");
        session.pending = error.ConnectionRefused;
        try std.testing.expect(session.client.stream == null and !registry.active(session));
        try registry.flush(deadline(io));
        try std.testing.expect(session.pending == null);
    }
}
