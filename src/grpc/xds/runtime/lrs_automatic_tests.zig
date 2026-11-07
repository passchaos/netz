//! Bootstrap provenance automatically binds independent, source-isolated LRS.
const std = @import("std");
const grpc = @import("../../mod.zig");
const control_plane = @import("../control_plane.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const fixture = @import("../cds/testing.zig");
const testing = @import("lrs_automatic/testing.zig");
const gpa = std.testing.allocator;
const Mode = testing.Mode;
const Counts = testing.Counts;
const Observed = testing.Observed;
const Peer = testing.Peer;
const Harness = testing.Harness;
const wait = testing.wait;
const noConnection = testing.noConnection;
const configuration = testing.configuration;
const self_lrs = testing.self_lrs;

fn runAutomatic(comptime mode: Mode, late: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const config = try configuration(&server);
    defer config.deinit();
    const plane = try control_plane.ControlPlane.init(gpa, io, config, .{});
    defer plane.deinit();
    var observed: Observed = .{ .io = io, .category = "automatic", .scenario = if (late) "late" else "initial", .mode = @tagName(mode) };
    var task = io.async(Peer.run, .{ &server, &observed });
    defer _ = task.cancel(io) catch {};
    var h = try Harness(mode).init(io, plane, gpa, false, false);
    var live = true;
    defer if (live) h.deinit();
    try h.discover();
    if (late) {
        try h.setCds("absent", false);
        try h.expectDisabled();
        try noConnection(io, &observed.connected);
    }
    try h.setCds("self", true);
    try wait(io, &observed.connected);
    _ = try observed.check();
    try h.call(true, "automatic");
    _ = try observed.awaitCounts(1, 1);
    const held = try h.begin();
    var held_live = true;
    defer if (held_live) held.release();
    if (late) try h.accept(cds.type_url, "a", "deleted", null) else try h.setCds("disabled", false);
    try h.expectDisabled();
    h.complete(held, false);
    held.release();
    held_live = false;
    try std.testing.expectEqual(Counts{ .issued = 2, .successful = 1, .failed = 1, .dropped = 1 }, try observed.awaitCounts(2, 1));
    try observed.expectClose(.{ .issued = 2, .successful = 1, .failed = 1, .dropped = 1 });
    h.deinit();
    live = false;
    try observed.awaitPeer(&task);
}

fn runProvenance(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server_a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server_a.deinit();
    var server_b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server_b.deinit();
    const config_a = try configuration(&server_a);
    defer config_a.deinit();
    const config_b = try configuration(&server_b);
    defer config_b.deinit();
    const plane_a = try control_plane.ControlPlane.init(gpa, io, config_a, .{});
    defer plane_a.deinit();
    const plane_b = try control_plane.ControlPlane.init(gpa, io, config_b, .{});
    defer plane_b.deinit();
    var a: Observed = .{ .io = io, .category = "source-a", .scenario = "provenance", .mode = @tagName(mode) };
    var b: Observed = .{ .io = io, .category = "source-b", .scenario = "provenance", .mode = @tagName(mode) };
    var task_a = io.async(Peer.run, .{ &server_a, &a });
    defer _ = task_a.cancel(io) catch {};
    var task_b = io.async(Peer.run, .{ &server_b, &b });
    defer _ = task_b.cancel(io) catch {};
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var h = try Harness(mode).init(io, plane_a, failing.allocator(), false, false);
    var live = true;
    defer if (live) h.deinit();
    try h.discover();
    try h.setCds("a-self", true);
    try wait(io, &a.connected);
    _ = try a.check();
    try h.call(true, "source-a");
    _ = try a.awaitCounts(1, 1);
    const held = try h.begin();
    var held_live = true;
    defer if (held_live) held.release();
    const old_selection = h.channel.state.lrs_stats.selection;
    try h.rebind(plane_b);
    const assignment = try fixture.assignment(gpa, "eds-a", "127.0.0.1", 1001);
    defer gpa.free(assignment);
    try h.accept(eds.type_url, "eds-a", "b-eds", assignment);
    try std.testing.expectEqualStrings("a-self", h.cdsVersion().?);
    try h.call(true, "source-a");
    _ = try a.awaitCounts(2, 2);
    try noConnection(io, &b.connected);
    const revision = h.channel.configurationRevision();
    const bad_bytes = try fixture.cluster(gpa, "a", "eds-a", "\xd2\x02\x02\x1a\x00");
    defer gpa.free(bad_bytes);
    var bad = try h.update(cds.type_url, "a", "b-nack", bad_bytes);
    defer bad.deinit();
    try std.testing.expectError(error.UnsupportedCdsFeature, h.apply(bad));
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("a-self", h.cdsVersion().?);
    const self_bytes = try fixture.cluster(gpa, "a", "eds-a", self_lrs);
    defer gpa.free(self_bytes);
    var candidate = try h.update(cds.type_url, "a", "b-self", self_bytes);
    defer candidate.deinit();
    const published_selection = h.channel.state.lrs_stats.selection;
    failing.fail_index = failing.alloc_index;
    const result = h.apply(candidate);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(published_selection == h.channel.state.lrs_stats.selection);
    try std.testing.expectEqualSlices(u8, old_selection.?.find("a", "eds-a").?.source_key, published_selection.?.find("a", "eds-a").?.source_key);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("a-self", h.cdsVersion().?);
    try h.call(true, "source-a");
    _ = try a.awaitCounts(3, 3);
    try noConnection(io, &b.connected);
    try std.testing.expectError(error.AdsNotConnected, h.apply(candidate));
    try std.testing.expectEqualStrings("b-self", h.cdsVersion().?);
    try wait(io, &b.connected);
    _ = try b.check();
    try h.call(false, "source-b");
    h.complete(held, true);
    held.release();
    held_live = false;
    try std.testing.expectEqual(Counts{ .issued = 4, .successful = 4, .dropped = 3 }, try a.awaitCounts(4, 3));
    try std.testing.expectEqual(Counts{ .issued = 1, .failed = 1, .dropped = 1 }, try b.awaitCounts(1, 1));
    try a.expectClose(.{ .issued = 4, .successful = 4, .dropped = 3 });
    try b.expectClose(.{ .issued = 1, .failed = 1, .dropped = 1 });
    h.deinit();
    live = false;
    try a.awaitPeer(&task_a);
    try b.awaitPeer(&task_b);
}

fn runDisabled(comptime mode: Mode, manual: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const config = try configuration(&server);
    defer config.deinit();
    const plane = try control_plane.ControlPlane.init(gpa, io, config, .{});
    defer plane.deinit();
    var h = try Harness(mode).init(io, plane, gpa, !manual, manual);
    defer h.deinit();
    try h.discover();
    try h.setCds("self", true);
    try h.expectDisabled();
    try std.testing.expectError(error.Timeout, server.acceptWithTimeout(.fromMilliseconds(150)));
}

fn runRefused(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    var server_live = true;
    defer if (server_live) server.deinit();
    const config = try configuration(&server);
    defer config.deinit();
    server.deinit();
    server_live = false;
    const plane = try control_plane.ControlPlane.init(gpa, io, config, .{});
    defer plane.deinit();
    var h = try Harness(mode).init(io, plane, gpa, false, false);
    defer h.deinit();
    try h.discover();
    const revision = h.channel.configurationRevision();
    try std.testing.expectEqual(@as(i128, 0), h.cdsAcceptedNs());
    const bytes = try fixture.cluster(gpa, "a", "eds-a", self_lrs);
    defer gpa.free(bytes);
    var value = try h.update(cds.type_url, "a", "refused-self", bytes);
    defer value.deinit();
    // Publication has a smaller budget than the independently owned LRS open.
    try std.testing.expectError(error.AdsNotConnected, h.applyUntil(value, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(250) })));
    try std.testing.expect(h.channel.configurationRevision() > revision);
    try std.testing.expectEqualStrings("refused-self", h.cdsVersion().?);
    try std.testing.expect(h.cdsAcceptedNs() > 0);
    try std.testing.expect(h.channel.state.lrs_stats.allocator != null);
    const source = h.client.source.?;
    const selected = h.channel.state.lrs_stats.selection.?.find("a", "eds-a").?;
    try std.testing.expectEqualSlices(u8, source.key, selected.source_key);
    const registration = try h.begin();
    defer registration.release();
    h.complete(registration, false);
    try std.testing.expectEqual(@as(usize, 1), h.controller.lrs_bindings.items.items.len);
    const binding = h.controller.lrs_bindings.items.items[0];
    try std.testing.expectEqualSlices(u8, source.key, binding.source.key);
    try std.testing.expect(binding.plane != plane);
    try std.testing.expectEqual(@as(usize, 1), binding.plane.servers.len);
    try std.testing.expectEqualStrings(source.server.uri, binding.plane.serverUri());
}

fn runSourceLimit(comptime mode: Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server_a = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server_a.deinit();
    var server_b = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server_b.deinit();
    const config_a = try configuration(&server_a);
    defer config_a.deinit();
    const config_b = try configuration(&server_b);
    defer config_b.deinit();
    const plane_a = try control_plane.ControlPlane.init(gpa, io, config_a, .{});
    defer plane_a.deinit();
    const plane_b = try control_plane.ControlPlane.init(gpa, io, config_b, .{});
    defer plane_b.deinit();
    var a: Observed = .{ .io = io, .category = "source-a", .scenario = "source-limit", .mode = @tagName(mode) };
    var b: Observed = .{ .io = io, .category = "source-b", .scenario = "source-limit", .mode = @tagName(mode) };
    var task_a = io.async(Peer.run, .{ &server_a, &a });
    defer _ = task_a.cancel(io) catch {};
    var task_b = io.async(Peer.run, .{ &server_b, &b });
    defer _ = task_b.cancel(io) catch {};
    var h = try Harness(mode).initLimited(io, plane_a, gpa, false, false, 1);
    var live = true;
    defer if (live) h.deinit();
    try h.discover();
    try h.setCds("a-self", true);
    try wait(io, &a.connected);
    _ = try a.check();
    const held = try h.begin();
    var held_live = true;
    defer if (held_live) held.release();
    const selected = h.channel.state.lrs_stats.selection;
    const revision = h.channel.configurationRevision();
    const accepted_ns = h.cdsAcceptedNs();
    try h.rebind(plane_b);
    try std.testing.expect(!std.mem.eql(u8, selected.?.find("a", "eds-a").?.source_key, h.client.source.?.key));
    const bytes = try fixture.cluster(gpa, "a", "eds-a", self_lrs);
    defer gpa.free(bytes);
    var candidate = try h.update(cds.type_url, "a", "b-over-limit", bytes);
    defer candidate.deinit();
    try std.testing.expectError(error.XdsLimitExceeded, h.apply(candidate));
    try std.testing.expect(selected == h.channel.state.lrs_stats.selection);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("a-self", h.cdsVersion().?);
    try std.testing.expectEqual(accepted_ns, h.cdsAcceptedNs());
    try std.testing.expectEqual(@as(usize, 1), h.controller.lrs_bindings.items.items.len);
    try std.testing.expectEqualSlices(u8, selected.?.find("a", "eds-a").?.source_key, h.controller.lrs_bindings.items.items[0].source.key);
    try noConnection(io, &b.connected);
    try std.testing.expectEqual(Counts{}, try b.check());
    try h.call(true, "source-a");
    h.complete(held, false);
    held.release();
    held_live = false;
    try std.testing.expectEqual(Counts{ .issued = 2, .successful = 1, .failed = 1, .dropped = 1 }, try a.awaitCounts(2, 1));
    // Draining calls does not free the slot while accepted CDS still selects A.
    try std.testing.expectError(error.XdsLimitExceeded, h.apply(candidate));
    try std.testing.expect(selected == h.channel.state.lrs_stats.selection);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expectEqualStrings("a-self", h.cdsVersion().?);
    try std.testing.expectEqual(accepted_ns, h.cdsAcceptedNs());
    try noConnection(io, &b.connected);
    try a.expectClose(.{ .issued = 2, .successful = 1, .failed = 1, .dropped = 1 });
    h.deinit();
    live = false;
    try a.awaitPeer(&task_a);
}

test "gRPC automatic SotW and delta LRS enable disabled destination stats and drain retired calls" {
    inline for (.{ Mode.sotw, Mode.delta }) |mode| {
        try runAutomatic(mode, false);
        try runAutomatic(mode, true);
    }
}
test "gRPC automatic LRS preserves accepted CDS provenance through rebind NACK and OOM" {
    try runProvenance(.sotw);
    try runProvenance(.delta);
}
test "gRPC automatic LRS respects opt-out and leaves manual source-null clients disabled" {
    inline for (.{ Mode.sotw, Mode.delta }) |mode| {
        try runDisabled(mode, false);
        try runDisabled(mode, true);
    }
}
test "gRPC automatic LRS publishes accepted self CDS before refused network opening" {
    try runRefused(.sotw);
    try runRefused(.delta);
}
test "gRPC automatic LRS source inventory limit preserves the published source and calls" {
    try runSourceLimit(.sotw);
    try runSourceLimit(.delta);
}
