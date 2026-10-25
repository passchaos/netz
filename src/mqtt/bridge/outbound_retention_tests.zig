//! Session expiry is an ownership loss, not corruption of a valid journal.
const std = @import("std");
const coordinator = @import("outbound_coordinator.zig");
const fixture = @import("outbound_retention_support.zig");

test "outbound coordinator expiry classifies source and target ownership at both pending QoS2 stages" {
    for ([_]coordinator.Phase{ .target_await_pubrec, .target_await_pubcomp }) |phase| {
        for ([_]bool{ false, true }) |source_expired| {
            for ([_]bool{ false, true }) |target_expired| try exercise(phase, source_expired, target_expired);
        }
    }
}

test "outbound coordinator expiry durably retires terminal source transactions and preserves target outcomes" {
    for ([_]coordinator.Phase{ .target_complete, .target_rejected }) |phase| {
        for ([_]bool{ false, true }) |source_expired| {
            for ([_]bool{ false, true }) |target_expired| try exercise(phase, source_expired, target_expired);
        }
    }
}

fn exercise(phase: coordinator.Phase, source_expired: bool, target_expired: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    const source_lifetime: u32 = if (source_expired) 1 else 60;
    const target_lifetime: u32 = if (target_expired) 1 else 60;
    try fixture.writeJournal(allocator, io, tmp.dir, &shutdown, source_lifetime, target_lifetime, phase);
    const now = std.Io.Clock.awake.now(io);
    const realtime = fixture.futureTime(io);
    var source = try fixture.client(allocator, io, &shutdown, "expiry-source", source_lifetime);
    defer source.deinit();
    var target = try fixture.client(allocator, io, &shutdown, "expiry-target", target_lifetime);
    defer target.deinit();
    const pending = phase == .target_await_pubrec or phase == .target_await_pubcomp;
    if (pending and (source_expired or target_expired)) {
        const expected = if (source_expired) error.SourceSessionLost else error.TargetSessionLost;
        try std.testing.expectError(expected, coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, now, realtime));
        // Failure precedes live Client installation and every network action.
        try std.testing.expectEqual(@as(usize, 0), (try source.outgoingStats()).incoming_qos2_count);
        try std.testing.expectEqual(@as(usize, 0), (try target.outgoingStats()).inflight_count);
        try std.testing.expect(source.connection() == null and target.connection() == null);
        return;
    }
    var store = try coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, now, realtime);
    var store_open = true;
    defer if (store_open) store.deinit();
    try std.testing.expectEqual(!source_expired, store.currentTransaction() != null);
    try std.testing.expect(source.hasSubscription("desired/#"));
    try std.testing.expectEqual(@as(usize, if (source_expired) 0 else 1), (try source.outgoingStats()).incoming_qos2_count);
    try std.testing.expectEqual(@as(usize, if (pending) 1 else 0), (try target.outgoingStats()).inflight_count);
    if (store.currentTransaction()) |transaction| try std.testing.expectEqual(phase, transaction.phase);
    if (!source_expired) return;
    store.deinit();
    store_open = false;
    var another_source = try fixture.client(allocator, io, &shutdown, "expiry-source", source_lifetime);
    defer another_source.deinit();
    var another_target = try fixture.client(allocator, io, &shutdown, "expiry-target", target_lifetime);
    defer another_target.deinit();
    var reopened = try coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &another_source, &another_target, now, realtime);
    defer reopened.deinit();
    try std.testing.expect(reopened.currentTransaction() == null);
    try std.testing.expect(another_source.hasSubscription("desired/#"));
    try std.testing.expectEqual(@as(usize, 0), (try another_source.outgoingStats()).incoming_qos2_count);
}

test "outbound coordinator validates checkpoint binding before source and target Session expiry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    try fixture.writeJournal(allocator, io, tmp.dir, &shutdown, 1, 1, .target_await_pubrec);
    try fixture.corruptSourceId(allocator, io, tmp.dir);
    var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 1);
    defer source.deinit();
    var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 1);
    defer target.deinit();
    try std.testing.expectError(error.CorruptCoordinatorSnapshot, coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, std.Io.Clock.awake.now(io), fixture.futureTime(io)));
    try std.testing.expectEqual(@as(usize, 0), (try source.outgoingStats()).incoming_qos2_count);
    try std.testing.expectEqual(@as(usize, 0), (try target.outgoingStats()).inflight_count);
}

test "outbound coordinator terminal expiry propagates journal retirement sync failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base_io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    try fixture.writeJournal(allocator, base_io, tmp.dir, &shutdown, 1, 60, .target_complete);
    const Probe = struct {
        // File.sync invokes the vtable synchronously on this test's owner.
        threadlocal var syncs: ?*usize = null;

        fn sync(_: ?*anyopaque, _: std.Io.File) std.Io.File.SyncError!void {
            syncs.?.* += 1;
            return error.InputOutput;
        }
    };
    var sync_count: usize = 0;
    Probe.syncs = &sync_count;
    defer Probe.syncs = null;
    var vtable = base_io.vtable.*;
    vtable.fileSync = Probe.sync;
    const io: std.Io = .{ .userdata = base_io.userdata, .vtable = &vtable };
    var source = try fixture.client(allocator, base_io, &shutdown, "expiry-source", 1);
    defer source.deinit();
    var target = try fixture.client(allocator, base_io, &shutdown, "expiry-target", 60);
    defer target.deinit();
    const now = std.Io.Clock.awake.now(base_io);
    const realtime = fixture.futureTime(base_io);
    try std.testing.expectError(error.InputOutput, coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, now, realtime));
    try std.testing.expectEqual(@as(usize, 1), sync_count);
    try std.testing.expect(source.connection() == null and target.connection() == null);
    // A failed fsync has ambiguous persistence. A fresh owner must be able
    // to recover either durable image without replaying the completed target.
    var next_source = try fixture.client(allocator, base_io, &shutdown, "expiry-source", 1);
    defer next_source.deinit();
    var next_target = try fixture.client(allocator, base_io, &shutdown, "expiry-target", 60);
    defer next_target.deinit();
    var restored = try coordinator.Store.restoreAt(allocator, base_io, tmp.dir, fixture.path, .{}, fixture.identity, &next_source, &next_target, now, realtime);
    defer restored.deinit();
    try std.testing.expect(restored.currentTransaction() == null);
    try std.testing.expectEqual(@as(usize, 0), (try next_target.outgoingStats()).inflight_count);
}
