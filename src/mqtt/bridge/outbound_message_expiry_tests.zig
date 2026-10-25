//! Message expiry ends PUBLISH replay while preserving accepted QoS 2 release.
const std = @import("std");
const coordinator = @import("outbound_coordinator.zig");
const fixture = @import("outbound_retention_support.zig");

test "outbound coordinator Message Expiry completes pending PUBLISH without corrupting restored journal" {
    for ([_]coordinator.Phase{ .target_await_pubrec, .target_await_pubcomp, .target_complete, .target_rejected }) |phase| {
        for ([_]u32{ 1, 60 }) |expiry| try restoreCase(phase, expiry);
    }
}

fn restoreCase(phase: coordinator.Phase, expiry: u32) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    {
        var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 60);
        defer source.deinit();
        var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 60);
        defer target.deinit();
        var store = try coordinator.Store.create(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target);
        defer store.deinit();
        try fixture.stageWithExpiry(&source, &target, &store, phase, expiry);
    }
    const expected_phase = if (phase == .target_await_pubrec and expiry == 1) .target_complete else phase;
    const expected_pending: usize = if (expected_phase == .target_await_pubrec or expected_phase == .target_await_pubcomp) 1 else 0;
    const realtime = fixture.futureTime(io);
    // The second restoration reads the normalized durable outcome without
    // extending the message's remaining lifetime or resending its PUBLISH.
    for (0..2) |_| {
        var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 60);
        defer source.deinit();
        var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 60);
        defer target.deinit();
        var restored = try coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, std.Io.Clock.awake.now(io), realtime);
        defer restored.deinit();
        const transaction = restored.currentTransaction().?;
        try std.testing.expectEqual(expected_phase, transaction.phase);
        try std.testing.expectEqual(@as(u8, if (expected_phase == .target_rejected) 0x87 else 0), transaction.target_reason_code);
        try std.testing.expectEqual(expected_pending, (try target.outgoingStats()).inflight_count);
        try std.testing.expectEqual(@as(usize, 1), (try source.outgoingStats()).incoming_qos2_count);
    }
}

test "outbound coordinator Message Expiry cannot hide a malformed transaction binding" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    {
        var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 60);
        defer source.deinit();
        var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 60);
        defer target.deinit();
        var store = try coordinator.Store.create(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target);
        defer store.deinit();
        try fixture.stageWithExpiry(&source, &target, &store, .target_await_pubrec, 1);
    }
    try fixture.corruptSourceId(allocator, io, tmp.dir);
    var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 60);
    defer source.deinit();
    var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 60);
    defer target.deinit();
    try std.testing.expectError(error.CorruptCoordinatorSnapshot, coordinator.Store.restoreAt(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target, std.Io.Clock.awake.now(io), fixture.futureTime(io)));
}

test "outbound coordinator Message Expiry commit retains live ownership on fsync failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    var source = try fixture.client(allocator, io, &shutdown, "expiry-source", 60);
    defer source.deinit();
    var target = try fixture.client(allocator, io, &shutdown, "expiry-target", 60);
    defer target.deinit();
    var store = try coordinator.Store.create(allocator, io, tmp.dir, fixture.path, .{}, fixture.identity, &source, &target);
    defer store.deinit();
    const Probe = struct {
        fn sync(_: ?*anyopaque, _: std.Io.File) std.Io.File.SyncError!void {
            return error.InputOutput;
        }
    };
    var vtable = io.vtable.*;
    vtable.fileSync = Probe.sync;
    store.log.io = .{ .userdata = io.userdata, .vtable = &vtable };
    try std.testing.expectError(error.InputOutput, fixture.stageWithExpiry(&source, &target, &store, .target_await_pubrec, 0));
    try std.testing.expect(store.currentTransaction() == null);
    try std.testing.expectEqual(@as(usize, 1), (try target.outgoingStats()).inflight_count);
    try std.testing.expectEqual(@as(usize, 1), (try source.outgoingStats()).incoming_qos2_count);
    store.log.io = io;
    _ = try store.commit(&source, &target, 1, 1, .{
        .phase = .target_await_pubrec,
        .source_session_epoch = 1,
        .target_session_epoch = 1,
        .source_packet_id = 77,
        .target_packet_id = 1,
        .source_retain = false,
        .source_topic = "source/topic",
        .source_payload = "old",
        .source_properties = &.{},
        .source_expiry_interval = 0,
    });
    try std.testing.expectEqual(coordinator.Phase.target_complete, store.currentTransaction().?.phase);
    try std.testing.expectEqual(@as(usize, 0), (try target.outgoingStats()).inflight_count);
}
