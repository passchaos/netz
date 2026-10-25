//! Snapshots retain desired subscriptions after the MQTT Session has expired.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const snapshot = @import("snapshot.zig");

fn client(allocator: std.mem.Allocator, io: std.Io, shutdown: *std.Io.Event, requested: u32) !reconnect.Client {
    return reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{ .protocol = .v5, .client_id = "expiry-snapshot", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = requested } }} }, .{}, shutdown);
}

fn stage(source: *reconnect.Client) !void {
    try source.seedSubscription(.{ .topic_filter = "desired/#", .qos = .exactly_once }, &.{.{ .varint = .{ .id = .subscription_identifier, .value = 7 } }});
    _ = try source.outgoing.beginImmediatePublish(source.outgoing_handle, "qos/out", "payload", .{ .qos = .exactly_once, .now = .zero }, 8);
    _ = try source.outgoing.stageIncomingQoS2(source.outgoing_handle, 77);
    try source.outgoing.markIncomingQoS2ReleasePending(source.outgoing_handle, 77);
}

test "MQTT retention snapshot expiry removes both QoS directions and preserves desired filters" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    source.retention.connected(3);
    source.retention.disconnected(.zero);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    // One second offline before saving, so exactly two seconds remain.
    try source.writeSessionSnapshotAt(&bytes, .fromNanoseconds(std.time.ns_per_s), .fromNanoseconds(10 * std.time.ns_per_s));
    for ([_]i96{ -1, 0, 2 * std.time.ns_per_s - 1, 2 * std.time.ns_per_s, 3 * std.time.ns_per_s }) |downtime| {
        var restored = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
        defer restored.deinit();
        try restored.restoreSessionSnapshotAt(bytes.items, .zero, .fromNanoseconds(10 * std.time.ns_per_s + downtime));
        const expired = downtime >= 2 * std.time.ns_per_s;
        const stats = try restored.outgoingStats();
        try std.testing.expectEqual(@as(usize, if (expired) 0 else 1), stats.inflight_count);
        try std.testing.expectEqual(@as(usize, if (expired) 0 else 1), stats.incoming_qos2_count);
        try std.testing.expectEqual(@as(u32, 3), restored.sessionExpiryInterval());
        try std.testing.expect(restored.hasSubscription("desired/#"));
        try std.testing.expectEqual(@as(?usize, if (expired) 0 else null), restored.subscription_replay_index);
    }
}

test "MQTT retention snapshot expiry does not renew across repeated restoration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    source.retention.connected(3);
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&first, .zero, .zero);
    var middle = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer middle.deinit();
    try middle.restoreSessionSnapshotAt(first.items, .zero, .fromNanoseconds(std.time.ns_per_s));
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(std.testing.allocator);
    try middle.writeSessionSnapshotAt(&second, .fromNanoseconds(std.time.ns_per_s), .fromNanoseconds(2 * std.time.ns_per_s));
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(second.items, .zero, .fromNanoseconds(3 * std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 0), (try restored.outgoingStats()).inflight_count);
    try std.testing.expect(restored.hasSubscription("desired/#"));
}

fn restoreFailure(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8) !void {
    var shutdown: std.Io.Event = .unset;
    var destination = try client(allocator, io, &shutdown, 60);
    defer destination.deinit();
    try destination.seedSubscription(.{ .topic_filter = "configured/#" }, &.{});
    destination.restoreSessionSnapshotAt(bytes, .zero, .fromNanoseconds(3 * std.time.ns_per_s)) catch |err| {
        try std.testing.expectEqual(@as(u32, 60), destination.sessionExpiryInterval());
        try std.testing.expectEqual(@as(usize, 1), destination.subscriptionCount());
        try std.testing.expect(destination.hasSubscription("configured/#"));
        try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).inflight_count);
        return err;
    };
    try std.testing.expectEqual(@as(u32, 1), destination.sessionExpiryInterval());
    try std.testing.expectEqual(@as(usize, 2), destination.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).inflight_count);
    try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).incoming_qos2_count);
}

fn encodeFailure(allocator: std.mem.Allocator, io: std.Io) !void {
    var shutdown: std.Io.Event = .unset;
    var source = try client(allocator, io, &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    source.retention.connected(0);
    source.retention.disconnected(.zero);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, "outer");
    source.writeSessionSnapshotAt(&bytes, .zero, .zero) catch |err| {
        try std.testing.expectEqualStrings("outer", bytes.items);
        try std.testing.expectEqual(@as(usize, 1), (try source.outgoingStats()).inflight_count);
        return err;
    };
}

test "MQTT retention snapshots restore and encode transactionally through allocation failures" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    source.retention.connected(1);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&bytes, .zero, .zero);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, restoreFailure, .{ threaded.io(), bytes.items });
    try std.testing.checkAllAllocationFailures(std.testing.allocator, encodeFailure, .{threaded.io()});
}

test "MQTT retention snapshot restores server-selected persistence and accepts version two" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 0);
    defer source.deinit();
    source.retention.connected(2);
    try stage(&source);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&bytes, .zero, .zero);
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown, 0);
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(bytes.items, .zero, .zero);
    try std.testing.expectEqual(@as(u32, 2), restored.sessionExpiryInterval());
    bytes.clearRetainingCapacity();
    try snapshot.encodeWithSubscriptions(&source.outgoing, source.outgoing_handle, .v5, source.clientId(), &bytes, std.testing.allocator, .zero, .zero, .{ .values = source.subscriptions.items, .replay_index = 0 });
    var old = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer old.deinit();
    try old.restoreSessionSnapshotAt(bytes.items, .zero, .zero);
    try std.testing.expectEqual(@as(u32, 60), old.sessionExpiryInterval());
    try std.testing.expectEqual(@as(usize, 1), (try old.outgoingStats()).inflight_count);
}

test "MQTT retention snapshots reject CRC-valid invalid metadata without changing the client" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&bytes, .zero, .zero);
    // Finite retention ends with u32 interval + optional u64 + CRC.
    const offset = bytes.items.len - 17;
    std.mem.writeInt(u32, bytes.items[offset..][0..4], 0, .big);
    std.mem.writeInt(u32, bytes.items[bytes.items.len - 4 ..][0..4], std.hash.crc.Crc32.hash(bytes.items[0 .. bytes.items.len - 4]), .big);
    var destination = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer destination.deinit();
    try std.testing.expectError(error.CorruptSnapshot, destination.restoreSessionSnapshotAt(bytes.items, .zero, .zero));
    try std.testing.expectEqual(@as(u32, 60), destination.sessionExpiryInterval());
    try std.testing.expectEqual(@as(usize, 0), destination.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).inflight_count);
}

test "MQTT retention file snapshot expiry keeps subscriptions and infinite lifetime remains durable" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer source.deinit();
    try stage(&source);
    source.retention.connected(3);
    try source.saveSessionSnapshotFileAt(tmp.dir, "client.snapshot", .zero, .zero);
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer restored.deinit();
    try restored.restoreSessionSnapshotFileAt(tmp.dir, "client.snapshot", .zero, .fromNanoseconds(4 * std.time.ns_per_s));
    try std.testing.expect(restored.hasSubscription("desired/#"));
    try std.testing.expectEqual(@as(usize, 0), (try restored.outgoingStats()).inflight_count);
    source.retention.connected(std.math.maxInt(u32));
    try source.saveSessionSnapshotFileAt(tmp.dir, "forever.snapshot", .zero, .zero);
    var forever = try client(std.testing.allocator, threaded.io(), &shutdown, 60);
    defer forever.deinit();
    try forever.restoreSessionSnapshotFileAt(tmp.dir, "forever.snapshot", .zero, .fromNanoseconds(@as(i96, 1) << 64));
    try std.testing.expectEqual(@as(u32, std.math.maxInt(u32)), forever.sessionExpiryInterval());
    try std.testing.expectEqual(@as(usize, 1), (try forever.outgoingStats()).inflight_count);
    try std.testing.expectEqual(@as(usize, 1), (try forever.outgoingStats()).incoming_qos2_count);
}
