//! A fully validated MQTT 5 image can supply an unassigned client's identity.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const snapshot = @import("snapshot.zig");

fn makeClient(allocator: std.mem.Allocator, io: std.Io, shutdown: *std.Io.Event, client_id: []const u8) !reconnect.Client {
    return reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = client_id,
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, shutdown);
}

fn image(io: std.Io) !std.ArrayList(u8) {
    var shutdown: std.Io.Event = .unset;
    var source = try makeClient(std.testing.allocator, io, &shutdown, "persisted-id");
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "saved/#", .qos = .exactly_once }, &.{});
    source.subscription_replay_index = 0;
    _ = try source.outgoing.beginImmediatePublish(source.outgoing_handle, "pending", "payload", .{ .qos = .exactly_once, .now = .zero }, 8);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&bytes, .zero, .zero);
    return bytes;
}

fn restoreFailure(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8) !void {
    var shutdown: std.Io.Event = .unset;
    var client = try makeClient(allocator, io, &shutdown, "");
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "configured/#" }, &.{});
    client.restoreSessionSnapshotAt(bytes, .zero, .zero) catch |err| {
        try std.testing.expectEqualStrings("", client.clientId());
        try std.testing.expectEqualStrings("", try client.outgoing.clientId(client.outgoing_handle));
        try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
        try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
        try std.testing.expect(client.subscription_replay_index == null);
        return err;
    };
    try std.testing.expectEqualStrings("persisted-id", client.clientId());
    try std.testing.expectEqualStrings("persisted-id", try client.outgoing.clientId(client.outgoing_handle));
    try std.testing.expectEqual(@as(usize, 2), client.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), (try client.outgoingStats()).inflight_count);
    try std.testing.expectEqual(@as(?usize, 0), client.subscription_replay_index);
}

test "MQTT reconnect assigned identity snapshot restore rolls back every allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var bytes = try image(threaded.io());
    defer bytes.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, restoreFailure, .{ threaded.io(), bytes.items });
}

fn repairCrc(bytes: []u8) void {
    std.mem.writeInt(u32, bytes[bytes.len - 4 ..][0..4], std.hash.crc.Crc32.hash(bytes[0 .. bytes.len - 4]), .big);
}

test "MQTT reconnect assigned identity snapshots preserve identity binding and reject corruption" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var bytes = try image(threaded.io());
    defer bytes.deinit(std.testing.allocator);
    var shutdown: std.Io.Event = .unset;
    var named = try makeClient(std.testing.allocator, threaded.io(), &shutdown, "configured-id");
    defer named.deinit();
    try std.testing.expectError(error.SnapshotClientMismatch, named.restoreSessionSnapshotAt(bytes.items, .zero, .zero));
    try std.testing.expectEqualStrings("configured-id", named.clientId());
    var unassigned = try makeClient(std.testing.allocator, threaded.io(), &shutdown, "");
    defer unassigned.deinit();
    try unassigned.seedSubscription(.{ .topic_filter = "saved/#", .qos = .at_most_once }, &.{});
    try std.testing.expectError(error.SnapshotSubscriptionMismatch, unassigned.restoreSessionSnapshotAt(bytes.items, .zero, .zero));
    try std.testing.expectEqualStrings("", unassigned.clientId());
    const envelope_id = std.mem.indexOf(u8, bytes.items, "persisted-id").?;
    for ([_]u8{ 0, 'x' }) |replacement| {
        const previous = bytes.items[envelope_id];
        bytes.items[envelope_id] = replacement;
        repairCrc(bytes.items);
        try std.testing.expectError(if (replacement == 0) error.CorruptSnapshot else error.SnapshotSessionCountMismatch, unassigned.restoreSessionSnapshotAt(bytes.items, .zero, .zero));
        try std.testing.expectEqualStrings("", unassigned.clientId());
        try std.testing.expectEqual(@as(usize, 0), (try unassigned.outgoingStats()).inflight_count);
        bytes.items[envelope_id] = previous;
        repairCrc(bytes.items);
    }
}

test "MQTT reconnect assigned identity loads from files and version one images" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bytes = try image(io);
    defer bytes.deinit(std.testing.allocator);
    try snapshot.saveAtomic(io, tmp.dir, "assigned.snapshot", bytes.items);
    var shutdown: std.Io.Event = .unset;
    var restored = try makeClient(std.testing.allocator, io, &shutdown, "");
    defer restored.deinit();
    try restored.restoreSessionSnapshotFileAt(tmp.dir, "assigned.snapshot", .zero, .zero);
    @memset(bytes.items, 0);
    try std.testing.expectEqualStrings("persisted-id", restored.clientId());
    try std.testing.expect(restored.hasSubscription("saved/#"));
    var version_one: std.ArrayList(u8) = .empty;
    defer version_one.deinit(std.testing.allocator);
    try snapshot.encode(&restored.outgoing, restored.outgoing_handle, .v5, restored.clientId(), &version_one, std.testing.allocator, .zero, .zero);
    var old = try makeClient(std.testing.allocator, io, &shutdown, "");
    defer old.deinit();
    try old.seedSubscription(.{ .topic_filter = "configured/#" }, &.{});
    try old.restoreSessionSnapshotAt(version_one.items, .zero, .zero);
    try std.testing.expectEqualStrings("persisted-id", old.clientId());
    try std.testing.expect(old.hasSubscription("configured/#"));
    try std.testing.expectEqual(@as(usize, 1), (try old.outgoingStats()).inflight_count);
}
