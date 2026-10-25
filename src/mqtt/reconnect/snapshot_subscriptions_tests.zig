//! Subscription metadata rejects ambiguous state and unwinds failed encodes.
const std = @import("std");
const mqtt = @import("../mod.zig");
const codec = @import("../persistence/codec.zig");
const metadata = @import("snapshot_subscriptions.zig");
const Owned = @import("subscription.zig").Owned;

test "MQTT subscription snapshot rejects a replay index beyond the saved filters" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try codec.appendInt(&bytes, std.testing.allocator, u32, 1);
    try codec.appendOptionalInt(&bytes, std.testing.allocator, u32, 2);
    var cursor = codec.Cursor.init(bytes.items);
    try std.testing.expectError(error.CorruptSnapshot, metadata.decode(&cursor, std.testing.allocator, .v5, 2));
}

test "MQTT subscription snapshot rejects truncated and duplicate saved requests" {
    var packet: std.ArrayList(u8) = .empty;
    defer packet.deinit(std.testing.allocator);
    try mqtt.Subscribe.write(&packet, std.testing.allocator, .v5, 1, &.{}, &.{.{ .topic_filter = "one", .qos = .at_least_once }});
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    for ([_]bool{ false, true }) |duplicate| {
        bytes.clearRetainingCapacity();
        try codec.appendInt(&bytes, std.testing.allocator, u32, if (duplicate) 2 else 1);
        try codec.appendOptionalInt(&bytes, std.testing.allocator, u32, null);
        try codec.appendBlob(&bytes, std.testing.allocator, packet.items[0 .. packet.items.len - @intFromBool(!duplicate)]);
        if (duplicate) try codec.appendBlob(&bytes, std.testing.allocator, packet.items);
        var cursor = codec.Cursor.init(bytes.items);
        try std.testing.expectError(error.CorruptSnapshot, metadata.decode(&cursor, std.testing.allocator, .v5, 3));
    }
}

test "MQTT subscription snapshot requires one canonical SUBSCRIBE per filter" {
    var packet: std.ArrayList(u8) = .empty;
    defer packet.deinit(std.testing.allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    const cases = [_]struct { protocol: mqtt.ProtocolVersion, packet_id: u16 = 1, dup: bool = false, count: usize = 1 }{
        .{ .protocol = .v5, .packet_id = 2 },
        .{ .protocol = .v3_1, .dup = true },
        .{ .protocol = .v5, .count = 2 },
    };
    const filters = [_]mqtt.Subscription{ .{ .topic_filter = "one" }, .{ .topic_filter = "two" } };
    for (cases) |case| {
        packet.clearRetainingCapacity();
        bytes.clearRetainingCapacity();
        try mqtt.Subscribe.writeWithDup(&packet, std.testing.allocator, case.protocol, case.dup, case.packet_id, &.{}, filters[0..case.count]);
        try codec.appendInt(&bytes, std.testing.allocator, u32, 1);
        try codec.appendOptionalInt(&bytes, std.testing.allocator, u32, null);
        try codec.appendBlob(&bytes, std.testing.allocator, packet.items);
        var cursor = codec.Cursor.init(bytes.items);
        try std.testing.expectError(error.CorruptSnapshot, metadata.decode(&cursor, std.testing.allocator, case.protocol, 2));
    }
}

fn allocationFailure(allocator: std.mem.Allocator, values: []const Owned) !void {
    const snapshot = @import("snapshot.zig");
    const session = @import("../session/mod.zig");
    var store = session.Store.init(allocator, .{ .max_sessions = 1 });
    defer store.deinit();
    const handle = (try store.open("encoding", false, 60, .zero)).handle;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, "outer");
    snapshot.encodeWithSubscriptions(&store, handle, .v5, "encoding", &bytes, allocator, .zero, .zero, .{ .values = values, .replay_index = 0 }) catch |err| {
        try std.testing.expectEqualStrings("outer", bytes.items);
        return err;
    };
    try std.testing.expectEqualStrings("outer", bytes.items[0..5]);
}

test "MQTT subscription snapshot encoding rolls back every allocation failure" {
    var value = try Owned.clone(std.testing.allocator, .{ .topic_filter = "encode/filter", .qos = .exactly_once }, &.{.{ .utf8_pair = .{ .id = .user_property, .key = "scope", .value = "owned" } }});
    defer value.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{@as([]const Owned, &.{value})});
}
