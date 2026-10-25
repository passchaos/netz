//! Reconstructing a client must retain desired subscriptions and replay state.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const snapshot = @import("snapshot.zig");

fn encode(source: *reconnect.Client) !std.ArrayList(u8) {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&result, .zero, .zero);
    return result;
}

fn client(allocator: std.mem.Allocator, io: std.Io, shutdown: *std.Io.Event) !reconnect.Client {
    return reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = "subscription-snapshot",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, shutdown);
}

test "MQTT reconnect snapshot retains subscriptions and partial recovery" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    const properties = [_]mqtt.Property{
        .{ .varint = .{ .id = .subscription_identifier, .value = 53 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "scope", .value = "owned" } },
    };
    try source.seedSubscription(.{ .topic_filter = "restore/first", .qos = .exactly_once, .no_local = true, .retain_as_published = true, .retain_handling = 1 }, &properties);
    try source.seedSubscription(.{ .topic_filter = "restore/second", .qos = .at_least_once }, &.{});
    source.subscription_replay_index = 1;
    const publish = try source.outgoing.beginImmediatePublish(source.outgoing_handle, "restore/qos", "durable", .{ .qos = .exactly_once, .now = .zero }, 16);
    const id = publish.packet_id;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try source.writeSessionSnapshotAt(&encoded, .zero, .zero);
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(encoded.items, .zero, .zero);
    try std.testing.expectEqual(@as(usize, 2), restored.subscriptionCount());
    try std.testing.expectEqual(@as(?usize, 1), restored.subscription_replay_index);
    try std.testing.expectEqualDeep(source.subscriptions.items[0].value(), restored.subscriptions.items[0].value());
    try std.testing.expectEqualDeep(@as([]const mqtt.Property, &properties), restored.subscriptions.items[0].properties);
    try std.testing.expect((try restored.outgoingQoSState(id)) != null);
    // Parsed subscription strings and properties must not borrow the image.
    @memset(encoded.items, 0);
    try std.testing.expectEqualStrings("restore/first", restored.subscriptions.items[0].filter);
    try std.testing.expectEqualStrings("owned", restored.subscriptions.items[0].properties[1].utf8_pair.value);
}

test "MQTT subscription snapshot merges compatible seeded filters transactionally" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "saved/a", .qos = .at_least_once }, &.{});
    try source.seedSubscription(.{ .topic_filter = "saved/b", .qos = .exactly_once }, &.{});
    source.subscription_replay_index = 1;
    var image = try encode(&source);
    defer image.deinit(std.testing.allocator);
    var destination = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer destination.deinit();
    try destination.seedSubscription(.{ .topic_filter = "saved/b", .qos = .exactly_once }, &.{});
    try destination.seedSubscription(.{ .topic_filter = "configured/c", .qos = .at_most_once }, &.{});
    try destination.restoreSessionSnapshotAt(image.items, .zero, .zero);
    try std.testing.expectEqual(@as(usize, 3), destination.subscriptionCount());
    try std.testing.expectEqual(@as(?usize, 1), destination.subscription_replay_index);
    try std.testing.expectEqualStrings("saved/a", destination.subscriptions.items[0].filter);
    try std.testing.expectEqualStrings("saved/b", destination.subscriptions.items[1].filter);
    try std.testing.expectEqualStrings("configured/c", destination.subscriptions.items[2].filter);
}

test "MQTT subscription snapshot mismatch and limits leave destination unchanged" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "saved/a", .qos = .exactly_once }, &.{});
    try source.seedSubscription(.{ .topic_filter = "saved/b", .qos = .at_least_once }, &.{});
    var image = try encode(&source);
    defer image.deinit(std.testing.allocator);
    var mismatch = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer mismatch.deinit();
    try mismatch.seedSubscription(.{ .topic_filter = "saved/a", .qos = .at_most_once }, &.{});
    try std.testing.expectError(error.SnapshotSubscriptionMismatch, mismatch.restoreSessionSnapshotAt(image.items, .zero, .zero));
    try std.testing.expectEqual(@as(usize, 1), mismatch.subscriptionCount());
    try std.testing.expectEqual(mqtt.QoS.at_most_once, mismatch.subscriptions.items[0].qos);
    try std.testing.expectEqual(@as(usize, 0), (try mismatch.outgoingStats()).inflight_count);
    var property_mismatch = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer property_mismatch.deinit();
    try property_mismatch.seedSubscription(.{ .topic_filter = "saved/a", .qos = .exactly_once }, &.{.{ .varint = .{ .id = .subscription_identifier, .value = 7 } }});
    try std.testing.expectError(error.SnapshotSubscriptionMismatch, property_mismatch.restoreSessionSnapshotAt(image.items, .zero, .zero));
    try std.testing.expectEqual(@as(usize, 1), property_mismatch.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 7), property_mismatch.subscriptions.items[0].properties[0].varint.value);
    var limited = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer limited.deinit();
    limited.client_options.max_subscriptions = 1;
    try std.testing.expectError(error.SnapshotLimitExceeded, limited.restoreSessionSnapshotAt(image.items, .zero, .zero));
    try std.testing.expectEqual(@as(usize, 0), limited.subscriptionCount());
    try std.testing.expect(limited.subscription_replay_index == null);
    limited.client_options.max_subscriptions = 2;
    try limited.seedSubscription(.{ .topic_filter = "extra", .qos = .at_most_once }, &.{});
    try std.testing.expectError(error.SnapshotLimitExceeded, limited.restoreSessionSnapshotAt(image.items, .zero, .zero));
    try std.testing.expectEqual(@as(usize, 1), limited.subscriptionCount());
}

test "MQTT subscription snapshot restore reads version one without replacing seeded configuration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    var image: std.ArrayList(u8) = .empty;
    defer image.deinit(std.testing.allocator);
    try snapshot.encode(&source.outgoing, source.outgoing_handle, .v5, source.options.value.client_id, &image, std.testing.allocator, .zero, .zero);
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer restored.deinit();
    try restored.seedSubscription(.{ .topic_filter = "configured", .qos = .exactly_once }, &.{});
    try restored.restoreSessionSnapshotAt(image.items, .zero, .zero);
    try std.testing.expectEqual(@as(usize, 1), restored.subscriptionCount());
    try std.testing.expect(restored.hasSubscription("configured"));
    try std.testing.expect(restored.subscription_replay_index == null);
}

fn allocationFailure(allocator: std.mem.Allocator, io: std.Io, image: []const u8) !void {
    var shutdown: std.Io.Event = .unset;
    var destination = try client(allocator, io, &shutdown);
    defer destination.deinit();
    try destination.seedSubscription(.{ .topic_filter = "existing", .qos = .at_least_once }, &.{});
    destination.restoreSessionSnapshotAt(image, .zero, .zero) catch |err| {
        try std.testing.expectEqual(@as(usize, 1), destination.subscriptionCount());
        try std.testing.expect(destination.hasSubscription("existing"));
        try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).inflight_count);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 2), destination.subscriptionCount());
    try std.testing.expect(destination.hasSubscription("saved"));
    try std.testing.expectEqual(@as(usize, 1), (try destination.outgoingStats()).inflight_count);
}

test "MQTT subscription snapshot restores atomically across all allocation failures" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "saved", .qos = .exactly_once }, &.{.{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } }});
    _ = try source.outgoing.beginImmediatePublish(source.outgoing_handle, "snapshot/qos", "owned", .{ .qos = .exactly_once, .now = .zero }, 16);
    var image = try encode(&source);
    defer image.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{ threaded.io(), image.items });
}

test "MQTT subscription snapshot owns its allocator after the QoS Store is swapped" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "owned/filter", .qos = .exactly_once }, &.{});
    var image = try encode(&source);
    defer image.deinit(std.testing.allocator);
    var decoded_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(decoded_allocator.deinit() == .ok) catch @panic("decoded allocator leaked");
    var other_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(other_allocator.deinit() == .ok) catch @panic("other allocator leaked");
    var restored = try snapshot.decode(decoded_allocator.allocator(), image.items, .{ .max_sessions = 1 }, .v5, "subscription-snapshot", .zero, .zero);
    var other = @import("../session/mod.zig").Store.init(other_allocator.allocator(), .{ .max_sessions = 1 });
    defer other.deinit();
    restored.store.swap(&other);
    restored.deinit();
}

test "MQTT subscription snapshot file API retains pending replay state" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "file/subscription", .qos = .exactly_once }, &.{});
    source.subscription_replay_index = 0;
    try source.saveSessionSnapshotFileAt(tmp.dir, "client.snapshot", .zero, .zero);
    var restored = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer restored.deinit();
    try restored.restoreSessionSnapshotFileAt(tmp.dir, "client.snapshot", .zero, .zero);
    try std.testing.expectEqual(@as(usize, 1), restored.subscriptionCount());
    try std.testing.expectEqual(@as(?usize, 0), restored.subscription_replay_index);
    try std.testing.expect(restored.hasSubscription("file/subscription"));
}

fn repairCrc(image: []u8) void {
    std.mem.writeInt(u32, image[image.len - 4 ..][0..4], std.hash.crc.Crc32.hash(image[0 .. image.len - 4]), .big);
}

test "MQTT subscription snapshot rejects invalid metadata before swapping QoS state" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "saved/a", .qos = .exactly_once }, &.{});
    try source.seedSubscription(.{ .topic_filter = "saved/b", .qos = .at_least_once }, &.{});
    _ = try source.outgoing.beginImmediatePublish(source.outgoing_handle, "snapshot/qos", "retained", .{ .qos = .exactly_once, .now = .zero }, 16);
    var image = try encode(&source);
    defer image.deinit(std.testing.allocator);
    const saved = std.mem.indexOf(u8, image.items, "saved/a").?;
    const options = saved + "saved/a".len;
    const mutations = [_]struct { offset: usize, replacement: u8 }{
        .{ .offset = options, .replacement = 0xff },
        .{ .offset = saved + "saved/".len, .replacement = 'b' },
    };
    for (mutations) |mutation| {
        var destination = try client(std.testing.allocator, threaded.io(), &shutdown);
        defer destination.deinit();
        try destination.seedSubscription(.{ .topic_filter = "existing", .qos = .at_most_once }, &.{});
        const previous = image.items[mutation.offset];
        image.items[mutation.offset] = mutation.replacement;
        repairCrc(image.items);
        try std.testing.expectError(error.CorruptSnapshot, destination.restoreSessionSnapshotAt(image.items, .zero, .zero));
        try std.testing.expectEqual(@as(usize, 1), destination.subscriptionCount());
        try std.testing.expect(destination.hasSubscription("existing"));
        try std.testing.expectEqual(@as(usize, 0), (try destination.outgoingStats()).inflight_count);
        image.items[mutation.offset] = previous;
        repairCrc(image.items);
    }
    var destination = try client(std.testing.allocator, threaded.io(), &shutdown);
    defer destination.deinit();
    const version_offset = "netz-mqtt-reconnect\x00".len;
    std.mem.writeInt(u32, image.items[version_offset..][0..4], 99, .big);
    repairCrc(image.items);
    try std.testing.expectError(error.UnsupportedSnapshotVersion, destination.restoreSessionSnapshotAt(image.items, .zero, .zero));
    try std.testing.expectEqual(@as(usize, 0), destination.subscriptionCount());
}
