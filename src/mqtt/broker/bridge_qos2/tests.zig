const std = @import("std");
const bridge_qos2_root = @import("../bridge_qos2.zig");

const mqtt = @import("../../mod.zig");
const persistence = @import("../../persistence/codec.zig");

const Key = bridge_qos2_root.Key;
const Phase = bridge_qos2_root.Phase;
const Publish = bridge_qos2_root.Publish;
const StageResult = bridge_qos2_root.StageResult;
const Store = bridge_qos2_root.Store;
const testKey = bridge_qos2_root.testKey;

test "bridge QoS2 store deep owns pending publish" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    var topic = [_]u8{ 'm', '/', 'a', 'p' };
    var payload = [_]u8{ 'o', 'n', 'e' };
    try std.testing.expectEqual(
        StageResult.inserted,
        try store.stage(
            testKey(7),
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = true,
                .topic = &topic,
                .packet_id = null,
                .payload = &payload,
            },
            .zero,
        ),
    );
    @memset(&topic, 'x');
    @memset(&payload, 'x');

    const pending = store.getPending(testKey(7)).?;
    try std.testing.expectEqualStrings("m/ap", pending.topic);
    try std.testing.expectEqualStrings("one", pending.payload);
    try std.testing.expect(pending.retain);
    try std.testing.expectEqual(@as(usize, 1), store.stats().entries);
    try std.testing.expect(store.stats().owned_bytes > 0);
}

test "bridge QoS2 store lazily reserves transaction and epoch tables" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var store = try Store.init(failing.allocator(), .{});
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.capacity);
    try std.testing.expectEqual(@as(usize, 0), store.epochs.capacity);

    const key = testKey(9);
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "bridge/lazy",
        .packet_id = null,
        .payload = "payload",
    };
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        store.stage(key, publish, .zero),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), store.stats().entries);
    try std.testing.expectEqual(@as(usize, 0), store.stats().owned_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.entries.capacity);

    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(
        StageResult.inserted,
        try store.stage(key, publish, .zero),
    );
    try std.testing.expect(store.entries.capacity != 0);

    const bridge_id = [_]u8{0xa7} ** 16;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        store.advanceSession(bridge_id),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        store.latestSessionEpoch(bridge_id),
    );
    try std.testing.expectEqual(@as(usize, 0), store.epochs.capacity);

    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(
        @as(u64, 1),
        try store.advanceSession(bridge_id),
    );
    try std.testing.expect(store.epochs.capacity != 0);
}

test "bridge QoS2 store rejects mismatched duplicate but accepts identical retry" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(11);
    var connection_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 3 } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = "remote",
        } },
    };
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/topic",
            .packet_id = null,
            .properties = &connection_properties,
            .payload = "payload",
        },
        .zero,
    );

    try std.testing.expectEqual(
        StageResult.duplicate,
        try store.stage(
            key,
            .{
                .dup = true,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/topic",
                .packet_id = null,
                .properties = &connection_properties,
                .payload = "payload",
            },
            .zero,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        store.stage(
            key,
            .{
                .dup = true,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/topic",
                .packet_id = null,
                .payload = "other",
            },
            .zero,
        ),
    );
}

test "bridge QoS2 store release rollback and commit are transactional" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(17);
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/release",
            .packet_id = null,
            .payload = "body",
        },
        .zero,
    );

    var first = store.release(key);
    try std.testing.expect(!first.duplicated);
    try std.testing.expect(first.claim != null);
    try std.testing.expect(store.getPending(key) == null);
    try store.rollbackRelease(&first.claim.?);
    try std.testing.expectEqualStrings(
        "mirror/release",
        store.getPending(key).?.topic,
    );

    var second = store.release(key);
    try std.testing.expect(!second.duplicated);
    try store.commitRelease(&second.claim.?);
    try std.testing.expectEqual(Phase.released, store.getPhase(key).?);

    const repeated = store.release(key);
    try std.testing.expect(repeated.duplicated);
    try std.testing.expect(repeated.claim == null);
    try std.testing.expect(store.complete(key));
    store.restoreReleased(key);
    try std.testing.expectEqual(Phase.released, store.getPhase(key).?);
}

test "bridge QoS2 store allows non-DUP replacement after released tombstone and completion" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(23);
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/reuse",
            .packet_id = null,
            .payload = "first",
        },
        .zero,
    );
    var claim = store.release(key).claim.?;
    try store.commitRelease(&claim);

    try std.testing.expectEqual(
        StageResult.replaced,
        try store.stage(
            key,
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = true,
                .topic = "mirror/reuse",
                .packet_id = null,
                .payload = "second",
            },
            .zero,
        ),
    );
    try std.testing.expectEqualStrings("second", store.getPending(key).?.payload);

    var claim_again = store.release(key).claim.?;
    try store.commitRelease(&claim_again);
    try std.testing.expect(store.complete(key));
    try std.testing.expect(store.getPhase(key) == null);

    try std.testing.expectEqual(
        StageResult.inserted,
        try store.stage(
            key,
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/reuse",
                .packet_id = null,
                .payload = "third",
            },
            .zero,
        ),
    );
}

test "bridge QoS2 replacement accounts the net owned-byte delta" {
    const allocator = std.testing.allocator;
    const key = testKey(24);
    const small_topic = "small";
    const large_topic = "larger-topic";
    const small_payload = "x";
    const large_payload = "larger-payload";
    const maximum = large_topic.len + large_payload.len;
    var store = try Store.init(allocator, .{
        .max_entries = 1,
        .max_owned_bytes = maximum,
    });
    defer store.deinit();

    _ = try store.stage(key, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = small_topic,
        .packet_id = null,
        .payload = small_payload,
    }, .zero);
    try std.testing.expectEqual(
        StageResult.replaced,
        try store.stage(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = large_topic,
            .packet_id = null,
            .payload = large_payload,
        }, .zero),
    );
    try std.testing.expectEqual(maximum, store.stats().owned_bytes);
}

test "bridge QoS2 store retires one upstream Session epoch" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 3,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();
    const first = testKey(24);
    var next_epoch = first;
    next_epoch.session_epoch += 1;
    _ = try store.stage(first, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "old",
        .packet_id = null,
        .payload = "one",
    }, .zero);
    _ = try store.stage(next_epoch, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "new",
        .packet_id = null,
        .payload = "two",
    }, .zero);

    try std.testing.expectEqual(
        @as(usize, 1),
        store.removeSession(first.bridge_id, first.session_epoch),
    );
    try std.testing.expect(store.getPhase(first) == null);
    try std.testing.expectEqual(Phase.pending, store.getPhase(next_epoch).?);
}

test "bridge QoS2 store enumerates epochs and removes bridge state" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{});
    defer store.deinit();
    const bridge_id = [_]u8{0x31} ** 16;
    const other_id = [_]u8{0x32} ** 16;
    const pending = Key{
        .bridge_id = bridge_id,
        .session_epoch = 4,
        .packet_id = 8,
    };
    var released = pending;
    released.packet_id = 9;
    var newer = pending;
    newer.session_epoch = 7;
    newer.packet_id = 10;
    var other = pending;
    other.bridge_id = other_id;

    for ([_]Key{ pending, released, newer, other }) |key| {
        _ = try store.stage(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bridge/enumerate",
            .packet_id = null,
            .payload = "value",
        }, .zero);
    }
    var claim = store.release(released).claim.?;
    try store.commitRelease(&claim);

    try std.testing.expectEqual(
        @as(?u64, 7),
        store.latestSessionEpoch(bridge_id),
    );
    const transactions = try store.sessionTransactionsAlloc(
        allocator,
        bridge_id,
        4,
    );
    defer allocator.free(transactions);
    try std.testing.expectEqual(@as(usize, 2), transactions.len);
    try std.testing.expectEqual(@as(u16, 8), transactions[0].packet_id);
    try std.testing.expectEqual(Phase.pending, transactions[0].phase);
    try std.testing.expectEqual(@as(u16, 9), transactions[1].packet_id);
    try std.testing.expectEqual(Phase.released, transactions[1].phase);

    try std.testing.expectEqual(Phase.pending, store.getPhase(pending).?);
    try std.testing.expectEqual(Phase.released, store.getPhase(released).?);
    try std.testing.expectEqual(
        @as(u64, 8),
        try store.advanceSession(bridge_id),
    );
    try std.testing.expectEqual(@as(usize, 3), store.removeBridge(bridge_id));
    try std.testing.expectEqual(
        @as(?u64, 8),
        store.latestSessionEpoch(bridge_id),
    );
    try std.testing.expectEqual(Phase.pending, store.getPhase(other).?);
}

test "bridge QoS2 epoch survives snapshot without transactions" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{});
    defer store.deinit();
    const bridge_id = [_]u8{0x71} ** 16;
    try std.testing.expectEqual(
        @as(u64, 1),
        try store.advanceSession(bridge_id),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(&encoded, allocator, .zero);

    var restored = try Store.init(allocator, .{});
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(&cursor, .zero, 0);
    try cursor.finish();
    try std.testing.expectEqual(
        @as(?u64, 1),
        restored.latestSessionEpoch(bridge_id),
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        try restored.advanceSession(bridge_id),
    );
}

test "bridge QoS2 epoch table is bounded" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 1,
        .max_owned_bytes = 1,
    });
    defer store.deinit();
    const first = [_]u8{0x81} ** 16;
    const second = [_]u8{0x82} ** 16;
    try std.testing.expectEqual(@as(u64, 1), try store.advanceSession(first));
    try std.testing.expectEqual(@as(u64, 2), try store.advanceSession(first));
    try std.testing.expectError(
        error.EntryLimitExceeded,
        store.advanceSession(second),
    );
}

test "bridge QoS2 store snapshot restores pending and released state and rejects corruption" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 4,
        .max_owned_bytes = 8192,
    });
    defer store.deinit();

    var expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 5,
    } }};

    const pending_key = testKey(31);
    const released_key = testKey(32);
    _ = try store.stage(
        pending_key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/pending",
            .packet_id = null,
            .properties = &expiry,
            .payload = "persisted",
        },
        .zero,
    );
    _ = try store.stage(
        released_key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = true,
            .topic = "mirror/released",
            .packet_id = null,
            .payload = "done-routing",
        },
        .zero,
    );
    var claim = store.release(released_key).claim.?;
    try store.commitRelease(&claim);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
    );

    var restored = try Store.init(allocator, .{
        .max_entries = 4,
        .max_owned_bytes = 8192,
    });
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        2 * std.time.ns_per_s,
    );
    try cursor.finish();
    try std.testing.expectEqual(Phase.pending, restored.getPhase(pending_key).?);
    try std.testing.expectEqual(Phase.released, restored.getPhase(released_key).?);
    try std.testing.expectEqualStrings(
        "persisted",
        restored.getPending(pending_key).?.payload,
    );

    var corrupt = try allocator.dupe(u8, encoded.items);
    defer allocator.free(corrupt);
    corrupt[0] ^= 0xff;
    var corrupt_cursor = persistence.Cursor.init(corrupt);
    try std.testing.expectError(
        error.UnsupportedSnapshotVersion,
        restored.restoreSnapshot(
            &corrupt_cursor,
            .zero,
            0,
        ),
    );
}
