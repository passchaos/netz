const std = @import("std");
const qos2_root = @import("../qos2.zig");

const mqtt = @import("../../mod.zig");
const persistence = @import("../../persistence/codec.zig");
const router = @import("../../router.zig");

const Pending = qos2_root.Pending;
const Store = qos2_root.Store;

test "QoS 2 pending coallocates message and source identity bytes" {
    try std.testing.expectError(
        error.InvalidUtf8,
        Pending.createWithSource(
            std.testing.allocator,
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = false,
                .topic = "invalid/source",
                .packet_id = 6,
                .payload = "payload",
            },
            "bad\xff",
            null,
            null,
            .zero,
        ),
    );

    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    var pending = try Pending.createWithSource(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "coallocated/topic",
            .packet_id = 7,
            .payload = "payload",
        },
        "client",
        "user",
        1883,
        .zero,
    );
    defer pending.deinit();

    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(pending.bytes.ptr) + pending.bytes.len,
        @intFromPtr(pending.source_client_id.?.ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(pending.source_client_id.?.ptr) +
            pending.source_client_id.?.len,
        @intFromPtr(pending.source_username.?.ptr),
    );
    try std.testing.expectEqualStrings(
        "coallocated/topic",
        pending.bytes[0..pending.topic_len],
    );
    try std.testing.expectEqualStrings(
        "payload",
        pending.bytes[pending.topic_len..],
    );
}

test "QoS 2 pending coallocation is failure-safe with properties" {
    const Context = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var properties = [_]mqtt.Property{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "source",
                .value = "test",
            } }};
            var pending = try Pending.createWithSource(
                allocator,
                .{
                    .dup = false,
                    .qos = .exactly_once,
                    .retain = false,
                    .topic = "failure/topic",
                    .packet_id = 9,
                    .properties = &properties,
                    .payload = "payload",
                },
                "client",
                "user",
                1883,
                .zero,
            );
            pending.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Context.run,
        .{},
    );
}

test "QoS 2 store reuses bounded pending storage" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var store = try Store.init(failing.allocator(), 2);
    defer store.deinit();
    const first_publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "cached/topic",
        .packet_id = 7,
        .payload = "payload",
    };
    try std.testing.expect(try store.recordWithSource(
        10,
        first_publish,
        "client",
        null,
        null,
        .zero,
    ));
    const allocations_after_first = failing.allocations;
    var first = store.take(10, 7).?;
    const first_storage = first.bytes.ptr;
    store.recycle(&first);
    try std.testing.expectEqual(
        @as(usize, 1),
        store.storage_cache.cachedBlockCount(),
    );

    var second_publish = first_publish;
    second_publish.packet_id = 8;
    try std.testing.expect(try store.recordWithSource(
        10,
        second_publish,
        "client",
        null,
        null,
        .zero,
    ));
    try std.testing.expectEqual(allocations_after_first, failing.allocations);
    var second = store.take(10, 8).?;
    try std.testing.expectEqual(
        @intFromPtr(first_storage),
        @intFromPtr(second.bytes.ptr),
    );
    store.recycle(&second);
}

test "QoS 2 store reserves its transaction map on first publish" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var store = try Store.init(failing.allocator(), 4096);
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.capacity());

    const publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "lazy/qos2",
        .packet_id = 7,
        .payload = "payload",
    };
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        store.record(10, publish, .zero),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), store.count());
    try std.testing.expectEqual(@as(usize, 0), store.entries.capacity());

    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expect(try store.record(10, publish, .zero));
    try std.testing.expect(store.entries.capacity() != 0);
    var pending = store.take(10, 7).?;
    store.recycle(&pending);
}

test "QoS 2 store transfers pending backing into a shared publication" {
    var store = try Store.init(std.testing.allocator, 8);
    defer store.deinit();
    var source_properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "source",
        .value = "pending",
    } }};
    try std.testing.expect(try store.recordWithSourceAndPublicationPrefix(
        10,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "shared/qos2",
            .packet_id = 7,
            .properties = &source_properties,
            .payload = "payload",
        },
        "publisher",
        "user",
        1883,
        .zero,
        true,
    ));
    var pending = store.take(10, 7).?;
    const message_pointer = pending.bytes.ptr;
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(std.testing.allocator);
    const publish = (try pending.asPublish(7, .zero, &properties)).?;

    const publication = try store.adoptPublication(
        &pending,
        publish,
        2,
        .zero,
    );
    try std.testing.expect(pending.storageTransferred());
    try std.testing.expectEqual(message_pointer, publication.topic().ptr);
    try std.testing.expectEqualStrings("shared/qos2", publication.topic());
    try std.testing.expectEqualStrings("payload", publication.payload());
    store.recycle(&pending);
    try std.testing.expectEqual(@as(usize, 1), publication.properties.len);
    try std.testing.expectEqualStrings(
        "source",
        publication.properties[0].utf8_pair.key,
    );
    try std.testing.expectEqualStrings(
        "pending",
        publication.properties[0].utf8_pair.value,
    );

    try std.testing.expectEqual(@as(usize, 0), store.storage_cache.cachedBlockCount());
    publication.release();
    publication.release();
    try std.testing.expect(store.storage_cache.cachedBlockCount() != 0);

    try std.testing.expect(try store.recordWithSourceAndPublicationPrefix(
        10,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "shared/qos2",
            .packet_id = 8,
            .properties = &source_properties,
            .payload = "payload",
        },
        "publisher",
        "user",
        1883,
        .zero,
        true,
    ));
    var reused = store.take(10, 8).?;
    try std.testing.expectEqual(message_pointer, reused.bytes.ptr);
    store.recycle(&reused);
}

test "QoS 2 publication transfer keeps pending ownership on failure" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var store = try Store.init(failing.allocator(), 1);
    defer store.deinit();
    var source_properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "key",
        .value = "value",
    } }};
    try std.testing.expect(try store.recordWithSourceAndPublicationPrefix(
        10,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "shared/failure",
            .packet_id = 7,
            .properties = &source_properties,
            .payload = "payload",
        },
        "publisher",
        null,
        null,
        .zero,
        true,
    ));
    var pending = store.take(10, 7).?;
    var pending_owned = true;
    defer if (pending_owned) store.recycle(&pending);
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(failing.allocator());
    const publish = (try pending.asPublish(7, .zero, &properties)).?;
    failing.fail_index = failing.alloc_index;

    try std.testing.expectError(
        error.OutOfMemory,
        store.adoptPublication(&pending, publish, 2, .zero),
    );
    try std.testing.expect(pending.canAdoptPublication());
    try std.testing.expectEqualStrings("shared/failure", publish.topic);
    try std.testing.expectEqualStrings("payload", publish.payload);
    store.recycle(&pending);
    pending_owned = false;
}

test "QoS 2 store owns bytes and preserves the first duplicate PUBLISH" {
    var store = try Store.init(std.testing.allocator, 2);
    defer store.deinit();

    var topic = [_]u8{ 'q', '/', '2' };
    var payload = [_]u8{ 'o', 'n', 'e' };
    var source_client_id = [_]u8{ 'c', 'l', 'i', 'e', 'n', 't' };
    var source_username = [_]u8{ 'u', 's', 'e', 'r' };
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .exactly_once,
        .retain = true,
        .topic = &topic,
        .packet_id = 7,
        .payload = &payload,
    };
    try std.testing.expect(try store.recordWithSource(
        10,
        publish,
        &source_client_id,
        &source_username,
        1883,
        std.Io.Timestamp.zero,
    ));
    @memset(&topic, 'x');
    @memset(&payload, 'x');
    @memset(&source_client_id, 'x');
    @memset(&source_username, 'x');

    var retry = publish;
    retry.dup = true;
    retry.topic = "q/2";
    retry.payload = "one";
    try std.testing.expect(!try store.record(
        10,
        retry,
        std.Io.Timestamp.zero,
    ));

    var repeated = retry;
    repeated.dup = false;
    repeated.topic = "q/2/replaced";
    repeated.payload = "two";
    try std.testing.expect(!try store.record(
        10,
        repeated,
        std.Io.Timestamp.zero,
    ));
    repeated.dup = true;
    repeated.topic = "q/2/conflicting-dup";
    repeated.payload = "three";
    try std.testing.expect(!try store.record(
        10,
        repeated,
        std.Io.Timestamp.zero,
    ));
    try std.testing.expectEqual(@as(usize, 1), store.count());

    var pending = store.take(10, 7).?;
    defer pending.deinit();
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(std.testing.allocator);
    const restored = (try pending.asPublish(
        7,
        std.Io.Timestamp.zero,
        &properties,
    )).?;
    try std.testing.expectEqualStrings("q/2", restored.topic);
    try std.testing.expectEqualStrings("one", restored.payload);
    try std.testing.expect(restored.retain);
    try std.testing.expectEqualStrings(
        "client",
        pending.source_client_id.?,
    );
    try std.testing.expectEqualStrings("user", pending.source_username.?);
    try std.testing.expectEqual(@as(?u64, 1883), pending.source_listener_id);
}

test "QoS 2 snapshot deducts downtime expiry" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, 2);
    defer store.deinit();
    const publisher_id: router.SubscriberId =
        (@as(u64, 1) << 63) | 9;
    var expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 2,
    } }};
    _ = try store.record(
        publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/expiring",
            .packet_id = 4,
            .properties = &expiry,
            .payload = "payload",
        },
        .zero,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );

    var restored = try Store.init(allocator, 2);
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        .zero,
        3 * std.time.ns_per_s,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );
    try cursor.finish();
    try std.testing.expectEqual(@as(usize, 0), restored.count());
}

test "QoS 2 snapshot preserves retained source identity" {
    const allocator = std.testing.allocator;
    const publisher_id: router.SubscriberId =
        (@as(u64, 1) << 63) | 11;
    var store = try Store.init(allocator, 1);
    defer store.deinit();
    _ = try store.recordWithSource(
        publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = true,
            .topic = "qos2/source",
            .packet_id = 9,
            .payload = "value",
        },
        "publisher",
        "writer",
        1883,
        .zero,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );

    var restored = try Store.init(allocator, 1);
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        .zero,
        0,
        {},
        struct {
            fn exists(_: void, _: router.SubscriberId) bool {
                return true;
            }
        }.exists,
    );
    try cursor.finish();
    var pending = restored.take(publisher_id, 9).?;
    defer pending.deinit();
    try std.testing.expectEqualStrings(
        "publisher",
        pending.source_client_id.?,
    );
    try std.testing.expectEqualStrings("writer", pending.source_username.?);
    try std.testing.expectEqual(@as(?u64, 1883), pending.source_listener_id);
}
