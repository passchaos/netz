const std = @import("std");
const mqtt = @import("../mod.zig");
const session = @import("mod.zig");
const allocator = std.testing.allocator;

fn source() !*session.SharedPublication {
    var properties = [_]mqtt.Property{
        .{ .utf8 = .{ .id = .content_type, .value = "application/octet-stream" } },
        .{ .binary = .{ .id = .correlation_data, .value = "binary\x00identity" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "shared-value" } },
        .{ .four_byte = .{ .id = .message_expiry_interval, .value = 10 } },
    };
    return session.SharedPublication.createFromPublish(allocator, .{ .dup = false, .qos = .exactly_once, .retain = false, .topic = "shared/properties", .packet_id = 1, .properties = &properties, .payload = "payload" }, 1, .zero);
}

test "Session shared properties retain Publication values while preserving per-Session metadata" {
    var store = session.Store.init(allocator, .{ .max_sessions = 2 });
    defer store.deinit();
    const first = try store.open("first", false, 60, .zero);
    const second = try store.open("second", false, 60, .zero);
    const publication = try source();
    var publication_owned = true;
    defer if (publication_owned) publication.release();
    var properties: [5]mqtt.Property = undefined;
    @memcpy(properties[0..4], publication.properties);
    properties[4] = .{ .varint = .{ .id = .subscription_identifier, .value = 17 } };
    var changed = false;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(first.handle, publication, .{ .qos = .at_least_once, .properties = &properties, .now = .zero }, &changed);
    properties[4].varint.value = 29;
    properties[3].four_byte.value = 8;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(second.handle, publication, .{ .qos = .exactly_once, .properties = &properties, .now = .zero }, &changed);
    const content_ptr = publication.properties[0].utf8.value.ptr;
    const correlation_ptr = publication.properties[1].binary.value.ptr;
    const trace_ptr = publication.properties[2].utf8_pair.value.ptr;
    publication.release();
    publication_owned = false;
    var one: [1]session.Transmission = undefined;
    var two: [1]session.Transmission = undefined;
    const a = (try store.drainInto(first.handle, .zero, 1, &one))[0].publish;
    const b = (try store.drainInto(second.handle, .zero, 1, &two))[0].publish;
    try std.testing.expectEqual(content_ptr, a.properties[0].utf8.value.ptr);
    try std.testing.expectEqual(correlation_ptr, b.properties[1].binary.value.ptr);
    try std.testing.expectEqual(trace_ptr, a.properties[2].utf8_pair.value.ptr);
    try std.testing.expect(a.properties.ptr != b.properties.ptr);
    try std.testing.expectEqual(@as(usize, 17), a.properties[4].varint.value);
    try std.testing.expectEqual(@as(usize, 29), b.properties[4].varint.value);
    try std.testing.expectEqual(@as(u32, 10), a.properties[3].four_byte.value);
    try std.testing.expectEqual(@as(u32, 8), b.properties[3].four_byte.value);
    _ = try store.handleAck(first.handle, .puback, a.packet_id, 0);
    try std.testing.expectEqualStrings("shared-value", b.properties[2].utf8_pair.value);
    _ = try store.handleAck(second.handle, .pubrec, b.packet_id, 0);
    _ = try store.handleAck(second.handle, .pubcomp, b.packet_id, 0);
}

test "Session shared properties copy unrelated caller values and preserve logical budgets" {
    const publication = try source();
    defer publication.release();
    var external = "application/octet-stream".*;
    var properties: [4]mqtt.Property = undefined;
    @memcpy(&properties, publication.properties);
    properties[0].utf8.value = &external;
    var shared = session.Store.init(allocator, .{});
    defer shared.deinit();
    var independent = session.Store.init(allocator, .{});
    defer independent.deinit();
    const a = try shared.open("same-name", false, 60, .zero);
    const b = try independent.open("same-name", false, 60, .zero);
    var changed = false;
    _ = try shared.enqueueSharedPublicationTrackingSnapshotChange(a.handle, publication, .{ .qos = .at_least_once, .properties = &properties, .now = .zero }, &changed);
    _ = try independent.enqueuePublish(b.handle, "shared/properties", "payload", .{ .qos = .at_least_once, .properties = &properties, .now = .zero });
    try std.testing.expectEqual((try independent.stats(b.handle)).owned_wire_bytes, (try shared.stats(a.handle)).owned_wire_bytes);
    external[0] = 'X';
    var output: [1]session.Transmission = undefined;
    const value = (try shared.drainInto(a.handle, .zero, 1, &output))[0].publish;
    try std.testing.expectEqualStrings("application/octet-stream", value.properties[0].utf8.value);
    try std.testing.expect(value.properties[0].utf8.value.ptr != publication.properties[0].utf8.value.ptr);
    try std.testing.expect(value.properties[1].binary.value.ptr != publication.properties[1].binary.value.ptr);
}

test "Session detach selection excludes partially shared property ownership" {
    const publication = try source();
    defer publication.release();
    var external = "application/octet-stream".*;
    var properties: [4]mqtt.Property = undefined;
    @memcpy(&properties, publication.properties);
    properties[0].utf8.value = &external;
    var store = session.Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("partial-owner", false, 60, .zero);
    var snapshot_changed = false;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(
        opened.handle,
        publication,
        .{
            .qos = .at_least_once,
            .properties = &properties,
            .now = .zero,
        },
        &snapshot_changed,
    );
    const selected = (try store.drainOneForDetachTrackingSnapshotChange(
        opened.handle,
        .zero,
        1,
        &snapshot_changed,
    )).?;
    try std.testing.expect(selected.transmission == .publish);
    try std.testing.expect(selected.shared_publication == null);
}

test "Session shared properties allocation and quota failures retain publication ownership" {
    const publication = try source();
    defer publication.release();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var store = session.Store.init(failing.allocator(), .{});
    defer store.deinit();
    const opened = try store.open("quota", false, 60, .zero);
    failing.fail_index = failing.alloc_index;
    var changed = false;
    try std.testing.expectError(error.OutOfMemory, store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = publication.properties, .now = .zero }, &changed));
    try std.testing.expectEqual(@as(usize, 1), publication.references.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), (try store.stats(opened.handle)).queued_count);
    failing.fail_index = std.math.maxInt(usize);
    store.options.max_session_bytes = 10;
    try std.testing.expectError(error.SessionByteLimitExceeded, store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = publication.properties, .now = .zero }, &changed));
    try std.testing.expectEqual(@as(usize, 1), publication.references.load(.acquire));
    store.options.max_session_bytes = std.math.maxInt(usize);
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = publication.properties, .now = .zero }, &changed);
    try std.testing.expectEqual(@as(usize, 2), publication.references.load(.acquire));
}

test "Session shared properties snapshot keeps independent ownership and expiry across source teardown" {
    const codec = @import("../persistence/codec.zig");
    var before: std.ArrayList(u8) = .empty;
    defer before.deinit(allocator);
    var expected_bytes: usize = 0;
    {
        var store = session.Store.init(allocator, .{});
        defer store.deinit();
        const publication = try source();
        defer publication.release();
        const opened = try store.open("saved", false, 60, .zero);
        var changed = false;
        _ = try store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = publication.properties, .now = .zero }, &changed);
        try store.disconnect(opened.handle, null, .zero);
        expected_bytes = (try store.stats(opened.handle)).owned_wire_bytes;
        try store.writeSnapshot(&before, allocator, .zero);
    }
    var restored = session.Store.init(allocator, .{});
    defer restored.deinit();
    var cursor = codec.Cursor.init(before.items);
    try restored.restoreSnapshot(&cursor, .fromNanoseconds(100 * std.time.ns_per_s), 2 * std.time.ns_per_s);
    try cursor.finish();
    const opened = try restored.open("saved", false, 60, .fromNanoseconds(100 * std.time.ns_per_s));
    try std.testing.expect(opened.session_present);
    try std.testing.expectEqual(expected_bytes, (try restored.stats(opened.handle)).owned_wire_bytes);
    var out: [1]session.Transmission = undefined;
    const value = (try restored.drainInto(opened.handle, .fromNanoseconds(100 * std.time.ns_per_s), 1, &out))[0].publish;
    try std.testing.expectEqual(@as(?u32, 8), value.message_expiry_interval);
    try std.testing.expectEqualStrings("application/octet-stream", value.properties[0].utf8.value);
    try std.testing.expectEqualStrings("binary\x00identity", value.properties[1].binary.value);
    try std.testing.expectEqualStrings("shared-value", value.properties[2].utf8_pair.value);
    _ = try restored.handleAck(opened.handle, .puback, value.packet_id, 0);
    try std.testing.expectEqual(@as(usize, 0), (try restored.stats(opened.handle)).queued_count);
    try std.testing.expectEqual(@as(usize, 0), (try restored.stats(opened.handle)).inflight_count);
}

test "Session shared properties forward a large ordered User Property set without value allocations" {
    var input: [128]mqtt.Property = undefined;
    for (&input) |*property| property.* = .{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "many-values" } };
    const publication = try session.SharedPublication.createFromPublish(allocator, .{ .dup = false, .qos = .at_least_once, .retain = false, .topic = "many/properties", .packet_id = 1, .properties = &input, .payload = "data" }, 1, .zero);
    defer publication.release();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var store = session.Store.init(failing.allocator(), .{});
    defer store.deinit();
    const opened = try store.open("large-metadata", false, 60, .zero);
    const before = failing.allocations;
    var changed = false;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = publication.properties, .now = .zero }, &changed);
    // One Session property descriptor array and one initial queue array.
    try std.testing.expectEqual(@as(usize, 2), failing.allocations - before);
    var out: [1]session.Transmission = undefined;
    const value = (try store.drainInto(opened.handle, .zero, 1, &out))[0].publish;
    try std.testing.expectEqual(@as(usize, 128), value.properties.len);
    for (value.properties, publication.properties) |property, original| {
        try std.testing.expectEqual(original.utf8_pair.key.ptr, property.utf8_pair.key.ptr);
        try std.testing.expectEqual(original.utf8_pair.value.ptr, property.utf8_pair.value.ptr);
    }
}

test "Session shared properties keep reordered caller metadata independently owned" {
    const publication = try source();
    defer publication.release();
    var input = [_]mqtt.Property{ publication.properties[2], publication.properties[0], publication.properties[1] };
    var store = session.Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("reordered", false, 60, .zero);
    var changed = false;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(opened.handle, publication, .{ .qos = .at_least_once, .properties = &input, .now = .zero }, &changed);
    var out: [1]session.Transmission = undefined;
    const value = (try store.drainInto(opened.handle, .zero, 1, &out))[0].publish;
    try std.testing.expectEqualStrings("shared-value", value.properties[0].utf8_pair.value);
    try std.testing.expectEqualStrings("application/octet-stream", value.properties[1].utf8.value);
    try std.testing.expect(value.properties[0].utf8_pair.value.ptr != input[0].utf8_pair.value.ptr);
}

test "Session shared properties preserve byte-identical snapshot representation" {
    const publication = try source();
    defer publication.release();
    var shared = session.Store.init(allocator, .{});
    defer shared.deinit();
    var independent = session.Store.init(allocator, .{});
    defer independent.deinit();
    const a = try shared.open("snapshot-equal", false, 60, .zero);
    const b = try independent.open("snapshot-equal", false, 60, .zero);
    var changed = false;
    _ = try shared.enqueueSharedPublicationTrackingSnapshotChange(a.handle, publication, .{ .qos = .exactly_once, .properties = publication.properties, .now = .zero }, &changed);
    _ = try independent.enqueuePublish(b.handle, "shared/properties", "payload", .{ .qos = .exactly_once, .properties = publication.properties, .now = .zero });
    try shared.disconnect(a.handle, null, .zero);
    try independent.disconnect(b.handle, null, .zero);
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(allocator);
    var two: std.ArrayList(u8) = .empty;
    defer two.deinit(allocator);
    try shared.writeSnapshot(&one, allocator, .zero);
    try independent.writeSnapshot(&two, allocator, .zero);
    try std.testing.expectEqualSlices(u8, two.items, one.items);
}
