//! Versioned, identity-bound persistence for one reconnecting MQTT Session.
//!
//! The caller owns durable file or journal replacement. This module only
//! encodes and transactionally decodes the reconnect client's Session Store so
//! a higher-level coordinator can atomically compose it with its own records.

const std = @import("std");
const mqtt = @import("../mod.zig");
const persistence = @import("../persistence/codec.zig");
const session = @import("../session/mod.zig");

const magic = "netz-mqtt-reconnect\x00";
const version: u32 = 1;

pub const Error = session.Error || persistence.Error || error{
    SnapshotClientMismatch,
    SnapshotProtocolMismatch,
    SnapshotSessionCountMismatch,
};

pub const Restored = struct {
    store: session.Store,
    handle: session.Handle,

    pub fn deinit(self: *Restored) void {
        self.store.deinit();
        self.* = undefined;
    }
};

pub fn encode(
    store: *session.Store,
    handle: session.Handle,
    protocol: mqtt.ProtocolVersion,
    client_id: []const u8,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error!void {
    if (!std.mem.eql(u8, try store.clientId(handle), client_id)) {
        return error.SnapshotClientMismatch;
    }
    const start = out.items.len;
    errdefer out.shrinkRetainingCapacity(start);
    try out.appendSlice(allocator, magic);
    try persistence.appendInt(out, allocator, u32, version);
    try persistence.appendInt(
        out,
        allocator,
        i64,
        clampI96ToI64(realtime_now.nanoseconds),
    );
    try persistence.appendInt(
        out,
        allocator,
        u8,
        protocol.byte(),
    );
    try persistence.appendBlob(out, allocator, client_id);
    try store.writeSnapshot(out, allocator, monotonic_now);
    try store.writeIncomingQoS2Snapshot(handle, out, allocator);
    try persistence.appendInt(
        out,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(out.items[start..]),
    );
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    store_options: session.Options,
    expected_protocol: mqtt.ProtocolVersion,
    expected_client_id: []const u8,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error!Restored {
    const minimum_len = magic.len + 5 * @sizeOf(u32) +
        @sizeOf(i64) + @sizeOf(u8);
    if (bytes.len < minimum_len) return error.CorruptSnapshot;
    const payload = bytes[0 .. bytes.len - @sizeOf(u32)];
    const expected_crc = std.mem.readInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        .big,
    );
    if (std.hash.crc.Crc32.hash(payload) != expected_crc) {
        return error.CorruptSnapshot;
    }

    var cursor = persistence.Cursor.init(payload);
    const found_magic = cursor.inner.readSlice(magic.len) catch
        return error.CorruptSnapshot;
    if (!std.mem.eql(u8, found_magic, magic)) {
        return error.CorruptSnapshot;
    }
    if (try cursor.readInt(u32) != version) {
        return error.UnsupportedSnapshotVersion;
    }
    const saved_realtime_ns = try cursor.readInt(i64);
    const protocol = std.enums.fromInt(
        mqtt.ProtocolVersion,
        try cursor.readInt(u8),
    ) orelse return error.CorruptSnapshot;
    if (protocol != expected_protocol) {
        return error.SnapshotProtocolMismatch;
    }
    const client_id = try cursor.readBlob();
    if (!std.mem.eql(u8, client_id, expected_client_id)) {
        return error.SnapshotClientMismatch;
    }

    var store = session.Store.init(allocator, store_options);
    errdefer store.deinit();
    try store.restoreSnapshot(
        &cursor,
        monotonic_now,
        persistence.elapsedDowntimeNs(
            saved_realtime_ns,
            clampI96ToI64(realtime_now.nanoseconds),
        ),
    );
    const stats = store.aggregateStats();
    if (stats.session_count != 1 or stats.connected_count != 0 or
        stats.subscription_count != 0)
    {
        return error.SnapshotSessionCountMismatch;
    }
    const handle = store.find(expected_client_id, monotonic_now) orelse
        return error.SnapshotSessionCountMismatch;
    try store.restoreIncomingQoS2Snapshot(handle, &cursor);
    try cursor.finish();
    return .{ .store = store, .handle = handle };
}

fn clampI96ToI64(value: i96) i64 {
    return @intCast(std.math.clamp(
        value,
        std.math.minInt(i64),
        std.math.maxInt(i64),
    ));
}

test "MQTT reconnect snapshot restores both QoS2 directions" {
    const allocator = std.testing.allocator;
    const options = session.Options{
        .max_sessions = 1,
        .max_queued_per_session = std.math.maxInt(u16),
        .max_inflight_per_session = std.math.maxInt(u16),
    };
    var store = session.Store.init(allocator, options);
    defer store.deinit();
    const opened = try store.open(
        "bridge-target",
        false,
        std.math.maxInt(u32),
        .zero,
    );
    const await_pubrec = try store.beginImmediatePublish(
        opened.handle,
        "outbound/one",
        "one",
        .{
            .qos = .exactly_once,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 10,
            } }},
            .now = .zero,
        },
        8,
    );
    const await_pubcomp = try store.beginImmediatePublish(
        opened.handle,
        "outbound/two",
        "two",
        .{ .qos = .exactly_once, .now = .zero },
        8,
    );
    try std.testing.expectEqual(
        session.AckAction.send_pubrel,
        try store.handleAck(
            opened.handle,
            .pubrec,
            await_pubcomp.packet_id,
            0,
        ),
    );
    _ = try store.recordIncomingQoS2(opened.handle, 41);
    _ = try store.recordIncomingQoS2(opened.handle, 42);
    try store.markIncomingQoS2ReleasePending(opened.handle, 42);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, "outer");
    const envelope_start = encoded.items.len;
    try encode(
        &store,
        opened.handle,
        .v5,
        "bridge-target",
        &encoded,
        allocator,
        std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(100 * std.time.ns_per_s),
    );
    try std.testing.expectEqualStrings("outer", encoded.items[0..envelope_start]);
    var restored = try decode(
        allocator,
        encoded.items[envelope_start..],
        options,
        .v5,
        "bridge-target",
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(101 * std.time.ns_per_s),
    );
    defer restored.deinit();
    try std.testing.expectEqual(
        session.IncomingQoS2State.await_pubrel,
        (try restored.store.incomingQoS2State(restored.handle, 41)).?,
    );
    try std.testing.expectEqual(
        session.IncomingQoS2State.release_pending,
        (try restored.store.incomingQoS2State(restored.handle, 42)).?,
    );

    const resumed = try restored.store.open(
        "bridge-target",
        false,
        std.math.maxInt(u32),
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
    );
    try std.testing.expect(resumed.session_present);
    var transmissions: [4]session.Transmission = undefined;
    const pending = try restored.store.drainInto(
        resumed.handle,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        8,
        &transmissions,
    );
    try std.testing.expectEqual(@as(usize, 2), pending.len);
    var saw_publish = false;
    var saw_pubrel = false;
    for (pending) |transmission| switch (transmission) {
        .publish => |publish| {
            try std.testing.expectEqual(await_pubrec.packet_id, publish.packet_id);
            try std.testing.expect(publish.dup);
            try std.testing.expectEqual(
                @as(?u32, 8),
                publish.message_expiry_interval,
            );
            saw_publish = true;
        },
        .pubrel => |pubrel| {
            try std.testing.expectEqual(await_pubcomp.packet_id, pubrel.packet_id);
            saw_pubrel = true;
        },
    };
    try std.testing.expect(saw_publish and saw_pubrel);
}

test "MQTT reconnect snapshot binds protocol client and checksum" {
    const allocator = std.testing.allocator;
    const options = session.Options{ .max_sessions = 1 };
    var store = session.Store.init(allocator, options);
    defer store.deinit();
    _ = try store.open(
        "snapshot-client",
        false,
        std.math.maxInt(u32),
        .zero,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encode(
        &store,
        (store.find("snapshot-client", .zero) orelse unreachable),
        .v5,
        "snapshot-client",
        &encoded,
        allocator,
        .zero,
        .zero,
    );
    try std.testing.expectError(
        error.SnapshotProtocolMismatch,
        decode(allocator, encoded.items, options, .v3_1_1, "snapshot-client", .zero, .zero),
    );
    try std.testing.expectError(
        error.SnapshotClientMismatch,
        decode(allocator, encoded.items, options, .v5, "other-client", .zero, .zero),
    );

    var trailing: std.ArrayList(u8) = .empty;
    defer trailing.deinit(allocator);
    try trailing.appendSlice(
        allocator,
        encoded.items[0 .. encoded.items.len - @sizeOf(u32)],
    );
    try trailing.append(allocator, 0xaa);
    try persistence.appendInt(
        &trailing,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(trailing.items),
    );
    try std.testing.expectError(
        error.CorruptSnapshot,
        decode(allocator, trailing.items, options, .v5, "snapshot-client", .zero, .zero),
    );

    encoded.items[magic.len] ^= 0x01;
    try std.testing.expectError(
        error.CorruptSnapshot,
        decode(allocator, encoded.items, options, .v5, "snapshot-client", .zero, .zero),
    );
}
