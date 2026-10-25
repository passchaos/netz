//! Versioned, identity-bound persistence for one reconnecting MQTT Session.
//!
//! The in-memory codec remains composable with larger coordinator records.
//! Standalone clients can additionally use the bounded file helpers below,
//! which fsync a temporary inode, atomically replace the destination, and sync
//! its parent directory before reporting success.

const std = @import("std");
const mqtt = @import("../mod.zig");
const persistence = @import("../persistence/codec.zig");
const durability = @import("../../internal/durability.zig");
const session = @import("../session/mod.zig");
pub const subscriptions = @import("snapshot_subscriptions.zig");

const magic = "netz-mqtt-reconnect\x00";
const version: u32 = 1;
const subscription_version: u32 = 2;
pub const max_snapshot_bytes: usize = 2 * persistence.max_blob_bytes;

pub const Error = session.Error || persistence.Error || subscriptions.Error || error{
    SnapshotClientMismatch,
    SnapshotProtocolMismatch,
    SnapshotSessionCountMismatch,
};

pub const FileError = Error || error{SnapshotNotFound} ||
    std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.Writer.Error || durability.Error ||
    std.Io.Dir.ReadFileAllocError;

pub const Restored = struct {
    allocator: std.mem.Allocator,
    store: session.Store,
    handle: session.Handle,
    subscription_state: subscriptions.State = .{},
    has_subscription_state: bool = false,

    pub fn deinit(self: *Restored) void {
        self.subscription_state.deinit(self.allocator);
        self.store.deinit();
        self.* = undefined;
    }
};

/// Write the original QoS-only version-one format for receipt coordinators.
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
    return encodeState(store, handle, protocol, client_id, out, allocator, monotonic_now, realtime_now, null);
}

/// Write version two, including deep-owned desired subscriptions and recovery
/// progress. On failure, retain the caller's existing output prefix.
pub fn encodeWithSubscriptions(store: *session.Store, handle: session.Handle, protocol: mqtt.ProtocolVersion, client_id: []const u8, out: *std.ArrayList(u8), allocator: std.mem.Allocator, monotonic_now: std.Io.Timestamp, realtime_now: std.Io.Timestamp, state: subscriptions.View) Error!void {
    return encodeState(store, handle, protocol, client_id, out, allocator, monotonic_now, realtime_now, state);
}

fn encodeState(store: *session.Store, handle: session.Handle, protocol: mqtt.ProtocolVersion, client_id: []const u8, out: *std.ArrayList(u8), allocator: std.mem.Allocator, monotonic_now: std.Io.Timestamp, realtime_now: std.Io.Timestamp, state: ?subscriptions.View) Error!void {
    if (!std.mem.eql(u8, try store.clientId(handle), client_id)) {
        return error.SnapshotClientMismatch;
    }
    const start = out.items.len;
    errdefer out.shrinkRetainingCapacity(start);
    try out.appendSlice(allocator, magic);
    try persistence.appendInt(out, allocator, u32, if (state != null) subscription_version else version);
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
    if (state) |value| try subscriptions.encode(out, allocator, protocol, value);
    try persistence.appendInt(
        out,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(out.items[start..]),
    );
    if (out.items.len - start > max_snapshot_bytes) return error.SnapshotLimitExceeded;
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
    return decodeWithSubscriptionLimit(allocator, bytes, store_options, expected_protocol, expected_client_id, monotonic_now, realtime_now, store_options.max_subscriptions_per_session);
}

/// Read either version. Reconnect subscription limits are independent of the
/// QoS Store's subscription capacity because desired filters live in Client.
pub fn decodeWithSubscriptionLimit(allocator: std.mem.Allocator, bytes: []const u8, store_options: session.Options, expected_protocol: mqtt.ProtocolVersion, expected_client_id: []const u8, monotonic_now: std.Io.Timestamp, realtime_now: std.Io.Timestamp, maximum_subscriptions: usize) Error!Restored {
    if (bytes.len > max_snapshot_bytes) return error.SnapshotLimitExceeded;
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
    const found_version = try cursor.readInt(u32);
    if (found_version != version and found_version != subscription_version) {
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
    var subscription_state = if (found_version == subscription_version)
        try subscriptions.decode(&cursor, allocator, protocol, maximum_subscriptions)
    else
        subscriptions.State{};
    errdefer subscription_state.deinit(allocator);
    try cursor.finish();
    return .{ .allocator = allocator, .store = store, .handle = handle, .subscription_state = subscription_state, .has_subscription_state = found_version == subscription_version };
}

pub fn saveAtomic(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    encoded: []const u8,
) FileError!void {
    if (encoded.len > max_snapshot_bytes) {
        return error.SnapshotLimitExceeded;
    }
    var atomic = try dir.createFileAtomic(io, sub_path, .{
        .replace = true,
        .permissions = snapshotPermissions(),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, encoded);
    try atomic.file.sync(io);
    try durability.replaceSynced(&atomic, io, dir);
}

pub fn loadAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) FileError![]u8 {
    return dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        // `limited` reports StreamTooLong when the file reaches its bound.
        // Read one sentinel byte so an exactly maximum-sized snapshot remains
        // legal while a larger file maps to SnapshotLimitExceeded.
        .limited(max_snapshot_bytes + 1),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.SnapshotNotFound,
        error.StreamTooLong => return error.SnapshotLimitExceeded,
        else => |e| return e,
    };
}

fn clampI96ToI64(value: i96) i64 {
    return @intCast(std.math.clamp(
        value,
        std.math.minInt(i64),
        std.math.maxInt(i64),
    ));
}

fn snapshotPermissions() std.Io.File.Permissions {
    if (comptime std.Io.File.Permissions == void) return {};
    if (comptime @hasDecl(std.Io.File.Permissions, "fromMode")) {
        return .fromMode(0o600);
    }
    return .default_file;
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

test "MQTT reconnect snapshot file round trips durable state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const options = session.Options{
        .max_sessions = 1,
        .max_queued_per_session = std.math.maxInt(u16),
        .max_inflight_per_session = std.math.maxInt(u16),
    };
    var store = session.Store.init(allocator, options);
    defer store.deinit();
    const opened = try store.open(
        "file-client",
        false,
        std.math.maxInt(u32),
        .zero,
    );
    const staged = try store.stageImmediatePublish(
        opened.handle,
        "file/topic",
        "durable",
        .{ .qos = .at_least_once, .now = .zero },
        8,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encode(
        &store,
        opened.handle,
        .v5,
        "file-client",
        &encoded,
        allocator,
        .zero,
        .zero,
    );
    try saveAtomic(io, tmp.dir, "session.db", encoded.items);
    const stat = try tmp.dir.statFile(io, "session.db", .{});
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        try std.testing.expectEqual(
            @as(std.posix.mode_t, 0o600),
            stat.permissions.toMode() & 0o777,
        );
    }
    const loaded = try loadAlloc(
        allocator,
        io,
        tmp.dir,
        "session.db",
    );
    defer allocator.free(loaded);
    try std.testing.expectEqualSlices(u8, encoded.items, loaded);
    var restored = try decode(
        allocator,
        loaded,
        options,
        .v5,
        "file-client",
        .zero,
        .zero,
    );
    defer restored.deinit();
    try std.testing.expectEqual(
        session.OutgoingQoSState.await_puback,
        (try restored.store.outgoingQoSState(
            restored.handle,
            staged,
        )).?,
    );
    try std.testing.expectError(
        error.SnapshotNotFound,
        loadAlloc(allocator, io, tmp.dir, "missing.db"),
    );
    var oversized = try tmp.dir.createFile(io, "oversized.db", .{});
    defer oversized.close(io);
    try oversized.setLength(io, max_snapshot_bytes + 1);
    try std.testing.expectError(
        error.SnapshotLimitExceeded,
        loadAlloc(allocator, io, tmp.dir, "oversized.db"),
    );
}

test "MQTT reconnect snapshot failed sync preserves installed file" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base_io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(base_io, .{
        .sub_path = "session.db",
        .data = "previous-snapshot",
    });

    const Probe = struct {
        delegate: std.Io,
        destination: std.Io.Dir,
        temporary: ?std.Io.File.Handle = null,
        renames: usize = 0,

        fn dirCreateFileAtomic(
            userdata: ?*anyopaque,
            dir: std.Io.Dir,
            sub_path: []const u8,
            options: std.Io.Dir.CreateFileAtomicOptions,
        ) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            const atomic = try self.delegate.vtable.dirCreateFileAtomic(
                self.delegate.userdata,
                dir,
                sub_path,
                options,
            );
            if (dir.handle == self.destination.handle) {
                self.temporary = atomic.file.handle;
            }
            return atomic;
        }

        fn fileSync(
            userdata: ?*anyopaque,
            file: std.Io.File,
        ) std.Io.File.SyncError!void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.temporary == file.handle) return error.InputOutput;
            return self.delegate.vtable.fileSync(
                self.delegate.userdata,
                file,
            );
        }

        fn dirRename(
            userdata: ?*anyopaque,
            old_dir: std.Io.Dir,
            old_sub_path: []const u8,
            new_dir: std.Io.Dir,
            new_sub_path: []const u8,
        ) std.Io.Dir.RenameError!void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.renames += 1;
            return self.delegate.vtable.dirRename(
                self.delegate.userdata,
                old_dir,
                old_sub_path,
                new_dir,
                new_sub_path,
            );
        }
    };

    var probe = Probe{ .delegate = base_io, .destination = tmp.dir };
    var vtable = base_io.vtable.*;
    vtable.dirCreateFileAtomic = Probe.dirCreateFileAtomic;
    vtable.fileSync = Probe.fileSync;
    vtable.dirRename = Probe.dirRename;
    const io: std.Io = .{ .userdata = &probe, .vtable = &vtable };
    try std.testing.expectError(
        error.InputOutput,
        saveAtomic(io, tmp.dir, "session.db", "replacement"),
    );
    try std.testing.expectEqual(@as(usize, 0), probe.renames);
    const unchanged = try tmp.dir.readFileAlloc(
        base_io,
        "session.db",
        allocator,
        .limited(64),
    );
    defer allocator.free(unchanged);
    try std.testing.expectEqualStrings("previous-snapshot", unchanged);
}
