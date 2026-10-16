//! Atomic, checksummed MQTT broker snapshots.
//!
//! Mosquitto persists independent client, subscription, client-message, base
//! message, and retained chunks through a synced temporary file followed by
//! rename. Netz uses the same durability shape while keeping Session and
//! retained section encoding inside their owning modules.

const std = @import("std");
const pending_qos2 = @import("../broker/qos2.zig");
const bridge_qos2 = @import("../broker/bridge_qos2.zig");
const retained = @import("../retained/mod.zig");
const session = @import("../session/mod.zig");
const will = @import("../will/mod.zig");
const durability = @import("../../internal/durability.zig");
pub const codec = @import("codec.zig");
pub const commit_log = @import("commit_log.zig");

const magic = "netz-mqtt-db\x00\x01";
const version: u32 = 7;
const max_section_bytes: usize = 1024 * 1024 * 1024;
pub const max_snapshot_bytes: usize = 5 *| max_section_bytes +| 224;

pub const Error = codec.Error || pending_qos2.Error || bridge_qos2.Error || retained.Error ||
    session.Error || will.Error || error{
    SnapshotNotFound,
    SnapshotBusy,
    CorruptSnapshot,
} || std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.Writer.Error ||
    durability.Error || std.Io.Dir.ReadFileAllocError;

pub const State = struct {
    retained: *retained.Store,
    sessions: *session.Store,
    wills: *will.Scheduler,
    will_publishers: *const will.PublisherMap,
    pending_qos2: *pending_qos2.Store,
    bridge_qos2: *bridge_qos2.Store,
};

pub const RestoredState = struct {
    retained: retained.Store,
    sessions: session.Store,
    wills: will.Scheduler,
    will_publishers: will.PublisherMap,
    pending_qos2: pending_qos2.Store,
    bridge_qos2: bridge_qos2.Store,
};

/// Encode and atomically install a quiescent broker-state snapshot.
///
/// `Broker.saveSnapshot` additionally validates broker lifecycle state and
/// serializes concurrent writers; this lower-level entry point remains useful
/// to callers that compose the persistence stores directly.
pub fn saveAtomic(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    state: State,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error!void {
    const encoded = try encode(
        allocator,
        state,
        monotonic_now,
        realtime_now,
    );
    defer allocator.free(encoded);
    try saveEncodedAtomic(io, dir, sub_path, encoded);
}

/// Atomically install an already-encoded snapshot.
///
/// Live brokers encode while holding their state barrier, then release that
/// barrier before the potentially slow filesystem write and fsync. Keeping
/// the durable replacement here ensures both quiescent and live checkpoints
/// use exactly the same atomic-file contract.
pub fn saveEncodedAtomic(
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    encoded: []const u8,
) Error!void {
    var atomic = try dir.createFileAtomic(io, sub_path, .{
        .replace = true,
        .permissions = snapshotPermissions(),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, encoded);
    try atomic.file.sync(io);
    try durability.replaceSynced(&atomic, io, dir);
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    retained_options: retained.Options,
    session_options: session.Options,
    will_options: will.Options,
    pending_qos2_maximum: usize,
    bridge_qos2_options: bridge_qos2.Options,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error!RestoredState {
    const bytes = dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        .limited(max_snapshot_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.SnapshotNotFound,
        else => |e| return e,
    };
    defer allocator.free(bytes);
    return decode(
        allocator,
        bytes,
        retained_options,
        session_options,
        will_options,
        pending_qos2_maximum,
        bridge_qos2_options,
        monotonic_now,
        realtime_now,
    );
}

pub fn encode(
    allocator: std.mem.Allocator,
    state: State,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error![]u8 {
    return encodeMode(
        allocator,
        state,
        monotonic_now,
        realtime_now,
        false,
    );
}

/// Encode a coherent live-broker checkpoint. Connected durable Sessions are
/// already represented as offline by their snapshot format; connected Wills
/// use crash semantics and begin their effective delay at this checkpoint.
pub fn encodeLive(
    allocator: std.mem.Allocator,
    state: State,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error![]u8 {
    return encodeMode(
        allocator,
        state,
        monotonic_now,
        realtime_now,
        true,
    );
}

fn encodeMode(
    allocator: std.mem.Allocator,
    state: State,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
    live_checkpoint: bool,
) Error![]u8 {
    var retained_bytes: std.ArrayList(u8) = .empty;
    defer retained_bytes.deinit(allocator);
    try state.retained.writeSnapshot(
        &retained_bytes,
        allocator,
        monotonic_now,
    );
    var session_bytes: std.ArrayList(u8) = .empty;
    defer session_bytes.deinit(allocator);
    try state.sessions.writeSnapshot(
        &session_bytes,
        allocator,
        monotonic_now,
    );
    var will_bytes: std.ArrayList(u8) = .empty;
    defer will_bytes.deinit(allocator);
    if (live_checkpoint) {
        try state.wills.writeLiveSnapshot(
            &will_bytes,
            allocator,
            monotonic_now,
            state.will_publishers,
        );
    } else {
        try state.wills.writeSnapshot(
            &will_bytes,
            allocator,
            monotonic_now,
            state.will_publishers,
        );
    }
    var qos2_bytes: std.ArrayList(u8) = .empty;
    defer qos2_bytes.deinit(allocator);
    const PublisherLookup = struct {
        fn exists(
            sessions: *session.Store,
            publisher_id: u64,
        ) bool {
            const route_id = sessionRouteId(publisher_id) orelse return false;
            const handle = sessions.handleForRouteId(route_id) orelse
                return false;
            const session_stats = sessions.stats(handle) catch return false;
            return session_stats.expiry_interval != 0;
        }
    };
    if (live_checkpoint) {
        try state.pending_qos2.writeLiveSnapshot(
            &qos2_bytes,
            allocator,
            monotonic_now,
            state.sessions,
            PublisherLookup.exists,
        );
    } else {
        try state.pending_qos2.writeSnapshot(
            &qos2_bytes,
            allocator,
            monotonic_now,
            state.sessions,
            PublisherLookup.exists,
        );
    }
    var bridge_qos2_bytes: std.ArrayList(u8) = .empty;
    defer bridge_qos2_bytes.deinit(allocator);
    try state.bridge_qos2.writeSnapshot(
        &bridge_qos2_bytes,
        allocator,
        monotonic_now,
    );

    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, magic);
    try codec.appendInt(&encoded, allocator, u32, version);
    try codec.appendInt(
        &encoded,
        allocator,
        i64,
        clampI96ToI64(realtime_now.nanoseconds),
    );
    try appendSection(&encoded, allocator, 1, retained_bytes.items);
    try appendSection(&encoded, allocator, 2, session_bytes.items);
    try appendSection(&encoded, allocator, 3, will_bytes.items);
    try appendSection(&encoded, allocator, 4, qos2_bytes.items);
    try appendSection(&encoded, allocator, 5, bridge_qos2_bytes.items);
    try codec.appendInt(
        &encoded,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(encoded.items),
    );
    return encoded.toOwnedSlice(allocator);
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    retained_options: retained.Options,
    session_options: session.Options,
    will_options: will.Options,
    pending_qos2_maximum: usize,
    bridge_qos2_options: bridge_qos2.Options,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error!RestoredState {
    if (bytes.len < magic.len + @sizeOf(u32) + @sizeOf(i64) +
        @sizeOf(u32))
    {
        return error.CorruptSnapshot;
    }
    const payload = bytes[0 .. bytes.len - @sizeOf(u32)];
    const expected_crc = std.mem.readInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        .big,
    );
    if (std.hash.crc.Crc32.hash(payload) != expected_crc) {
        return error.CorruptSnapshot;
    }
    var cursor = codec.Cursor.init(payload);
    const found_magic = cursor.inner.readSlice(magic.len) catch
        return error.CorruptSnapshot;
    if (!std.mem.eql(u8, found_magic, magic)) {
        return error.CorruptSnapshot;
    }
    const found_version = try cursor.readInt(u32);
    if (found_version != version) {
        return error.UnsupportedSnapshotVersion;
    }
    const saved_realtime_ns = try cursor.readInt(i64);
    const downtime_ns = codec.elapsedDowntimeNs(
        saved_realtime_ns,
        clampI96ToI64(realtime_now.nanoseconds),
    );

    const retained_section = try readSection(&cursor, 1);
    const session_section = try readSection(&cursor, 2);
    const will_section = try readSection(&cursor, 3);
    const qos2_section = try readSection(&cursor, 4);
    const bridge_qos2_section = try readSection(&cursor, 5);
    try cursor.finish();

    var staged_retained = retained.Store.init(
        allocator,
        retained_options,
    );
    errdefer staged_retained.deinit();
    var retained_cursor = codec.Cursor.init(retained_section);
    try staged_retained.restoreSnapshot(
        &retained_cursor,
        monotonic_now,
        downtime_ns,
    );
    try retained_cursor.finish();

    var staged_sessions = session.Store.init(
        allocator,
        session_options,
    );
    errdefer staged_sessions.deinit();
    var session_cursor = codec.Cursor.init(session_section);
    try staged_sessions.restoreSnapshot(
        &session_cursor,
        monotonic_now,
        downtime_ns,
    );
    try session_cursor.finish();

    var staged_wills = will.Scheduler.init(allocator, will_options);
    errdefer staged_wills.deinit();
    var staged_publishers: will.PublisherMap = .empty;
    errdefer staged_publishers.deinit(allocator);
    var will_cursor = codec.Cursor.init(will_section);
    try staged_wills.restoreSnapshot(
        &will_cursor,
        monotonic_now,
        downtime_ns,
        &staged_publishers,
    );
    try will_cursor.finish();

    var staged_qos2 = try pending_qos2.Store.init(
        allocator,
        pending_qos2_maximum,
    );
    errdefer staged_qos2.deinit();
    var qos2_cursor = codec.Cursor.init(qos2_section);
    try staged_qos2.restoreSnapshot(
        &qos2_cursor,
        monotonic_now,
        downtime_ns,
        &staged_sessions,
        struct {
            fn exists(
                sessions: *session.Store,
                publisher_id: u64,
            ) bool {
                return sessionRouteId(publisher_id) != null and
                    sessions.handleForRouteId(
                        sessionRouteId(publisher_id).?,
                    ) != null;
            }
        }.exists,
    );
    try qos2_cursor.finish();

    var staged_bridge_qos2 = try bridge_qos2.Store.init(
        allocator,
        bridge_qos2_options,
    );
    errdefer staged_bridge_qos2.deinit();
    var bridge_qos2_cursor = codec.Cursor.init(bridge_qos2_section);
    try staged_bridge_qos2.restoreSnapshot(
        &bridge_qos2_cursor,
        monotonic_now,
        downtime_ns,
    );
    try bridge_qos2_cursor.finish();

    return .{
        .retained = staged_retained,
        .sessions = staged_sessions,
        .wills = staged_wills,
        .will_publishers = staged_publishers,
        .pending_qos2 = staged_qos2,
        .bridge_qos2 = staged_bridge_qos2,
    };
}

fn sessionRouteId(id: u64) ?u64 {
    const tag: u64 = 1 << 63;
    if ((id & tag) == 0) return null;
    return id & ~tag;
}

fn appendSection(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: u32,
    bytes: []const u8,
) codec.Error!void {
    if (bytes.len > max_section_bytes) {
        return error.SnapshotLimitExceeded;
    }
    try codec.appendInt(out, allocator, u32, kind);
    try codec.appendInt(out, allocator, u32, @intCast(bytes.len));
    try codec.appendInt(
        out,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(bytes),
    );
    try out.appendSlice(allocator, bytes);
}

fn readSection(
    cursor: *codec.Cursor,
    expected_kind: u32,
) codec.Error![]const u8 {
    if (try cursor.readInt(u32) != expected_kind) {
        return error.CorruptSnapshot;
    }
    const len = try cursor.readInt(u32);
    if (len > max_section_bytes) return error.SnapshotLimitExceeded;
    const expected_crc = try cursor.readInt(u32);
    const bytes = cursor.inner.readSlice(len) catch
        return error.CorruptSnapshot;
    if (std.hash.crc.Crc32.hash(bytes) != expected_crc) {
        return error.CorruptSnapshot;
    }
    return bytes;
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
