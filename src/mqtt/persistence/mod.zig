//! Atomic, checksummed MQTT broker snapshots.
//!
//! Mosquitto persists independent client, subscription, client-message, base
//! message, and retained chunks through a synced temporary file followed by
//! rename. Netz uses the same durability shape while keeping Session and
//! retained section encoding inside their owning modules.

const std = @import("std");
const retained = @import("../retained/mod.zig");
const session = @import("../session/mod.zig");
const will = @import("../will/mod.zig");
pub const codec = @import("codec.zig");

const magic = "netz-mqtt-db\x00\x01";
const version: u32 = 2;
const max_section_bytes: usize = 1024 * 1024 * 1024;
const max_snapshot_bytes: usize = 3 * max_section_bytes + 160;

pub const Error = codec.Error || retained.Error || session.Error || will.Error || error{
    SnapshotNotFound,
    SnapshotBusy,
    CorruptSnapshot,
} || std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.Writer.Error || std.Io.File.SyncError ||
    std.Io.File.Atomic.ReplaceError || std.Io.Dir.ReadFileAllocError;

pub const State = struct {
    retained: *retained.Store,
    sessions: *session.Store,
    wills: *will.Scheduler,
    will_publishers: *const will.PublisherMap,
};

pub const RestoredState = struct {
    retained: retained.Store,
    sessions: session.Store,
    wills: will.Scheduler,
    will_publishers: will.PublisherMap,
};

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

    var atomic = try dir.createFileAtomic(io, sub_path, .{
        .replace = true,
        .permissions = snapshotPermissions(),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, encoded);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    retained_options: retained.Options,
    session_options: session.Options,
    will_options: will.Options,
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
    try state.wills.writeSnapshot(
        &will_bytes,
        allocator,
        monotonic_now,
        state.will_publishers,
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
    if (try cursor.readInt(u32) != version) {
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

    return .{
        .retained = staged_retained,
        .sessions = staged_sessions,
        .wills = staged_wills,
        .will_publishers = staged_publishers,
    };
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
