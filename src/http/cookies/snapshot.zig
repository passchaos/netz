//! Versioned, checksummed, atomically replaceable CookieJar snapshots.

const std = @import("std");
const durability = @import("../../internal/durability.zig");

const magic = "netz-http-cookie-jar\x00";
const version: u32 = 2;
const legacy_version: u32 = 1;
pub const max_snapshot_bytes: usize = 32 * 1024 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    CorruptSnapshot,
    UnsupportedSnapshotVersion,
    SnapshotLimitExceeded,
    SnapshotPolicyMismatch,
};

pub const FileError = Error || error{SnapshotNotFound} ||
    std.Io.Dir.CreateFileAtomicError || std.Io.File.Writer.Error ||
    durability.Error || std.Io.Dir.ReadFileAllocError;

pub const Record = struct {
    name: []u8,
    value: []u8,
    domain: []u8,
    path: []u8,
    expires_at: ?i64,
    secure: bool,
    http_only: bool,
    host_only: bool,
    partitioned: bool,
    partition_site: []u8,
    partition_secure: bool,
    partition_cross_site_ancestor: bool,
    same_site: u8,
    created_at: i64,
    creation_order: u64,
    last_access_order: u64,
    transferred: bool = false,

    fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        if (!self.transferred) {
            allocator.free(self.name);
            allocator.free(self.value);
            allocator.free(self.domain);
            allocator.free(self.path);
            allocator.free(self.partition_site);
        }
        self.* = undefined;
    }
};

pub const Decoded = struct {
    allocator: std.mem.Allocator,
    saved_at: i64,
    sequence: u64,
    records: []Record,

    pub fn deinit(self: *Decoded) void {
        for (self.records) |*record| record.deinit(self.allocator);
        self.allocator.free(self.records);
        self.* = undefined;
    }
};

pub fn encode(
    cookies: anytype,
    sequence: u64,
    now_unix_seconds: i64,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!void {
    const start = out.items.len;
    errdefer out.shrinkRetainingCapacity(start);
    var count: usize = 0;
    for (cookies) |cookie| {
        const expires_at = cookie.expires_at orelse continue;
        if (expires_at <= now_unix_seconds) continue;
        count += 1;
    }
    if (count > std.math.maxInt(u32)) return error.SnapshotLimitExceeded;

    try out.appendSlice(allocator, magic);
    try appendInt(out, allocator, u32, version);
    try appendInt(out, allocator, i64, now_unix_seconds);
    try appendInt(out, allocator, u64, sequence);
    try appendInt(out, allocator, u32, @intCast(count));
    for (cookies) |cookie| {
        const expires_at = cookie.expires_at orelse continue;
        if (expires_at <= now_unix_seconds) continue;
        var flags: u8 = 0;
        flags |= @as(u8, @intFromBool(cookie.secure)) << 0;
        flags |= @as(u8, @intFromBool(cookie.http_only)) << 1;
        flags |= @as(u8, @intFromBool(cookie.host_only)) << 2;
        flags |= @as(u8, @intFromBool(cookie.partition_site != null)) << 3;
        flags |= @as(u8, @intFromBool(cookie.partition_secure)) << 4;
        flags |= @as(u8, @intFromBool(
            cookie.partition_cross_site_ancestor,
        )) << 5;
        try appendInt(out, allocator, u8, flags);
        try appendInt(
            out,
            allocator,
            u8,
            @intFromEnum(cookie.same_site),
        );
        try appendInt(out, allocator, i64, expires_at);
        try appendInt(out, allocator, i64, cookie.created_at);
        try appendInt(out, allocator, u64, cookie.creation_order);
        try appendInt(out, allocator, u64, cookie.last_access_order);
        try appendBlob(out, allocator, cookie.name);
        try appendBlob(out, allocator, cookie.value);
        try appendBlob(out, allocator, cookie.domain);
        try appendBlob(out, allocator, cookie.path);
        try appendBlob(
            out,
            allocator,
            cookie.partition_site orelse &.{},
        );
        if (out.items.len - start > max_snapshot_bytes - @sizeOf(u32)) {
            return error.SnapshotLimitExceeded;
        }
    }
    try appendInt(
        out,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(out.items[start..]),
    );
    if (out.items.len - start > max_snapshot_bytes) {
        return error.SnapshotLimitExceeded;
    }
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_records: usize,
) Error!Decoded {
    if (bytes.len > max_snapshot_bytes) return error.SnapshotLimitExceeded;
    if (bytes.len < magic.len + @sizeOf(u32) * 3 +
        @sizeOf(i64) + @sizeOf(u64)) return error.CorruptSnapshot;
    const payload = bytes[0 .. bytes.len - @sizeOf(u32)];
    const expected_crc = std.mem.readInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        .big,
    );
    if (std.hash.crc.Crc32.hash(payload) != expected_crc) {
        return error.CorruptSnapshot;
    }
    var cursor = Cursor{ .bytes = payload };
    if (!std.mem.eql(u8, try cursor.readSlice(magic.len), magic)) {
        return error.CorruptSnapshot;
    }
    const encoded_version = try cursor.readInt(u32);
    if (encoded_version != version and encoded_version != legacy_version) {
        return error.UnsupportedSnapshotVersion;
    }
    const saved_at = try cursor.readInt(i64);
    const sequence = try cursor.readInt(u64);
    const count = try cursor.readInt(u32);
    if (count > max_records) return error.SnapshotLimitExceeded;

    var records: std.ArrayList(Record) = .empty;
    errdefer {
        for (records.items) |*record| record.deinit(allocator);
        records.deinit(allocator);
    }
    try records.ensureTotalCapacity(allocator, count);
    for (0..count) |_| {
        const flags = try cursor.readInt(u8);
        const allowed_flags: u8 = if (encoded_version == legacy_version)
            0x07
        else
            0x3f;
        if (flags & ~allowed_flags != 0) return error.CorruptSnapshot;
        const same_site = try cursor.readInt(u8);
        if (same_site > 3) return error.CorruptSnapshot;
        const expires_at = try cursor.readInt(i64);
        const created_at = try cursor.readInt(i64);
        const creation_order = try cursor.readInt(u64);
        const last_access_order = try cursor.readInt(u64);
        const name = try cursor.readBlobAlloc(allocator);
        errdefer allocator.free(name);
        const value = try cursor.readBlobAlloc(allocator);
        errdefer allocator.free(value);
        const domain = try cursor.readBlobAlloc(allocator);
        errdefer allocator.free(domain);
        const path = try cursor.readBlobAlloc(allocator);
        errdefer allocator.free(path);
        const partition_site = if (encoded_version == legacy_version)
            try allocator.dupe(u8, "")
        else
            try cursor.readBlobAlloc(allocator);
        errdefer allocator.free(partition_site);
        records.appendAssumeCapacity(.{
            .name = name,
            .value = value,
            .domain = domain,
            .path = path,
            .expires_at = expires_at,
            .secure = flags & 0x01 != 0,
            .http_only = flags & 0x02 != 0,
            .host_only = flags & 0x04 != 0,
            .partitioned = flags & 0x08 != 0,
            .partition_site = partition_site,
            .partition_secure = flags & 0x10 != 0,
            .partition_cross_site_ancestor = flags & 0x20 != 0,
            .same_site = same_site,
            .created_at = created_at,
            .creation_order = creation_order,
            .last_access_order = last_access_order,
        });
    }
    if (cursor.index != payload.len) return error.CorruptSnapshot;
    return .{
        .allocator = allocator,
        .saved_at = saved_at,
        .sequence = sequence,
        .records = try records.toOwnedSlice(allocator),
    };
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
        .limited(max_snapshot_bytes + 1),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.SnapshotNotFound,
        error.StreamTooLong => return error.SnapshotLimitExceeded,
        else => |other| return other,
    };
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    const old_len = out.items.len;
    try out.resize(allocator, old_len + @sizeOf(T));
    std.mem.writeInt(T, out.items[old_len..][0..@sizeOf(T)], value, .big);
}

fn appendBlob(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: []const u8,
) Error!void {
    if (value.len > std.math.maxInt(u32)) return error.SnapshotLimitExceeded;
    try appendInt(out, allocator, u32, @intCast(value.len));
    try out.appendSlice(allocator, value);
}

const Cursor = struct {
    bytes: []const u8,
    index: usize = 0,

    fn readSlice(self: *Cursor, len: usize) Error![]const u8 {
        const end = std.math.add(usize, self.index, len) catch
            return error.CorruptSnapshot;
        if (end > self.bytes.len) return error.CorruptSnapshot;
        defer self.index = end;
        return self.bytes[self.index..end];
    }

    fn readInt(self: *Cursor, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.readSlice(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }

    fn readBlobAlloc(
        self: *Cursor,
        allocator: std.mem.Allocator,
    ) Error![]u8 {
        const len = try self.readInt(u32);
        return allocator.dupe(u8, try self.readSlice(len));
    }
};

fn snapshotPermissions() std.Io.File.Permissions {
    if (comptime std.Io.File.Permissions == void) return {};
    if (comptime @hasDecl(std.Io.File.Permissions, "fromMode")) {
        return .fromMode(0o600);
    }
    return .default_file;
}
