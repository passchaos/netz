//! Crash-tolerant append journal for coherent MQTT broker state images.
//!
//! Each committed record contains one independently checksummed live snapshot.
//! This first implementation deliberately favors complete recovery semantics
//! over write amplification: every durable transition can be replayed without
//! coupling the log format to private retained/Session/Will layouts. A later
//! compactor may replace state-image records with smaller typed deltas without
//! changing the torn-tail and sequence guarantees implemented here.

const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const durability = @import("../../internal/durability.zig");

const file_magic = "netz-mqtt-journal\x00\x01";
const version: u32 = 1;
const record_magic = "TXN1";
const record_footer_magic = "END1";
const record_prefix_len = record_magic.len + @sizeOf(u64) +
    @sizeOf(u64) + @sizeOf(u32);
const record_header_len = record_prefix_len + @sizeOf(u32);
const record_footer_len = record_footer_magic.len + @sizeOf(u64);

pub const default_max_file_bytes: usize = 1024 * 1024 * 1024;
pub const default_max_record_bytes: usize = 512 * 1024 * 1024;

pub const Error = std.mem.Allocator.Error ||
    std.Io.Dir.ReadFileAllocError || std.Io.File.OpenError ||
    std.Io.File.LengthError || std.Io.File.SetLengthError ||
    std.Io.File.Writer.Error || std.Io.File.Writer.SeekError ||
    std.Io.Writer.Error || durability.Error ||
    std.Io.Dir.CreateFileAtomicError || error{
    CommitLogNotFound,
    EmptyCommitLog,
    CorruptCommitLog,
    UnsupportedCommitLogVersion,
    CommitLogTooLarge,
    CommitRecordTooLarge,
    CommitSequenceExhausted,
};

pub const Options = struct {
    max_file_bytes: usize = default_max_file_bytes,
    max_record_bytes: usize = default_max_record_bytes,
};

const Inspection = struct {
    valid_len: usize,
    next_sequence: u64,
    latest_start: usize = 0,
    latest_len: usize = 0,

    fn latest(self: Inspection, bytes: []const u8) ?[]const u8 {
        if (self.latest_len == 0) return null;
        return bytes[self.latest_start..][0..self.latest_len];
    }
};

pub const Log = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []u8,
    options: Options,
    valid_len: usize,
    next_sequence: u64,

    /// Create an empty journal, atomically discarding any older generation.
    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: Options,
    ) Error!Log {
        try validateOptions(options);
        const owned_path = try allocator.dupe(u8, sub_path);
        errdefer allocator.free(owned_path);
        var atomic = try dir.createFileAtomic(io, sub_path, .{
            .replace = true,
            .permissions = privateFilePermissions(),
        });
        defer atomic.deinit(io);
        try atomic.file.writeStreamingAll(io, fileHeader());
        try atomic.file.sync(io);
        try durability.replaceSynced(&atomic, io, dir);
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .sub_path = owned_path,
            .options = options,
            .valid_len = fileHeader().len,
            .next_sequence = 1,
        };
    }

    /// Atomically create a journal with one complete initial transaction.
    pub fn createWithInitial(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: Options,
        snapshot: []const u8,
    ) Error!Log {
        try validateOptions(options);
        if (snapshot.len == 0 or snapshot.len > options.max_record_bytes) {
            return error.CommitRecordTooLarge;
        }
        const total_len = std.math.add(
            usize,
            fileHeader().len + record_header_len + record_footer_len,
            snapshot.len,
        ) catch return error.CommitLogTooLarge;
        if (total_len > options.max_file_bytes) {
            return error.CommitLogTooLarge;
        }
        const owned_path = try allocator.dupe(u8, sub_path);
        errdefer allocator.free(owned_path);
        var header: [record_header_len]u8 = undefined;
        writeRecordHeader(&header, 1, snapshot);
        var footer: [record_footer_len]u8 = undefined;
        writeRecordFooter(&footer, 1);
        var atomic = try dir.createFileAtomic(io, sub_path, .{
            .replace = true,
            .permissions = privateFilePermissions(),
        });
        defer atomic.deinit(io);
        try atomic.file.writeStreamingAll(io, fileHeader());
        try atomic.file.writeStreamingAll(io, &header);
        try atomic.file.writeStreamingAll(io, snapshot);
        try atomic.file.writeStreamingAll(io, &footer);
        try atomic.file.sync(io);
        try durability.replaceSynced(&atomic, io, dir);
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .sub_path = owned_path,
            .options = options,
            .valid_len = total_len,
            .next_sequence = 2,
        };
    }

    /// Open an existing journal and truncate only an incomplete final record.
    ///
    /// Header, CRC, and sequence corruption is never treated as a torn write.
    /// Only a short final header or payload is recoverable, preserving the
    /// newest fully synced transaction instead of hiding committed damage.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: Options,
    ) Error!Log {
        try validateOptions(options);
        const bytes = dir.readFileAlloc(
            io,
            sub_path,
            allocator,
            .limited(options.max_file_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.CommitLogNotFound,
            error.StreamTooLong => return error.CommitLogTooLarge,
            else => |other| return other,
        };
        defer allocator.free(bytes);
        const inspection = try inspect(bytes, options);
        const owned_path = try allocator.dupe(u8, sub_path);
        errdefer allocator.free(owned_path);

        if (inspection.valid_len != bytes.len) {
            var file = try dir.openFile(io, sub_path, .{
                .mode = .write_only,
            });
            defer file.close(io);
            try file.setLength(io, inspection.valid_len);
            try file.sync(io);
        }
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .sub_path = owned_path,
            .options = options,
            .valid_len = inspection.valid_len,
            .next_sequence = inspection.next_sequence,
        };
    }

    pub fn deinit(self: *Log) void {
        self.allocator.free(self.sub_path);
        self.* = undefined;
    }

    /// Return an owned copy of the newest complete state image.
    pub fn latestAlloc(self: *Log) Error![]u8 {
        const bytes = self.dir.readFileAlloc(
            self.io,
            self.sub_path,
            self.allocator,
            .limited(self.options.max_file_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.CommitLogNotFound,
            error.StreamTooLong => return error.CommitLogTooLarge,
            else => |other| return other,
        };
        defer self.allocator.free(bytes);
        const inspection = try inspect(bytes, self.options);
        if (inspection.valid_len != bytes.len) {
            // A torn suffix can appear after this Log was opened (for example,
            // after a failed append). Recover it under the caller's external
            // serialization before exposing the last committed transaction.
            var file = try self.dir.openFile(self.io, self.sub_path, .{
                .mode = .write_only,
            });
            defer file.close(self.io);
            try file.setLength(self.io, inspection.valid_len);
            try file.sync(self.io);
            self.valid_len = inspection.valid_len;
            self.next_sequence = inspection.next_sequence;
        }
        const latest = inspection.latest(bytes) orelse
            return error.EmptyCommitLog;
        return self.allocator.dupe(u8, latest);
    }

    /// Append and fsync one transaction before reporting it committed.
    pub fn append(self: *Log, snapshot: []const u8) Error!u64 {
        if (snapshot.len == 0 or snapshot.len > self.options.max_record_bytes) {
            return error.CommitRecordTooLarge;
        }
        if (self.next_sequence == 0) return error.CommitSequenceExhausted;
        const total_len = std.math.add(
            usize,
            record_header_len + record_footer_len,
            snapshot.len,
        ) catch return error.CommitLogTooLarge;
        if (total_len > self.options.max_file_bytes -| self.valid_len) {
            // A complete state image is itself a valid baseline, so reaching
            // the configured history bound can compact without losing
            // recovery coverage. `reset` performs an atomic synced replace.
            try self.reset(snapshot);
            return 1;
        }

        var header: [record_header_len]u8 = undefined;
        writeRecordHeader(&header, self.next_sequence, snapshot);
        var footer: [record_footer_len]u8 = undefined;
        writeRecordFooter(&footer, self.next_sequence);
        var file = try self.dir.createFile(self.io, self.sub_path, .{
            .truncate = false,
            .permissions = privateFilePermissions(),
        });
        defer file.close(self.io);
        const actual_len = try file.length(self.io);
        if (actual_len < self.valid_len) return error.CorruptCommitLog;
        if (actual_len != self.valid_len) {
            // A prior failed/partial append never became a committed record.
            // Remove its suffix before retrying so scanning stays unambiguous.
            try file.setLength(self.io, self.valid_len);
        }
        var writer = file.writer(self.io, &.{});
        try writer.seekTo(self.valid_len);
        try writer.interface.writeAll(&header);
        try writer.interface.writeAll(snapshot);
        try writer.interface.writeAll(&footer);
        try writer.interface.flush();
        try file.sync(self.io);

        const sequence = self.next_sequence;
        self.valid_len += total_len;
        self.next_sequence +%= 1;
        return sequence;
    }

    /// Atomically replace all older transactions with one complete baseline.
    ///
    /// The replacement is constructed and fsynced under a different inode, so
    /// a crash leaves either the old append history or the new baseline. This
    /// is the compaction boundary that keeps a full-state journal bounded.
    pub fn reset(self: *Log, snapshot: []const u8) Error!void {
        if (snapshot.len == 0 or snapshot.len > self.options.max_record_bytes) {
            return error.CommitRecordTooLarge;
        }
        const total_len = std.math.add(
            usize,
            fileHeader().len + record_header_len + record_footer_len,
            snapshot.len,
        ) catch return error.CommitLogTooLarge;
        if (total_len > self.options.max_file_bytes) {
            return error.CommitLogTooLarge;
        }
        var header: [record_header_len]u8 = undefined;
        writeRecordHeader(&header, 1, snapshot);
        var footer: [record_footer_len]u8 = undefined;
        writeRecordFooter(&footer, 1);
        var atomic = try self.dir.createFileAtomic(
            self.io,
            self.sub_path,
            .{
                .replace = true,
                .permissions = privateFilePermissions(),
            },
        );
        defer atomic.deinit(self.io);
        try atomic.file.writeStreamingAll(self.io, fileHeader());
        try atomic.file.writeStreamingAll(self.io, &header);
        try atomic.file.writeStreamingAll(self.io, snapshot);
        try atomic.file.writeStreamingAll(self.io, &footer);
        // `Atomic.replace` closes the temporary file. Syncing it explicitly
        // beforehand makes the new baseline durable before the rename.
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
        self.valid_len = total_len;
        self.next_sequence = 2;
        try durability.syncDirectory(self.io, self.dir);
    }
};

fn validateOptions(options: Options) Error!void {
    if (options.max_record_bytes == 0 or
        options.max_file_bytes < fileHeader().len + record_header_len +
            record_footer_len + 1 or
        options.max_record_bytes > options.max_file_bytes)
    {
        return error.CommitLogTooLarge;
    }
}

fn writeRecordFooter(
    out: *[record_footer_len]u8,
    sequence: u64,
) void {
    @memcpy(out[0..record_footer_magic.len], record_footer_magic);
    std.mem.writeInt(
        u64,
        out[record_footer_magic.len..][0..8],
        sequence,
        .big,
    );
}

fn fileHeader() *const [file_magic.len + @sizeOf(u32)]u8 {
    const Static = struct {
        const bytes = blk: {
            var out: [file_magic.len + @sizeOf(u32)]u8 = undefined;
            @memcpy(out[0..file_magic.len], file_magic);
            std.mem.writeInt(u32, out[file_magic.len..][0..4], version, .big);
            break :blk out;
        };
    };
    return &Static.bytes;
}

fn writeRecordHeader(
    out: *[record_header_len]u8,
    sequence: u64,
    snapshot: []const u8,
) void {
    @memcpy(out[0..record_magic.len], record_magic);
    var offset: usize = record_magic.len;
    std.mem.writeInt(u64, out[offset..][0..8], sequence, .big);
    offset += 8;
    std.mem.writeInt(u64, out[offset..][0..8], snapshot.len, .big);
    offset += 8;
    std.mem.writeInt(
        u32,
        out[offset..][0..4],
        std.hash.crc.Crc32.hash(snapshot),
        .big,
    );
    offset += 4;
    std.debug.assert(offset == record_prefix_len);
    std.mem.writeInt(
        u32,
        out[offset..][0..4],
        std.hash.crc.Crc32.hash(out[0..record_prefix_len]),
        .big,
    );
}

fn inspect(bytes: []const u8, options: Options) Error!Inspection {
    const file_header = fileHeader();
    if (bytes.len < file_header.len or
        !std.mem.eql(u8, bytes[0..file_header.len], file_header))
    {
        if (bytes.len >= file_magic.len and
            std.mem.eql(u8, bytes[0..file_magic.len], file_magic))
        {
            return error.UnsupportedCommitLogVersion;
        }
        return error.CorruptCommitLog;
    }

    var result = Inspection{
        .valid_len = file_header.len,
        .next_sequence = 1,
    };
    var offset = file_header.len;
    while (offset < bytes.len) {
        if (bytes.len - offset < record_header_len) break;
        const header = bytes[offset..][0..record_header_len];
        if (!std.mem.eql(u8, header[0..record_magic.len], record_magic)) {
            return error.CorruptCommitLog;
        }
        const expected_header_crc = std.mem.readInt(
            u32,
            header[record_prefix_len..][0..4],
            .big,
        );
        if (std.hash.crc.Crc32.hash(header[0..record_prefix_len]) !=
            expected_header_crc)
        {
            return error.CorruptCommitLog;
        }
        var header_offset: usize = record_magic.len;
        const sequence = std.mem.readInt(
            u64,
            header[header_offset..][0..8],
            .big,
        );
        header_offset += 8;
        if (sequence != result.next_sequence) {
            return error.CorruptCommitLog;
        }
        const encoded_len = std.mem.readInt(
            u64,
            header[header_offset..][0..8],
            .big,
        );
        header_offset += 8;
        const payload_len = std.math.cast(usize, encoded_len) orelse
            return error.CommitRecordTooLarge;
        if (payload_len == 0 or payload_len > options.max_record_bytes) {
            return error.CommitRecordTooLarge;
        }
        const payload_crc = std.mem.readInt(
            u32,
            header[header_offset..][0..4],
            .big,
        );
        const payload_start = offset + record_header_len;
        if (payload_len > bytes.len - payload_start) break;
        const payload = bytes[payload_start..][0..payload_len];
        const footer_start = payload_start + payload_len;
        if (record_footer_len > bytes.len - footer_start) break;
        const footer = bytes[footer_start..][0..record_footer_len];
        if (std.hash.crc.Crc32.hash(payload) != payload_crc) {
            return error.CorruptCommitLog;
        }
        if (!std.mem.eql(
            u8,
            footer[0..record_footer_magic.len],
            record_footer_magic,
        ) or std.mem.readInt(
            u64,
            footer[record_footer_magic.len..][0..8],
            .big,
        ) != sequence) {
            return error.CorruptCommitLog;
        }
        result.latest_start = payload_start;
        result.latest_len = payload_len;
        result.valid_len = footer_start + record_footer_len;
        result.next_sequence +%= 1;
        if (result.next_sequence == 0 and result.valid_len != bytes.len) {
            return error.CommitSequenceExhausted;
        }
        offset = result.valid_len;
    }
    return result;
}

fn privateFilePermissions() std.Io.File.Permissions {
    if (comptime std.Io.File.Permissions == void) return {};
    if (comptime @hasDecl(std.Io.File.Permissions, "fromMode")) {
        return .fromMode(0o600);
    }
    return .default_file;
}

test "MQTT commit log recovers latest complete record" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var log = try Log.create(allocator, io, tmp.dir, "state.log", .{});
    try std.testing.expectEqual(@as(u64, 1), try log.append("first"));
    try std.testing.expectEqual(@as(u64, 2), try log.append("second"));
    log.deinit();

    var reopened = try Log.open(allocator, io, tmp.dir, "state.log", .{});
    defer reopened.deinit();
    const latest = try reopened.latestAlloc();
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("second", latest);
    try std.testing.expectEqual(@as(u64, 3), reopened.next_sequence);
}

test "MQTT commit log truncates torn tail but rejects committed corruption" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var log = try Log.create(allocator, io, tmp.dir, "state.log", .{});
    _ = try log.append("stable");
    const stable_len = log.valid_len;
    log.deinit();
    var file = try tmp.dir.createFile(io, "state.log", .{ .truncate = false });
    defer file.close(io);
    var writer = file.writer(io, &.{});
    try writer.seekTo(stable_len);
    try writer.interface.writeAll("TXN1\x00\x00");
    try writer.interface.flush();

    var repaired = try Log.open(allocator, io, tmp.dir, "state.log", .{});
    const latest = try repaired.latestAlloc();
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("stable", latest);
    try std.testing.expectEqual(stable_len, repaired.valid_len);
    repaired.deinit();

    const bytes = try tmp.dir.readFileAlloc(
        io,
        "state.log",
        allocator,
        .limited(default_max_file_bytes),
    );
    defer allocator.free(bytes);
    bytes[bytes.len - 1] ^= 0xff;
    try tmp.dir.writeFile(io, .{
        .sub_path = "state.log",
        .data = bytes,
        .flags = .{ .truncate = true },
    });
    try std.testing.expectError(
        error.CorruptCommitLog,
        Log.open(allocator, io, tmp.dir, "state.log", .{}),
    );
}

test "MQTT commit log reset compacts history atomically" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var log = try Log.create(allocator, io, tmp.dir, "state.log", .{});
    defer log.deinit();
    _ = try log.append("old-1");
    _ = try log.append("old-2");
    try log.reset("baseline");
    try std.testing.expectEqual(@as(u64, 2), log.next_sequence);
    try std.testing.expectEqual(@as(u64, 2), try log.append("newest"));

    const latest = try log.latestAlloc();
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("newest", latest);
}

test "MQTT commit log latest recovery repairs a failed append suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var log = try Log.createWithInitial(
        allocator,
        io,
        tmp.dir,
        "state.log",
        .{},
        "stable",
    );
    defer log.deinit();
    var file = try tmp.dir.createFile(io, "state.log", .{ .truncate = false });
    defer file.close(io);
    var writer = file.writer(io, &.{});
    try writer.seekTo(log.valid_len);
    try writer.interface.writeAll("TXN1\x00");
    try writer.interface.flush();

    const latest = try log.latestAlloc();
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("stable", latest);
    try std.testing.expectEqual(log.valid_len, try file.length(io));
}

test "MQTT commit log auto compacts at configured bound" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    const options = Options{
        .max_record_bytes = 16,
        .max_file_bytes = fileHeader().len +
            2 * (record_header_len + record_footer_len + 6),
    };
    var log = try Log.createWithInitial(
        allocator,
        io,
        tmp.dir,
        "state.log",
        options,
        "first!",
    );
    defer log.deinit();
    try std.testing.expectEqual(@as(u64, 2), try log.append("second"));
    // A third record cannot fit; append atomically replaces the old history
    // with this new baseline and returns its reset sequence number.
    try std.testing.expectEqual(@as(u64, 1), try log.append("third!"));
    try std.testing.expectEqual(@as(u64, 2), log.next_sequence);
    const latest = try log.latestAlloc();
    defer allocator.free(latest);
    try std.testing.expectEqualStrings("third!", latest);
}
