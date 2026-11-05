//! Test-only temporary directories that prefer memory-backed `/dev/shm`.
//!
//! Journal and commit-log tests write small files repeatedly. On a busy host
//! those writes can block behind ext4 journal commits for minutes, which turns
//! timing-bounded tests into multi-minute stalls. Using tmpfs keeps the same
//! file semantics without waiting for shared-disk writeback. Systems without
//! `/dev/shm` fall back to `.zig-cache/tmp`.
const std = @import("std");
const builtin = @import("builtin");

const random_bytes_count = 12;
const sub_path_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

pub const TmpDir = struct {
    dir: std.Io.Dir,
    parent_dir: std.Io.Dir,
    sub_path: [sub_path_len]u8,
    root: []const u8,

    pub fn cleanup(self: *TmpDir) void {
        const io = std.testing.io;
        self.dir.close(io);
        self.parent_dir.deleteTree(io, &self.sub_path) catch {};
        self.parent_dir.close(io);
        self.* = undefined;
    }

    /// Absolute path for a file inside this temporary directory.
    pub fn path(self: *const TmpDir, buffer: []u8, sub_path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{s}/{s}/{s}", .{
            self.root, self.sub_path[0..], sub_path,
        });
    }
};

pub fn tmpDir(opts: std.Io.Dir.OpenOptions) TmpDir {
    comptime std.debug.assert(builtin.is_test);
    if (builtin.os.tag == .linux) {
        if (shmTmpDir(opts)) |value| return value;
    }
    return cacheTmpDir(opts);
}

fn randomSubPath() [sub_path_len]u8 {
    var random_bytes: [random_bytes_count]u8 = undefined;
    std.testing.io.random(&random_bytes);
    var sub_path: [sub_path_len]u8 = undefined;
    _ = std.base64.url_safe.Encoder.encode(&sub_path, &random_bytes);
    return sub_path;
}

fn shmTmpDir(opts: std.Io.Dir.OpenOptions) ?TmpDir {
    const io = std.testing.io;
    const sub_path = randomSubPath();
    var parent_dir = std.Io.Dir.openDirAbsolute(io, "/dev/shm", .{}) catch return null;
    const dir = parent_dir.createDirPathOpen(io, &sub_path, .{ .open_options = opts }) catch {
        parent_dir.close(io);
        return null;
    };
    return .{
        .dir = dir,
        .parent_dir = parent_dir,
        .sub_path = sub_path,
        .root = "/dev/shm",
    };
}

fn cacheTmpDir(opts: std.Io.Dir.OpenOptions) TmpDir {
    const io = std.testing.io;
    const sub_path = randomSubPath();
    var cache_dir = std.Io.Dir.cwd().createDirPathOpen(io, ".zig-cache", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache dir");
    defer cache_dir.close(io);
    const parent_dir = cache_dir.createDirPathOpen(io, "tmp", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache/tmp dir");
    const dir = parent_dir.createDirPathOpen(io, &sub_path, .{ .open_options = opts }) catch
        @panic("unable to make tmp dir for testing: unable to make and open the tmp dir");
    return .{
        .dir = dir,
        .parent_dir = parent_dir,
        .sub_path = sub_path,
        .root = ".zig-cache/tmp",
    };
}

test "test temp dir prefers the memory-backed store" {
    if (builtin.os.tag != .linux) return;
    var tmp = tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expect(std.mem.startsWith(u8, tmp.root, "/dev/shm"));
    var buffer: [128]u8 = undefined;
    const probe_path = try tmp.path(&buffer, "probe");
    try std.testing.expect(std.mem.startsWith(u8, probe_path, "/dev/shm/"));
}
