//! Test-only temporary directories that prefer memory-backed `/dev/shm`.
//!
//! Journal and commit-log tests write small files repeatedly. On a busy host
//! those writes can block behind ext4 journal commits for minutes, which turns
//! timing-bounded tests into multi-minute stalls. Using tmpfs keeps the same
//! file semantics without waiting for shared-disk writeback. Systems without
//! `/dev/shm` fall back to `std.testing.tmpDir`.
const std = @import("std");
const builtin = @import("builtin");

const random_bytes_count = 12;
const sub_path_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

pub fn tmpDir(opts: std.Io.Dir.OpenOptions) std.testing.TmpDir {
    comptime std.debug.assert(builtin.is_test);
    if (builtin.os.tag == .linux) {
        if (shmTmpDir(opts)) |value| return value;
    }
    return std.testing.tmpDir(opts);
}

fn shmTmpDir(opts: std.Io.Dir.OpenOptions) ?std.testing.TmpDir {
    const io = std.testing.io;
    var random_bytes: [random_bytes_count]u8 = undefined;
    io.random(&random_bytes);
    var sub_path: [sub_path_len]u8 = undefined;
    _ = std.base64.url_safe.Encoder.encode(&sub_path, &random_bytes);
    var parent_dir = std.Io.Dir.openDirAbsolute(io, "/dev/shm", .{}) catch return null;
    const dir = parent_dir.createDirPathOpen(io, &sub_path, .{ .open_options = opts }) catch {
        parent_dir.close(io);
        return null;
    };
    return .{ .dir = dir, .parent_dir = parent_dir, .sub_path = sub_path };
}

test "test temp dir prefers the memory-backed store" {
    if (builtin.os.tag != .linux) return;
    const io = std.testing.io;
    var tmp = tmpDir(.{});
    defer tmp.cleanup();
    const probe = std.Io.Dir.openDirAbsolute(io, "/dev/shm", .{}) catch return;
    defer probe.close(io);
    probe.access(io, &tmp.sub_path, .{}) catch return error.TestUnexpectedResult;
}
