//! Crash-recoverable PID-file ownership for the configured MQTT broker.
//!
//! The open file retains an exclusive advisory lock for the broker lifetime.
//! This rejects a concurrent cooperating instance while allowing a new process
//! to reclaim the stale file after a crash. The final path component is never
//! followed through a symbolic link, and cleanup removes the path only when it
//! still names the inode and exact PID text acquired by this owner.

const std = @import("std");
const builtin = @import("builtin");

const max_pid_text_len = 32;
const max_acquire_attempts = 8;

pub const PidFile = struct {
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    file: std.Io.File,
    inode: std.Io.File.INode,
    expected: [max_pid_text_len]u8,
    expected_len: usize,

    /// Acquire `path` without following a final-component symbolic link.
    /// Existing unlocked files are stale and are replaced in place only after
    /// the exclusive lock succeeds. The path is borrowed until `deinit`.
    pub fn acquire(
        io: std.Io,
        dir: std.Io.Dir,
        path: []const u8,
        pid: u64,
    ) !PidFile {
        if (path.len == 0 or pid == 0) return error.InvalidPidFile;

        var expected: [max_pid_text_len]u8 = undefined;
        const pid_text = std.fmt.bufPrint(&expected, "{d}\n", .{pid}) catch
            return error.InvalidPidFile;

        for (0..max_acquire_attempts) |_| {
            var file = openLocked(io, dir, path) catch |err| switch (err) {
                error.WouldBlock => return error.PidFileLocked,
                error.PathAlreadyExists, error.FileNotFound => continue,
                else => return err,
            };
            errdefer file.close(io);

            const locked_stat = try file.stat(io);
            if (locked_stat.kind != .file or locked_stat.nlink == 0) {
                file.close(io);
                continue;
            }
            try file.setLength(io, 0);
            try file.writeStreamingAll(io, pid_text);

            var result = PidFile{
                .io = io,
                .dir = dir,
                .path = path,
                .file = file,
                .inode = locked_stat.inode,
                .expected = expected,
                .expected_len = pid_text.len,
            };
            if (result.pathStillOwned()) return result;
            file.close(io);
        }
        return error.PidFileChanged;
    }

    /// Remove only this owner's unchanged path, then release the process lock.
    /// Cleanup is best-effort so it is safe in an error-path `defer`.
    pub fn deinit(self: *PidFile) void {
        if (self.pathStillOwned()) {
            self.dir.deleteFile(self.io, self.path) catch {};
        }
        self.file.close(self.io);
        self.* = undefined;
    }

    fn pathStillOwned(self: *const PidFile) bool {
        var current = self.dir.openFile(self.io, self.path, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
        }) catch return false;
        defer current.close(self.io);

        const stat = current.stat(self.io) catch return false;
        if (stat.kind != .file or stat.inode != self.inode) return false;

        var contents: [max_pid_text_len + 1]u8 = undefined;
        const read = current.readPositionalAll(self.io, &contents, 0) catch
            return false;
        return read == self.expected_len and std.mem.eql(
            u8,
            contents[0..read],
            self.expected[0..self.expected_len],
        );
    }
};

fn openLocked(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
) !std.Io.File {
    return dir.openFile(io, path, .{
        .mode = .read_write,
        .allow_directory = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => dir.createFile(io, path, .{
            .read = true,
            .truncate = false,
            .exclusive = true,
            .lock = .exclusive,
            .lock_nonblocking = true,
        }),
        else => err,
    };
}

pub fn currentProcessId() u64 {
    return if (comptime builtin.os.tag == .windows)
        std.os.windows.GetCurrentProcessId()
    else
        @intCast(std.c.getpid());
}

test "MQTT PID file owns one process and reclaims stale content" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "broker.pid",
        .data = "999999\n",
    });
    var first = try PidFile.acquire(io, tmp.dir, "broker.pid", 12345);
    defer first.deinit();

    var contents: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "12345\n",
        try tmp.dir.readFile(io, "broker.pid", &contents),
    );
    try std.testing.expectError(
        error.PidFileLocked,
        PidFile.acquire(io, tmp.dir, "broker.pid", 54321),
    );
}

test "MQTT PID file removes only its own unchanged path" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var owner = try PidFile.acquire(io, tmp.dir, "broker.pid", 111);
    try tmp.dir.deleteFile(io, "broker.pid");
    try tmp.dir.writeFile(io, .{
        .sub_path = "broker.pid",
        .data = "replacement\n",
    });
    owner.deinit();

    var contents: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "replacement\n",
        try tmp.dir.readFile(io, "broker.pid", &contents),
    );
}

test "MQTT PID file disappears after normal release" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var owner = try PidFile.acquire(io, tmp.dir, "broker.pid", 222);
    owner.deinit();
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.openFile(io, "broker.pid", .{}),
    );
}

test "MQTT PID file rejects a final-component symbolic link" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }

    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "target",
        .data = "unchanged\n",
    });
    try tmp.dir.symLink(io, "target", "broker.pid", .{});

    try std.testing.expectError(
        error.SymLinkLoop,
        PidFile.acquire(io, tmp.dir, "broker.pid", 333),
    );
    var contents: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "unchanged\n",
        try tmp.dir.readFile(io, "target", &contents),
    );
}
