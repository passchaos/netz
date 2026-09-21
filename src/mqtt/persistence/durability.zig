//! Filesystem durability helpers shared by MQTT snapshots and commit logs.
//!
//! Syncing a temporary file before an atomic rename protects its contents, but
//! POSIX filesystems do not promise that the new directory entry survives a
//! crash until the containing directory is synced as well.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = std.Io.File.Atomic.ReplaceError || std.Io.Dir.OpenError ||
    std.Io.File.SyncError;

/// Install an already-synced atomic file and persist the resulting directory
/// entry on platforms whose directory handles support fsync through std.Io.
/// A directory-sync error is reported after the replacement has taken place.
pub fn replaceSynced(
    atomic: *std.Io.File.Atomic,
    io: std.Io,
    dir: std.Io.Dir,
) Error!void {
    try atomic.replace(io);
    try syncDirectory(io, dir);
}

/// Persist directory-entry changes through a synchronization-capable handle.
/// Unsupported targets retain atomic replacement but cannot strengthen it with
/// a portable directory-sync guarantee through the current std.Io surface.
pub fn syncDirectory(
    io: std.Io,
    dir: std.Io.Dir,
) (std.Io.Dir.OpenError || std.Io.File.SyncError)!void {
    if (comptime !supportsDirectorySync()) return;
    // On Linux an ordinary non-iterable Dir may use O_PATH, which cannot be
    // fsynced. Reopen the same directory read-only so the I/O backend receives
    // a synchronization-capable handle without bypassing std.Io.
    var sync_dir = try dir.openDir(io, ".", .{ .iterate = true });
    defer sync_dir.close(io);
    const directory_file: std.Io.File = .{
        .handle = sync_dir.handle,
        .flags = .{ .nonblocking = false },
    };
    try directory_file.sync(io);
}

fn supportsDirectorySync() bool {
    return switch (builtin.os.tag) {
        .linux,
        .freebsd,
        .netbsd,
        .openbsd,
        .dragonfly,
        .illumos,
        => true,
        else => false,
    };
}

test "MQTT atomic replace syncs the parent directory and propagates failure" {
    if (comptime !supportsDirectorySync()) return error.SkipZigTest;

    const Probe = struct {
        delegate: std.Io,
        source_directory_handle: std.Io.File.Handle,
        sync_directory_handle: ?std.Io.File.Handle = null,
        calls: usize = 0,
        renames: usize = 0,
        wrong_order: bool = false,

        fn fileSync(
            userdata: ?*anyopaque,
            file: std.Io.File,
        ) std.Io.File.SyncError!void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (file.handle == self.sync_directory_handle) {
                if (self.renames != 1) self.wrong_order = true;
                return error.InputOutput;
            }
            if (self.renames != 0) self.wrong_order = true;
            return self.delegate.vtable.fileSync(
                self.delegate.userdata,
                file,
            );
        }

        fn dirOpenDir(
            userdata: ?*anyopaque,
            dir: std.Io.Dir,
            sub_path: []const u8,
            options: std.Io.Dir.OpenOptions,
        ) std.Io.Dir.OpenError!std.Io.Dir {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            const opened = try self.delegate.vtable.dirOpenDir(
                self.delegate.userdata,
                dir,
                sub_path,
                options,
            );
            if (dir.handle == self.source_directory_handle and
                std.mem.eql(u8, sub_path, ".") and
                options.iterate)
            {
                self.sync_directory_handle = opened.handle;
            }
            return opened;
        }

        fn dirClose(
            userdata: ?*anyopaque,
            dirs: []const std.Io.Dir,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return self.delegate.vtable.dirClose(
                self.delegate.userdata,
                dirs,
            );
        }

        fn fileClose(
            userdata: ?*anyopaque,
            files: []const std.Io.File,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return self.delegate.vtable.fileClose(
                self.delegate.userdata,
                files,
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
            try self.delegate.vtable.dirRename(
                self.delegate.userdata,
                old_dir,
                old_sub_path,
                new_dir,
                new_sub_path,
            );
            self.renames += 1;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base_io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try syncDirectory(base_io, tmp.dir);
    var probe = Probe{
        .delegate = base_io,
        .source_directory_handle = tmp.dir.handle,
    };
    var vtable = base_io.vtable.*;
    vtable.fileSync = Probe.fileSync;
    vtable.fileClose = Probe.fileClose;
    vtable.dirOpenDir = Probe.dirOpenDir;
    vtable.dirClose = Probe.dirClose;
    vtable.dirRename = Probe.dirRename;
    const io: std.Io = .{ .userdata = &probe, .vtable = &vtable };

    var atomic = try tmp.dir.createFileAtomic(base_io, "state", .{
        .replace = true,
    });
    defer atomic.deinit(base_io);
    try atomic.file.writeStreamingAll(base_io, "durable");
    try atomic.file.sync(io);
    try std.testing.expectError(
        error.InputOutput,
        replaceSynced(&atomic, io, tmp.dir),
    );
    try std.testing.expectEqual(@as(usize, 2), probe.calls);
    try std.testing.expectEqual(@as(usize, 1), probe.renames);
    try std.testing.expect(probe.sync_directory_handle != null);
    try std.testing.expect(!probe.wrong_order);

    const bytes = try tmp.dir.readFileAlloc(
        base_io,
        "state",
        std.testing.allocator,
        .limited(16),
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("durable", bytes);
}
