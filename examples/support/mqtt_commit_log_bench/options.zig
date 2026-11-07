//! Bounded benchmark arguments and ownership of one temporary journal directory.
const std = @import("std");

pub const default_directory = ".zig-cache/mqtt-commit-log-bench";
pub const max_iterations: usize = 1000;
pub const max_samples: usize = 16;
pub const max_metadata_bytes: usize = 4096;
pub const session_counts = [_]usize{ 1, 32, 256 };
pub const queued_per_session: usize = 8;
pub const payload_bytes: usize = 256;

pub const Config = struct {
    iterations: usize = 10,
    samples: usize = 3,
    metadata_bytes: usize = 0,
    /// Borrowed from the process arena. A supplied parent must already exist.
    directory: ?[]const u8 = null,
    /// Optional caller-selected path, borrowed from the process arena.
    snapshot_output: ?[]const u8 = null,
    help: bool = false,
};

pub const help_text =
    \\Usage: bench-mqtt-commit-log [--iterations=1..1000] [--samples=1..16]
    \\                            [--metadata-bytes=0..4096]
    \\                            [--snapshot-output=PATH]
    \\                            [--directory=EXISTING_PARENT] [--help]
    \\Defaults: iterations=10 samples=3 metadata_bytes=0
    \\          directory=.zig-cache/mqtt-commit-log-bench
    \\Cases: sessions=1,32,256 queued_qos1_per_session=8 payload_bytes=256
    \\Each run creates and removes a unique child under the selected parent.
    \\--snapshot-output exports a deterministic 1-session fixture with selected metadata.
    \\For snapshot export, --metadata-bytes=64 is recommended. Default: no export.
    \\
;

pub fn parse(init: std.process.Init) !Config {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    var config: Config = .{};
    var index: usize = 1;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--help")) {
            config.help = true;
            continue;
        }
        const separator = std.mem.indexOfScalar(u8, argument, '=');
        const name = argument[0 .. separator orelse argument.len];
        const option: enum { iterations, samples, metadata_bytes, directory, snapshot_output } =
            if (std.mem.eql(u8, name, "--iterations")) .iterations else if (std.mem.eql(u8, name, "--samples")) .samples else if (std.mem.eql(u8, name, "--metadata-bytes")) .metadata_bytes else if (std.mem.eql(u8, name, "--directory")) .directory else if (std.mem.eql(u8, name, "--snapshot-output")) .snapshot_output else return error.InvalidArgument;
        const value = if (separator) |offset|
            argument[offset + 1 ..]
        else blk: {
            index += 1;
            if (index >= arguments.len or std.mem.startsWith(u8, arguments[index], "--")) return error.InvalidArgument;
            break :blk arguments[index];
        };
        switch (option) {
            .iterations => config.iterations = try boundedInteger(value, 1, max_iterations),
            .samples => config.samples = try boundedInteger(value, 1, max_samples),
            .metadata_bytes => config.metadata_bytes = try boundedInteger(value, 0, max_metadata_bytes),
            .directory => {
                try validatePath(value);
                config.directory = value;
            },
            .snapshot_output => {
                try validatePath(value);
                config.snapshot_output = value;
            },
        }
    }
    return config;
}

fn boundedInteger(value: []const u8, minimum: usize, maximum: usize) error{InvalidArgument}!usize {
    if (value.len == 0) return error.InvalidArgument;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidArgument;
    const number = std.fmt.parseInt(usize, value, 10) catch return error.InvalidArgument;
    if (number < minimum or number > maximum) return error.InvalidArgument;
    return number;
}

fn validatePath(value: []const u8) error{InvalidArgument}!void {
    if (value.len == 0 or value.len >= std.Io.Dir.max_path_bytes or
        std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArgument;
}

pub const WorkDirectory = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    path: []const u8,
    child_name: [36]u8,
    dir_open: bool = true,
    child_exists: bool = true,

    pub fn create(allocator: std.mem.Allocator, io: std.Io, directory: ?[]const u8) !WorkDirectory {
        const parent_path = directory orelse default_directory;
        try validatePath(parent_path);
        if (directory == null) try std.Io.Dir.cwd().createDirPath(io, parent_path);
        const parent = try std.Io.Dir.cwd().openDir(io, parent_path, .{});
        errdefer parent.close(io);

        // Exclusive mkdir establishes ownership. Collisions never transfer
        // ownership of an existing child, and retries remain bounded.
        for (0..8) |_| {
            var nonce: [16]u8 = undefined;
            io.random(&nonce);
            const encoded = std.fmt.bytesToHex(nonce, .lower);
            var child_name: [36]u8 = undefined;
            @memcpy(child_name[0..4], "run-");
            @memcpy(child_name[4..], &encoded);
            parent.createDir(io, &child_name, .default_dir) catch |err| {
                if (err == error.PathAlreadyExists) continue;
                return err;
            };
            errdefer parent.deleteTree(io, &child_name) catch {};
            const dir = try parent.openDir(io, &child_name, .{
                .iterate = true,
                .follow_symlinks = false,
            });
            errdefer dir.close(io);
            const path = try std.fs.path.join(allocator, &.{ parent_path, &child_name });
            return .{
                .allocator = allocator,
                .io = io,
                .parent = parent,
                .dir = dir,
                .path = path,
                .child_name = child_name,
            };
        }
        return error.WorkDirectoryCollision;
    }

    /// Close journal files before calling this. Propagate cleanup failures
    /// explicitly when requested; deinit also attempts cleanup on error paths.
    pub fn cleanup(self: *WorkDirectory) std.Io.Dir.DeleteTreeError!void {
        if (self.dir_open) {
            self.dir.close(self.io);
            self.dir_open = false;
        }
        if (self.child_exists) {
            try self.parent.deleteTree(self.io, &self.child_name);
            self.child_exists = false;
        }
    }

    pub fn deinit(self: *WorkDirectory) void {
        self.cleanup() catch {};
        self.parent.close(self.io);
        self.allocator.free(self.path);
        self.* = undefined;
    }
};
