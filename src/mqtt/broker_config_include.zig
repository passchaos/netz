//! Bounded expansion of Mosquitto-style include_dir configuration files.
//!
//! Directories are expanded in declaration order. Their top-level .conf
//! regular files use Mosquitto's case-insensitive-first filename ordering.

const std = @import("std");
const test_tmp = @import("../internal/test_tmp_dir.zig");

pub const max_file_bytes: usize = 1024 * 1024;
pub const max_total_bytes: usize = 4 * 1024 * 1024;
pub const max_include_directories: usize = 32;
pub const max_include_files: usize = 256;
pub const max_directory_entries: usize = 1024;

pub const Error = std.mem.Allocator.Error || error{
    ConfigFileNotFound,
    EmptyConfig,
    InvalidDirective,
    NestedIncludeDirectory,
    ConfigFileTooLarge,
    ConfigSetTooLarge,
    TooManyIncludeDirectories,
    TooManyIncludeFiles,
    TooManyIncludeDirectoryEntries,
    InvalidIncludeFile,
};

pub const Source = struct {
    bytes: []const u8,
    scope: usize,
};

pub const Document = struct {
    allocator: std.mem.Allocator,
    buffers: [][]u8,
    sources: []Source,
    scope_count: usize,

    pub fn deinit(self: *Document) void {
        for (self.buffers) |buffer| self.allocator.free(buffer);
        self.allocator.free(self.buffers);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    base_dir: std.Io.Dir,
    buffers: std.ArrayList([]u8) = .empty,
    sources: std.ArrayList(Source) = .empty,
    total_bytes: usize = 0,
    include_directories: usize = 0,
    include_files: usize = 0,
    next_scope: usize = 1,

    fn deinit(self: *Builder) void {
        for (self.buffers.items) |buffer| self.allocator.free(buffer);
        self.buffers.deinit(self.allocator);
        self.sources.deinit(self.allocator);
    }

    fn readFile(
        self: *Builder,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) (Error || std.Io.Dir.ReadFileAllocError)![]u8 {
        const source = dir.readFileAlloc(
            self.io,
            sub_path,
            self.allocator,
            .limited(max_file_bytes + 1),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.ConfigFileTooLarge,
            else => return err,
        };
        errdefer self.allocator.free(source);
        if (source.len > max_file_bytes) return error.ConfigFileTooLarge;
        self.total_bytes = std.math.add(
            usize,
            self.total_bytes,
            source.len,
        ) catch return error.ConfigSetTooLarge;
        if (self.total_bytes > max_total_bytes) return error.ConfigSetTooLarge;
        try self.buffers.append(self.allocator, source);
        return source;
    }

    fn readRegularFile(
        self: *Builder,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) (Error || std.Io.Dir.ReadFileAllocError)![]u8 {
        var file = dir.openFile(self.io, sub_path, .{
            .allow_directory = false,
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.IsDir, error.SymLinkLoop => return error.InvalidIncludeFile,
            else => return err,
        };
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = reader.interface.allocRemaining(
            self.allocator,
            .limited(max_file_bytes + 1),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.ConfigFileTooLarge,
            error.ReadFailed => return reader.err.?,
            else => |e| return e,
        };
        errdefer self.allocator.free(source);
        if (source.len > max_file_bytes) return error.ConfigFileTooLarge;
        self.total_bytes = std.math.add(
            usize,
            self.total_bytes,
            source.len,
        ) catch return error.ConfigSetTooLarge;
        if (self.total_bytes > max_total_bytes) return error.ConfigSetTooLarge;
        try self.buffers.append(self.allocator, source);
        return source;
    }

    fn appendSource(self: *Builder, bytes: []const u8, scope: usize) !void {
        if (bytes.len == 0) return;
        try self.sources.append(self.allocator, .{
            .bytes = bytes,
            .scope = scope,
        });
    }

    fn expandMain(self: *Builder, source: []const u8) !void {
        var segment_start: usize = 0;
        var offset: usize = 0;
        while (nextLine(source, &offset)) |line| {
            const directive = includeDirective(line.bytes) catch |err| switch (err) {
                error.NotIncludeDirective => continue,
                else => |e| return e,
            };
            try self.appendSource(source[segment_start..line.start], 0);
            try self.expandDirectory(directive);
            segment_start = line.next;
        }
        try self.appendSource(source[segment_start..], 0);
    }

    fn expandDirectory(self: *Builder, sub_path: []const u8) !void {
        if (self.include_directories == max_include_directories) {
            return error.TooManyIncludeDirectories;
        }
        self.include_directories += 1;

        var directory = try self.base_dir.openDir(self.io, sub_path, .{
            .iterate = true,
        });
        defer directory.close(self.io);
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| self.allocator.free(name);
            names.deinit(self.allocator);
        }
        var iterator = directory.iterate();
        var entry_count: usize = 0;
        while (try iterator.next(self.io)) |entry| {
            entry_count += 1;
            if (entry_count > max_directory_entries) {
                return error.TooManyIncludeDirectoryEntries;
            }
            if (entry.name.len <= ".conf".len or
                !std.mem.endsWith(u8, entry.name, ".conf")) continue;
            const kind = if (entry.kind == .unknown)
                (try directory.statFile(self.io, entry.name, .{
                    .follow_symlinks = false,
                })).kind
            else
                entry.kind;
            if (kind != .file) return error.InvalidIncludeFile;
            if (self.include_files == max_include_files) {
                return error.TooManyIncludeFiles;
            }
            const name = try self.allocator.dupe(u8, entry.name);
            errdefer self.allocator.free(name);
            try names.append(self.allocator, name);
            self.include_files += 1;
        }
        std.sort.insertion([]u8, names.items, {}, nameLessThan);

        for (names.items) |name| {
            const included = try self.readRegularFile(directory, name);
            try rejectNestedInclude(included);
            const scope = self.next_scope;
            self.next_scope += 1;
            try self.appendSource(included, scope);
        }
    }

    fn finish(self: *Builder) !Document {
        const buffers = try self.buffers.toOwnedSlice(self.allocator);
        errdefer {
            for (buffers) |buffer| self.allocator.free(buffer);
            self.allocator.free(buffers);
        }
        const sources = try self.sources.toOwnedSlice(self.allocator);
        return .{
            .allocator = self.allocator,
            .buffers = buffers,
            .sources = sources,
            .scope_count = self.next_scope,
        };
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error ||
    std.Io.Dir.StatFileError || std.Io.Dir.ReadFileAllocError)!Document {
    var builder = Builder{
        .allocator = allocator,
        .io = io,
        .base_dir = dir,
    };
    errdefer builder.deinit();
    const main_source = builder.readFile(dir, sub_path) catch |err| switch (err) {
        error.FileNotFound => return error.ConfigFileNotFound,
        else => return err,
    };
    if (main_source.len == 0) return error.EmptyConfig;
    try builder.expandMain(main_source);
    return builder.finish();
}

test "missing root config is distinct from dependent file failures" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(
        error.ConfigFileNotFound,
        load(
            std.testing.allocator,
            io,
            tmp.dir,
            "missing.conf",
        ),
    );
}

const Line = struct {
    bytes: []const u8,
    start: usize,
    next: usize,
};

fn nextLine(source: []const u8, offset: *usize) ?Line {
    if (offset.* >= source.len) return null;
    const start = offset.*;
    const newline = std.mem.indexOfScalarPos(u8, source, start, '\n');
    const end = newline orelse source.len;
    offset.* = if (newline == null) source.len else end + 1;
    const raw = source[start..end];
    const without_comment = if (std.mem.indexOfScalar(u8, raw, '#')) |index|
        raw[0..index]
    else
        raw;
    return .{
        .bytes = std.mem.trim(u8, without_comment, " \t\r"),
        .start = start,
        .next = offset.*,
    };
}

fn includeDirective(line: []const u8) error{
    NotIncludeDirective,
    InvalidDirective,
}![]const u8 {
    if (line.len == 0) return error.NotIncludeDirective;
    var words = std.mem.tokenizeAny(u8, line, " \t");
    if (!std.mem.eql(u8, words.next().?, "include_dir")) {
        return error.NotIncludeDirective;
    }
    // Mosquitto consumes the remainder of the line for include_dir, allowing
    // directory paths containing spaces without quoting.
    const path = std.mem.trim(u8, words.rest(), " \t");
    if (path.len == 0) return error.InvalidDirective;
    if (std.mem.indexOfScalar(u8, path, 0) != null) {
        return error.InvalidDirective;
    }
    return path;
}

fn rejectNestedInclude(source: []const u8) error{NestedIncludeDirectory}!void {
    var offset: usize = 0;
    while (nextLine(source, &offset)) |line| {
        _ = includeDirective(line.bytes) catch |err| switch (err) {
            error.NotIncludeDirective => continue,
            error.InvalidDirective => return error.NestedIncludeDirectory,
        };
        return error.NestedIncludeDirectory;
    }
}

fn nameLessThan(_: void, lhs: []u8, rhs: []u8) bool {
    const length = @min(lhs.len, rhs.len);
    for (lhs[0..length], rhs[0..length]) |left, right| {
        const left_upper = std.ascii.toUpper(left);
        const right_upper = std.ascii.toUpper(right);
        if (left_upper != right_upper) return left_upper < right_upper;
        if (left != right) return left < right;
    }
    return lhs.len < rhs.len;
}

test "include directory expansion follows Mosquitto order and file scopes" {
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "one.d", .default_dir);
    var one = try tmp.dir.openDir(io, "one.d", .{});
    defer one.close(io);
    try one.writeFile(io, .{ .sub_path = "b.conf", .data = "listener 6\n" });
    try one.writeFile(io, .{ .sub_path = "A.conf", .data = "listener 3\n" });
    try one.writeFile(io, .{ .sub_path = "a.conf", .data = "listener 4\n" });
    try one.writeFile(io, .{ .sub_path = "B.conf", .data = "listener 5\n" });
    try one.writeFile(io, .{ .sub_path = "ignored.txt", .data = "bad\n" });
    try tmp.dir.createDir(io, "two dir", .default_dir);
    var two = try tmp.dir.openDir(io, "two dir", .{});
    defer two.close(io);
    try two.writeFile(io, .{ .sub_path = "00.conf", .data = "listener 7\n" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "listener 1\ninclude_dir one.d\n" ++
            "include_dir two dir\nmax_connections 2\n",
    });

    var document = try load(
        std.testing.allocator,
        io,
        tmp.dir,
        "main.conf",
    );
    defer document.deinit();
    try std.testing.expectEqual(@as(usize, 7), document.sources.len);
    try std.testing.expectEqual(@as(usize, 6), document.scope_count);
    try std.testing.expectEqualStrings("listener 1\n", document.sources[0].bytes);
    try std.testing.expectEqualStrings("listener 3\n", document.sources[1].bytes);
    try std.testing.expectEqualStrings("listener 4\n", document.sources[2].bytes);
    try std.testing.expectEqualStrings("listener 5\n", document.sources[3].bytes);
    try std.testing.expectEqualStrings("listener 6\n", document.sources[4].bytes);
    try std.testing.expectEqualStrings("listener 7\n", document.sources[5].bytes);
    try std.testing.expectEqualStrings("max_connections 2\n", document.sources[6].bytes);
    try std.testing.expectEqual(@as(usize, 0), document.sources[0].scope);
    try std.testing.expectEqual(@as(usize, 0), document.sources[6].scope);
    for (document.sources[1..6], 1..) |source, scope| {
        try std.testing.expectEqual(scope, source.scope);
    }
}

test "include directory expansion rejects nested directives" {
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "nested.d", .default_dir);
    var nested = try tmp.dir.openDir(io, "nested.d", .{});
    defer nested.close(io);
    try nested.writeFile(io, .{
        .sub_path = "nested.conf",
        .data = "include_dir other.d\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir nested.d\n",
    });
    try std.testing.expectError(
        error.NestedIncludeDirectory,
        load(std.testing.allocator, io, tmp.dir, "main.conf"),
    );
}

test "include directory expansion rejects non-regular conf entries" {
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "listeners.d", .default_dir);
    var included = try tmp.dir.openDir(io, "listeners.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "target",
        .data = "listener 1883\n",
    });
    try included.symLink(io, "target", "linked.conf", .{});
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir listeners.d\n",
    });
    try std.testing.expectError(
        error.InvalidIncludeFile,
        load(std.testing.allocator, io, tmp.dir, "main.conf"),
    );
}

test "include directory expansion bounds file count and file size" {
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "many.d", .default_dir);
    var many = try tmp.dir.openDir(io, "many.d", .{});
    defer many.close(io);
    var name_buffer: [32]u8 = undefined;
    for (0..max_include_files + 1) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "{d}.conf", .{index});
        try many.writeFile(io, .{ .sub_path = name, .data = "# empty\n" });
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "many.conf",
        .data = "include_dir many.d\n",
    });
    try std.testing.expectError(
        error.TooManyIncludeFiles,
        load(std.testing.allocator, io, tmp.dir, "many.conf"),
    );

    try tmp.dir.createDir(io, "large.d", .default_dir);
    var large = try tmp.dir.openDir(io, "large.d", .{});
    defer large.close(io);
    const oversized = try std.testing.allocator.alloc(u8, max_file_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, '#');
    try large.writeFile(io, .{
        .sub_path = "large.conf",
        .data = oversized,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "large.conf",
        .data = "include_dir large.d\n",
    });
    try std.testing.expectError(
        error.ConfigFileTooLarge,
        load(std.testing.allocator, io, tmp.dir, "large.conf"),
    );
}

test "include directory expansion bounds directories entries and total bytes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "empty.d", .default_dir);
    var main_source: std.ArrayList(u8) = .empty;
    defer main_source.deinit(allocator);
    for (0..max_include_directories + 1) |_| {
        try main_source.appendSlice(allocator, "include_dir empty.d\n");
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "directories.conf",
        .data = main_source.items,
    });
    try std.testing.expectError(
        error.TooManyIncludeDirectories,
        load(allocator, io, tmp.dir, "directories.conf"),
    );

    try tmp.dir.createDir(io, "entries.d", .default_dir);
    var entries = try tmp.dir.openDir(io, "entries.d", .{});
    defer entries.close(io);
    var name_buffer: [32]u8 = undefined;
    for (0..max_directory_entries + 1) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "{d}.txt", .{index});
        try entries.writeFile(io, .{ .sub_path = name, .data = "" });
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "entries.conf",
        .data = "include_dir entries.d\n",
    });
    try std.testing.expectError(
        error.TooManyIncludeDirectoryEntries,
        load(allocator, io, tmp.dir, "entries.conf"),
    );

    try tmp.dir.createDir(io, "total.d", .default_dir);
    var total = try tmp.dir.openDir(io, "total.d", .{});
    defer total.close(io);
    const chunk = try allocator.alloc(u8, 900 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, '#');
    for (0..5) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "{d}.conf", .{index});
        try total.writeFile(io, .{ .sub_path = name, .data = chunk });
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "total.conf",
        .data = "include_dir total.d\n",
    });
    try std.testing.expectError(
        error.ConfigSetTooLarge,
        load(allocator, io, tmp.dir, "total.conf"),
    );
}
