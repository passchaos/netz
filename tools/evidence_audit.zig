//! Audit the `source_sha256` maps recorded in docs/evidence JSON files.
//!
//! This is a reporting tool, not a release gate: hashes legitimately drift as
//! the source evolves, so stale entries are counted and reported but only fail
//! with `--strict`. Unresolved paths (for example fixture-relative names that
//! cannot be mapped back to the repository) are reported separately. Recorded
//! paths may use a `vail/` or `regexz/` prefix for code that moved to a sibling
//! package.

const std = @import("std");
const harnessz = @import("harnessz");

const max_evidence_bytes: usize = 16 * 1024 * 1024;

const Options = struct {
    root: []const u8 = ".",
    strict: bool = false,
    fail_unresolved: bool = false,
    max_unresolved: ?usize = null,
    example_limit: usize = 10,
};

const Report = struct {
    files: usize = 0,
    matched: usize = 0,
    stale: usize = 0,
    unresolved: usize = 0,
    invalid: usize = 0,
    unreadable: usize = 0,
    example_limit: usize = 10,
    stale_examples: usize = 0,
    unresolved_examples: usize = 0,

    fn entries(self: Report) usize {
        return self.matched + self.stale + self.unresolved;
    }
};

const Cache = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMapUnmanaged([]u8) = .empty,

    fn deinit(self: *Cache) void {
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    fn get(self: *const Cache, path: []const u8) ?[]const u8 {
        return self.map.get(path);
    }

    fn put(self: *Cache, path: []const u8, hex: []u8) !void {
        const key = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(key);
        self.map.put(self.allocator, key, hex) catch |err| {
            self.allocator.free(hex);
            return err;
        };
    }
};

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var options: Options = .{};
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--root=")) {
            options.root = arg["--root=".len..];
            if (options.root.len == 0) return error.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--strict")) {
            options.strict = true;
        } else if (std.mem.eql(u8, arg, "--fail-unresolved")) {
            options.fail_unresolved = true;
        } else if (std.mem.startsWith(u8, arg, "--max-unresolved=")) {
            options.max_unresolved = try std.fmt.parseInt(
                usize,
                arg["--max-unresolved=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--limit=")) {
            options.example_limit = try std.fmt.parseInt(
                usize,
                arg["--limit=".len..],
                10,
            );
        } else {
            return error.InvalidArgument;
        }
    }

    const arena = init.arena.allocator();
    const evidence_path = try std.fs.path.join(
        arena,
        &.{ options.root, "docs", "evidence" },
    );
    var evidence_dir = std.Io.Dir.cwd().openDir(
        io,
        evidence_path,
        .{ .iterate = true },
    ) catch |err| {
        std.debug.print(
            "evidence audit: cannot open {s}: {s}\n",
            .{ evidence_path, @errorName(err) },
        );
        return 1;
    };
    defer evidence_dir.close(io);

    const vail_path = try std.fs.path.join(
        arena,
        &.{ options.root, "..", "vail" },
    );
    var vail_dir: ?std.Io.Dir = std.Io.Dir.cwd().openDir(
        io,
        vail_path,
        .{},
    ) catch null;
    defer if (vail_dir) |*dir| dir.close(io);

    const regexz_path = try std.fs.path.join(
        arena,
        &.{ options.root, "..", "regexz" },
    );
    var regexz_dir: ?std.Io.Dir = std.Io.Dir.cwd().openDir(
        io,
        regexz_path,
        .{},
    ) catch null;
    defer if (regexz_dir) |*dir| dir.close(io);

    var report: Report = .{ .example_limit = options.example_limit };
    var cache: Cache = .{ .allocator = allocator };
    defer cache.deinit();

    var walker = try evidence_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".json")) continue;

        const bytes = entry.dir.readFileAlloc(
            io,
            entry.basename,
            allocator,
            .limited(max_evidence_bytes),
        ) catch |err| {
            report.unreadable += 1;
            if (report.unreadable <= report.example_limit) {
                std.debug.print(
                    "unreadable: {s}: {s}\n",
                    .{ entry.path, @errorName(err) },
                );
            }
            continue;
        };
        defer allocator.free(bytes);

        var parsed = std.json.parseFromSlice(
            std.json.Value,
            allocator,
            bytes,
            .{},
        ) catch |err| {
            report.invalid += 1;
            if (report.invalid <= report.example_limit) {
                std.debug.print(
                    "invalid-json: {s}: {s}\n",
                    .{ entry.path, @errorName(err) },
                );
            }
            continue;
        };
        defer parsed.deinit();

        switch (parsed.value) {
            .object => {},
            else => continue,
        }
        const source_hashes = parsed.value.object.get("source_sha256") orelse
            continue;
        switch (source_hashes) {
            .object => {},
            else => continue,
        }
        report.files += 1;

        var iterator = source_hashes.object.iterator();
        while (iterator.next()) |source| {
            const source_path = source.key_ptr.*;
            const expected = switch (source.value_ptr.*) {
                .string => |value| value,
                else => continue,
            };
            const actual = try hashRecordedPath(
                allocator,
                io,
                std.Io.Dir.cwd(),
                vail_dir,
                regexz_dir,
                &cache,
                source_path,
            );
            if (actual) |hex| {
                if (std.ascii.eqlIgnoreCase(hex, expected)) {
                    report.matched += 1;
                } else {
                    report.stale += 1;
                    if (report.stale_examples < report.example_limit) {
                        report.stale_examples += 1;
                        std.debug.print(
                            "stale: {s}: {s} (recorded {s}, actual {s})\n",
                            .{ entry.path, source_path, expected, hex },
                        );
                    }
                }
            } else {
                report.unresolved += 1;
                if (report.unresolved_examples < report.example_limit) {
                    report.unresolved_examples += 1;
                    std.debug.print(
                        "unresolved: {s}: {s}\n",
                        .{ entry.path, source_path },
                    );
                }
            }
        }
    }

    std.debug.print(
        "evidence audit: files={d} entries={d} matched={d} stale={d} unresolved={d} invalid={d} unreadable={d}\n",
        .{
            report.files,
            report.entries(),
            report.matched,
            report.stale,
            report.unresolved,
            report.invalid,
            report.unreadable,
        },
    );

    if (report.invalid != 0 or report.unreadable != 0) return 1;
    if (options.strict and (report.stale != 0 or report.unresolved != 0)) {
        return 1;
    }
    if (options.fail_unresolved and report.unresolved != 0) return 1;
    if (options.max_unresolved) |limit| {
        if (report.unresolved > limit) {
            std.debug.print(
                "evidence audit: unresolved {d} exceeds limit {d}\n",
                .{ report.unresolved, limit },
            );
            return 1;
        }
    }
    return 0;
}

fn hashRecordedPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    vail: ?std.Io.Dir,
    regexz: ?std.Io.Dir,
    cache: *Cache,
    recorded_path: []const u8,
) !?[]const u8 {
    if (cache.get(recorded_path)) |cached| return cached;

    if (try hashCandidate(allocator, io, cwd, recorded_path)) |hex| {
        try cache.put(recorded_path, hex);
        return hex;
    }
    if (std.mem.startsWith(u8, recorded_path, "netz/")) {
        if (try hashCandidate(
            allocator,
            io,
            cwd,
            recorded_path["netz/".len..],
        )) |hex| {
            try cache.put(recorded_path, hex);
            return hex;
        }
    }
    if (std.mem.startsWith(u8, recorded_path, "vail/")) {
        if (vail) |dir| {
            if (try hashCandidate(
                allocator,
                io,
                dir,
                recorded_path["vail/".len..],
            )) |hex| {
                try cache.put(recorded_path, hex);
                return hex;
            }
        }
    }
    if (std.mem.startsWith(u8, recorded_path, "regexz/")) {
        if (regexz) |dir| {
            if (try hashCandidate(
                allocator,
                io,
                dir,
                recorded_path["regexz/".len..],
            )) |hex| {
                try cache.put(recorded_path, hex);
                return hex;
            }
        }
    }
    return null;
}

fn hashCandidate(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
) !?[]u8 {
    if (path.len == 0) return null;
    if (std.fs.path.isAbsolute(path)) return null;
    if (std.mem.indexOf(u8, path, "..") != null) return null;
    return harnessz.provenance.hashFileHex(
        allocator,
        io,
        dir,
        path,
    ) catch null;
}
