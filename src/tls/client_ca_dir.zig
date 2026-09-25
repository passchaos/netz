//! Bounded, deterministic CA-directory loading for TLS client authentication.
//!
//! Regular files must end in `.pem`. OpenSSL `rehash` certificate symlinks
//! (`hhhhhhhh.N`) are also followed; duplicate link contents are ignored so a
//! normal `.pem` plus its generated link contributes the certificate once.

const std = @import("std");
const client_ca_file = @import("client_ca_file.zig");

pub const max_directory_entries: usize = 1024;
pub const max_certificate_files: usize = client_ca_file.max_certificates * 2;
pub const max_file_bytes: usize = 1024 * 1024;
pub const max_total_bytes: usize = client_ca_file.max_file_bytes;

pub const Error = client_ca_file.Error || error{
    EmptyCertificateDirectory,
    TooManyDirectoryEntries,
    TooManyCertificateFiles,
    CertificateDirectoryTooLarge,
    InvalidRehashLink,
};

const CandidateKind = enum { pem, rehash_link };

const Candidate = struct {
    name: []u8,
    kind: CandidateKind,
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error ||
    std.Io.Dir.ReadLinkError || std.Io.Dir.StatFileError ||
    std.Io.Dir.ReadFileAllocError)!client_ca_file.File {
    return loadCombined(allocator, io, dir, null, sub_path);
}

/// Load a CA directory together with an optional CA bundle file. The combined
/// trust set is parsed once so limits and duplicate Subjects apply globally.
pub fn loadCombined(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    file_sub_path: ?[]const u8,
    directory_sub_path: []const u8,
) (Error || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error ||
    std.Io.Dir.ReadLinkError || std.Io.Dir.StatFileError ||
    std.Io.Dir.ReadFileAllocError)!client_ca_file.File {
    var directory = try dir.openDir(io, directory_sub_path, .{
        .iterate = true,
    });
    defer directory.close(io);

    var candidates: std.ArrayList(Candidate) = .empty;
    defer {
        for (candidates.items) |candidate| allocator.free(candidate.name);
        candidates.deinit(allocator);
    }
    var iterator = directory.iterate();
    var entry_count: usize = 0;
    while (try iterator.next(io)) |entry| {
        entry_count += 1;
        if (entry_count > max_directory_entries) {
            return error.TooManyDirectoryEntries;
        }
        const resolved_kind = if (entry.kind == .unknown)
            (try directory.statFile(io, entry.name, .{
                .follow_symlinks = false,
            })).kind
        else
            entry.kind;
        const kind: CandidateKind = switch (resolved_kind) {
            .file => if (std.mem.endsWith(u8, entry.name, ".pem"))
                .pem
            else
                continue,
            .sym_link => if (isRehashCertificateLink(entry.name))
                .rehash_link
            else
                continue,
            else => continue,
        };
        if (candidates.items.len == max_certificate_files) {
            return error.TooManyCertificateFiles;
        }
        try candidates.append(allocator, .{
            .name = try allocator.dupe(u8, entry.name),
            .kind = kind,
        });
    }
    if (candidates.items.len == 0) return error.EmptyCertificateDirectory;
    std.sort.insertion(Candidate, candidates.items, {}, candidateLessThan);

    var sources: std.ArrayList([]u8) = .empty;
    defer {
        for (sources.items) |source| allocator.free(source);
        sources.deinit(allocator);
    }
    var total_bytes: usize = 0;
    if (file_sub_path) |path| {
        const source = dir.readFileAlloc(
            io,
            path,
            allocator,
            .limited(client_ca_file.max_file_bytes + 1),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.CertificateTooLarge,
            else => return err,
        };
        errdefer allocator.free(source);
        if (source.len > client_ca_file.max_file_bytes) {
            return error.CertificateTooLarge;
        }
        total_bytes = std.math.add(usize, source.len, 1) catch
            return error.CertificateDirectoryTooLarge;
        if (total_bytes > max_total_bytes) {
            return error.CertificateDirectoryTooLarge;
        }
        try sources.append(allocator, source);
    }

    var directory_source_count: usize = 0;
    for (candidates.items) |candidate| {
        var target_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const read_name = if (candidate.kind == .rehash_link) blk: {
            const target_len = try directory.readLink(
                io,
                candidate.name,
                &target_buffer,
            );
            const target = target_buffer[0..target_len];
            if (std.fs.path.basename(target).len != target.len or
                !std.mem.endsWith(u8, target, ".pem"))
            {
                return error.InvalidRehashLink;
            }
            const target_stat = try directory.statFile(io, target, .{
                .follow_symlinks = false,
            });
            if (target_stat.kind != .file) return error.InvalidRehashLink;
            break :blk target;
        } else candidate.name;
        const stat = try directory.statFile(io, read_name, .{
            .follow_symlinks = false,
        });
        if (stat.kind != .file) return error.InvalidPem;
        const source = directory.readFileAlloc(
            io,
            read_name,
            allocator,
            .limited(max_file_bytes + 1),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.CertificateTooLarge,
            else => return err,
        };
        errdefer allocator.free(source);
        if (source.len > max_file_bytes) return error.CertificateTooLarge;
        directory_source_count += 1;
        if (candidate.kind == .rehash_link and containsSource(sources.items, source)) {
            allocator.free(source);
            continue;
        }
        total_bytes = std.math.add(usize, total_bytes, source.len) catch
            return error.CertificateDirectoryTooLarge;
        total_bytes = std.math.add(usize, total_bytes, 1) catch
            return error.CertificateDirectoryTooLarge;
        if (total_bytes > max_total_bytes) {
            return error.CertificateDirectoryTooLarge;
        }
        try sources.append(allocator, source);
    }
    if (directory_source_count == 0) return error.EmptyCertificateDirectory;

    var combined: std.ArrayList(u8) = .empty;
    defer combined.deinit(allocator);
    try combined.ensureTotalCapacity(allocator, total_bytes);
    for (sources.items) |source| {
        try combined.appendSlice(allocator, source);
        try combined.append(allocator, '\n');
    }
    return client_ca_file.parse(
        allocator,
        combined.items,
        std.Io.Timestamp.now(io, .real).toSeconds(),
    );
}

fn containsSource(sources: []const []u8, candidate: []const u8) bool {
    for (sources) |source| {
        if (std.mem.eql(u8, source, candidate)) return true;
    }
    return false;
}

fn candidateLessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
    if (lhs.kind != rhs.kind) return @intFromEnum(lhs.kind) < @intFromEnum(rhs.kind);
    return std.mem.order(u8, lhs.name, rhs.name) == .lt;
}

fn isRehashCertificateLink(name: []const u8) bool {
    if (name.len < 10) return false;
    for (name[0..8]) |byte| {
        if (!std.ascii.isHex(byte)) return false;
    }
    if (name[8] != '.') return false;
    for (name[9..]) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

const first_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBVTCB/KADAgECAgkAs84+0pSp5UkwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwT
    \\cXVpYy16aWcgaW50ZXJvcCBDQTAeFw0yNjAzMTIwNDI1MDdaFw0zNjAzMDkwNDI1
    \\MDdaMB4xHDAaBgNVBAMME3F1aWMtemlnIGludGVyb3AgQ0EwWTATBgcqhkjOPQIB
    \\BggqhkjOPQMBBwNCAAS3jQ8iTpDTZ87j4sfrPztu4hr8d/Ep3m9Vt/+QmhVtVdrC
    \\uL+E7wLBHXKqkY7oBWt7WMjuTJHfsMzaQwNQvFm/oyMwITAPBgNVHRMBAf8EBTAD
    \\AQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiAbTTSRHrX8prIw
    \\4IJHkUCOEjBHCjflLVAlc3MnopJ/1AIhAIOQS3USGjl6TbHMGvRt2gZUNe+HXjq5
    \\64pxXZ9qM6nG
    \\-----END CERTIFICATE-----
;

const second_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBhDCCASmgAwIBAgICEAAwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl
    \\c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBgxFjAUBgNV
    \\BAMMDUNSTCBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQantue
    \\ZFhV35+7BoVoG9/+jPWbhpRoMPiTYHDqJfZk7qZab4SMQITgtsFnZ5n5up9IOZnP
    \\bgML6KLa9BKOmrxYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
    \\BjAdBgNVHQ4EFgQU4Y88Ik092FGXnPjSSa7GXltOPjQwHwYDVR0jBBgwFoAU4Y88
    \\Ik092FGXnPjSSa7GXltOPjQwCgYIKoZIzj0EAwIDSQAwRgIhAPUbM4y3hpf9d8SU
    \\VmCYJBEtqK4aEvFU6CF+czPw9xkTAiEAnz2ASewLVc2Uc42VgyUKR19yy8SlGYvX
    \\h7Mb4/RIYtM=
    \\-----END CERTIFICATE-----
;

test "client CA directory loads sorted PEM files and rehash links once" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    try directory.writeFile(io, .{ .sub_path = "z.pem", .data = second_ca_pem });
    try directory.writeFile(io, .{ .sub_path = "a.pem", .data = first_ca_pem });
    try directory.writeFile(io, .{ .sub_path = "ignored.txt", .data = "broken" });
    try directory.symLink(io, "a.pem", "0123abcd.0", .{});

    var file = try load(std.testing.allocator, io, tmp.dir, "cas");
    defer file.deinit();
    try std.testing.expectEqual(@as(usize, 2), file.certificates.len);
    var first = try client_ca_file.parse(
        std.testing.allocator,
        first_ca_pem,
        1_900_000_000,
    );
    defer first.deinit();
    try std.testing.expectEqualSlices(u8, first.certificates[0], file.certificates[0]);
}

test "client CA directory accepts an OpenSSL rehash link" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    try directory.writeFile(io, .{ .sub_path = "root.pem", .data = second_ca_pem });
    try directory.symLink(io, "root.pem", "89abcdef.12", .{});

    var file = try load(std.testing.allocator, io, tmp.dir, "cas");
    defer file.deinit();
    try std.testing.expectEqual(@as(usize, 1), file.certificates.len);
}

test "client CA directory rejects rehash links outside the directory" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "outside.pem",
        .data = first_ca_pem,
    });
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    try directory.symLink(io, "../outside.pem", "0123abcd.0", .{});
    try std.testing.expectError(
        error.InvalidRehashLink,
        load(std.testing.allocator, io, tmp.dir, "cas"),
    );
}

test "client CA directory combines a CA file and directory" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "common.pem",
        .data = first_ca_pem,
    });
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    try directory.writeFile(io, .{
        .sub_path = "second.pem",
        .data = second_ca_pem,
    });

    var file = try loadCombined(
        std.testing.allocator,
        io,
        tmp.dir,
        "common.pem",
        "cas",
    );
    defer file.deinit();
    try std.testing.expectEqual(@as(usize, 2), file.certificates.len);
}

test "client CA directory fails closed for empty malformed and duplicate inputs" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "empty", .default_dir);
    try std.testing.expectError(
        error.EmptyCertificateDirectory,
        load(std.testing.allocator, io, tmp.dir, "empty"),
    );

    try tmp.dir.createDir(io, "malformed", .default_dir);
    var malformed = try tmp.dir.openDir(io, "malformed", .{});
    defer malformed.close(io);
    try malformed.writeFile(io, .{ .sub_path = "root.pem", .data = "broken" });
    try std.testing.expectError(
        error.InvalidPem,
        load(std.testing.allocator, io, tmp.dir, "malformed"),
    );

    try tmp.dir.createDir(io, "duplicate", .default_dir);
    var duplicate = try tmp.dir.openDir(io, "duplicate", .{});
    defer duplicate.close(io);
    try duplicate.writeFile(io, .{ .sub_path = "a.pem", .data = first_ca_pem });
    try duplicate.writeFile(io, .{ .sub_path = "b.pem", .data = first_ca_pem });
    try std.testing.expectError(
        error.DuplicateCertificateAuthority,
        load(std.testing.allocator, io, tmp.dir, "duplicate"),
    );
}

test "client CA directory bounds selected files" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    var name_buffer: [32]u8 = undefined;
    for (0..max_certificate_files + 1) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "{d}.pem", .{index});
        try directory.writeFile(io, .{ .sub_path = name, .data = "broken" });
    }
    try std.testing.expectError(
        error.TooManyCertificateFiles,
        load(std.testing.allocator, io, tmp.dir, "cas"),
    );
}

test "client CA directory bounds each selected file" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "cas", .default_dir);
    var directory = try tmp.dir.openDir(io, "cas", .{});
    defer directory.close(io);
    const oversized = try std.testing.allocator.alloc(u8, max_file_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'x');
    try directory.writeFile(io, .{
        .sub_path = "oversized.pem",
        .data = oversized,
    });
    try std.testing.expectError(
        error.CertificateTooLarge,
        load(std.testing.allocator, io, tmp.dir, "cas"),
    );
}
