//! Small wire fixtures for SDS Secret tests.
const std = @import("std");

pub const Builder = struct {
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    pub fn deinit(self: *Builder) void {
        self.data.deinit(self.allocator);
    }
    fn integer(self: *Builder, raw: u64) !void {
        var value = raw;
        while (value >= 128) : (value >>= 7) {
            try self.data.append(self.allocator, @as(u8, @truncate(value)) | 0x80);
        }
        try self.data.append(self.allocator, @intCast(value));
    }
    pub fn number(self: *Builder, field: u32, value: u64) !void {
        try self.integer(@as(u64, field) * 8);
        try self.integer(value);
    }
    pub fn wrapper(self: *Builder, field: u32, value: u64) !void {
        var nested = Builder{ .allocator = self.allocator };
        defer nested.deinit();
        try nested.number(1, value);
        try self.bytes(field, nested.data.items);
    }
    pub fn bytes(self: *Builder, field: u32, value: []const u8) !void {
        try self.integer(@as(u64, field) * 8 + 2);
        try self.integer(value.len);
        try self.data.appendSlice(self.allocator, value);
    }
};

pub const SanSpec = struct {
    kind: enum { exact, prefix, suffix, contains },
    value: []const u8,
    ignore_case: bool = false,
};

fn dataSource(gpa: std.mem.Allocator, value: []const u8) !Builder {
    var source = Builder{ .allocator = gpa };
    errdefer source.deinit();
    try source.bytes(1, value);
    return source;
}

pub fn tlsSecret(
    gpa: std.mem.Allocator,
    name: []const u8,
    chain: []const u8,
    key: []const u8,
) ![]u8 {
    var certificate = Builder{ .allocator = gpa };
    defer certificate.deinit();
    var chain_source = try dataSource(gpa, chain);
    defer chain_source.deinit();
    var key_source = try dataSource(gpa, key);
    defer key_source.deinit();
    try certificate.bytes(1, chain_source.data.items);
    try certificate.bytes(2, key_source.data.items);
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    try out.bytes(2, certificate.data.items);
    return out.data.toOwnedSlice(gpa);
}

pub fn validationSecret(
    gpa: std.mem.Allocator,
    name: []const u8,
    trusted_ca: []const u8,
    sans: []const SanSpec,
) ![]u8 {
    return validationSecretHashes(gpa, name, trusted_ca, sans, &.{});
}

pub fn validationSecretHashes(
    gpa: std.mem.Allocator,
    name: []const u8,
    trusted_ca: []const u8,
    sans: []const SanSpec,
    hashes: []const [32]u8,
) ![]u8 {
    return validationSecretPins(gpa, name, trusted_ca, sans, hashes, &.{});
}

pub fn validationSecretPins(
    gpa: std.mem.Allocator,
    name: []const u8,
    trusted_ca: []const u8,
    sans: []const SanSpec,
    hashes: []const [32]u8,
    spkis: []const [32]u8,
) ![]u8 {
    var validation = Builder{ .allocator = gpa };
    defer validation.deinit();
    var trusted = try dataSource(gpa, trusted_ca);
    defer trusted.deinit();
    try validation.bytes(1, trusted.data.items);
    for (sans) |san| {
        var matcher = Builder{ .allocator = gpa };
        defer matcher.deinit();
        try matcher.bytes(switch (san.kind) {
            .exact => 1,
            .prefix => 2,
            .suffix => 3,
            .contains => 7,
        }, san.value);
        if (san.ignore_case) try matcher.number(6, 1);
        try validation.bytes(9, matcher.data.items);
    }
    for (hashes) |hash| {
        const encoded = std.fmt.bytesToHex(hash, .lower);
        try validation.bytes(2, &encoded);
    }
    for (spkis) |spki| {
        var buffer: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
        const encoded = std.base64.standard.Encoder.encode(&buffer, &spki);
        try validation.bytes(3, encoded);
    }
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    try out.bytes(3, validation.data.items);
    return out.data.toOwnedSlice(gpa);
}
