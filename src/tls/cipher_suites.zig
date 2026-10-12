//! Strict OpenSSL-style names for the TLS 1.3 suites implemented by vail.

const std = @import("std");
const vail = @import("vail");

pub const Suite = vail.tls.cipher_suite.Suite;
pub const Tls12Suite = vail.tls.tls12.Suite;

pub const Error = std.mem.Allocator.Error || error{
    EmptyCipherSuiteList,
    UnsupportedCipherSuite,
    DuplicateCipherSuite,
};

const Entry = struct {
    name: []const u8,
    suite: Suite,
};

const entries = [_]Entry{
    .{ .name = "TLS_AES_128_GCM_SHA256", .suite = .aes_128_gcm_sha256 },
    .{ .name = "TLS_AES_256_GCM_SHA384", .suite = .aes_256_gcm_sha384 },
    .{ .name = "TLS_CHACHA20_POLY1305_SHA256", .suite = .chacha20_poly1305_sha256 },
    .{ .name = "TLS_AES_128_CCM_SHA256", .suite = .aes_128_ccm_sha256 },
    .{ .name = "TLS_AES_128_CCM_8_SHA256", .suite = .aes_128_ccm_8_sha256 },
    .{ .name = "TLS_SM4_GCM_SM3", .suite = .sm4_gcm_sm3 },
    .{ .name = "TLS_SM4_CCM_SM3", .suite = .sm4_ccm_sm3 },
};

const Tls12Entry = struct {
    name: []const u8,
    suite: Tls12Suite,
};

const tls12_entries = [_]Tls12Entry{
    .{ .name = "ECDHE-ECDSA-AES128-GCM-SHA256", .suite = .ecdhe_ecdsa_aes_128_gcm_sha256 },
    .{ .name = "ECDHE-ECDSA-AES256-GCM-SHA384", .suite = .ecdhe_ecdsa_aes_256_gcm_sha384 },
    .{ .name = "ECDHE-RSA-AES128-GCM-SHA256", .suite = .ecdhe_rsa_aes_128_gcm_sha256 },
    .{ .name = "ECDHE-RSA-AES256-GCM-SHA384", .suite = .ecdhe_rsa_aes_256_gcm_sha384 },
    .{ .name = "ECDHE-RSA-CHACHA20-POLY1305", .suite = .ecdhe_rsa_chacha20_poly1305_sha256 },
    .{ .name = "ECDHE-ECDSA-CHACHA20-POLY1305", .suite = .ecdhe_ecdsa_chacha20_poly1305_sha256 },
};

pub fn parseOpenSslList(
    allocator: std.mem.Allocator,
    value: []const u8,
) Error![]Suite {
    if (value.len == 0) return error.EmptyCipherSuiteList;
    var suites: std.ArrayList(Suite) = .empty;
    defer suites.deinit(allocator);

    var names = std.mem.splitScalar(u8, value, ':');
    while (names.next()) |cipher_name| {
        const suite = parseName(cipher_name) orelse
            return error.UnsupportedCipherSuite;
        for (suites.items) |existing| {
            if (existing == suite) return error.DuplicateCipherSuite;
        }
        try suites.append(allocator, suite);
    }
    if (suites.items.len == 0) return error.EmptyCipherSuiteList;
    return suites.toOwnedSlice(allocator);
}

pub fn parseName(cipher_name: []const u8) ?Suite {
    inline for (entries) |entry| {
        if (std.mem.eql(u8, cipher_name, entry.name)) return entry.suite;
    }
    return null;
}

pub fn opensslName(suite: Suite) []const u8 {
    inline for (entries) |entry| {
        if (suite == entry.suite) return entry.name;
    }
    unreachable;
}

pub fn parseOpenSslTls12List(
    allocator: std.mem.Allocator,
    value: []const u8,
) Error![]Tls12Suite {
    if (value.len == 0) return error.EmptyCipherSuiteList;
    var suites: std.ArrayList(Tls12Suite) = .empty;
    defer suites.deinit(allocator);
    var names = std.mem.splitScalar(u8, value, ':');
    while (names.next()) |cipher_name| {
        const suite = parseTls12Name(cipher_name) orelse
            return error.UnsupportedCipherSuite;
        for (suites.items) |existing| {
            if (existing == suite) return error.DuplicateCipherSuite;
        }
        try suites.append(allocator, suite);
    }
    if (suites.items.len == 0) return error.EmptyCipherSuiteList;
    return suites.toOwnedSlice(allocator);
}

pub fn parseTls12Name(cipher_name: []const u8) ?Tls12Suite {
    inline for (tls12_entries) |entry| {
        if (std.mem.eql(u8, cipher_name, entry.name)) return entry.suite;
    }
    return null;
}

pub fn opensslTls12Name(suite: Tls12Suite) []const u8 {
    inline for (tls12_entries) |entry| {
        if (suite == entry.suite) return entry.name;
    }
    unreachable;
}

test "TLS 1.3 cipher suite list preserves caller preference" {
    inline for (entries) |entry| {
        try std.testing.expectEqual(entry.suite, parseName(entry.name).?);
        try std.testing.expectEqualStrings(
            entry.name,
            opensslName(entry.suite),
        );
    }
    const suites = try parseOpenSslList(
        std.testing.allocator,
        "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:" ++
            "TLS_AES_128_CCM_8_SHA256",
    );
    defer std.testing.allocator.free(suites);
    try std.testing.expectEqualSlices(Suite, &.{
        .chacha20_poly1305_sha256,
        .aes_256_gcm_sha384,
        .aes_128_ccm_8_sha256,
    }, suites);
    for (suites, 0..) |suite, index| {
        try std.testing.expectEqualStrings(
            switch (index) {
                0 => "TLS_CHACHA20_POLY1305_SHA256",
                1 => "TLS_AES_256_GCM_SHA384",
                else => "TLS_AES_128_CCM_8_SHA256",
            },
            opensslName(suite),
        );
    }
}

test "TLS 1.3 cipher suite list rejects empty unknown and duplicate names" {
    try std.testing.expectError(
        error.EmptyCipherSuiteList,
        parseOpenSslList(std.testing.allocator, ""),
    );
    for ([_][]const u8{ ":", "TLS_AES_128_GCM_SHA256:", "TLS_AES_128_GCM_SHA256::TLS_AES_256_GCM_SHA384" }) |value| {
        try std.testing.expectError(
            error.UnsupportedCipherSuite,
            parseOpenSslList(std.testing.allocator, value),
        );
    }
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        parseOpenSslList(std.testing.allocator, "DEFAULT"),
    );
    try std.testing.expectError(
        error.DuplicateCipherSuite,
        parseOpenSslList(
            std.testing.allocator,
            "TLS_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256",
        ),
    );
}

test "TLS 1.2 cipher suite list preserves caller preference" {
    const suites = try parseOpenSslTls12List(
        std.testing.allocator,
        "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384",
    );
    defer std.testing.allocator.free(suites);
    try std.testing.expectEqualSlices(Tls12Suite, &.{
        .ecdhe_rsa_chacha20_poly1305_sha256,
        .ecdhe_ecdsa_aes_256_gcm_sha384,
    }, suites);
    try std.testing.expectEqualStrings(
        "ECDHE-RSA-CHACHA20-POLY1305",
        opensslTls12Name(suites[0]),
    );
}

test "TLS 1.2 cipher suite list rejects empty unknown and duplicate names" {
    try std.testing.expectError(
        error.EmptyCipherSuiteList,
        parseOpenSslTls12List(std.testing.allocator, ""),
    );
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        parseOpenSslTls12List(std.testing.allocator, "DEFAULT"),
    );
    try std.testing.expectError(
        error.DuplicateCipherSuite,
        parseOpenSslTls12List(
            std.testing.allocator,
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        ),
    );
}
