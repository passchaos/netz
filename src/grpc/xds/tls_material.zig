//! Inline xDS cluster TLS material shared by EDS, STATIC and DNS projections.
const std = @import("std");
const vail = @import("vail");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const server_identity_file = @import("../../tls/server_identity_file.zig");

pub const VersionPolicy = tls_stream.VersionPolicy;
pub const Tls12CipherSuite = tls_stream.Tls12CipherSuite;

pub const SanMatch = enum { exact, prefix, suffix, contains };
pub const SanMatcher = struct {
    kind: SanMatch,
    value: []const u8,
    ignore_case: bool = false,
};

pub const Config = struct {
    server_name: []const u8 = "",
    trusted_ca: []const u8 = "",
    certificate_chain: []const u8 = "",
    private_key: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,
    tls12_cipher_suites: ?[]const tls_stream.Tls12CipherSuite = null,
    san_matchers: ?[]const SanMatcher = null,
};

pub const Error = std.mem.Allocator.Error || server_identity_file.Error || error{
    InvalidTlsMaterial,
    MissingPrivateKey,
    MissingCertificate,
};

pub const Material = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_loaded: bool = false,
    lock: std.Io.RwLock = .init,
    identity: ?server_identity_file.Identity = null,
    server_name: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite = &.{},
    san_matchers: []const OwnedSanMatcher = &.{},

    const OwnedSanMatcher = struct { kind: SanMatch, value: []u8, ignore_case: bool };

    pub fn create(gpa: std.mem.Allocator, io: std.Io, config: Config) Error!*Material {
        if ((config.certificate_chain.len == 0) != (config.private_key.len == 0)) {
            return if (config.certificate_chain.len == 0) error.MissingCertificate else error.MissingPrivateKey;
        }
        const self = try gpa.create(Material);
        self.* = .{ .allocator = gpa, .io = io, .version_policy = config.version_policy };
        errdefer self.deinit();
        self.server_name = try gpa.dupe(u8, config.server_name);
        if (config.tls12_cipher_suites) |suites| {
            if (suites.len != 0) self.tls12_cipher_suites = try gpa.dupe(tls_stream.Tls12CipherSuite, suites);
        }
        if (config.trusted_ca.len != 0) {
            addCerts(gpa, io, &self.bundle, config.trusted_ca) catch return error.InvalidTlsMaterial;
            if (self.bundle.map.count() == 0) return error.InvalidTlsMaterial;
            self.bundle_loaded = true;
        }
        if (config.san_matchers) |matchers| {
            if (matchers.len != 0) {
                if (!self.bundle_loaded) return error.InvalidTlsMaterial;
                const owned = try gpa.alloc(OwnedSanMatcher, matchers.len);
                var initialized: usize = 0;
                errdefer {
                    for (owned[0..initialized]) |matcher| gpa.free(matcher.value);
                    gpa.free(owned);
                }
                for (matchers, owned) |matcher, *value| {
                    value.* = .{ .kind = matcher.kind, .value = try gpa.dupe(u8, matcher.value), .ignore_case = matcher.ignore_case };
                    initialized += 1;
                }
                self.san_matchers = owned;
            }
        }
        if (config.certificate_chain.len != 0) {
            self.identity = server_identity_file.parse(gpa, config.certificate_chain, config.private_key) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidTlsMaterial,
            };
        }
        return self;
    }
    pub fn deinit(self: *Material) void {
        if (self.server_name.len != 0) self.allocator.free(self.server_name);
        if (self.tls12_cipher_suites.len != 0) self.allocator.free(self.tls12_cipher_suites);
        if (self.san_matchers.len != 0) {
            for (self.san_matchers) |matcher| self.allocator.free(matcher.value);
            self.allocator.free(self.san_matchers);
        }
        if (self.identity) |*identity| identity.deinit();
        self.bundle.deinit(self.allocator);
        self.allocator.destroy(self);
    }
    pub fn serverName(self: *const Material, fallback: []const u8) []const u8 {
        return if (self.server_name.len != 0) self.server_name else fallback;
    }
    pub fn options(self: *Material) http2.runtime.TlsConnectOptions {
        var result: http2.runtime.TlsConnectOptions = .{};
        if (self.version_policy) |policy| result.protocol_policy = policy;
        if (self.tls12_cipher_suites.len != 0) result.tls12_cipher_suites = self.tls12_cipher_suites;
        if (self.bundle_loaded) result.ca_bundle = .{ .bundle = &self.bundle, .lock = &self.lock };
        if (self.san_matchers.len != 0) {
            result.server_verifier = .{ .verify_trust = verifySanTrust, .context = self };
        }
        if (self.identity) |*identity| {
            const value = identity.serverIdentity();
            result.client_identity = .{
                .certificate_chain = value.certificate_chain,
                .signer = value.signer,
                .certificate_type = value.certificate_type,
            };
        }
        return result;
    }

    fn verifySanTrust(context: ?*anyopaque, trust: vail.tls.auth.TrustContext) anyerror!void {
        const self: *Material = @ptrCast(@alignCast(context orelse return error.CertificateUntrusted));
        const now = std.Io.Clock.Timestamp.now(self.io, .real).raw.nanoseconds;
        var verifier = vail.x509.trust.BundleVerifier{ .bundle = &self.bundle, .now_seconds = @intCast(@divTrunc(now, std.time.ns_per_s)) };
        try verifier.serverChainVerifier().verifyTrust(trust.server_name, trust.chain);
        if (trust.chain.len == 0) return error.CertificateUntrusted;
        const leaf = std.crypto.Certificate.parse(.{ .buffer = trust.chain[0], .index = 0 }) catch return error.CertificateUntrusted;
        try self.checkSans(leaf.subjectAltName());
    }

    fn checkSans(self: *const Material, encoded: []const u8) !void {
        if (encoded.len == 0) return error.CertificateHostMismatch;
        var reader = DerNames{ .bytes = encoded };
        const sequence = reader.next() orelse return error.InvalidCertificateExtension;
        if (sequence.tag != 0x30) return error.InvalidCertificateExtension;
        var names = DerNames{ .bytes = sequence.value };
        var matched = false;
        while (names.next()) |name| {
            const text = switch (name.tag) {
                0x81, 0x82, 0x86 => name.value,
                else => continue,
            };
            for (self.san_matchers) |matcher| {
                if (matches(matcher, text)) {
                    matched = true;
                    break;
                }
            }
            if (matched) break;
        }
        if (!matched) return error.CertificateHostMismatch;
    }
};

const DerNames = struct {
    bytes: []const u8,
    index: usize = 0,
    const Element = struct { tag: u8, value: []const u8 };

    fn next(self: *DerNames) ?Element {
        if (self.index >= self.bytes.len) return null;
        const tag = self.bytes[self.index];
        self.index += 1;
        if (self.index >= self.bytes.len) return null;
        var length: usize = 0;
        const first = self.bytes[self.index];
        self.index += 1;
        if (first & 0x80 == 0) {
            length = first;
        } else {
            const count = first & 0x7f;
            if (count == 0 or count > 4 or self.index + count > self.bytes.len) return null;
            for (self.bytes[self.index..][0..count]) |byte| length = length * 256 + byte;
            self.index += count;
        }
        if (self.index + length > self.bytes.len) return null;
        const value = self.bytes[self.index..][0..length];
        self.index += length;
        return .{ .tag = tag, .value = value };
    }
};

fn matches(matcher: Material.OwnedSanMatcher, text: []const u8) bool {
    return switch (matcher.kind) {
        .exact => if (matcher.ignore_case) std.ascii.eqlIgnoreCase(text, matcher.value) else std.mem.eql(u8, text, matcher.value),
        .prefix => if (matcher.ignore_case) std.ascii.startsWithIgnoreCase(text, matcher.value) else std.mem.startsWith(u8, text, matcher.value),
        .suffix => if (matcher.ignore_case) std.ascii.endsWithIgnoreCase(text, matcher.value) else std.mem.endsWith(u8, text, matcher.value),
        .contains => if (matcher.ignore_case) indexIgnoreCase(text, matcher.value) else std.mem.indexOf(u8, text, matcher.value) != null,
    };
}

fn indexIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

fn addCerts(gpa: std.mem.Allocator, io: std.Io, bundle: *std.crypto.Certificate.Bundle, source: []const u8) !void {
    const now = std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
    const now_sec: i64 = @intCast(@divTrunc(now, std.time.ns_per_s));
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    if (std.mem.indexOf(u8, source, begin_marker) == null) {
        const start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.ensureUnusedCapacity(gpa, source.len);
        bundle.bytes.appendSliceAssumeCapacity(source);
        try bundle.parseCert(gpa, start, now_sec);
        return;
    }
    const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, source, start_index, begin_marker)) |begin| {
        const cert_start = begin + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, source, cert_start, end_marker) orelse return error.InvalidTlsMaterial;
        start_index = cert_end + end_marker.len;
        const encoded = std.mem.trim(u8, source[cert_start..cert_end], " \t\r\n");
        try bundle.bytes.ensureUnusedCapacity(gpa, encoded.len / 4 * 3 + 1);
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        const dest = bundle.bytes.allocatedSlice()[decoded_start..];
        const decoded_len = base64.decode(dest, encoded) catch return error.InvalidTlsMaterial;
        bundle.bytes.items.len += decoded_len;
        try bundle.parseCert(gpa, decoded_start, now_sec);
    }
}

test "xDS TLS SAN matchers accept and reject leaf names" {
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{tls_testing.certificate_base64});
    defer allocator.free(pem);
    var der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&der, tls_testing.certificate_base64);
    const leaf = try std.crypto.Certificate.parse(.{ .buffer = &der, .index = 0 });
    var matching = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .san_matchers = &.{.{ .kind = .exact, .value = "localhost" }} });
    defer matching.deinit();
    try matching.checkSans(leaf.subjectAltName());
    var rejecting = try Material.create(allocator, std.testing.io, .{ .trusted_ca = pem, .san_matchers = &.{.{ .kind = .exact, .value = "other" }} });
    defer rejecting.deinit();
    try std.testing.expectError(error.CertificateHostMismatch, rejecting.checkSans(leaf.subjectAltName()));
}
