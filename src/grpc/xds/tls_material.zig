//! Inline xDS cluster TLS material shared by EDS, STATIC and DNS projections.
const std = @import("std");
const builtin = @import("builtin");
const vail = @import("vail");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const server_identity_file = @import("../../tls/server_identity_file.zig");
const root_trust = @import("../../trust.zig");

pub const VersionPolicy = tls_stream.VersionPolicy;
pub const Tls12CipherSuite = tls_stream.Tls12CipherSuite;

pub const SanMatch = enum { exact, prefix, suffix, contains };
/// Envoy v3 SubjectAltNameMatcher.SanType.
pub const SanType = enum { email, dns, uri, ip };
pub const SanMatcher = struct {
    kind: SanMatch,
    value: []const u8,
    ignore_case: bool = false,
    /// Null matches any textual SAN (legacy `match_subject_alt_names`).
    /// A value restricts matching to that SAN type, including IP addresses.
    san_type: ?SanType = null,
};

pub const Config = struct {
    server_name: []const u8 = "",
    trusted_ca: []const u8 = "",
    certificate_chain: []const u8 = "",
    private_key: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,
    tls12_cipher_suites: ?[]const tls_stream.Tls12CipherSuite = null,
    san_matchers: ?[]const SanMatcher = null,
    /// SHA-256 hashes of DER-encoded certificates accepted in the peer chain.
    verify_certificate_hashes: ?[]const [32]u8 = null,
    /// SHA-256 hashes of DER-encoded SubjectPublicKeyInfo values accepted in
    /// the peer chain.
    verify_certificate_spkis: ?[]const [32]u8 = null,
    /// Use the platform trust store instead of inline `trusted_ca`. Envoy and
    /// gRPC also default to system roots when no CA source is configured but
    /// identity or hash verification is requested.
    system_root_certs: bool = false,
    /// Use the compiled-in Mozilla CCADB roots instead of the platform store.
    /// Ignored when `trusted_ca` is supplied.
    bundled_root_certs: bool = false,
    /// Use the operating system certificate verifier. Ignored when
    /// `trusted_ca` is supplied.
    platform_root_certs: bool = false,
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
    bundled_store: ?vail.x509.trust.SystemStore = null,
    platform_verifier: ?vail.x509.platform.Verifier = null,
    lock: std.Io.RwLock = .init,
    identity: ?server_identity_file.Identity = null,
    server_name: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite = &.{},
    san_matchers: []const OwnedSanMatcher = &.{},
    verify_certificate_hashes: []const [32]u8 = &.{},
    verify_certificate_spkis: []const [32]u8 = &.{},

    const OwnedSanMatcher = struct { kind: SanMatch, value: []u8, ignore_case: bool, san_type: ?SanType = null };

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
        const needs_san_checks =
            (config.san_matchers != null and config.san_matchers.?.len != 0) or
            (config.verify_certificate_hashes != null and config.verify_certificate_hashes.?.len != 0) or
            (config.verify_certificate_spkis != null and config.verify_certificate_spkis.?.len != 0);
        const wants_identity_verification =
            config.system_root_certs or
            config.bundled_root_certs or
            config.platform_root_certs or
            needs_san_checks;
        if (config.trusted_ca.len != 0) {
            addCerts(gpa, io, &self.bundle, config.trusted_ca) catch return error.InvalidTlsMaterial;
            if (self.bundle.map.count() == 0) return error.InvalidTlsMaterial;
            self.bundle_loaded = true;
        } else if (config.bundled_root_certs) {
            self.bundled_store = root_trust.initBundledStore(
                gpa,
                std.Io.Timestamp.now(io, .real),
            ) catch return error.InvalidTlsMaterial;
        } else if (config.platform_root_certs) {
            self.platform_verifier = vail.x509.platform.Verifier.init(
                gpa,
                .{ .verify_host = !needs_san_checks },
            ) catch return error.InvalidTlsMaterial;
        } else if (wants_identity_verification) {
            // No inline CA: use the platform trust store, matching Envoy/gRPC.
            self.bundle.rescan(gpa, io, std.Io.Timestamp.now(io, .real)) catch return error.InvalidTlsMaterial;
            if (self.bundle.map.count() == 0) return error.InvalidTlsMaterial;
            self.bundle_loaded = true;
        }
        if (config.san_matchers) |matchers| {
            if (matchers.len != 0) {
                if (!self.hasTrust()) return error.InvalidTlsMaterial;
                const owned = try gpa.alloc(OwnedSanMatcher, matchers.len);
                var initialized: usize = 0;
                errdefer {
                    for (owned[0..initialized]) |matcher| gpa.free(matcher.value);
                    gpa.free(owned);
                }
                for (matchers, owned) |matcher, *value| {
                    value.* = .{
                        .kind = matcher.kind,
                        .value = try gpa.dupe(u8, matcher.value),
                        .ignore_case = matcher.ignore_case,
                        .san_type = matcher.san_type,
                    };
                    initialized += 1;
                }
                self.san_matchers = owned;
            }
        }
        if (config.verify_certificate_hashes) |hashes| {
            if (hashes.len != 0) {
                if (!self.hasTrust()) return error.InvalidTlsMaterial;
                self.verify_certificate_hashes = try gpa.dupe([32]u8, hashes);
            }
        }
        if (config.verify_certificate_spkis) |spkis| {
            if (spkis.len != 0) {
                if (!self.hasTrust()) return error.InvalidTlsMaterial;
                self.verify_certificate_spkis = try gpa.dupe([32]u8, spkis);
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
        if (self.verify_certificate_hashes.len != 0) self.allocator.free(self.verify_certificate_hashes);
        if (self.verify_certificate_spkis.len != 0) self.allocator.free(self.verify_certificate_spkis);
        if (self.identity) |*identity| identity.deinit();
        if (self.bundled_store) |*store| store.deinit();
        if (self.platform_verifier) |*verifier| verifier.deinit();
        self.bundle.deinit(self.allocator);
        self.allocator.destroy(self);
    }
    fn hasTrust(self: *const Material) bool {
        return self.bundled_store != null or
            self.platform_verifier != null or
            self.bundle_loaded;
    }
    pub fn serverName(self: *const Material, fallback: []const u8) []const u8 {
        return if (self.server_name.len != 0) self.server_name else fallback;
    }
    pub fn options(self: *Material) http2.runtime.TlsConnectOptions {
        var result: http2.runtime.TlsConnectOptions = .{};
        if (self.version_policy) |policy| result.protocol_policy = policy;
        if (self.tls12_cipher_suites.len != 0) result.tls12_cipher_suites = self.tls12_cipher_suites;
        const needs_san_checks =
            self.san_matchers.len != 0 or
            self.verify_certificate_hashes.len != 0 or
            self.verify_certificate_spkis.len != 0;
        if (self.bundled_store != null or self.platform_verifier != null) {
            result.server_verifier = .{
                .verify_trust = if (needs_san_checks) verifySanTrust else verifyBundledTrust,
                .context = self,
            };
        } else {
            if (self.bundle_loaded) result.ca_bundle = .{ .bundle = &self.bundle, .lock = &self.lock };
            if (needs_san_checks) {
                result.server_verifier = .{ .verify_trust = verifySanTrust, .context = self };
            }
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

    fn trustVerifier(
        self: *Material,
        now_seconds: i64,
    ) vail.x509.trust.BundleVerifier {
        if (self.bundled_store) |*store| return store.verifier(now_seconds);
        return .{ .bundle = &self.bundle, .now_seconds = now_seconds };
    }

    pub fn verifySanTrust(context: ?*anyopaque, trust: vail.tls.auth.TrustContext) anyerror!void {
        const self: *Material = @ptrCast(@alignCast(context orelse return error.CertificateUntrusted));
        if (self.platform_verifier) |*platform| {
            var chain_only = trust;
            chain_only.server_name = null;
            const trust_verifier = platform.clientVerifier();
            const callback = trust_verifier.verify_trust orelse
                return error.CertificateUntrusted;
            try callback(trust_verifier.context, chain_only);
        } else {
            const now = std.Io.Clock.Timestamp.now(self.io, .real).raw.nanoseconds;
            var verifier = self.trustVerifier(@intCast(@divTrunc(now, std.time.ns_per_s)));
            try vail.tls.auth.ClientVerifier.fromTrustVerifier(
                verifier.serverChainVerifier(),
            ).verifyTrust(trust.server_name, trust.chain);
        }
        if (trust.chain.len == 0) return error.CertificateUntrusted;
        if (self.verify_certificate_hashes.len != 0) {
            var pinned = false;
            for (trust.chain) |certificate| {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(certificate, &digest, .{});
                for (self.verify_certificate_hashes) |expected| {
                    if (std.mem.eql(u8, &digest, &expected)) {
                        pinned = true;
                        break;
                    }
                }
                if (pinned) break;
            }
            if (!pinned) return error.CertificateUntrusted;
        }
        if (self.verify_certificate_spkis.len != 0) {
            var pinned = false;
            for (trust.chain) |certificate| {
                const spki = certificateSpki(certificate) orelse continue;
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(spki, &digest, .{});
                for (self.verify_certificate_spkis) |expected| {
                    if (std.mem.eql(u8, &digest, &expected)) {
                        pinned = true;
                        break;
                    }
                }
                if (pinned) break;
            }
            if (!pinned) return error.CertificateUntrusted;
        }
        if (self.san_matchers.len != 0) {
            const leaf = std.crypto.Certificate.parse(.{ .buffer = trust.chain[0], .index = 0 }) catch return error.CertificateUntrusted;
            try self.checkSans(leaf.subjectAltName());
        }
    }

    /// Hostname-verifying callback used when bundled roots or the platform
    /// verifier are selected without xDS SAN matchers or certificate pins.
    pub fn verifyBundledTrust(context: ?*anyopaque, trust: vail.tls.auth.TrustContext) anyerror!void {
        const self: *Material = @ptrCast(@alignCast(context orelse return error.CertificateUntrusted));
        if (self.platform_verifier) |*platform| {
            const trust_verifier = platform.clientVerifier();
            const callback = trust_verifier.verify_trust orelse
                return error.CertificateUntrusted;
            try callback(trust_verifier.context, trust);
            return;
        }
        const now = std.Io.Clock.Timestamp.now(self.io, .real).raw.nanoseconds;
        var verifier = self.trustVerifier(@intCast(@divTrunc(now, std.time.ns_per_s)));
        try vail.tls.auth.ClientVerifier.fromTrustVerifier(
            verifier.clientVerifier(),
        ).verifyTrust(trust.server_name, trust.chain);
    }

    pub fn checkSans(self: *const Material, encoded: []const u8) !void {
        if (encoded.len == 0) return error.CertificateHostMismatch;
        var reader = DerNames{ .bytes = encoded };
        const sequence = reader.next() orelse return error.InvalidCertificateExtension;
        if (sequence.tag != 0x30) return error.InvalidCertificateExtension;
        var names = DerNames{ .bytes = sequence.value };
        var ip_text: [39]u8 = undefined;
        var matched = false;
        while (names.next()) |name| {
            const san_type: SanType, const text: []const u8 = switch (name.tag) {
                0x81 => .{ .email, name.value },
                0x82 => .{ .dns, name.value },
                0x86 => .{ .uri, name.value },
                0x87 => .{
                    .ip,
                    formatIp(name.value, &ip_text) orelse continue,
                },
                else => continue,
            };
            for (self.san_matchers) |matcher| {
                // Legacy matchers never match IP SANs, matching Envoy.
                if (matcher.san_type) |required| {
                    if (required != san_type) continue;
                } else if (san_type == .ip) continue;
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

pub fn certificateSpki(bytes: []const u8) ?[]const u8 {
    const der = std.crypto.Certificate.der;
    const outer = der.Element.parse(bytes, 0) catch return null;
    const tbs = der.Element.parse(bytes, outer.slice.start) catch return null;
    var index = tbs.slice.start;
    var element = der.Element.parse(bytes, index) catch return null;
    if (bytes[index] == 0xa0) {
        index = element.slice.end;
        element = der.Element.parse(bytes, index) catch return null;
    }
    // serialNumber
    index = element.slice.end;
    // signature, issuer, validity, subject
    for (0..4) |_| {
        element = der.Element.parse(bytes, index) catch return null;
        index = element.slice.end;
    }
    const spki = der.Element.parse(bytes, index) catch return null;
    return bytes[index..spki.slice.end];
}

/// Format a DER IP SAN (4 or 16 raw bytes) as text. Returns null for any
/// other length.
pub fn formatIp(bytes: []const u8, out: *[39]u8) ?[]const u8 {
    if (bytes.len == 4) {
        return std.fmt.bufPrint(out, "{d}.{d}.{d}.{d}", .{
            bytes[0], bytes[1], bytes[2], bytes[3],
        }) catch null;
    }
    if (bytes.len != 16) return null;
    var groups: [8]u16 = undefined;
    for (0..8) |index| {
        groups[index] = (@as(u16, bytes[index * 2]) << 8) | bytes[index * 2 + 1];
    }
    // RFC 5952: compress the longest run of two or more zero groups.
    var best_start: usize = 8;
    var best_len: usize = 0;
    var scan: usize = 0;
    while (scan < 8) {
        if (groups[scan] != 0) {
            scan += 1;
            continue;
        }
        var run: usize = 1;
        while (scan + run < 8 and groups[scan + run] == 0) run += 1;
        if (run > best_len) {
            best_len = run;
            best_start = scan;
        }
        scan += run;
    }
    var written: usize = 0;
    var index: usize = 0;
    while (index < 8) {
        if (index == best_start and best_len >= 2) {
            out[written] = ':';
            written += 1;
            out[written] = ':';
            written += 1;
            index += best_len;
            continue;
        }
        if (written != 0 and out[written - 1] != ':') {
            out[written] = ':';
            written += 1;
        }
        var digits: [4]u8 = undefined;
        var count: usize = 0;
        var value = groups[index];
        if (value == 0) {
            digits[0] = '0';
            count = 1;
        } else {
            while (value != 0) : (value >>= 4) {
                digits[count] = "0123456789abcdef"[value & 0xf];
                count += 1;
            }
        }
        while (count > 0) {
            count -= 1;
            out[written] = digits[count];
            written += 1;
        }
        index += 1;
    }
    return out[0..written];
}

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

pub fn sanSequence(out: []u8, entries: []const struct { tag: u8, value: []const u8 }) []const u8 {
    var length: usize = 0;
    for (entries) |entry| length += 2 + entry.value.len;
    var written: usize = 0;
    out[written] = 0x30;
    written += 1;
    out[written] = @intCast(length);
    written += 1;
    for (entries) |entry| {
        out[written] = entry.tag;
        written += 1;
        out[written] = @intCast(entry.value.len);
        written += 1;
        @memcpy(out[written..][0..entry.value.len], entry.value);
        written += entry.value.len;
    }
    return out[0..written];
}

test {
    _ = @import("tls_material/tests.zig");
}
