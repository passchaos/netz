//! Bounded cache for repeated X.509 bundle verification.
//!
//! Cache hits skip certificate-path parsing and issuer-signature checks for an
//! exact server-name, leaf-first DER chain, and stapled OCSP state. TLS
//! CertificateVerify remains a separate mandatory handshake step, so every
//! connection still proves possession of the certified private key. The trust
//! bundle and verification time snapshot must remain unchanged for the
//! lifetime of the cache. Replace the cache whenever either changes, so
//! successful entries cannot outlive a trust-policy or time update.

const std = @import("std");
const vail = @import("vail");

const Sha256 = std.crypto.hash.sha2.Sha256;
const digest_len = Sha256.digest_length;

pub const Entry = struct {
    occupied: bool = false,
    digest: [digest_len]u8 = undefined,
};

pub const Stats = struct {
    hits: u64,
    misses: u64,
};

pub const BundleVerifierCache = struct {
    io: std.Io,
    verifier: vail.x509.trust.BundleVerifier,
    entries: []Entry,
    mutex: std.Io.Mutex = .init,
    hits: std.atomic.Value(u64) = .init(0),
    misses: std.atomic.Value(u64) = .init(0),

    pub fn init(
        io: std.Io,
        bundle: *const std.crypto.Certificate.Bundle,
        now_seconds: i64,
        entries: []Entry,
    ) BundleVerifierCache {
        for (entries) |*entry| entry.* = .{};
        return .{
            .io = io,
            .verifier = .{
                .bundle = bundle,
                .now_seconds = now_seconds,
            },
            .entries = entries,
        };
    }

    pub fn clientVerifier(
        self: *BundleVerifierCache,
    ) vail.tls.auth.ClientVerifier {
        return .{
            .verify_trust = verifyTrust,
            .context = self,
        };
    }

    pub fn stats(self: *const BundleVerifierCache) Stats {
        return .{
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
        };
    }

    fn verifyTrust(
        context: ?*anyopaque,
        trust: vail.tls.auth.TrustContext,
    ) anyerror!void {
        const self: *BundleVerifierCache = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        if (self.entries.len == 0) {
            _ = self.misses.fetchAdd(1, .monotonic);
            return self.verifier.verify(trust);
        }
        const digest = fingerprint(trust);
        const slot = slotFor(digest, self.entries.len);
        self.mutex.lockUncancelable(self.io);
        const hit = self.entries[slot].occupied and
            std.crypto.timing_safe.eql(
                [digest_len]u8,
                self.entries[slot].digest,
                digest,
            );
        self.mutex.unlock(self.io);
        if (hit) {
            _ = self.hits.fetchAdd(1, .monotonic);
            return;
        }

        _ = self.misses.fetchAdd(1, .monotonic);
        try self.verifier.verify(trust);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.entries[slot] = .{ .occupied = true, .digest = digest };
    }
};

fn fingerprint(trust: vail.tls.auth.TrustContext) [digest_len]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(&.{@intFromBool(trust.server_name != null)});
    hashField(&hasher, trust.server_name orelse &.{});
    hashLength(&hasher, trust.chain.len);
    for (trust.chain) |certificate| hashField(&hasher, certificate);
    if (trust.ocsp_responses) |responses| {
        hasher.update(&.{1});
        hashLength(&hasher, responses.len);
        for (responses) |response| {
            hasher.update(&.{@intFromBool(response != null)});
            hashField(&hasher, response orelse &.{});
        }
    } else {
        hasher.update(&.{ 0, @intFromBool(trust.ocsp_response != null) });
        hashField(&hasher, trust.ocsp_response orelse &.{});
    }
    var digest: [digest_len]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn hashField(hasher: *Sha256, bytes: []const u8) void {
    hashLength(hasher, bytes.len);
    hasher.update(bytes);
}

fn hashLength(hasher: *Sha256, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .big);
    hasher.update(&encoded);
}

fn slotFor(digest: [digest_len]u8, capacity: usize) usize {
    return @intCast(
        std.mem.readInt(u64, digest[0..8], .big) %
            @as(u64, @intCast(capacity)),
    );
}

test "bundle verifier cache retains only successful exact identities" {
    const testing_identity = @import("testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [testing_identity.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        testing_identity.certificate_base64,
    );
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &certificate_der);
    try bundle.parseCert(allocator, 0, 1_900_000_000);

    var entries: [2]Entry = undefined;
    var cache = BundleVerifierCache.init(
        io,
        &bundle,
        1_900_000_000,
        &entries,
    );
    const verifier = cache.clientVerifier();
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try std.testing.expectEqual(Stats{ .hits = 1, .misses = 1 }, cache.stats());

    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.verifyTrust("other.example", &.{&certificate_der}),
    );
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.verifyTrust("other.example", &.{&certificate_der}),
    );
    try std.testing.expectEqual(Stats{ .hits = 1, .misses = 3 }, cache.stats());
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try std.testing.expectEqual(Stats{ .hits = 2, .misses = 3 }, cache.stats());
}

test "bundle verifier cache with no entries always delegates" {
    const testing_identity = @import("testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [testing_identity.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        testing_identity.certificate_base64,
    );
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &certificate_der);
    try bundle.parseCert(allocator, 0, 1_900_000_000);

    var cache = BundleVerifierCache.init(
        io,
        &bundle,
        1_900_000_000,
        &.{},
    );
    const verifier = cache.clientVerifier();
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try std.testing.expectEqual(Stats{ .hits = 0, .misses = 2 }, cache.stats());
}

test "bundle verifier cache misses when any DER byte changes" {
    const testing_identity = @import("testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [testing_identity.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        testing_identity.certificate_base64,
    );
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.bytes.appendSlice(allocator, &certificate_der);
    try bundle.parseCert(allocator, 0, 1_900_000_000);

    var entries: [1]Entry = undefined;
    var cache = BundleVerifierCache.init(
        io,
        &bundle,
        1_900_000_000,
        &entries,
    );
    const verifier = cache.clientVerifier();
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    var changed = certificate_der;
    changed[changed.len - 1] ^= 1;
    // This fixture is also the configured trust anchor, so changing only its
    // self-signature remains a valid equivalent-anchor presentation. It must
    // nevertheless miss rather than reuse the exact-DER cache entry.
    try verifier.verifyTrust("localhost", &.{&changed});
    try std.testing.expectEqual(Stats{ .hits = 0, .misses = 2 }, cache.stats());
    try verifier.verifyTrust("localhost", &.{&certificate_der});
    try std.testing.expectEqual(Stats{ .hits = 0, .misses = 3 }, cache.stats());
}

test "bundle verifier cache fingerprint includes stapled OCSP state" {
    const chain = [_][]const u8{"leaf"};
    const missing = fingerprint(.{
        .server_name = "localhost",
        .chain = &chain,
        .ocsp_responses = &.{null},
    });
    const good = fingerprint(.{
        .server_name = "localhost",
        .chain = &chain,
        .ocsp_response = "good",
        .ocsp_responses = &.{"good"},
    });
    const revoked = fingerprint(.{
        .server_name = "localhost",
        .chain = &chain,
        .ocsp_response = "revoked",
        .ocsp_responses = &.{"revoked"},
    });
    try std.testing.expect(!std.mem.eql(u8, &missing, &good));
    try std.testing.expect(!std.mem.eql(u8, &good, &revoked));
}
