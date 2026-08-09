//! TLS 1.3 server Certificate and CertificateVerify helpers.
//!
//! The handshake codec is certificate-format agnostic, while the built-in
//! Ed25519 authenticator accepts either a raw 32-byte public key or an X.509
//! leaf whose SubjectPublicKeyInfo uses Ed25519. Applications can additionally
//! provide a trust callback for chain, validity, EKU, and policy validation.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const signature_scheme_ed25519: u16 = 0x0807;
pub const handshake_type_certificate: u8 = 0x0b;
pub const handshake_type_certificate_verify: u8 = 0x0f;
const server_certificate_verify_context =
    "TLS 1.3, server CertificateVerify";

pub const Error = std.mem.Allocator.Error || error{
    InvalidCertificate,
    EmptyCertificateChain,
    CertificateTooLarge,
    UnsupportedCertificateKey,
    UnsupportedSignatureScheme,
    InvalidCertificateVerify,
    BadCertificateVerify,
    CertificateUntrusted,
};

pub const ServerIdentity = struct {
    /// DER-encoded leaf-first certificate chain. A single raw 32-byte
    /// Ed25519 public key is also accepted for compact pinned-key deployments.
    certificate_chain: []const []const u8,
    signing_key: Ed25519.KeyPair,
    /// Optional hardening noise for Ed25519 signing. It must be fresh for each
    /// signature when non-null.
    signing_noise: ?[Ed25519.noise_length]u8 = null,

    pub fn validate(self: ServerIdentity) Error!void {
        if (self.certificate_chain.len == 0) {
            return error.EmptyCertificateChain;
        }
        const leaf_key = try certificatePublicKey(
            self.certificate_chain[0],
        );
        if (!std.mem.eql(
            u8,
            &leaf_key,
            &self.signing_key.public_key.toBytes(),
        )) {
            return error.InvalidCertificate;
        }
    }
};

pub const TrustContext = struct {
    server_name: ?[]const u8,
    chain: []const []const u8,
};

pub const TrustCallback = *const fn (
    context: ?*anyopaque,
    trust: TrustContext,
) anyerror!void;

pub const ClientVerifier = struct {
    /// The callback owns X.509 chain/path/time/hostname/EKU policy. The codec
    /// always verifies CertificateVerify possession independently afterward.
    verify_trust: ?TrustCallback = null,
    context: ?*anyopaque = null,
    pinned_ed25519_public_key: ?[Ed25519.PublicKey.encoded_length]u8 = null,

    pub fn verifyTrust(
        self: ClientVerifier,
        server_name: ?[]const u8,
        chain: []const []const u8,
    ) Error!void {
        if (chain.len == 0) return error.EmptyCertificateChain;
        if (self.verify_trust) |verify| {
            verify(self.context, .{
                .server_name = server_name,
                .chain = chain,
            }) catch return error.CertificateUntrusted;
            return;
        }
        if (self.pinned_ed25519_public_key) |pinned| {
            const actual = try certificatePublicKey(chain[0]);
            if (!std.crypto.timing_safe.eql(
                [Ed25519.PublicKey.encoded_length]u8,
                actual,
                pinned,
            )) {
                return error.CertificateUntrusted;
            }
            return;
        }
        return error.CertificateUntrusted;
    }
};

pub const ParsedCertificate = struct {
    entries: [][]const u8,

    pub fn deinit(self: *ParsedCertificate, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const ParsedCertificateVerify = struct {
    scheme: u16,
    signature: []const u8,
};

pub fn writeCertificate(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chain: []const []const u8,
) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    const original_len = list.items.len;
    errdefer list.items.len = original_len;

    var entries: std.ArrayList(u8) = .empty;
    defer entries.deinit(allocator);
    for (chain) |cert| {
        if (cert.len == 0 or cert.len > std.math.maxInt(u24)) {
            return error.CertificateTooLarge;
        }
        var cert_len: [3]u8 = undefined;
        writeU24(&cert_len, @intCast(cert.len));
        try entries.appendSlice(allocator, &cert_len);
        try entries.appendSlice(allocator, cert);
        // Per-certificate extensions are intentionally empty.
        try entries.appendSlice(allocator, &.{ 0, 0 });
    }
    if (entries.items.len > std.math.maxInt(u24)) {
        return error.CertificateTooLarge;
    }

    const body_len = 1 + 3 + entries.items.len;
    if (body_len > std.math.maxInt(u24)) return error.CertificateTooLarge;
    try list.append(allocator, handshake_type_certificate);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try list.append(allocator, 0); // certificate_request_context
    var entries_len: [3]u8 = undefined;
    writeU24(&entries_len, @intCast(entries.items.len));
    try list.appendSlice(allocator, &entries_len);
    try list.appendSlice(allocator, entries.items);
}

pub fn parseCertificate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!ParsedCertificate {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_certificate) {
        return error.InvalidCertificate;
    }
    const body_len = try readU24At(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidCertificate;
    const context_len = try readByte(bytes, &pos);
    if (context_len != 0) return error.InvalidCertificate;
    const entries_len = try readU24At(bytes, &pos);
    const entries_end = std.math.add(usize, pos, entries_len) catch
        return error.InvalidCertificate;
    if (entries_end != bytes.len) return error.InvalidCertificate;

    var entries: std.ArrayList([]const u8) = .empty;
    errdefer entries.deinit(allocator);
    while (pos < entries_end) {
        const cert_len = try readU24At(bytes, &pos);
        if (cert_len == 0) return error.InvalidCertificate;
        const cert = try readSlice(bytes, &pos, cert_len);
        const extensions_len = try readInt(u16, bytes, &pos);
        _ = try readSlice(bytes, &pos, extensions_len);
        try entries.append(allocator, cert);
    }
    if (entries.items.len == 0) return error.EmptyCertificateChain;
    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn writeCertificateVerify(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    transcript_hash: [Sha256.digest_length]u8,
    noise: ?[Ed25519.noise_length]u8,
) Error!void {
    var signed_content: [
        64 + server_certificate_verify_context.len + 1 +
            Sha256.digest_length
    ]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(
        signed_content[64 .. 64 + server_certificate_verify_context.len],
        server_certificate_verify_context,
    );
    const separator = 64 + server_certificate_verify_context.len;
    signed_content[separator] = 0;
    @memcpy(signed_content[separator + 1 ..], &transcript_hash);
    const signature = key_pair.sign(&signed_content, noise) catch
        return error.InvalidCertificateVerify;
    const signature_bytes = signature.toBytes();

    const body_len = 2 + 2 + signature_bytes.len;
    try list.append(allocator, handshake_type_certificate_verify);
    var body_len_bytes: [3]u8 = undefined;
    writeU24(&body_len_bytes, @intCast(body_len));
    try list.appendSlice(allocator, &body_len_bytes);
    try appendInt(list, allocator, u16, signature_scheme_ed25519);
    try appendInt(list, allocator, u16, signature_bytes.len);
    try list.appendSlice(allocator, &signature_bytes);
}

pub fn parseCertificateVerify(
    bytes: []const u8,
) Error!ParsedCertificateVerify {
    var pos: usize = 0;
    if (try readByte(bytes, &pos) != handshake_type_certificate_verify) {
        return error.InvalidCertificateVerify;
    }
    const body_len = try readU24At(bytes, &pos);
    if (body_len != bytes.len - pos) return error.InvalidCertificateVerify;
    const scheme = try readInt(u16, bytes, &pos);
    if (scheme != signature_scheme_ed25519) {
        return error.UnsupportedSignatureScheme;
    }
    const signature_len = try readInt(u16, bytes, &pos);
    if (signature_len != Ed25519.Signature.encoded_length) {
        return error.InvalidCertificateVerify;
    }
    const signature = try readSlice(bytes, &pos, signature_len);
    if (pos != bytes.len) return error.InvalidCertificateVerify;
    return .{ .scheme = scheme, .signature = signature };
}

pub fn verifyCertificateVerify(
    certificate: []const u8,
    parsed: ParsedCertificateVerify,
    transcript_hash: [Sha256.digest_length]u8,
) Error!void {
    if (parsed.scheme != signature_scheme_ed25519 or
        parsed.signature.len != Ed25519.Signature.encoded_length)
    {
        return error.UnsupportedSignatureScheme;
    }
    const public_key_bytes = try certificatePublicKey(certificate);
    const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes) catch
        return error.InvalidCertificate;
    const signature = Ed25519.Signature.fromBytes(
        parsed.signature[0..Ed25519.Signature.encoded_length].*,
    );

    var verifier = signature.verifier(public_key) catch
        return error.BadCertificateVerify;
    verifier.update(" " ** 64);
    verifier.update(server_certificate_verify_context);
    verifier.update(&.{0});
    verifier.update(&transcript_hash);
    verifier.verify() catch return error.BadCertificateVerify;
}

fn certificatePublicKey(certificate: []const u8) Error![32]u8 {
    if (certificate.len == Ed25519.PublicKey.encoded_length) {
        _ = Ed25519.PublicKey.fromBytes(
            certificate[0..Ed25519.PublicKey.encoded_length].*,
        ) catch return error.InvalidCertificate;
        return certificate[0..Ed25519.PublicKey.encoded_length].*;
    }
    const parsed = try parseX509(certificate);
    if (parsed.pub_key_algo != .curveEd25519) {
        return error.UnsupportedCertificateKey;
    }
    const public_key = parsed.pubKey();
    if (public_key.len != Ed25519.PublicKey.encoded_length) {
        return error.InvalidCertificate;
    }
    return public_key[0..Ed25519.PublicKey.encoded_length].*;
}

fn parseX509(certificate: []const u8) Error!Certificate.Parsed {
    return Certificate.parse(.{
        .buffer = certificate,
        .index = 0,
    }) catch return error.InvalidCertificate;
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: anytype,
) std.mem.Allocator.Error!void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .big);
    try list.appendSlice(allocator, &bytes);
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    if (pos.* >= bytes.len) return error.InvalidCertificate;
    const value = bytes[pos.*];
    pos.* += 1;
    return value;
}

fn readInt(
    comptime T: type,
    bytes: []const u8,
    pos: *usize,
) Error!T {
    const slice = try readSlice(bytes, pos, @sizeOf(T));
    return std.mem.readInt(T, slice[0..@sizeOf(T)], .big);
}

fn readSlice(
    bytes: []const u8,
    pos: *usize,
    len: usize,
) Error![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch
        return error.InvalidCertificate;
    if (end > bytes.len) return error.InvalidCertificate;
    const result = bytes[pos.*..end];
    pos.* = end;
    return result;
}

fn readU24At(bytes: []const u8, pos: *usize) Error!usize {
    const slice = try readSlice(bytes, pos, 3);
    return readU24(slice[0..3]);
}

fn readU24(bytes: *const [3]u8) usize {
    return (@as(usize, bytes[0]) << 16) |
        (@as(usize, bytes[1]) << 8) |
        bytes[2];
}

fn writeU24(bytes: *[3]u8, value: u24) void {
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}
