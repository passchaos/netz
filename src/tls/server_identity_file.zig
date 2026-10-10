//! Strict file-backed TLS server identities.
//!
//! This loader supports PEM X.509 chains with unencrypted P-256/P-384 SEC1 or
//! PKCS#8 keys, RFC 8410 Ed25519 PKCS#8 keys, and 2048/3072/4096-bit RSA
//! PKCS#1/PKCS#8 keys. Unsupported PEM labels, ambiguous DER, parameters that
//! cannot be represented by the TLS signer, and certificate/key mismatches fail
//! closed.

const std = @import("std");
const vail = @import("vail");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const Rsa = vail.crypto.rsa;
const ServerIdentity = vail.tls.auth.ServerIdentity;

pub const max_certificate_file_bytes: usize = 4 * 1024 * 1024;
pub const max_private_key_file_bytes: usize = 64 * 1024;
pub const max_certificates: usize = 16;
pub const max_certificate_der_bytes: usize = 1024 * 1024;
pub const max_private_key_der_bytes: usize = 16 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    EmptyCertificateChain,
    TooManyCertificates,
    CertificateTooLarge,
    PrivateKeyTooLarge,
    InvalidPem,
    UnsupportedPrivateKey,
    InvalidPrivateKey,
    InvalidCertificate,
    CertificateKeyMismatch,
};

pub const Identity = struct {
    allocator: std.mem.Allocator,
    certificate_chain: [][]const u8,
    key_pair: KeyPair,

    pub const KeyPair = union(enum) {
        ecdsa_p256_sha256: EcdsaP256Sha256.KeyPair,
        ecdsa_p384_sha384: EcdsaP384Sha384.KeyPair,
        ed25519: Ed25519.KeyPair,
        rsa_pss: *RsaKeyPair,
    };

    pub const RsaKeyPair = struct {
        encoded: []u8,
        prepared: Rsa.PreparedPrivateKey,
        signature_scheme: u16,
    };

    pub fn deinit(self: *Identity) void {
        for (self.certificate_chain) |certificate| {
            self.allocator.free(@constCast(certificate));
        }
        self.allocator.free(self.certificate_chain);
        deinitKeyPair(self.allocator, &self.key_pair);
        self.* = undefined;
    }

    /// The returned identity borrows the certificate chain and signer from
    /// this object and must not outlive it.
    pub fn serverIdentity(self: *const Identity) ServerIdentity {
        return .{
            .certificate_chain = self.certificate_chain,
            .signer = switch (self.key_pair) {
                .ecdsa_p256_sha256 => |key_pair| .{
                    .ecdsa_p256_sha256 = .{ .key_pair = key_pair },
                },
                .ecdsa_p384_sha384 => |key_pair| .{
                    .ecdsa_p384_sha384 = .{ .key_pair = key_pair },
                },
                .ed25519 => |key_pair| .{
                    .ed25519 = .{ .key_pair = key_pair },
                },
                .rsa_pss => |rsa| .{
                    .rsa_pss = .{
                        .prepared_key = &rsa.prepared,
                        .signature_scheme = rsa.signature_scheme,
                        // The stream handshake replaces this before signing.
                        .io = undefined,
                    },
                },
            },
        };
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    certificate_path: []const u8,
    private_key_path: []const u8,
) (Error || std.Io.Dir.ReadFileAllocError)!Identity {
    const certificate_source = try dir.readFileAlloc(
        io,
        certificate_path,
        allocator,
        .limited(max_certificate_file_bytes + 1),
    );
    defer allocator.free(certificate_source);
    if (certificate_source.len > max_certificate_file_bytes) {
        return error.CertificateTooLarge;
    }

    const private_key_source = try dir.readFileAlloc(
        io,
        private_key_path,
        allocator,
        .limited(max_private_key_file_bytes + 1),
    );
    defer {
        std.crypto.secureZero(u8, private_key_source);
        allocator.free(private_key_source);
    }
    if (private_key_source.len > max_private_key_file_bytes) {
        return error.PrivateKeyTooLarge;
    }
    return parse(allocator, certificate_source, private_key_source);
}

pub fn parse(
    allocator: std.mem.Allocator,
    certificate_source: []const u8,
    private_key_pem: []const u8,
) Error!Identity {
    if (certificate_source.len > max_certificate_file_bytes) {
        return error.CertificateTooLarge;
    }
    if (private_key_pem.len > max_private_key_file_bytes) {
        return error.PrivateKeyTooLarge;
    }

    var certificates: std.ArrayList([]const u8) = .empty;
    defer certificates.deinit(allocator);
    errdefer for (certificates.items) |certificate| {
        allocator.free(@constCast(certificate));
    };
    try parseCertificatePem(allocator, certificate_source, &certificates);

    const key_der = try parsePrivateKeyPem(allocator, private_key_pem);
    defer {
        std.crypto.secureZero(u8, key_der.bytes);
        allocator.free(key_der.bytes);
    }
    var key_pair = try parsePrivateKeyDer(
        allocator,
        key_der.label,
        key_der.bytes,
    );
    errdefer deinitKeyPair(allocator, &key_pair);

    const owned_chain = try certificates.toOwnedSlice(allocator);
    errdefer {
        for (owned_chain) |certificate| allocator.free(@constCast(certificate));
        allocator.free(owned_chain);
    }
    var identity: Identity = .{
        .allocator = allocator,
        .certificate_chain = owned_chain,
        .key_pair = key_pair,
    };
    identity.serverIdentity().validate() catch |err| switch (err) {
        error.InvalidCertificate,
        error.UnsupportedCertificateKey,
        => return error.CertificateKeyMismatch,
        else => return error.InvalidCertificate,
    };
    return identity;
}

const PemLabel = enum { sec1, rsa_pkcs1, pkcs8 };

const DecodedPrivateKey = struct {
    label: PemLabel,
    bytes: []u8,
};

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
    return .{
        .bytes = std.mem.trim(u8, source[start..end], " \t\r"),
        .start = start,
        .next = offset.*,
    };
}

fn parseCertificatePem(
    allocator: std.mem.Allocator,
    source: []const u8,
    certificates: *std.ArrayList([]const u8),
) Error!void {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var offset: usize = 0;
    while (nextLine(source, &offset)) |line| {
        if (line.bytes.len == 0) continue;
        if (!std.mem.eql(u8, line.bytes, begin)) return error.InvalidPem;
        const body_start = line.next;
        var body_end: ?usize = null;
        while (nextLine(source, &offset)) |body_line| {
            if (std.mem.eql(u8, body_line.bytes, end)) {
                body_end = body_line.start;
                break;
            }
            if (std.mem.startsWith(u8, body_line.bytes, "-----")) {
                return error.InvalidPem;
            }
        }
        const encoded_end = body_end orelse return error.InvalidPem;
        if (certificates.items.len == max_certificates) {
            return error.TooManyCertificates;
        }
        const certificate = try decodePemBody(
            allocator,
            source[body_start..encoded_end],
            max_certificate_der_bytes,
            false,
        );
        errdefer allocator.free(certificate);
        try validateCertificateDer(certificate);
        try certificates.append(allocator, certificate);
    }
    if (certificates.items.len == 0) return error.EmptyCertificateChain;
}

fn parsePrivateKeyPem(
    allocator: std.mem.Allocator,
    source: []const u8,
) Error!DecodedPrivateKey {
    var offset: usize = 0;
    var decoded: ?DecodedPrivateKey = null;
    errdefer if (decoded) |key| {
        std.crypto.secureZero(u8, key.bytes);
        allocator.free(key.bytes);
    };
    while (nextLine(source, &offset)) |line| {
        if (line.bytes.len == 0) continue;
        if (decoded != null) return error.InvalidPem;
        const label: PemLabel = if (std.mem.eql(
            u8,
            line.bytes,
            "-----BEGIN EC PRIVATE KEY-----",
        ))
            .sec1
        else if (std.mem.eql(
            u8,
            line.bytes,
            "-----BEGIN RSA PRIVATE KEY-----",
        ))
            .rsa_pkcs1
        else if (std.mem.eql(
            u8,
            line.bytes,
            "-----BEGIN PRIVATE KEY-----",
        ))
            .pkcs8
        else if (std.mem.startsWith(u8, line.bytes, "-----BEGIN "))
            return error.UnsupportedPrivateKey
        else
            return error.InvalidPem;
        const end_marker = switch (label) {
            .sec1 => "-----END EC PRIVATE KEY-----",
            .rsa_pkcs1 => "-----END RSA PRIVATE KEY-----",
            .pkcs8 => "-----END PRIVATE KEY-----",
        };
        const body_start = line.next;
        var body_end: ?usize = null;
        while (nextLine(source, &offset)) |body_line| {
            if (std.mem.eql(u8, body_line.bytes, end_marker)) {
                body_end = body_line.start;
                break;
            }
            if (std.mem.startsWith(u8, body_line.bytes, "-----")) {
                return error.InvalidPem;
            }
        }
        const encoded_end = body_end orelse return error.InvalidPem;
        decoded = .{
            .label = label,
            .bytes = try decodePemBody(
                allocator,
                source[body_start..encoded_end],
                max_private_key_der_bytes,
                true,
            ),
        };
    }
    return decoded orelse error.InvalidPem;
}

fn decodePemBody(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    max_decoded_bytes: usize,
    secret: bool,
) Error![]u8 {
    var compact: std.ArrayList(u8) = .empty;
    defer {
        if (secret) std.crypto.secureZero(u8, compact.items);
        compact.deinit(allocator);
    }
    for (encoded) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => try compact.append(allocator, byte),
    };
    if (compact.items.len == 0) return error.InvalidPem;
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(
        compact.items,
    ) catch return error.InvalidPem;
    if (decoded_len == 0) return error.InvalidPem;
    if (decoded_len > max_decoded_bytes) {
        return if (secret) error.PrivateKeyTooLarge else error.CertificateTooLarge;
    }
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer {
        if (secret) std.crypto.secureZero(u8, decoded);
        allocator.free(decoded);
    }
    std.base64.standard.Decoder.decode(decoded, compact.items) catch {
        return error.InvalidPem;
    };
    return decoded;
}

const DerReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn read(self: *DerReader, expected_tag: u8) Error![]const u8 {
        if (self.offset + 2 > self.bytes.len) return error.InvalidPrivateKey;
        if (self.bytes[self.offset] != expected_tag) {
            return error.InvalidPrivateKey;
        }
        self.offset += 1;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                self.offset + count > self.bytes.len or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidPrivateKey;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                if (length >
                    (std.math.maxInt(usize) - @as(usize, byte)) / 256)
                {
                    return error.InvalidPrivateKey;
                }
                length = length * 256 + byte;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidPrivateKey;
        }
        if (length > self.bytes.len - self.offset) {
            return error.InvalidPrivateKey;
        }
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return value;
    }

    fn done(self: DerReader) bool {
        return self.offset == self.bytes.len;
    }
};

const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_rsa_encryption = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};
const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_rsassa_pss_shake128 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1e,
};
const oid_rsassa_pss_shake256 = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1f,
};

fn parsePrivateKeyDer(
    allocator: std.mem.Allocator,
    label: PemLabel,
    der: []const u8,
) Error!Identity.KeyPair {
    if (der.len == 0 or der.len > max_private_key_der_bytes) {
        return error.InvalidPrivateKey;
    }
    return switch (label) {
        .sec1 => parseSec1PrivateKey(der, null, true),
        .rsa_pkcs1 => .{
            .rsa_pss = try parseRsaPrivateKey(allocator, der),
        },
        .pkcs8 => parsePkcs8PrivateKey(allocator, der),
    };
}

fn parsePkcs8PrivateKey(
    allocator: std.mem.Allocator,
    der: []const u8,
) Error!Identity.KeyPair {
    var outer = DerReader{ .bytes = der };
    const sequence = try outer.read(0x30);
    if (!outer.done()) return error.InvalidPrivateKey;
    var fields = DerReader{ .bytes = sequence };
    if (!std.mem.eql(u8, try fields.read(0x02), &.{0x00})) {
        return error.InvalidPrivateKey;
    }
    const algorithm = try fields.read(0x30);
    var algorithm_fields = DerReader{ .bytes = algorithm };
    const algorithm_oid = try algorithm_fields.read(0x06);
    const key_kind: KeyKind = if (std.mem.eql(
        u8,
        algorithm_oid,
        &oid_ec_public_key,
    )) blk: {
        const curve_oid = try algorithm_fields.read(0x06);
        break :blk if (std.mem.eql(u8, curve_oid, &oid_prime256v1))
            .p256
        else if (std.mem.eql(u8, curve_oid, &oid_secp384r1))
            .p384
        else
            return error.InvalidPrivateKey;
    } else if (std.mem.eql(u8, algorithm_oid, &oid_ed25519))
        .ed25519
    else if (std.mem.eql(u8, algorithm_oid, &oid_rsa_encryption) or
        std.mem.eql(u8, algorithm_oid, &oid_rsassa_pss) or
        std.mem.eql(u8, algorithm_oid, &oid_rsassa_pss_shake128) or
        std.mem.eql(u8, algorithm_oid, &oid_rsassa_pss_shake256))
    {
        return .{ .rsa_pss = try parseRsaPrivateKey(allocator, der) };
    } else return error.UnsupportedPrivateKey;
    if (!algorithm_fields.done()) return error.InvalidPrivateKey;
    const inner = try fields.read(0x04);
    if (!fields.done()) return error.InvalidPrivateKey;
    return switch (key_kind) {
        .p256, .p384 => parseSec1PrivateKey(inner, key_kind, false),
        .ed25519 => parseEd25519PrivateKey(inner),
    };
}

fn parseRsaPrivateKey(
    allocator: std.mem.Allocator,
    der: []const u8,
) Error!*Identity.RsaKeyPair {
    const encoded = try allocator.dupe(u8, der);
    errdefer {
        std.crypto.secureZero(u8, encoded);
        allocator.free(encoded);
    }
    const private_key = Rsa.PrivateKey.fromDer(encoded) catch |err| switch (err) {
        error.UnsupportedModulusBits,
        error.UnsupportedPublicExponent,
        error.KeyAlgorithmMismatch,
        => return error.UnsupportedPrivateKey,
        else => return error.InvalidPrivateKey,
    };
    const signature_scheme = try rsaSignatureScheme(private_key);
    var prepared = private_key.prepare() catch |err| switch (err) {
        error.UnsupportedModulusBits,
        error.UnsupportedPublicExponent,
        error.KeyAlgorithmMismatch,
        => return error.UnsupportedPrivateKey,
        else => return error.InvalidPrivateKey,
    };
    errdefer prepared.deinit();
    const key_pair = try allocator.create(Identity.RsaKeyPair);
    key_pair.* = .{
        .encoded = encoded,
        .prepared = prepared,
        .signature_scheme = signature_scheme,
    };
    return key_pair;
}

fn rsaSignatureScheme(private_key: Rsa.PrivateKey) Error!u16 {
    const constraints = private_key.pss_constraints orelse
        return vail.tls.auth.signature_scheme_rsa_pss_rsae_sha256;
    const profile = switch (constraints) {
        .unrestricted => return vail.tls.auth.signature_scheme_rsa_pss_pss_sha256,
        .restricted => |profile| profile,
    };
    if (profile.trailer_field != 1 or profile.hash != profile.mgf_hash) {
        return error.UnsupportedPrivateKey;
    }
    return switch (profile.hash) {
        .sha256 => if (profile.salt_length <= 32)
            vail.tls.auth.signature_scheme_rsa_pss_pss_sha256
        else
            error.UnsupportedPrivateKey,
        .sha384 => if (profile.salt_length <= 48)
            vail.tls.auth.signature_scheme_rsa_pss_pss_sha384
        else
            error.UnsupportedPrivateKey,
        .sha512 => if (profile.salt_length <= 64)
            vail.tls.auth.signature_scheme_rsa_pss_pss_sha512
        else
            error.UnsupportedPrivateKey,
        else => error.UnsupportedPrivateKey,
    };
}

fn deinitKeyPair(
    allocator: std.mem.Allocator,
    key_pair: *Identity.KeyPair,
) void {
    if (key_pair.* == .rsa_pss) {
        const rsa = key_pair.rsa_pss;
        rsa.prepared.deinit();
        std.crypto.secureZero(u8, rsa.encoded);
        allocator.free(rsa.encoded);
        std.crypto.secureZero(Identity.RsaKeyPair, rsa[0..1]);
        allocator.destroy(rsa);
    }
    std.crypto.secureZero(u8, std.mem.asBytes(key_pair));
    key_pair.* = undefined;
}

const KeyKind = enum { p256, p384, ed25519 };

fn parseSec1PrivateKey(
    der: []const u8,
    expected_kind: ?KeyKind,
    require_parameters: bool,
) Error!Identity.KeyPair {
    var outer = DerReader{ .bytes = der };
    const sequence = try outer.read(0x30);
    if (!outer.done()) return error.InvalidPrivateKey;
    var fields = DerReader{ .bytes = sequence };
    if (!std.mem.eql(u8, try fields.read(0x02), &.{0x01})) {
        return error.InvalidPrivateKey;
    }
    const private_key = try fields.read(0x04);

    var parameter_kind: ?KeyKind = null;
    if (!fields.done() and fields.bytes[fields.offset] == 0xa0) {
        const parameters = try fields.read(0xa0);
        var parameter_fields = DerReader{ .bytes = parameters };
        const curve_oid = try parameter_fields.read(0x06);
        parameter_kind = if (std.mem.eql(u8, curve_oid, &oid_prime256v1))
            .p256
        else if (std.mem.eql(u8, curve_oid, &oid_secp384r1))
            .p384
        else
            return error.InvalidPrivateKey;
        if (!parameter_fields.done()) return error.InvalidPrivateKey;
    }
    if (require_parameters and parameter_kind == null) {
        return error.InvalidPrivateKey;
    }
    const kind = expected_kind orelse parameter_kind.?;
    if (parameter_kind) |actual| {
        if (actual != kind) return error.InvalidPrivateKey;
    }

    var encoded_public_key: ?[]const u8 = null;
    if (!fields.done() and fields.bytes[fields.offset] == 0xa1) {
        const public_wrapper = try fields.read(0xa1);
        var public_fields = DerReader{ .bytes = public_wrapper };
        const bit_string = try public_fields.read(0x03);
        if (!public_fields.done() or bit_string.len == 0 or bit_string[0] != 0) {
            return error.InvalidPrivateKey;
        }
        encoded_public_key = bit_string[1..];
    }
    if (!fields.done()) return error.InvalidPrivateKey;

    return switch (kind) {
        .p256 => .{ .ecdsa_p256_sha256 = try parseEcKeyPair(
            EcdsaP256Sha256,
            std.crypto.ecc.P256,
            private_key,
            encoded_public_key,
        ) },
        .p384 => .{ .ecdsa_p384_sha384 = try parseEcKeyPair(
            EcdsaP384Sha384,
            std.crypto.ecc.P384,
            private_key,
            encoded_public_key,
        ) },
        .ed25519 => return error.InvalidPrivateKey,
    };
}

fn parseEcKeyPair(
    comptime Scheme: type,
    comptime Curve: type,
    bytes: []const u8,
    encoded_public_key: ?[]const u8,
) Error!Scheme.KeyPair {
    if (bytes.len != Scheme.SecretKey.encoded_length) {
        return error.InvalidPrivateKey;
    }
    var scalar: [Scheme.SecretKey.encoded_length]u8 = undefined;
    @memcpy(&scalar, bytes);
    defer std.crypto.secureZero(u8, &scalar);
    const parsed_scalar = Curve.scalar.Scalar.fromBytes(scalar, .big) catch
        return error.InvalidPrivateKey;
    if (parsed_scalar.isZero()) return error.InvalidPrivateKey;
    const secret_key = Scheme.SecretKey.fromBytes(scalar) catch
        return error.InvalidPrivateKey;
    const key_pair = Scheme.KeyPair.fromSecretKey(secret_key) catch
        return error.InvalidPrivateKey;
    if (encoded_public_key) |encoded| {
        const actual = key_pair.public_key.toUncompressedSec1();
        if (!std.mem.eql(u8, encoded, &actual)) {
            return error.InvalidPrivateKey;
        }
    }
    return key_pair;
}

fn parseEd25519PrivateKey(inner: []const u8) Error!Identity.KeyPair {
    var seed_reader = DerReader{ .bytes = inner };
    const seed_bytes = try seed_reader.read(0x04);
    if (!seed_reader.done() or seed_bytes.len != Ed25519.KeyPair.seed_length) {
        return error.InvalidPrivateKey;
    }
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memcpy(&seed, seed_bytes);
    defer std.crypto.secureZero(u8, &seed);
    return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch
        return error.InvalidPrivateKey };
}

fn validateCertificateDer(der: []const u8) Error!void {
    if (der.len == 0 or der.len > max_certificate_der_bytes) {
        return error.CertificateTooLarge;
    }
    var outer = DerReader{ .bytes = der };
    _ = outer.read(0x30) catch return error.InvalidCertificate;
    if (!outer.done()) return error.InvalidCertificate;
    _ = std.crypto.Certificate.parse(.{
        .buffer = der,
        .index = 0,
    }) catch return error.InvalidCertificate;
}

const certificate_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2Nh
    \\bGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIw
    \\EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAA
    \\RawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65
    \\oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2Nh
    \\bGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wX
    \\gSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6s
    \\MvbrhNjKU=
    \\-----END CERTIFICATE-----
;

const sec1_private_key_pem =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI0oAoG
    \\CCqGSM49AwEH
    \\-----END EC PRIVATE KEY-----
;

const pkcs8_private_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCASNFZ4mrze
    \\8SNFZ4mrze8SNFZ4mrze8SNFZ4mrze8SNA==
    \\-----END PRIVATE KEY-----
;

test "server identity file parses SEC1 and PKCS8 P-256 keys" {
    inline for (.{ sec1_private_key_pem, pkcs8_private_key_pem }) |key_pem| {
        var identity = try parse(std.testing.allocator, certificate_pem, key_pem);
        defer identity.deinit();
        try std.testing.expectEqual(@as(usize, 1), identity.certificate_chain.len);
        try identity.serverIdentity().validate();
    }
}

test "server identity file parses P-384 and Ed25519 PKCS8 keys" {
    const p384_der_hex =
        "3081b6020100301006072a8648ce3d020106052b8104002204819e" ++
        "30819b0201010430f70d151aad5ced2202849b19e262d2bfa65ead" ++
        "11d8a025e7657c6e8b004ea0b37f79ac927be2bc1c06a0ce607da" ++
        "62b46a164036200046221b2d856a7fe4295357509134a3eabae4f7" ++
        "8889e1244a2158c19c10dab58c3269cc5b467396a2093b5dfa3e3" ++
        "635106215c5586c1d99be9087fb2448f2dd4e4a061f5556884e028" ++
        "ee2b5d095ec2a897f3a588e1238e7c62160313e6cd8c65d8";
    var p384_der: [p384_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p384_der, p384_der_hex);
    var p384 = try parsePrivateKeyDer(
        std.testing.allocator,
        .pkcs8,
        &p384_der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p384));
    try std.testing.expect(p384 == .ecdsa_p384_sha384);

    const ed25519_der_hex =
        "302e020100300506032b657004220420" ++
        "85aefc9f41a80df3cad89138c8dfa7f4f33b3b8485a60092b833a08640c903b6";
    var ed25519_der: [ed25519_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ed25519_der, ed25519_der_hex);
    var ed25519 = try parsePrivateKeyDer(
        std.testing.allocator,
        .pkcs8,
        &ed25519_der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ed25519));
    try std.testing.expect(ed25519 == .ed25519);
}

test "server identity file parses RSA PKCS8 and PKCS1 keys" {
    const allocator = std.testing.allocator;
    const vectors = vail.crypto.testing.rsa_signing;
    var certificate_der: [vectors.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate_der, vectors.certificate_hex);
    const certificate = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        &certificate_der,
    );
    defer allocator.free(certificate);

    for ([_]struct {
        label: []const u8,
        encoded: []const u8,
    }{
        .{ .label = "PRIVATE KEY", .encoded = vectors.private_key_pkcs8_hex },
        .{ .label = "RSA PRIVATE KEY", .encoded = vectors.private_key_pkcs1_hex },
    }) |case| {
        const der = try allocator.alloc(u8, case.encoded.len / 2);
        defer {
            std.crypto.secureZero(u8, der);
            allocator.free(der);
        }
        _ = try std.fmt.hexToBytes(der, case.encoded);
        const private_key = try encodePemForTest(allocator, case.label, der);
        defer {
            std.crypto.secureZero(u8, private_key);
            allocator.free(private_key);
        }
        var identity = try parse(allocator, certificate, private_key);
        defer identity.deinit();
        try std.testing.expect(identity.key_pair == .rsa_pss);
        try std.testing.expectEqual(
            @as(usize, 256),
            identity.key_pair.rsa_pss.prepared.signatureLength(),
        );
        try identity.serverIdentity().validate();
    }
}

test "server identity file rejects an RSA key for an EC certificate" {
    const allocator = std.testing.allocator;
    const encoded = vail.crypto.testing.rsa_signing.private_key_pkcs8_hex;
    const der = try allocator.alloc(u8, encoded.len / 2);
    defer {
        std.crypto.secureZero(u8, der);
        allocator.free(der);
    }
    _ = try std.fmt.hexToBytes(der, encoded);
    const private_key = try encodePemForTest(allocator, "PRIVATE KEY", der);
    defer {
        std.crypto.secureZero(u8, private_key);
        allocator.free(private_key);
    }
    try std.testing.expectError(
        error.CertificateKeyMismatch,
        parse(allocator, certificate_pem, private_key),
    );
}

test "server identity file parses a constrained RSA-PSS PKCS8 key" {
    const allocator = std.testing.allocator;
    const certificate = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        vail.x509.testing.rsa_pss_constrained_leaf,
    );
    defer allocator.free(certificate);
    const private_key = try encodePemForTest(
        allocator,
        "PRIVATE KEY",
        vail.x509.testing.rsa_pss_constrained_private_key,
    );
    defer {
        std.crypto.secureZero(u8, private_key);
        allocator.free(private_key);
    }
    var identity = try parse(allocator, certificate, private_key);
    defer identity.deinit();
    try std.testing.expect(identity.key_pair == .rsa_pss);
    try identity.serverIdentity().validate();
}

test "server identity file parses a P-384 SEC1 key" {
    const der_hex =
        "3081a40201010430fd54b21ecf364a932c6e4aff7c014767c08ee4c2" ++
        "133451524423b6192bcb8088d097018dd6cd279fe8589841aac20167" ++
        "a00706052b81040022a164036200049aedd7293ee3a6be895ecc021a" ++
        "ee391ce0951a360c26f58b863cb8fa0a815d7f6ab1dc2a67858a55" ++
        "3b1e084f698abaafc841f103b475ec7eb33a4f1e1041d18d92008c" ++
        "5b10de8d6317bd44ff1214f00a6da9acc864a16dc14293bb380497c" ++
        "48d";
    var der: [der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&der, der_hex);
    var key = try parsePrivateKeyDer(
        std.testing.allocator,
        .sec1,
        &der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    try std.testing.expect(key == .ecdsa_p384_sha384);
}

test "server identity file rejects unsupported and malformed modern private keys" {
    const ed25519_der_hex =
        "302e020100300506032b657004220420" ++
        "85aefc9f41a80df3cad89138c8dfa7f4f33b3b8485a60092b833a08640c903b6";
    var ed25519_der: [ed25519_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ed25519_der, ed25519_der_hex);
    ed25519_der[10] = 0x05;
    try std.testing.expectError(
        error.UnsupportedPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .pkcs8, &ed25519_der),
    );

    const p384_der_hex =
        "3081b6020100301006072a8648ce3d020106052b8104002204819e" ++
        "30819b0201010430f70d151aad5ced2202849b19e262d2bfa65ead" ++
        "11d8a025e7657c6e8b004ea0b37f79ac927be2bc1c06a0ce607da" ++
        "62b46a164036200046221b2d856a7fe4295357509134a3eabae4f7" ++
        "8889e1244a2158c19c10dab58c3269cc5b467396a2093b5dfa3e3" ++
        "635106215c5586c1d99be9087fb2448f2dd4e4a061f5556884e028" ++
        "ee2b5d095ec2a897f3a588e1238e7c62160313e6cd8c65d8";
    var p384_der: [p384_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p384_der, p384_der_hex);
    p384_der[33] ^= 1;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .pkcs8, &p384_der),
    );
}

test "server identity file preserves a leaf-first certificate chain" {
    const chain_pem = certificate_pem ++ "\n" ++ certificate_pem;
    var identity = try parse(
        std.testing.allocator,
        chain_pem,
        sec1_private_key_pem,
    );
    defer identity.deinit();
    try std.testing.expectEqual(@as(usize, 2), identity.certificate_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        identity.certificate_chain[0],
        identity.certificate_chain[1],
    );
}

test "server identity file loads certificate and key files" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.crt",
        .data = certificate_pem,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.key",
        .data = pkcs8_private_key_pem,
    });
    var identity = try load(
        std.testing.allocator,
        io,
        tmp.dir,
        "server.crt",
        "server.key",
    );
    defer identity.deinit();
    try identity.serverIdentity().validate();
}

test "server identity file rejects mismatched certificate and key" {
    const mismatched_key =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI1oAoG
        \\CCqGSM49AwEH
        \\-----END EC PRIVATE KEY-----
    ;
    try std.testing.expectError(
        error.CertificateKeyMismatch,
        parse(std.testing.allocator, certificate_pem, mismatched_key),
    );
}

test "server identity file rejects malformed PEM and unsupported labels" {
    try std.testing.expectError(
        error.EmptyCertificateChain,
        parse(std.testing.allocator, "", sec1_private_key_pem),
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        parse(
            std.testing.allocator,
            "-----BEGIN CERTIFICATE-----\nAA==\n" ++
                "-----END CERTIFICATE-----\n",
            sec1_private_key_pem,
        ),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(std.testing.allocator, certificate_pem, "-----BEGIN PRIVATE KEY-----\nAA==\n"),
    );
    try std.testing.expectError(
        error.UnsupportedPrivateKey,
        parse(std.testing.allocator, certificate_pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n" ++
            "-----END ENCRYPTED PRIVATE KEY-----\n"),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(std.testing.allocator, certificate_pem, sec1_private_key_pem ++ sec1_private_key_pem),
    );
}

test "server identity file rejects ambiguous private key DER" {
    const valid_sec1 = [_]u8{
        0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0xa0,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    };
    _ = try parsePrivateKeyDer(std.testing.allocator, .sec1, &valid_sec1);

    var wrong_curve = valid_sec1;
    wrong_curve[wrong_curve.len - 1] = 0x08;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .sec1, &wrong_curve),
    );

    const trailing = valid_sec1 ++ .{0x00};
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .sec1, &trailing),
    );

    const non_canonical_length = [_]u8{ 0x30, 0x81, 0x31 } ++
        valid_sec1[2..].*;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(
            std.testing.allocator,
            .sec1,
            &non_canonical_length,
        ),
    );
}

test "server identity file rejects zero and non-canonical P-256 scalars" {
    const template = [_]u8{
        0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0xa0,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    };
    var zero = template;
    @memset(zero[7..39], 0);
    const zero_pem = try encodePrivateKeyForTest(std.testing.allocator, &zero);
    defer std.testing.allocator.free(zero_pem);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parse(std.testing.allocator, certificate_pem, zero_pem),
    );

    var non_canonical = template;
    @memset(non_canonical[7..39], 0xff);
    const non_canonical_pem = try encodePrivateKeyForTest(
        std.testing.allocator,
        &non_canonical,
    );
    defer std.testing.allocator.free(non_canonical_pem);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parse(std.testing.allocator, certificate_pem, non_canonical_pem),
    );
}

fn encodePrivateKeyForTest(
    allocator: std.mem.Allocator,
    der: []const u8,
) ![]u8 {
    return encodePemForTest(allocator, "EC PRIVATE KEY", der);
}

fn encodePemForTest(
    allocator: std.mem.Allocator,
    label: []const u8,
    der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(der.len);
    const prefix_len = "-----BEGIN ".len + label.len + "-----\n".len;
    const suffix_len = "\n-----END ".len + label.len + "-----\n".len;
    const pem = try allocator.alloc(
        u8,
        prefix_len + encoded_len + suffix_len,
    );
    var output: std.Io.Writer = .fixed(pem);
    try output.print("-----BEGIN {s}-----\n", .{label});
    const body_start = output.end;
    _ = std.base64.standard.Encoder.encode(
        pem[body_start..][0..encoded_len],
        der,
    );
    output.end += encoded_len;
    try output.print("\n-----END {s}-----\n", .{label});
    return pem;
}
