//! Strict file-backed TLS server identities.
//!
//! This loader intentionally supports one production profile: a PEM X.509
//! certificate chain and an unencrypted P-256 private key encoded as SEC1 or
//! PKCS#8. Unsupported PEM labels, ambiguous DER, and certificate/key
//! mismatches fail closed.

const std = @import("std");
const vail = @import("vail");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
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
    key_pair: EcdsaP256Sha256.KeyPair,

    pub fn deinit(self: *Identity) void {
        for (self.certificate_chain) |certificate| {
            self.allocator.free(@constCast(certificate));
        }
        self.allocator.free(self.certificate_chain);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_pair));
        self.* = undefined;
    }

    /// The returned identity borrows the certificate chain and signer from
    /// this object and must not outlive it.
    pub fn serverIdentity(self: *const Identity) ServerIdentity {
        return .{
            .certificate_chain = self.certificate_chain,
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = self.key_pair,
            } },
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
    var scalar = try parsePrivateKeyDer(key_der.label, key_der.bytes);
    defer std.crypto.secureZero(u8, &scalar);
    const parsed_scalar = std.crypto.ecc.P256.scalar.Scalar.fromBytes(
        scalar,
        .big,
    ) catch return error.InvalidPrivateKey;
    if (parsed_scalar.isZero()) return error.InvalidPrivateKey;
    const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch {
        return error.InvalidPrivateKey;
    };
    const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch {
        return error.InvalidPrivateKey;
    };

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
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&identity.key_pair));
    identity.serverIdentity().validate() catch |err| switch (err) {
        error.InvalidCertificate => return error.CertificateKeyMismatch,
        else => return error.InvalidCertificate,
    };
    return identity;
}

const PemLabel = enum { sec1, pkcs8 };

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
            "-----BEGIN PRIVATE KEY-----",
        ))
            .pkcs8
        else if (std.mem.startsWith(u8, line.bytes, "-----BEGIN "))
            return error.UnsupportedPrivateKey
        else
            return error.InvalidPem;
        const end_marker = switch (label) {
            .sec1 => "-----END EC PRIVATE KEY-----",
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

fn parsePrivateKeyDer(label: PemLabel, der: []const u8) Error![32]u8 {
    if (der.len == 0 or der.len > max_private_key_der_bytes) {
        return error.InvalidPrivateKey;
    }
    return switch (label) {
        .sec1 => parseSec1PrivateKey(der, true),
        .pkcs8 => parsePkcs8PrivateKey(der),
    };
}

fn parsePkcs8PrivateKey(der: []const u8) Error![32]u8 {
    var outer = DerReader{ .bytes = der };
    const sequence = try outer.read(0x30);
    if (!outer.done()) return error.InvalidPrivateKey;
    var fields = DerReader{ .bytes = sequence };
    if (!std.mem.eql(u8, try fields.read(0x02), &.{0x00})) {
        return error.InvalidPrivateKey;
    }
    const algorithm = try fields.read(0x30);
    var algorithm_fields = DerReader{ .bytes = algorithm };
    if (!std.mem.eql(u8, try algorithm_fields.read(0x06), &oid_ec_public_key) or
        !std.mem.eql(u8, try algorithm_fields.read(0x06), &oid_prime256v1) or
        !algorithm_fields.done())
    {
        return error.InvalidPrivateKey;
    }
    const inner = try fields.read(0x04);
    if (!fields.done()) return error.InvalidPrivateKey;
    return parseSec1PrivateKey(inner, false);
}

fn parseSec1PrivateKey(
    der: []const u8,
    require_parameters: bool,
) Error![32]u8 {
    var outer = DerReader{ .bytes = der };
    const sequence = try outer.read(0x30);
    if (!outer.done()) return error.InvalidPrivateKey;
    var fields = DerReader{ .bytes = sequence };
    if (!std.mem.eql(u8, try fields.read(0x02), &.{0x01})) {
        return error.InvalidPrivateKey;
    }
    const private_key = try fields.read(0x04);
    if (private_key.len != 32) return error.InvalidPrivateKey;
    var scalar: [32]u8 = undefined;
    @memcpy(&scalar, private_key);
    errdefer std.crypto.secureZero(u8, &scalar);

    var has_parameters = false;
    if (!fields.done() and fields.bytes[fields.offset] == 0xa0) {
        const parameters = try fields.read(0xa0);
        var parameter_fields = DerReader{ .bytes = parameters };
        if (!std.mem.eql(
            u8,
            try parameter_fields.read(0x06),
            &oid_prime256v1,
        ) or !parameter_fields.done()) {
            return error.InvalidPrivateKey;
        }
        has_parameters = true;
    }
    if (require_parameters and !has_parameters) return error.InvalidPrivateKey;

    var encoded_public_key: ?[65]u8 = null;
    if (!fields.done() and fields.bytes[fields.offset] == 0xa1) {
        const public_wrapper = try fields.read(0xa1);
        var public_fields = DerReader{ .bytes = public_wrapper };
        const bit_string = try public_fields.read(0x03);
        if (!public_fields.done() or bit_string.len != 66 or
            bit_string[0] != 0)
        {
            return error.InvalidPrivateKey;
        }
        var public_key: [65]u8 = undefined;
        @memcpy(&public_key, bit_string[1..]);
        encoded_public_key = public_key;
    }
    if (!fields.done()) return error.InvalidPrivateKey;

    if (encoded_public_key) |encoded| {
        const secret = EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch {
            return error.InvalidPrivateKey;
        };
        const pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch {
            return error.InvalidPrivateKey;
        };
        if (!std.mem.eql(
            u8,
            &encoded,
            &pair.public_key.toUncompressedSec1(),
        )) {
            return error.InvalidPrivateKey;
        }
    }
    return scalar;
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
    _ = try parsePrivateKeyDer(.sec1, &valid_sec1);

    var wrong_curve = valid_sec1;
    wrong_curve[wrong_curve.len - 1] = 0x08;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(.sec1, &wrong_curve),
    );

    const trailing = valid_sec1 ++ .{0x00};
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(.sec1, &trailing),
    );

    const non_canonical_length = [_]u8{ 0x30, 0x81, 0x31 } ++
        valid_sec1[2..].*;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(.sec1, &non_canonical_length),
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
    const encoded_len = std.base64.standard.Encoder.calcSize(der.len);
    const prefix = "-----BEGIN EC PRIVATE KEY-----\n";
    const suffix = "\n-----END EC PRIVATE KEY-----\n";
    const pem = try allocator.alloc(u8, prefix.len + encoded_len + suffix.len);
    @memcpy(pem[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(
        pem[prefix.len..][0..encoded_len],
        der,
    );
    @memcpy(pem[prefix.len + encoded_len ..], suffix);
    return pem;
}
