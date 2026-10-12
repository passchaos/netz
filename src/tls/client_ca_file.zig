//! Strict owned CA bundles for TLS client-certificate authentication.
//!
//! Every trust anchor must be a currently valid CA for the clientAuth purpose.
//! Additional non-CA certificates are retained only when they are valid CRL
//! signers, and are never advertised in CertificateRequest or trusted as
//! client-certificate issuers.

const std = @import("std");
const vail = @import("vail");

const Certificate = std.crypto.Certificate;

pub const max_file_bytes: usize = 4 * 1024 * 1024;
pub const max_certificates: usize = 64;
pub const max_certificate_der_bytes: usize = 1024 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    EmptyCertificateFile,
    TooManyCertificates,
    CertificateTooLarge,
    CertificateAuthoritiesTooLarge,
    InvalidPem,
    InvalidCertificateAuthority,
    DuplicateCertificateAuthority,
};

pub const File = struct {
    allocator: std.mem.Allocator,
    certificates: [][]const u8,
    crl_signers: [][]const u8 = &.{},
    certificate_authorities: [][]const u8,
    bundle: Certificate.Bundle,

    pub fn deinit(self: *File) void {
        self.bundle.deinit(self.allocator);
        self.allocator.free(self.certificate_authorities);
        for (self.certificates) |certificate| {
            self.allocator.free(@constCast(certificate));
        }
        self.allocator.free(self.certificates);
        for (self.crl_signers) |certificate| {
            self.allocator.free(@constCast(certificate));
        }
        self.allocator.free(self.crl_signers);
        self.* = undefined;
    }

    pub fn verifier(
        self: *const File,
        now_seconds: i64,
    ) vail.x509.trust.ClientCertificateBundleVerifier {
        return .{
            .bundle = &self.bundle,
            .now_seconds = now_seconds,
        };
    }

    pub fn authorities(self: *const File) []const []const u8 {
        return self.certificate_authorities;
    }

    /// Append the validated DER certificates to another trust bundle. The
    /// destination owns its copies; this File remains independently owned.
    pub fn appendToBundle(
        self: *const File,
        allocator: std.mem.Allocator,
        destination: *Certificate.Bundle,
        now_seconds: i64,
    ) Certificate.Bundle.ParseCertError!void {
        for (self.certificates) |certificate| {
            const start = destination.bytes.items.len;
            try destination.bytes.appendSlice(allocator, certificate);
            destination.parseCert(
                allocator,
                @intCast(start),
                now_seconds,
            ) catch |err| {
                destination.bytes.items.len = start;
                return err;
            };
        }
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || std.Io.Dir.ReadFileAllocError)!File {
    const source = try dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        .limited(max_file_bytes + 1),
    );
    defer allocator.free(source);
    if (source.len > max_file_bytes) return error.CertificateTooLarge;
    return parse(
        allocator,
        source,
        std.Io.Timestamp.now(io, .real).toSeconds(),
    );
}

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    now_seconds: i64,
) Error!File {
    if (source.len > max_file_bytes) return error.CertificateTooLarge;

    var certificates: std.ArrayList([]const u8) = .empty;
    defer certificates.deinit(allocator);
    errdefer for (certificates.items) |certificate| {
        allocator.free(@constCast(certificate));
    };
    var crl_signers: std.ArrayList([]const u8) = .empty;
    defer crl_signers.deinit(allocator);
    errdefer for (crl_signers.items) |certificate| {
        allocator.free(@constCast(certificate));
    };
    var authorities: std.ArrayList([]const u8) = .empty;
    defer authorities.deinit(allocator);
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    var authorities_wire_bytes: usize = 0;

    var offset: usize = 0;
    while (nextLine(source, &offset)) |line| {
        if (line.bytes.len == 0) continue;
        if (!std.mem.eql(
            u8,
            line.bytes,
            "-----BEGIN CERTIFICATE-----",
        )) return error.InvalidPem;
        const body_start = line.next;
        var body_end: ?usize = null;
        while (nextLine(source, &offset)) |body_line| {
            if (std.mem.eql(
                u8,
                body_line.bytes,
                "-----END CERTIFICATE-----",
            )) {
                body_end = body_line.start;
                break;
            }
            if (std.mem.startsWith(u8, body_line.bytes, "-----")) {
                return error.InvalidPem;
            }
        }
        const encoded_end = body_end orelse return error.InvalidPem;
        if (certificates.items.len + crl_signers.items.len == max_certificates) {
            return error.TooManyCertificates;
        }
        const certificate = try decodePemBody(
            allocator,
            source[body_start..encoded_end],
        );
        errdefer allocator.free(certificate);
        const parsed = parseCertificate(certificate) catch
            return error.InvalidCertificateAuthority;
        const is_client_ca = blk: {
            vail.x509.trust.validateClientCertificateAuthority(
                certificate,
                now_seconds,
            ) catch break :blk false;
            break :blk true;
        };
        if (!is_client_ca) vail.x509.trust.validateCertificateRevocationListSigner(
            certificate,
            now_seconds,
        ) catch return error.InvalidCertificateAuthority;
        for (certificates.items) |existing| {
            const existing_parsed = parseCertificate(existing) catch
                unreachable;
            if (std.mem.eql(
                u8,
                existing_parsed.subject(),
                parsed.subject(),
            )) return error.DuplicateCertificateAuthority;
        }
        for (crl_signers.items) |existing| {
            const existing_parsed = parseCertificate(existing) catch
                unreachable;
            if (std.mem.eql(
                u8,
                existing_parsed.subject(),
                parsed.subject(),
            )) return error.DuplicateCertificateAuthority;
        }
        if (!is_client_ca) {
            try crl_signers.append(allocator, certificate);
            continue;
        }
        const authority = fullSubjectName(certificate) catch
            return error.InvalidCertificateAuthority;
        if (authority.len == 0 or authority.len > std.math.maxInt(u16)) {
            return error.CertificateAuthoritiesTooLarge;
        }
        authorities_wire_bytes = std.math.add(
            usize,
            authorities_wire_bytes,
            2 + authority.len,
        ) catch return error.CertificateAuthoritiesTooLarge;
        if (authorities_wire_bytes > std.math.maxInt(u16)) {
            return error.CertificateAuthoritiesTooLarge;
        }

        const bundle_start = bundle.bytes.items.len;
        try bundle.bytes.appendSlice(allocator, certificate);
        bundle.parseCert(
            allocator,
            @intCast(bundle_start),
            now_seconds,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidCertificateAuthority,
        };
        if (bundle.bytes.items.len == bundle_start) {
            return error.InvalidCertificateAuthority;
        }
        try certificates.append(allocator, certificate);
        errdefer _ = certificates.pop();
        try authorities.append(allocator, authority);
    }
    if (certificates.items.len == 0) return error.EmptyCertificateFile;

    const owned_certificates = try certificates.toOwnedSlice(allocator);
    errdefer {
        for (owned_certificates) |certificate| {
            allocator.free(@constCast(certificate));
        }
        allocator.free(owned_certificates);
    }
    const owned_crl_signers = try crl_signers.toOwnedSlice(allocator);
    errdefer {
        for (owned_crl_signers) |certificate| {
            allocator.free(@constCast(certificate));
        }
        allocator.free(owned_crl_signers);
    }
    const owned_authorities = try authorities.toOwnedSlice(allocator);
    errdefer allocator.free(owned_authorities);
    return .{
        .allocator = allocator,
        .certificates = owned_certificates,
        .crl_signers = owned_crl_signers,
        .certificate_authorities = owned_authorities,
        .bundle = bundle,
    };
}

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

fn decodePemBody(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) Error![]u8 {
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(allocator);
    for (encoded) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => try compact.append(allocator, byte),
    };
    if (compact.items.len == 0) return error.InvalidPem;
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(
        compact.items,
    ) catch return error.InvalidPem;
    if (decoded_len == 0) return error.InvalidPem;
    if (decoded_len > max_certificate_der_bytes) {
        return error.CertificateTooLarge;
    }
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, compact.items) catch
        return error.InvalidPem;
    return decoded;
}

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    var reader = DerReader{ .bytes = der };
    _ = try reader.read(0x30);
    if (!reader.done()) return error.InvalidDer;
    return Certificate.parse(.{ .buffer = der, .index = 0 });
}

fn fullSubjectName(der: []const u8) ![]const u8 {
    var top = DerReader{ .bytes = der };
    const certificate = try top.read(0x30);
    if (!top.done()) return error.InvalidDer;
    var certificate_fields = DerReader{ .bytes = certificate.value };
    const tbs = try certificate_fields.read(0x30);
    var fields = DerReader{ .bytes = tbs.value };
    var first = try fields.readAny();
    if (first.tag == 0xa0) first = try fields.read(0x02);
    if (first.tag != 0x02) return error.InvalidDer;
    _ = try fields.read(0x30);
    _ = try fields.read(0x30);
    _ = try fields.read(0x30);
    const subject = try fields.read(0x30);
    return tbs.value[subject.start..subject.end];
}

const Element = struct {
    tag: u8,
    start: usize,
    end: usize,
    value: []const u8,
};

const DerReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn read(self: *DerReader, expected_tag: u8) !Element {
        const element = try self.readAny();
        if (element.tag != expected_tag) return error.InvalidDer;
        return element;
    }

    fn readAny(self: *DerReader) !Element {
        if (self.offset + 2 > self.bytes.len) return error.InvalidDer;
        const start = self.offset;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        if ((tag & 0x1f) == 0x1f) return error.InvalidDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidDer;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidDer;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidDer;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidDer;
        }
        if (length > self.bytes.len - self.offset) return error.InvalidDer;
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return .{
            .tag = tag,
            .start = start,
            .end = self.offset,
            .value = value,
        };
    }

    fn done(self: DerReader) bool {
        return self.offset == self.bytes.len;
    }
};

const ca_pem =
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

const leaf_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBgzCCASqgAwIBAgIJAMklErU+FL04MAoGCCqGSM49BAMCMB4xHDAaBgNVBAMM
    \\E3F1aWMtemlnIGludGVyb3AgQ0EwHhcNMjYwMzEyMTUzMzM1WhcNMzYwMzA5MTUz
    \\MzM1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
    \\BwNCAARTMns09goeQ3p8Ws6i8oCqHHbbt+czZfUUMjWDVoO93AlWvUHu9HLTNQ7W
    \\BWRA8kZ6cncadFzlVtUZYeZHFG6fo1swWTA/BgNVHREEODA2gglsb2NhbGhvc3SC
    \\B3NlcnZlcjSCCHNlcnZlcjQ2hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMAkGA1Ud
    \\EwQCMAAwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA0cAMEQCIFKWL/UrEDzNdWCZ
    \\5us833b7ESITAHSb6bJFu6ZppJsGAiBgalDEBhK/fbDti9LZuhvEqIZlLBuFCYGJ
    \\jU0l+QUuXQ==
    \\-----END CERTIFICATE-----
;

test "client CA file owns trust bundle and DER authority names" {
    var file = try parse(std.testing.allocator, ca_pem, 1_900_000_000);
    defer file.deinit();
    try std.testing.expectEqual(@as(usize, 1), file.certificates.len);
    try std.testing.expectEqual(@as(usize, 1), file.authorities().len);
    try std.testing.expectEqual(@as(u8, 0x30), file.authorities()[0][0]);
    const parsed = try parseCertificate(file.certificates[0]);
    try std.testing.expectEqualStrings(
        parsed.subject(),
        file.authorities()[0][2..],
    );
    var verifier = file.verifier(1_900_000_000);
    _ = verifier.clientVerifier();
}

test "client CA file appends owned certificates to a server trust bundle" {
    const allocator = std.testing.allocator;
    var file = try parse(allocator, ca_pem, 1_900_000_000);
    defer file.deinit();
    var destination: Certificate.Bundle = .empty;
    defer destination.deinit(allocator);
    try file.appendToBundle(allocator, &destination, 1_900_000_000);
    try std.testing.expectEqual(@as(usize, 1), destination.map.count());
    const bytes_after_first = destination.bytes.items.len;
    try file.appendToBundle(allocator, &destination, 1_900_000_000);
    try std.testing.expectEqual(@as(usize, 1), destination.map.count());
    try std.testing.expectEqual(bytes_after_first, destination.bytes.items.len);
}

test "client CA file rejects non-CA, duplicate, and malformed input" {
    try std.testing.expectError(
        error.InvalidCertificateAuthority,
        parse(std.testing.allocator, leaf_pem, 1_900_000_000),
    );
    try std.testing.expectError(
        error.DuplicateCertificateAuthority,
        parse(
            std.testing.allocator,
            ca_pem ++ "\n" ++ ca_pem,
            1_900_000_000,
        ),
    );
    try std.testing.expectError(
        error.EmptyCertificateFile,
        parse(std.testing.allocator, "", 1_900_000_000),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(
            std.testing.allocator,
            "-----BEGIN CERTIFICATE-----\nAA==\n",
            1_900_000_000,
        ),
    );
}

test "client CA file loads from a bounded file" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "clients.pem", .data = ca_pem });
    var file = try load(
        std.testing.allocator,
        io,
        tmp.dir,
        "clients.pem",
    );
    defer file.deinit();
    try std.testing.expectEqual(@as(usize, 1), file.certificates.len);
}
