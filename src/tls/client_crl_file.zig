//! Strict owned CRL bundles for TLS client-certificate authentication.
//!
//! Each PEM CRL must be signed by exactly one CA in the configured client CA
//! file. The composite verifier first validates the client chain and then
//! requires a matching CRL for the leaf issuer before checking its serial.

const std = @import("std");
const vail = @import("vail");
const client_ca_file = @import("client_ca_file.zig");

pub const max_file_bytes: usize = 4 * 1024 * 1024;
pub const max_crls: usize = 64;
pub const max_crl_der_bytes: usize = 1024 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    EmptyCrlFile,
    TooManyCrls,
    CrlTooLarge,
    InvalidPem,
    InvalidCrl,
    MissingCrlIssuer,
    DuplicateCrlIssuer,
    CrlNotFound,
    CertificateRevoked,
};

pub const File = struct {
    allocator: std.mem.Allocator,
    sources: [][]u8,
    lists: []vail.x509.crl.List,

    pub fn deinit(self: *File) void {
        self.allocator.free(self.lists);
        for (self.sources) |source| self.allocator.free(source);
        self.allocator.free(self.sources);
        self.* = undefined;
    }

    pub fn verifyLeaf(self: File, certificate_der: []const u8) Error!void {
        for (self.lists) |list| {
            const revoked = list.isRevoked(certificate_der) catch |err| switch (err) {
                error.IssuerMismatch => continue,
                else => return error.InvalidCrl,
            };
            if (revoked) return error.CertificateRevoked;
            return;
        }
        return error.CrlNotFound;
    }
};

pub const Verifier = struct {
    trust: vail.x509.trust.ClientCertificateBundleVerifier,
    crls: *const File,

    pub fn clientVerifier(self: *const Verifier) vail.tls.auth.ClientVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: Verifier,
        context: vail.tls.auth.TrustContext,
    ) !void {
        try self.trust.verify(context);
        if (context.chain.len == 0) return error.CrlNotFound;
        try self.crls.verifyLeaf(context.chain[0]);
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: vail.tls.auth.TrustContext,
    ) anyerror!void {
        const self: *const Verifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verify(trust_context);
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    client_cas: *const client_ca_file.File,
) (Error || std.Io.Dir.ReadFileAllocError)!File {
    const source = try dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        .limited(max_file_bytes + 1),
    );
    defer allocator.free(source);
    if (source.len > max_file_bytes) return error.CrlTooLarge;
    return parse(
        allocator,
        source,
        client_cas,
        std.Io.Timestamp.now(io, .real).toSeconds(),
    );
}

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    client_cas: *const client_ca_file.File,
    now_seconds: i64,
) Error!File {
    if (source.len > max_file_bytes) return error.CrlTooLarge;
    var sources: std.ArrayList([]u8) = .empty;
    defer sources.deinit(allocator);
    errdefer for (sources.items) |crl| allocator.free(crl);
    var lists: std.ArrayList(vail.x509.crl.List) = .empty;
    defer lists.deinit(allocator);

    var offset: usize = 0;
    while (nextLine(source, &offset)) |line| {
        if (line.bytes.len == 0) continue;
        if (!std.mem.eql(u8, line.bytes, "-----BEGIN X509 CRL-----")) {
            return error.InvalidPem;
        }
        const body_start = line.next;
        var body_end: ?usize = null;
        while (nextLine(source, &offset)) |body_line| {
            if (std.mem.eql(
                u8,
                body_line.bytes,
                "-----END X509 CRL-----",
            )) {
                body_end = body_line.start;
                break;
            }
            if (std.mem.startsWith(u8, body_line.bytes, "-----")) {
                return error.InvalidPem;
            }
        }
        const encoded_end = body_end orelse return error.InvalidPem;
        if (sources.items.len == max_crls) return error.TooManyCrls;
        const crl_der = try decodePemBody(
            allocator,
            source[body_start..encoded_end],
        );
        errdefer allocator.free(crl_der);

        var matched: ?vail.x509.crl.List = null;
        for (client_cas.certificates) |ca_der| {
            const candidate = vail.x509.crl.parseAndVerify(
                crl_der,
                ca_der,
                now_seconds,
            ) catch |err| switch (err) {
                error.IssuerMismatch => continue,
                else => return error.InvalidCrl,
            };
            if (matched != null) return error.DuplicateCrlIssuer;
            matched = candidate;
        }
        const list = matched orelse return error.MissingCrlIssuer;
        for (lists.items) |existing| {
            if (std.mem.eql(
                u8,
                existing.issuer_name,
                list.issuer_name,
            )) return error.DuplicateCrlIssuer;
        }
        try sources.append(allocator, crl_der);
        errdefer _ = sources.pop();
        try lists.append(allocator, list);
    }
    if (sources.items.len == 0) return error.EmptyCrlFile;

    const owned_sources = try sources.toOwnedSlice(allocator);
    errdefer {
        for (owned_sources) |crl| allocator.free(crl);
        allocator.free(owned_sources);
    }
    const owned_lists = try lists.toOwnedSlice(allocator);
    errdefer allocator.free(owned_lists);
    return .{
        .allocator = allocator,
        .sources = owned_sources,
        .lists = owned_lists,
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
    if (decoded_len > max_crl_der_bytes) return error.CrlTooLarge;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, compact.items) catch
        return error.InvalidPem;
    return decoded;
}

const ca_pem =
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

const crl_pem =
    \\-----BEGIN X509 CRL-----
    \\MIHUMH0CAQEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRlc3QgUm9vdBcN
    \\MjYwOTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjAjMCECAhACFw0yNjA5MjIxOTAy
    \\MzFaMAwwCgYDVR0VBAMKAQGgDzANMAsGA1UdFAQEAgIQADAKBggqhkjOPQQDAgNH
    \\ADBEAiAcMtii8815JG7qfPRtjkJKxxWmrCnIW01AFwAjEEgkqgIgJNMKp1VLVy22
    \\tfQaelszInC3rbiKsCifZE4eYEmms/8=
    \\-----END X509 CRL-----
;

const good_base64 =
    "MIIBlDCCATmgAwIBAgICEAEwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBYxFDASBgNV" ++
    "BAMMC2dvb2QtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWQ6bctG2" ++
    "c8QseTp/gBMXYeuqnNYn7TiCJr9E9+os+4kuiZ+AdSqPsorbp/VAONrhbjkyYwTy" ++
    "4iqeZEYmjy4h7KN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYD" ++
    "VR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFPbNjkXzEROtcFB/jpriCQRx5Xd+" ++
    "MB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMCA0kA" ++
    "MEYCIQDS2PsKUe7bgIU6ktMWa9J7z/dRt8ZskJT+QzggaiZ0hQIhAIuXlBXP0iGg" ++
    "W3MfGt8dY47up1C9sqSmlxMxpWG0tkKG";
const revoked_base64 =
    "MIIBlzCCATygAwIBAgICEAIwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ1JMIFRl" ++
    "c3QgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMBkxFzAVBgNV" ++
    "BAMMDnJldm9rZWQtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfOEs" ++
    "A83kNW0KeINCBpHrxhJW07yht+u4R+h/mriq0ohvAqq4xo+CYuPNYfVM8uDEpvFa" ++
    "W0mHf5ffORS3zcXFWKN1MHMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4Aw" ++
    "EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHjbxgNaDfc+edyrH/FcgLXx" ++
    "lJnWMB8GA1UdIwQYMBaAFOGPPCJNPdhRl5z40kmuxl5bTj40MAoGCCqGSM49BAMC" ++
    "A0kAMEYCIQDmRnZBG6KpALNt5yfzutiD3wy4zU88qgI87M3csPE2pQIhAIk+S4vd" ++
    "vM8Mlu1nZe4M0YkCWi7omb60P32wFmllWa63";

fn decodeFixture(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    return decoded;
}

test "client CRL file verifies trusted and revoked leaves" {
    const allocator = std.testing.allocator;
    var cas = try client_ca_file.parse(allocator, ca_pem, 1_800_000_000);
    defer cas.deinit();
    var crls = try parse(allocator, crl_pem, &cas, 1_800_000_000);
    defer crls.deinit();
    const good = try decodeFixture(allocator, good_base64);
    defer allocator.free(good);
    const revoked = try decodeFixture(allocator, revoked_base64);
    defer allocator.free(revoked);

    try crls.verifyLeaf(good);
    try std.testing.expectError(
        error.CertificateRevoked,
        crls.verifyLeaf(revoked),
    );
    var verifier = Verifier{
        .trust = cas.verifier(1_800_000_000),
        .crls = &crls,
    };
    try verifier.verify(.{ .server_name = null, .chain = &.{good} });
    try std.testing.expectError(
        error.CertificateRevoked,
        verifier.verify(.{ .server_name = null, .chain = &.{revoked} }),
    );
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.clientVerifier().verifyTrust(null, &.{revoked}),
    );
}

test "client CRL file rejects duplicate and malformed lists" {
    const allocator = std.testing.allocator;
    var cas = try client_ca_file.parse(allocator, ca_pem, 1_800_000_000);
    defer cas.deinit();
    try std.testing.expectError(
        error.DuplicateCrlIssuer,
        parse(allocator, crl_pem ++ "\n" ++ crl_pem, &cas, 1_800_000_000),
    );
    try std.testing.expectError(
        error.EmptyCrlFile,
        parse(allocator, "", &cas, 1_800_000_000),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(
            allocator,
            "-----BEGIN X509 CRL-----\nAA==\n",
            &cas,
            1_800_000_000,
        ),
    );
}
