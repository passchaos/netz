//! Strict owned CRL bundles for TLS client-certificate authentication.
//!
//! Each PEM CRL must be signed by exactly one CA in the configured client CA
//! file. Complete lists may be followed by one or more compatible delta CRLs;
//! the newest delta is combined with its base before the client leaf is
//! checked. Directly signed indirect CRLs are authorized against their target
//! CA and still require the leaf's cRLIssuer distribution-point binding. The
//! composite verifier first validates the client chain and then requires
//! complete revocation coverage for the leaf issuer.

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
    DuplicateCrlNumber,
    MissingBaseCrl,
    CrlNotFound,
    CertificateRevoked,
};

pub const File = struct {
    allocator: std.mem.Allocator,
    sources: [][]u8,
    lists: []vail.x509.crl.List,
    combined_lists: []vail.x509.crl.CombinedList,
    indirect_lists: []vail.x509.crl.AuthorizedIndirectList,
    indirect_combined_lists: []vail.x509.crl.AuthorizedIndirectCombinedList,

    pub fn deinit(self: *File) void {
        self.allocator.free(self.indirect_combined_lists);
        self.allocator.free(self.indirect_lists);
        self.allocator.free(self.combined_lists);
        self.allocator.free(self.lists);
        for (self.sources) |source| self.allocator.free(source);
        self.allocator.free(self.sources);
        self.* = undefined;
    }

    pub fn verifyLeaf(
        self: *const File,
        certificate_der: []const u8,
    ) Error!void {
        const certificate = std.crypto.Certificate.parse(.{
            .buffer = certificate_der,
            .index = 0,
        }) catch return error.InvalidCrl;
        const verified = vail.x509.crl.VerifiedSet{
            .lists = self.lists,
            .combined_lists = self.combined_lists,
            .indirect_lists = self.indirect_lists,
            .indirect_combined_lists = self.indirect_combined_lists,
        };
        for (self.lists) |list| {
            // Every accepted delta has a matching complete list. Trying one
            // issuer certificate per complete list lets VerifiedSet enforce
            // the matching scope and apply the newest compatible delta.
            if (list.isDelta() or list.isIndirect()) continue;
            if (try verifyForIssuer(
                &verified,
                certificate_der,
                list.issuer_certificate_der,
            )) return;
        }
        for (self.indirect_combined_lists) |authorized| {
            if (!certificateIssuerMatches(
                certificate,
                authorized.certificate_issuer_der,
            )) continue;
            if (try verifyForIssuer(
                &verified,
                certificate_der,
                authorized.certificate_issuer_der,
            )) return;
        }
        for (self.indirect_lists) |authorized| {
            if (!certificateIssuerMatches(
                certificate,
                authorized.certificate_issuer_der,
            )) continue;
            if (try verifyForIssuer(
                &verified,
                certificate_der,
                authorized.certificate_issuer_der,
            )) return;
        }
        return error.CrlNotFound;
    }
};

fn verifyForIssuer(
    verified: *const vail.x509.crl.VerifiedSet,
    certificate_der: []const u8,
    issuer_der: []const u8,
) Error!bool {
    verified.policy(true).verify(
        certificate_der,
        issuer_der,
    ) catch |err| switch (err) {
        error.CertificateRevocationStatusUnavailable => return false,
        error.CertificateRevoked => return error.CertificateRevoked,
        else => return error.InvalidCrl,
    };
    return true;
}

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

fn certificateIssuerMatches(
    certificate: std.crypto.Certificate.Parsed,
    issuer_der: []const u8,
) bool {
    const issuer = std.crypto.Certificate.parse(.{
        .buffer = issuer_der,
        .index = 0,
    }) catch return false;
    return vail.x509.distinguished_name.eql(
        certificate.issuer(),
        issuer.subject(),
    ) catch false;
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
            if (!std.mem.eql(
                u8,
                existing.issuer_certificate_der,
                list.issuer_certificate_der,
            )) continue;
            if (!sameScope(existing, list)) continue;
            if (!existing.isDelta() and !list.isDelta()) {
                return error.DuplicateCrlIssuer;
            }
            if (existing.isDelta() and list.isDelta() and
                std.mem.eql(
                    u8,
                    existing.crl_number orelse return error.InvalidCrl,
                    list.crl_number orelse return error.InvalidCrl,
                ))
            {
                return error.DuplicateCrlNumber;
            }
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
    const combined_lists = try combineDeltaCrls(allocator, owned_lists);
    errdefer allocator.free(combined_lists);
    const indirect_lists = try authorizeIndirectLists(
        allocator,
        owned_lists,
        combined_lists,
        client_cas.certificates,
        now_seconds,
    );
    errdefer allocator.free(indirect_lists);
    const indirect_combined_lists = try authorizeIndirectCombinedLists(
        allocator,
        combined_lists,
        client_cas.certificates,
        now_seconds,
    );
    errdefer allocator.free(indirect_combined_lists);
    return .{
        .allocator = allocator,
        .sources = owned_sources,
        .lists = owned_lists,
        .combined_lists = combined_lists,
        .indirect_lists = indirect_lists,
        .indirect_combined_lists = indirect_combined_lists,
    };
}

fn authorizeIndirectLists(
    allocator: std.mem.Allocator,
    lists: []const vail.x509.crl.List,
    combined_lists: []const vail.x509.crl.CombinedList,
    certificate_issuers: []const []const u8,
    now_seconds: i64,
) Error![]vail.x509.crl.AuthorizedIndirectList {
    var authorized: std.ArrayList(
        vail.x509.crl.AuthorizedIndirectList,
    ) = .empty;
    defer authorized.deinit(allocator);
    for (lists) |list| {
        if (!list.isIndirect() or list.isDelta() or
            isCombinedBase(combined_lists, list)) continue;
        var matched = false;
        for (certificate_issuers) |issuer| {
            const candidate = vail.x509.crl.AuthorizedIndirectList.init(
                list,
                issuer,
                now_seconds,
            ) catch |err| switch (err) {
                error.InvalidIssuer => continue,
                else => return error.InvalidCrl,
            };
            try authorized.append(allocator, candidate);
            matched = true;
        }
        if (!matched) return error.MissingCrlIssuer;
    }
    return authorized.toOwnedSlice(allocator);
}

fn authorizeIndirectCombinedLists(
    allocator: std.mem.Allocator,
    combined_lists: []const vail.x509.crl.CombinedList,
    certificate_issuers: []const []const u8,
    now_seconds: i64,
) Error![]vail.x509.crl.AuthorizedIndirectCombinedList {
    var authorized: std.ArrayList(
        vail.x509.crl.AuthorizedIndirectCombinedList,
    ) = .empty;
    defer authorized.deinit(allocator);
    for (combined_lists) |combined| {
        if (!combined.base.isIndirect()) continue;
        var matched = false;
        for (certificate_issuers) |issuer| {
            const candidate =
                vail.x509.crl.AuthorizedIndirectCombinedList.init(
                    combined,
                    issuer,
                    now_seconds,
                ) catch |err| switch (err) {
                    error.InvalidIssuer => continue,
                    else => return error.InvalidCrl,
                };
            try authorized.append(allocator, candidate);
            matched = true;
        }
        if (!matched) return error.MissingCrlIssuer;
    }
    return authorized.toOwnedSlice(allocator);
}

fn isCombinedBase(
    combined_lists: []const vail.x509.crl.CombinedList,
    list: vail.x509.crl.List,
) bool {
    for (combined_lists) |combined| {
        if (combined.base.der.ptr == list.der.ptr and
            combined.base.der.len == list.der.len) return true;
    }
    return false;
}

fn sameScope(
    a: vail.x509.crl.List,
    b: vail.x509.crl.List,
) bool {
    const a_scope = if (a.issuing_distribution_point) |point|
        point.encoded
    else
        null;
    const b_scope = if (b.issuing_distribution_point) |point|
        point.encoded
    else
        null;
    if (a_scope == null or b_scope == null) return a_scope == null and
        b_scope == null;
    return std.mem.eql(u8, a_scope.?, b_scope.?);
}

fn combineDeltaCrls(
    allocator: std.mem.Allocator,
    lists: []const vail.x509.crl.List,
) Error![]vail.x509.crl.CombinedList {
    var combined_lists: std.ArrayList(vail.x509.crl.CombinedList) = .empty;
    defer combined_lists.deinit(allocator);
    var matched_deltas = [_]bool{false} ** max_crls;

    for (lists) |base| {
        if (base.isDelta()) continue;
        var newest: ?vail.x509.crl.CombinedList = null;
        for (lists, 0..) |delta, delta_index| {
            if (!delta.isDelta()) continue;
            const combined = vail.x509.crl.CombinedList.init(
                base,
                delta,
            ) catch |err| switch (err) {
                error.InvalidDeltaCrl, error.CrlScopeMismatch => continue,
                else => return error.InvalidCrl,
            };
            matched_deltas[delta_index] = true;
            if (newest == null or deltaIsNewer(
                combined.delta,
                newest.?.delta,
            )) newest = combined;
        }
        if (newest) |combined| {
            try combined_lists.append(allocator, combined);
        }
    }
    for (lists, 0..) |list, index| {
        if (list.isDelta() and !matched_deltas[index]) {
            return error.MissingBaseCrl;
        }
    }
    return combined_lists.toOwnedSlice(allocator);
}

fn deltaIsNewer(
    candidate: vail.x509.crl.List,
    current: vail.x509.crl.List,
) bool {
    if (candidate.this_update != current.this_update) {
        return candidate.this_update > current.this_update;
    }
    return compareUnsigned(
        candidate.crl_number orelse return false,
        current.crl_number orelse return true,
    ) == .gt;
}

fn compareUnsigned(a_encoded: []const u8, b_encoded: []const u8) std.math.Order {
    const a = if (a_encoded.len > 1 and a_encoded[0] == 0)
        a_encoded[1..]
    else
        a_encoded;
    const b = if (b_encoded.len > 1 and b_encoded[0] == 0)
        b_encoded[1..]
    else
        b_encoded;
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return std.mem.order(u8, a, b);
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

fn decodeHexFixture(comptime encoded: []const u8) [encoded.len / 2]u8 {
    var decoded: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch unreachable;
    return decoded;
}

fn encodePemForTest(
    allocator: std.mem.Allocator,
    label: []const u8,
    der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(der.len);
    const prefix = "-----BEGIN ";
    const middle = "-----\n";
    const suffix_prefix = "\n-----END ";
    const suffix = "-----\n";
    const pem = try allocator.alloc(
        u8,
        prefix.len + label.len + middle.len + encoded_len +
            suffix_prefix.len + label.len + suffix.len,
    );
    var offset: usize = 0;
    @memcpy(pem[offset..][0..prefix.len], prefix);
    offset += prefix.len;
    @memcpy(pem[offset..][0..label.len], label);
    offset += label.len;
    @memcpy(pem[offset..][0..middle.len], middle);
    offset += middle.len;
    _ = std.base64.standard.Encoder.encode(
        pem[offset..][0..encoded_len],
        der,
    );
    offset += encoded_len;
    @memcpy(pem[offset..][0..suffix_prefix.len], suffix_prefix);
    offset += suffix_prefix.len;
    @memcpy(pem[offset..][0..label.len], label);
    offset += label.len;
    @memcpy(pem[offset..][0..suffix.len], suffix);
    return pem;
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

test "client CRL file applies a direct delta over its base" {
    const allocator = std.testing.allocator;
    const vectors = vail.x509.testing.path_vectors;
    const now = 1_790_844_200;
    const ca_der = decodeHexFixture(vectors.delta_crl_ca_hex);
    const held = decodeHexFixture(vectors.delta_crl_held_hex);
    const added = decodeHexFixture(vectors.delta_crl_added_hex);
    const clean = decodeHexFixture(vectors.delta_crl_clean_hex);
    const base_der = decodeHexFixture(vectors.delta_crl_base_hex);
    const delta_der = decodeHexFixture(vectors.delta_crl_delta_hex);
    const indirect_der = decodeHexFixture(vectors.delta_crl_indirect_hex);
    const indirect_target = decodeHexFixture(
        vectors.delta_crl_indirect_target_hex,
    );
    const indirect_authorized_der = decodeHexFixture(
        vectors.delta_crl_indirect_authorized_hex,
    );
    const delegated_der = decodeHexFixture(
        vectors.indirect_crl_delegate_crl_hex,
    );

    const ca_source = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        &ca_der,
    );
    defer allocator.free(ca_source);
    var cas = try client_ca_file.parse(allocator, ca_source, now);
    defer cas.deinit();

    const base_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &base_der,
    );
    defer allocator.free(base_source);
    const delta_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &delta_der,
    );
    defer allocator.free(delta_source);
    const indirect_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &indirect_der,
    );
    defer allocator.free(indirect_source);
    const indirect_authorized_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &indirect_authorized_der,
    );
    defer allocator.free(indirect_authorized_source);
    const delegated_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &delegated_der,
    );
    defer allocator.free(delegated_source);
    const crl_source = try std.mem.concat(
        allocator,
        u8,
        &.{ base_source, delta_source },
    );
    defer allocator.free(crl_source);

    var crls = try parse(allocator, crl_source, &cas, now);
    defer crls.deinit();
    try std.testing.expectEqual(@as(usize, 2), crls.lists.len);
    try std.testing.expectEqual(
        @as(usize, 1),
        crls.combined_lists.len,
    );
    // The base held serial is removed by the delta, while the delta adds the
    // second serial. A clean leaf remains accepted.
    try crls.verifyLeaf(&held);
    try std.testing.expectError(
        error.CertificateRevoked,
        crls.verifyLeaf(&added),
    );
    try crls.verifyLeaf(&clean);

    var verifier = Verifier{
        .trust = cas.verifier(now),
        .crls = &crls,
    };
    try verifier.verify(.{ .server_name = null, .chain = &.{&held} });
    try std.testing.expectError(
        error.CertificateRevoked,
        verifier.verify(.{ .server_name = null, .chain = &.{&added} }),
    );

    try std.testing.expectError(
        error.MissingBaseCrl,
        parse(allocator, delta_source, &cas, now),
    );
    var indirect = try parse(allocator, indirect_source, &cas, now);
    defer indirect.deinit();
    try std.testing.expectEqual(@as(usize, 1), indirect.indirect_lists.len);
    try std.testing.expectError(error.CrlNotFound, indirect.verifyLeaf(&held));

    var authorized = try parse(
        allocator,
        indirect_authorized_source,
        &cas,
        now,
    );
    defer authorized.deinit();
    try std.testing.expectEqual(@as(usize, 1), authorized.indirect_lists.len);
    try std.testing.expectError(
        error.CertificateRevoked,
        authorized.verifyLeaf(&indirect_target),
    );
    var indirect_verifier = Verifier{
        .trust = cas.verifier(now),
        .crls = &authorized,
    };
    try std.testing.expectError(
        error.CertificateRevoked,
        indirect_verifier.verify(.{
            .server_name = null,
            .chain = &.{&indirect_target},
        }),
    );

    // A CRL signed by a delegated certificate is still rejected until the
    // caller supplies that signer's authenticated chain explicitly.
    try std.testing.expectError(
        error.MissingCrlIssuer,
        parse(allocator, delegated_source, &cas, now),
    );
    const duplicate_delta_source = try std.mem.concat(
        allocator,
        u8,
        &.{ base_source, delta_source, delta_source },
    );
    defer allocator.free(duplicate_delta_source);
    try std.testing.expectError(
        error.DuplicateCrlNumber,
        parse(allocator, duplicate_delta_source, &cas, now),
    );
}

test "client CRL file selects the newest compatible delta" {
    const allocator = std.testing.allocator;
    const vectors = vail.x509.testing.path_vectors;
    const now = 1_790_848_980;
    const ca_der = decodeHexFixture(vectors.freshest_crl_ca_hex);
    const held = decodeHexFixture(vectors.freshest_crl_held_hex);
    const clean = decodeHexFixture(vectors.freshest_crl_clean_hex);
    const base_der = decodeHexFixture(vectors.freshest_crl_base_hex);
    const old_der = decodeHexFixture(vectors.freshest_crl_delta_old_hex);
    const newest_der = decodeHexFixture(
        vectors.freshest_crl_delta_new_hex,
    );

    const ca_source = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        &ca_der,
    );
    defer allocator.free(ca_source);
    var cas = try client_ca_file.parse(allocator, ca_source, now);
    defer cas.deinit();

    const base_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &base_der,
    );
    defer allocator.free(base_source);
    const old_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &old_der,
    );
    defer allocator.free(old_source);
    const newest_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &newest_der,
    );
    defer allocator.free(newest_source);
    const crl_source = try std.mem.concat(
        allocator,
        u8,
        &.{ base_source, old_source, newest_source },
    );
    defer allocator.free(crl_source);

    var crls = try parse(allocator, crl_source, &cas, now);
    defer crls.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        crls.combined_lists.len,
    );
    try std.testing.expectError(
        error.CertificateRevoked,
        crls.verifyLeaf(&held),
    );
    try crls.verifyLeaf(&clean);
}

fn parseDeltaForAllocationTest(
    allocator: std.mem.Allocator,
    source: []const u8,
    cas: *const client_ca_file.File,
    now: i64,
) !void {
    var crls = try parse(allocator, source, cas, now);
    defer crls.deinit();
}

test "client base and delta CRL allocation failures are transactional" {
    const allocator = std.testing.allocator;
    const vectors = vail.x509.testing.path_vectors;
    const now = 1_790_844_200;
    const ca_der = decodeHexFixture(vectors.delta_crl_ca_hex);
    const base_der = decodeHexFixture(vectors.delta_crl_base_hex);
    const delta_der = decodeHexFixture(vectors.delta_crl_delta_hex);
    const ca_source = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        &ca_der,
    );
    defer allocator.free(ca_source);
    const base_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &base_der,
    );
    defer allocator.free(base_source);
    const delta_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &delta_der,
    );
    defer allocator.free(delta_source);
    const crl_source = try std.mem.concat(
        allocator,
        u8,
        &.{ base_source, delta_source },
    );
    defer allocator.free(crl_source);
    var cas = try client_ca_file.parse(allocator, ca_source, now);
    defer cas.deinit();

    try std.testing.checkAllAllocationFailures(
        allocator,
        parseDeltaForAllocationTest,
        .{ crl_source, &cas, now },
    );

    const indirect_der = decodeHexFixture(
        vectors.delta_crl_indirect_authorized_hex,
    );
    const indirect_source = try encodePemForTest(
        allocator,
        "X509 CRL",
        &indirect_der,
    );
    defer allocator.free(indirect_source);
    try std.testing.checkAllAllocationFailures(
        allocator,
        parseDeltaForAllocationTest,
        .{ indirect_source, &cas, now },
    );
}
