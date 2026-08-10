const std = @import("std");
const quic = @import("mod.zig");
const vail = @import("vail");

pub const secret_len = vail.crypto.mac.key_len;
pub const nonce_len = 16;
pub const mac_len = vail.crypto.mac.tag_len;
pub const fingerprint_len = mac_len;

const magic = "netz-av1";
const version_len = 4;
const body_len = magic.len + 1 + version_len + 8 + 8 + nonce_len;
pub const token_len = body_len + mac_len;

pub const Secret = [secret_len]u8;
pub const Nonce = [nonce_len]u8;
pub const Fingerprint = [fingerprint_len]u8;

pub const ReplayFilterSnapshot = struct {
    fingerprints: []Fingerprint,

    pub fn deinit(self: *ReplayFilterSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprints);
        self.* = undefined;
    }
};

pub const Kind = enum(u8) {
    retry = 0,
    new_token = 1,
};

pub const Context = struct {
    kind: Kind,
    version: quic.Version = .version_1,
    issued_ns: i64,
    lifetime_ns: u64,
    peer_address: []const u8,
    nonce: Nonce,
};

pub const Validation = struct {
    kind: Kind,
    version: quic.Version,
    issued_ns: i64,
    lifetime_ns: u64,
    nonce: Nonce,
};

pub const Error = error{
    InvalidToken,
    TokenExpired,
    TokenNotYetValid,
    TokenReplay,
} || std.mem.Allocator.Error;

pub fn encode(allocator: std.mem.Allocator, secret: Secret, context: Context) Error![]u8 {
    try validateContext(context);
    const out = try allocator.alloc(u8, token_len);
    errdefer allocator.free(out);

    @memcpy(out[0..magic.len], magic);
    out[magic.len] = @intFromEnum(context.kind);
    std.mem.writeInt(u32, out[magic.len + 1 ..][0..version_len], context.version.wireValue(), .big);
    std.mem.writeInt(u64, out[magic.len + 1 + version_len ..][0..8], @intCast(context.issued_ns), .big);
    std.mem.writeInt(u64, out[magic.len + 1 + version_len + 8 ..][0..8], context.lifetime_ns, .big);
    @memcpy(out[magic.len + 1 + version_len + 16 ..][0..nonce_len], &context.nonce);

    const tag = tokenMac(secret, out[0..body_len], context.peer_address);
    @memcpy(out[body_len..], &tag);
    return out;
}

pub fn encodeRetry(
    allocator: std.mem.Allocator,
    secret: Secret,
    context: Context,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
) Error![]u8 {
    if (context.kind != .retry) return error.InvalidToken;
    const binding = try retryPeerBinding(allocator, context.peer_address, original_destination_connection_id, retry_source_connection_id);
    defer allocator.free(binding);
    return encode(allocator, secret, .{
        .kind = context.kind,
        .version = context.version,
        .issued_ns = context.issued_ns,
        .lifetime_ns = context.lifetime_ns,
        .peer_address = binding,
        .nonce = context.nonce,
    });
}

pub fn validateRetry(
    allocator: std.mem.Allocator,
    secret: Secret,
    expected_version: quic.Version,
    now_ns: i64,
    peer_address: []const u8,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    token: []const u8,
) Error!Validation {
    const binding = try retryPeerBinding(allocator, peer_address, original_destination_connection_id, retry_source_connection_id);
    defer allocator.free(binding);
    return validate(secret, .retry, expected_version, now_ns, binding, token);
}

pub fn validateRetryAnySecret(
    allocator: std.mem.Allocator,
    secrets: []const Secret,
    expected_version: quic.Version,
    now_ns: i64,
    peer_address: []const u8,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    token: []const u8,
) Error!Validation {
    const binding = try retryPeerBinding(allocator, peer_address, original_destination_connection_id, retry_source_connection_id);
    defer allocator.free(binding);
    return validateAnySecret(secrets, .retry, expected_version, now_ns, binding, token);
}

pub fn validate(secret: Secret, expected_kind: Kind, expected_version: quic.Version, now_ns: i64, peer_address: []const u8, token: []const u8) Error!Validation {
    try validateEnvelope(token);
    if (std.enums.fromInt(Kind, token[magic.len]) != expected_kind) return error.InvalidToken;

    const version_wire = std.mem.readInt(u32, token[magic.len + 1 ..][0..version_len], .big);
    const version: quic.Version = @enumFromInt(version_wire);
    if (version.wireValue() != expected_version.wireValue()) return error.InvalidToken;
    if (version == .negotiation) return error.InvalidToken;

    const issued_u64 = std.mem.readInt(u64, token[magic.len + 1 + version_len ..][0..8], .big);
    if (issued_u64 > @as(u64, @intCast(std.math.maxInt(i64)))) return error.InvalidToken;
    const issued_ns: i64 = @intCast(issued_u64);
    const lifetime_ns = std.mem.readInt(u64, token[magic.len + 1 + version_len + 8 ..][0..8], .big);
    if (lifetime_ns == 0) return error.InvalidToken;
    const nonce = token[magic.len + 1 + version_len + 16 ..][0..nonce_len].*;

    const expected = tokenMac(secret, token[0..body_len], peer_address);
    const got = token[body_len..][0..mac_len].*;
    if (!vail.crypto.mac.verify(expected, got)) return error.InvalidToken;

    if (now_ns < issued_ns) return error.TokenNotYetValid;
    const expires = expiresAt(issued_ns, lifetime_ns) orelse return error.InvalidToken;
    if (now_ns > expires) return error.TokenExpired;

    return .{ .kind = expected_kind, .version = version, .issued_ns = issued_ns, .lifetime_ns = lifetime_ns, .nonce = nonce };
}

pub fn validateAnySecret(secrets: []const Secret, expected_kind: Kind, expected_version: quic.Version, now_ns: i64, peer_address: []const u8, token: []const u8) Error!Validation {
    if (secrets.len == 0) return error.InvalidToken;
    var temporal: ?Error = null;
    for (secrets) |secret| {
        return validate(secret, expected_kind, expected_version, now_ns, peer_address, token) catch |err| switch (err) {
            error.InvalidToken => continue,
            error.TokenExpired, error.TokenNotYetValid => {
                if (temporal == null) temporal = err;
                continue;
            },
            else => return err,
        };
    }
    if (temporal) |err| return err;
    return error.InvalidToken;
}

pub fn fingerprint(token: []const u8) Error!Fingerprint {
    try validateEnvelope(token);
    return token[body_len..][0..fingerprint_len].*;
}

pub const ReplayFilter = struct {
    allocator: std.mem.Allocator,
    max_entries: usize,
    fingerprints: std.ArrayList(Fingerprint) = .empty,
    head: usize = 0,
    len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) ReplayFilter {
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    pub fn initWithSnapshot(
        allocator: std.mem.Allocator,
        max_entries: usize,
        snapshot: ReplayFilterSnapshot,
    ) Error!ReplayFilter {
        var filter = ReplayFilter.init(allocator, max_entries);
        errdefer filter.deinit();
        try filter.appendSnapshotFingerprints(snapshot.fingerprints);
        return filter;
    }

    pub fn deinit(self: *ReplayFilter) void {
        self.fingerprints.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn entryCount(self: ReplayFilter) usize {
        return self.len;
    }

    pub fn exportSnapshot(
        self: ReplayFilter,
        allocator: std.mem.Allocator,
    ) Error!ReplayFilterSnapshot {
        const fingerprints = try allocator.alloc(Fingerprint, self.len);
        errdefer allocator.free(fingerprints);
        var copied: usize = 0;
        while (copied < self.len) : (copied += 1) {
            const index = (self.head + copied) % self.fingerprints.items.len;
            fingerprints[copied] = self.fingerprints.items[index];
        }
        return .{ .fingerprints = fingerprints };
    }

    pub fn contains(self: ReplayFilter, token: []const u8) Error!bool {
        const fp = try fingerprint(token);
        var checked: usize = 0;
        while (checked < self.len) : (checked += 1) {
            const index = (self.head + checked) % self.fingerprints.items.len;
            const existing = self.fingerprints.items[index];
            if (vail.crypto.mac.verify(existing, fp)) return true;
        }
        return false;
    }

    pub fn rememberValidated(self: *ReplayFilter, token: []const u8) Error!void {
        const fp = try fingerprint(token);
        var checked: usize = 0;
        while (checked < self.len) : (checked += 1) {
            const index = (self.head + checked) % self.fingerprints.items.len;
            const existing = self.fingerprints.items[index];
            if (vail.crypto.mac.verify(existing, fp)) return error.TokenReplay;
        }
        if (self.max_entries == 0) return;

        if (self.len < self.max_entries) {
            const tail = if (self.fingerprints.items.len == 0) 0 else (self.head + self.len) % self.max_entries;
            if (tail < self.fingerprints.items.len) {
                self.fingerprints.items[tail] = fp;
            } else {
                try self.fingerprints.append(self.allocator, fp);
            }
            self.len += 1;
            return;
        }

        // Keep the replay filter as a fixed-size FIFO ring.  `orderedRemove(0)`
        // was correct but shifted every stored fingerprint on each eviction;
        // Retry/NEW_TOKEN replay filters can sit on hot UDP paths, so advancing
        // the head matches VecDeque-style reference implementations without
        // changing the visible "oldest token is forgotten first" policy.
        self.fingerprints.items[self.head] = fp;
        self.head = (self.head + 1) % self.fingerprints.items.len;
    }

    fn appendSnapshotFingerprints(
        self: *ReplayFilter,
        fingerprints: []const Fingerprint,
    ) Error!void {
        if (self.max_entries == 0 or fingerprints.len == 0) return;
        var retained: std.ArrayList(Fingerprint) = .empty;
        defer retained.deinit(self.allocator);

        var index = fingerprints.len;
        while (index != 0 and retained.items.len < self.max_entries) {
            index -= 1;
            const candidate = fingerprints[index];
            if (containsFingerprint(retained.items, candidate)) continue;
            try retained.append(self.allocator, candidate);
        }

        try self.fingerprints.ensureUnusedCapacity(self.allocator, retained.items.len);
        var out = retained.items.len;
        while (out != 0) {
            out -= 1;
            self.fingerprints.appendAssumeCapacity(retained.items[out]);
        }
        self.head = 0;
        self.len = retained.items.len;
    }
};

fn containsFingerprint(fingerprints: []const Fingerprint, wanted: Fingerprint) bool {
    for (fingerprints) |existing| {
        if (vail.crypto.mac.verify(existing, wanted)) return true;
    }
    return false;
}

pub fn validateAnySecretAndRemember(secrets: []const Secret, expected_kind: Kind, expected_version: quic.Version, now_ns: i64, peer_address: []const u8, token: []const u8, replay: *ReplayFilter) Error!Validation {
    const validation = try validateAnySecret(secrets, expected_kind, expected_version, now_ns, peer_address, token);
    try replay.rememberValidated(token);
    return validation;
}

fn retryPeerBinding(allocator: std.mem.Allocator, peer_address: []const u8, odcid: []const u8, rscid: []const u8) Error![]u8 {
    if (odcid.len == 0 or odcid.len > 20 or rscid.len == 0 or rscid.len > 20) return error.InvalidToken;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, peer_address);
    try out.append(allocator, 0xff);
    try out.append(allocator, @intCast(odcid.len));
    try out.appendSlice(allocator, odcid);
    try out.append(allocator, @intCast(rscid.len));
    try out.appendSlice(allocator, rscid);
    return out.toOwnedSlice(allocator);
}

fn validateContext(context: Context) Error!void {
    if (context.issued_ns < 0 or context.lifetime_ns == 0 or context.peer_address.len == 0) return error.InvalidToken;
    if (context.version == .negotiation) return error.InvalidToken;
    _ = expiresAt(context.issued_ns, context.lifetime_ns) orelse return error.InvalidToken;
}

fn validateEnvelope(token: []const u8) Error!void {
    if (token.len != token_len) return error.InvalidToken;
    if (!std.mem.eql(u8, token[0..magic.len], magic)) return error.InvalidToken;
    _ = std.enums.fromInt(Kind, token[magic.len]) orelse return error.InvalidToken;
}

fn expiresAt(issued_ns: i64, lifetime_ns: u64) ?i64 {
    if (issued_ns < 0) return null;
    const max_lifetime: u64 = @intCast(std.math.maxInt(i64) - issued_ns);
    if (lifetime_ns > max_lifetime) return null;
    return issued_ns + @as(i64, @intCast(lifetime_ns));
}

fn tokenMac(secret: Secret, body: []const u8, peer_address: []const u8) [mac_len]u8 {
    return vail.crypto.mac.authenticate(
        &secret,
        "netz/quic/address-validation/v1",
        &.{ body, peer_address },
    );
}

test "QUIC address validation token validates kind lifetime version and peer address" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x42} ** secret_len;
    const nonce: Nonce = [_]u8{0x99} ** nonce_len;
    const token = try encode(allocator, secret, .{ .kind = .retry, .issued_ns = 100, .lifetime_ns = 50, .peer_address = "peer-a", .nonce = nonce });
    defer allocator.free(token);

    const validation = try validate(secret, .retry, .version_1, 120, "peer-a", token);
    try std.testing.expectEqual(Kind.retry, validation.kind);
    try std.testing.expectEqual(quic.Version.version_1, validation.version);
    try std.testing.expectEqual(@as(i64, 100), validation.issued_ns);
    try std.testing.expectEqual(@as(u64, 50), validation.lifetime_ns);
    try std.testing.expectEqualSlices(u8, &nonce, &validation.nonce);

    try std.testing.expectError(error.InvalidToken, validate(secret, .new_token, .version_1, 120, "peer-a", token));
    try std.testing.expectError(error.InvalidToken, validate(secret, .retry, .version_2, 120, "peer-a", token));
    try std.testing.expectError(error.InvalidToken, validate(secret, .retry, .version_1, 120, "peer-b", token));
    try std.testing.expectError(error.TokenNotYetValid, validate(secret, .retry, .version_1, 99, "peer-a", token));
    try std.testing.expectError(error.TokenExpired, validate(secret, .retry, .version_1, 151, "peer-a", token));
}

test "QUIC Retry address token binds ODCID and RSCID" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x91} ** secret_len;
    const nonce: Nonce = [_]u8{0x92} ** nonce_len;
    const odcid = [_]u8{ 1, 2, 3, 4 };
    const rscid = [_]u8{ 5, 6, 7, 8 };

    const token = try encodeRetry(allocator, secret, .{
        .kind = .retry,
        .issued_ns = 100,
        .lifetime_ns = 500,
        .peer_address = "client-path",
        .nonce = nonce,
    }, &odcid, &rscid);
    defer allocator.free(token);

    const validation = try validateRetry(allocator, secret, .version_1, 120, "client-path", &odcid, &rscid, token);
    try std.testing.expectEqual(Kind.retry, validation.kind);
    try std.testing.expectEqualSlices(u8, &nonce, &validation.nonce);
    try std.testing.expectEqual(Kind.retry, (try validateRetryAnySecret(
        allocator,
        &[_]Secret{secret},
        .version_1,
        120,
        "client-path",
        &odcid,
        &rscid,
        token,
    )).kind);

    const wrong_odcid = [_]u8{ 1, 2, 3, 9 };
    try std.testing.expectError(error.InvalidToken, validateRetry(allocator, secret, .version_1, 120, "client-path", &wrong_odcid, &rscid, token));
    const wrong_rscid = [_]u8{ 5, 6, 7, 9 };
    try std.testing.expectError(error.InvalidToken, validateRetry(allocator, secret, .version_1, 120, "client-path", &odcid, &wrong_rscid, token));
    try std.testing.expectError(error.InvalidToken, encodeRetry(allocator, secret, .{
        .kind = .new_token,
        .issued_ns = 100,
        .lifetime_ns = 500,
        .peer_address = "client-path",
        .nonce = nonce,
    }, &odcid, &rscid));
}

test "QUIC address validation token validates rotated secrets" {
    const allocator = std.testing.allocator;
    const old: Secret = [_]u8{0x11} ** secret_len;
    const current: Secret = [_]u8{0x22} ** secret_len;
    const token = try encode(allocator, old, .{ .kind = .new_token, .issued_ns = 1, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x33} ** nonce_len });
    defer allocator.free(token);
    const secrets = [_]Secret{ current, old };
    try std.testing.expectEqual(Kind.new_token, (try validateAnySecret(&secrets, .new_token, .version_1, 10, "peer", token)).kind);
    try std.testing.expectError(error.InvalidToken, validateAnySecret(&[_]Secret{current}, .new_token, .version_1, 10, "peer", token));
}

test "QUIC address validation replay filter rejects duplicate fingerprints" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x55} ** secret_len;
    const token = try encode(allocator, secret, .{ .kind = .retry, .issued_ns = 1, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x66} ** nonce_len });
    defer allocator.free(token);
    const secrets = [_]Secret{secret};
    var replay = ReplayFilter.init(allocator, 2);
    defer replay.deinit();

    _ = try validateAnySecretAndRemember(&secrets, .retry, .version_1, 10, "peer", token, &replay);
    try std.testing.expect(try replay.contains(token));
    try std.testing.expectError(error.TokenReplay, validateAnySecretAndRemember(&secrets, .retry, .version_1, 10, "peer", token, &replay));
}

test "QUIC address validation replay filter evicts oldest fingerprint" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x77} ** secret_len;
    const a = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 1, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x01} ** nonce_len });
    defer allocator.free(a);
    const b = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 2, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x02} ** nonce_len });
    defer allocator.free(b);
    const c = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 3, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x03} ** nonce_len });
    defer allocator.free(c);
    var replay = ReplayFilter.init(allocator, 2);
    defer replay.deinit();
    try replay.rememberValidated(a);
    try replay.rememberValidated(b);
    try replay.rememberValidated(c);
    try std.testing.expect(!try replay.contains(a));
    try std.testing.expect(try replay.contains(b));
    try std.testing.expect(try replay.contains(c));

    const d = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 4, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x04} ** nonce_len });
    defer allocator.free(d);
    try replay.rememberValidated(d);
    try std.testing.expect(!try replay.contains(b));
    try std.testing.expect(try replay.contains(c));
    try std.testing.expect(try replay.contains(d));
    try std.testing.expectEqual(@as(usize, 2), replay.len);
    try std.testing.expectEqual(@as(usize, 2), replay.fingerprints.items.len);
}

test "QUIC address validation replay filter exports and restores snapshots" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x88} ** secret_len;
    const a = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 1, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x0a} ** nonce_len });
    defer allocator.free(a);
    const b = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 2, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x0b} ** nonce_len });
    defer allocator.free(b);
    const c = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 3, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x0c} ** nonce_len });
    defer allocator.free(c);

    var replay = ReplayFilter.init(allocator, 2);
    defer replay.deinit();
    try replay.rememberValidated(a);
    try replay.rememberValidated(b);
    try replay.rememberValidated(c);

    var snapshot = try replay.exportSnapshot(allocator);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), snapshot.fingerprints.len);

    var restored = try ReplayFilter.initWithSnapshot(allocator, 2, snapshot);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.entryCount());
    try std.testing.expect(!try restored.contains(a));
    try std.testing.expect(try restored.contains(b));
    try std.testing.expect(try restored.contains(c));
    try std.testing.expectError(error.TokenReplay, restored.rememberValidated(b));

    var trimmed = try ReplayFilter.initWithSnapshot(allocator, 1, snapshot);
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 1), trimmed.entryCount());
    try std.testing.expect(!try trimmed.contains(b));
    try std.testing.expect(try trimmed.contains(c));
}
