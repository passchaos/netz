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
    InvalidCapacity,
    InvalidToken,
    TokenExpired,
    TokenNotYetValid,
    TokenReplay,
} || std.mem.Allocator.Error;

pub fn encode(allocator: std.mem.Allocator, secret: Secret, context: Context) Error![]u8 {
    try validateContext(context);
    const out = try allocator.alloc(u8, token_len);
    errdefer allocator.free(out);
    _ = try encodeInto(out[0..token_len], secret, context);
    return out;
}

/// Encode the fixed-size authenticated token into caller-owned storage.
pub fn encodeInto(
    storage: *[token_len]u8,
    secret: Secret,
    context: Context,
) Error![]const u8 {
    try validateContext(context);
    @memcpy(storage[0..magic.len], magic);
    storage[magic.len] = @intFromEnum(context.kind);
    std.mem.writeInt(u32, storage[magic.len + 1 ..][0..version_len], context.version.wireValue(), .big);
    std.mem.writeInt(u64, storage[magic.len + 1 + version_len ..][0..8], @intCast(context.issued_ns), .big);
    std.mem.writeInt(u64, storage[magic.len + 1 + version_len + 8 ..][0..8], context.lifetime_ns, .big);
    @memcpy(storage[magic.len + 1 + version_len + 16 ..][0..nonce_len], &context.nonce);

    const tag = tokenMac(secret, storage[0..body_len], context.peer_address);
    @memcpy(storage[body_len..], &tag);
    return storage;
}

pub fn encodeRetry(
    allocator: std.mem.Allocator,
    secret: Secret,
    context: Context,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
) Error![]u8 {
    _ = try validateRetryContext(
        context,
        original_destination_connection_id,
        retry_source_connection_id,
    );
    const out = try allocator.alloc(u8, token_len);
    errdefer allocator.free(out);
    _ = try encodeRetryInto(
        out[0..token_len],
        secret,
        context,
        original_destination_connection_id,
        retry_source_connection_id,
    );
    return out;
}

/// Encode a Retry token without materializing the ODCID/RSCID binding. The MAC
/// absorbs that logical binding as one length-delimited part, preserving exact
/// wire compatibility with `encode` while avoiding scratch allocation.
pub fn encodeRetryInto(
    storage: *[token_len]u8,
    secret: Secret,
    context: Context,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
) Error![]const u8 {
    const binding_len = try validateRetryContext(
        context,
        original_destination_connection_id,
        retry_source_connection_id,
    );
    writeTokenBody(storage[0..body_len], context);
    const tag = retryTokenMac(
        secret,
        storage[0..body_len],
        context.peer_address,
        original_destination_connection_id,
        retry_source_connection_id,
        binding_len,
    );
    @memcpy(storage[body_len..], &tag);
    return storage;
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
    _ = allocator;
    const validation = try parseValidationEnvelope(
        .retry,
        expected_version,
        token,
    );
    const binding_len = try retryBindingLen(
        peer_address,
        original_destination_connection_id,
        retry_source_connection_id,
    );
    const expected = retryTokenMac(
        secret,
        token[0..body_len],
        peer_address,
        original_destination_connection_id,
        retry_source_connection_id,
        binding_len,
    );
    const got = token[body_len..][0..mac_len].*;
    if (!vail.crypto.mac.verify(expected, got)) return error.InvalidToken;
    try validateLifetime(validation, now_ns);
    return validation;
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
    _ = allocator;
    if (secrets.len == 0) return error.InvalidToken;
    const validation = try parseValidationEnvelope(
        .retry,
        expected_version,
        token,
    );
    const binding_len = try retryBindingLen(
        peer_address,
        original_destination_connection_id,
        retry_source_connection_id,
    );
    const got = token[body_len..][0..mac_len].*;
    for (secrets) |secret| {
        const expected = retryTokenMac(
            secret,
            token[0..body_len],
            peer_address,
            original_destination_connection_id,
            retry_source_connection_id,
            binding_len,
        );
        if (vail.crypto.mac.verify(expected, got)) {
            try validateLifetime(validation, now_ns);
            return validation;
        }
    }
    return error.InvalidToken;
}

pub fn validate(secret: Secret, expected_kind: Kind, expected_version: quic.Version, now_ns: i64, peer_address: []const u8, token: []const u8) Error!Validation {
    const validation = try parseValidationEnvelope(
        expected_kind,
        expected_version,
        token,
    );
    const expected = tokenMac(secret, token[0..body_len], peer_address);
    const got = token[body_len..][0..mac_len].*;
    if (!vail.crypto.mac.verify(expected, got)) return error.InvalidToken;
    try validateLifetime(validation, now_ns);
    return validation;
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
    /// Fingerprints are fixed-size MAC tags copied by value into the index.
    /// The ArrayList remains the FIFO ring that defines eviction/snapshot
    /// order, while this map keeps replay checks independent of filter size.
    fingerprint_index: std.AutoHashMapUnmanaged(Fingerprint, void) = .empty,
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
        self.fingerprint_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn entryCount(self: *const ReplayFilter) usize {
        return self.len;
    }

    pub fn exportSnapshot(
        self: *const ReplayFilter,
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

    pub fn contains(self: *const ReplayFilter, token: []const u8) Error!bool {
        const fp = try fingerprint(token);
        return self.fingerprint_index.count() != 0 and
            self.fingerprint_index.contains(fp);
    }

    pub fn rememberValidated(self: *ReplayFilter, token: []const u8) Error!void {
        if (self.max_entries == 0) return;
        const fp = try fingerprint(token);
        const slot = try self.fingerprint_index.getOrPut(self.allocator, fp);
        if (slot.found_existing) return error.TokenReplay;
        errdefer _ = self.fingerprint_index.remove(fp);

        if (self.len < self.max_entries) {
            try self.fingerprints.ensureUnusedCapacity(self.allocator, 1);
            const tail = if (self.fingerprints.items.len == 0) 0 else (self.head + self.len) % self.max_entries;
            if (tail < self.fingerprints.items.len) {
                self.fingerprints.items[tail] = fp;
            } else {
                self.fingerprints.appendAssumeCapacity(fp);
            }
            slot.value_ptr.* = {};
            self.len += 1;
            return;
        }

        // Keep the replay filter as a fixed-size FIFO ring.  `orderedRemove(0)`
        // was correct but shifted every stored fingerprint on each eviction;
        // Retry/NEW_TOKEN replay filters can sit on hot UDP paths, so advancing
        // the head matches VecDeque-style reference implementations without
        // changing the visible "oldest token is forgotten first" policy.
        _ = self.fingerprint_index.remove(self.fingerprints.items[self.head]);
        self.fingerprints.items[self.head] = fp;
        self.fingerprint_index.getPtr(fp).?.* = {};
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
        const index_capacity = std.math.cast(
            @TypeOf(self.fingerprint_index).Size,
            retained.items.len,
        ) orelse return error.OutOfMemory;
        try self.fingerprint_index.ensureUnusedCapacity(self.allocator, index_capacity);
        var out = retained.items.len;
        while (out != 0) {
            out -= 1;
            self.fingerprints.appendAssumeCapacity(retained.items[out]);
            self.fingerprint_index.putAssumeCapacityNoClobber(retained.items[out], {});
        }
        self.head = 0;
        self.len = retained.items.len;
    }
};

/// Owning, thread-safe facade for sharing a `ReplayFilter` between concurrent
/// token-validation tasks. Every operation on the owned filter is serialized,
/// including read-only queries and snapshot export, because the underlying
/// hash map and ring are deliberately not thread-safe on their own.
///
/// The supplied `io` is retained by value and must remain usable for the full
/// lifetime of this wrapper; it drives mutex contention and wakeups. The
/// allocator supplied at initialization is owned only by the caller and must
/// outlive the wrapper. Access through this wrapper is serialized, so its use
/// by the underlying filter does not itself require a thread-safe allocator.
///
/// Initialization returns the wrapper by value, but after publishing its
/// address to other tasks it must not be copied or moved. Callers must quiesce
/// all operations before `deinit`; the mutex protects filter state, not the
/// lifetime of the wrapper or of caller-owned token buffers. Snapshots returned
/// by `exportSnapshot` are independently owned by its allocator and remain
/// valid after the mutex is released.
pub const SharedReplayFilter = struct {
    io: std.Io,
    filter: ReplayFilter,
    mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
    ) Error!SharedReplayFilter {
        if (max_entries == 0) return error.InvalidCapacity;
        return .{
            .io = io,
            .filter = .init(allocator, max_entries),
        };
    }

    pub fn initWithSnapshot(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
        snapshot: ReplayFilterSnapshot,
    ) Error!SharedReplayFilter {
        if (max_entries == 0) return error.InvalidCapacity;
        return .{
            .io = io,
            .filter = try .initWithSnapshot(
                allocator,
                max_entries,
                snapshot,
            ),
        };
    }

    pub fn deinit(self: *SharedReplayFilter) void {
        // Synchronization cannot make destruction safe while another caller
        // still owns `self`; external quiescence is therefore required.
        self.filter.deinit();
        self.* = undefined;
    }

    pub fn entryCount(self: *SharedReplayFilter) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.filter.entryCount();
    }

    pub fn exportSnapshot(
        self: *SharedReplayFilter,
        allocator: std.mem.Allocator,
    ) Error!ReplayFilterSnapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.filter.exportSnapshot(allocator);
    }

    pub fn contains(
        self: *SharedReplayFilter,
        token: []const u8,
    ) Error!bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.filter.contains(token);
    }

    /// Atomically reject an already-seen token or remember its fingerprint.
    /// The critical section covers both the duplicate check and insertion, so
    /// exactly one concurrent caller can accept a particular token.
    pub fn rememberValidated(
        self: *SharedReplayFilter,
        token: []const u8,
    ) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.filter.rememberValidated(token);
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

/// Authenticate and time-check a token before atomically admitting its
/// fingerprint through a shared replay filter. Validation itself is stateless
/// and therefore remains outside the mutex; only the check-and-insert step
/// requires serialization.
pub fn validateAnySecretAndRememberShared(
    secrets: []const Secret,
    expected_kind: Kind,
    expected_version: quic.Version,
    now_ns: i64,
    peer_address: []const u8,
    token: []const u8,
    replay: *SharedReplayFilter,
) Error!Validation {
    const validation = try validateAnySecret(
        secrets,
        expected_kind,
        expected_version,
        now_ns,
        peer_address,
        token,
    );
    try replay.rememberValidated(token);
    return validation;
}

fn retryBindingLen(
    peer_address: []const u8,
    odcid: []const u8,
    rscid: []const u8,
) Error!usize {
    if (odcid.len == 0 or odcid.len > 20 or rscid.len == 0 or rscid.len > 20) {
        return error.InvalidToken;
    }
    const ids_len = std.math.add(usize, odcid.len, rscid.len) catch
        return error.InvalidToken;
    return std.math.add(usize, peer_address.len, 3 + ids_len) catch
        error.InvalidToken;
}

fn validateRetryContext(context: Context, odcid: []const u8, rscid: []const u8) Error!usize {
    if (context.kind != .retry) return error.InvalidToken;
    try validateContext(context);
    return retryBindingLen(context.peer_address, odcid, rscid);
}

fn writeTokenBody(out: *[body_len]u8, context: Context) void {
    @memcpy(out[0..magic.len], magic);
    out[magic.len] = @intFromEnum(context.kind);
    std.mem.writeInt(u32, out[magic.len + 1 ..][0..version_len], context.version.wireValue(), .big);
    std.mem.writeInt(u64, out[magic.len + 1 + version_len ..][0..8], @intCast(context.issued_ns), .big);
    std.mem.writeInt(u64, out[magic.len + 1 + version_len + 8 ..][0..8], context.lifetime_ns, .big);
    @memcpy(out[magic.len + 1 + version_len + 16 ..][0..nonce_len], &context.nonce);
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

fn parseValidationEnvelope(
    expected_kind: Kind,
    expected_version: quic.Version,
    token: []const u8,
) Error!Validation {
    try validateEnvelope(token);
    if (std.enums.fromInt(Kind, token[magic.len]) != expected_kind) {
        return error.InvalidToken;
    }

    const version_wire = std.mem.readInt(
        u32,
        token[magic.len + 1 ..][0..version_len],
        .big,
    );
    const version: quic.Version = @enumFromInt(version_wire);
    if (version.wireValue() != expected_version.wireValue() or
        version == .negotiation) return error.InvalidToken;

    const issued_u64 = std.mem.readInt(
        u64,
        token[magic.len + 1 + version_len ..][0..8],
        .big,
    );
    if (issued_u64 > @as(u64, @intCast(std.math.maxInt(i64)))) {
        return error.InvalidToken;
    }
    const issued_ns: i64 = @intCast(issued_u64);
    const lifetime_ns = std.mem.readInt(
        u64,
        token[magic.len + 1 + version_len + 8 ..][0..8],
        .big,
    );
    if (lifetime_ns == 0) return error.InvalidToken;
    return .{
        .kind = expected_kind,
        .version = version,
        .issued_ns = issued_ns,
        .lifetime_ns = lifetime_ns,
        .nonce = token[magic.len + 1 + version_len + 16 ..][0..nonce_len].*,
    };
}

fn validateLifetime(validation: Validation, now_ns: i64) Error!void {
    if (now_ns < validation.issued_ns) return error.TokenNotYetValid;
    const expires = expiresAt(
        validation.issued_ns,
        validation.lifetime_ns,
    ) orelse return error.InvalidToken;
    if (now_ns > expires) return error.TokenExpired;
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

fn retryTokenMac(
    secret: Secret,
    body: []const u8,
    peer_address: []const u8,
    odcid: []const u8,
    rscid: []const u8,
    binding_len: usize,
) [mac_len]u8 {
    var separator_and_odcid_len = [_]u8{ 0xff, @intCast(odcid.len) };
    var rscid_len = [_]u8{@intCast(rscid.len)};
    var binding_len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &binding_len_bytes, binding_len, .big);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(&secret);
    const domain = "netz/quic/address-validation/v1";
    var domain_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &domain_len, domain.len, .big);
    hmac.update(&domain_len);
    hmac.update(domain);

    var body_len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &body_len_bytes, body.len, .big);
    hmac.update(&body_len_bytes);
    hmac.update(body);
    hmac.update(&binding_len_bytes);
    hmac.update(peer_address);
    hmac.update(&separator_and_odcid_len);
    hmac.update(odcid);
    hmac.update(&rscid_len);
    hmac.update(rscid);
    var tag: [mac_len]u8 = undefined;
    hmac.final(&tag);
    return tag;
}

test "QUIC address validation token validates kind lifetime version and peer address" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x42} ** secret_len;
    const nonce: Nonce = [_]u8{0x99} ** nonce_len;
    const token = try encode(allocator, secret, .{ .kind = .retry, .issued_ns = 100, .lifetime_ns = 50, .peer_address = "peer-a", .nonce = nonce });
    defer allocator.free(token);
    var direct_storage: [token_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        token,
        try encodeInto(
            &direct_storage,
            secret,
            .{
                .kind = .retry,
                .issued_ns = 100,
                .lifetime_ns = 50,
                .peer_address = "peer-a",
                .nonce = nonce,
            },
        ),
    );

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

    var direct_storage: [token_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        token,
        try encodeRetryInto(
            &direct_storage,
            secret,
            .{
                .kind = .retry,
                .issued_ns = 100,
                .lifetime_ns = 500,
                .peer_address = "client-path",
                .nonce = nonce,
            },
            &odcid,
            &rscid,
        ),
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const no_alloc_validation = try validateRetry(
        no_alloc.allocator(),
        secret,
        .version_1,
        120,
        "client-path",
        &odcid,
        &rscid,
        token,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &nonce,
        &no_alloc_validation.nonce,
    );
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
    try std.testing.expectEqual(@as(usize, 1), replay.fingerprint_index.count());
    try std.testing.expectError(error.TokenReplay, validateAnySecretAndRemember(&secrets, .retry, .version_1, 10, "peer", token, &replay));
}

test "shared QUIC address validation replay filter admits one concurrent caller" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .concurrent_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const secret: Secret = [_]u8{0x5a} ** secret_len;
    const token = try encode(allocator, secret, .{
        .kind = .retry,
        .issued_ns = 1,
        .lifetime_ns = 100,
        .peer_address = "peer",
        .nonce = [_]u8{0x6b} ** nonce_len,
    });
    defer allocator.free(token);
    const secrets = [_]Secret{secret};
    var replay = try SharedReplayFilter.init(allocator, io, 8);
    defer replay.deinit();

    const contender_count = 8;
    const Outcome = enum { pending, accepted, replayed, failed };
    var start: std.Io.Event = .unset;
    const Contender = struct {
        fn run(
            shared: *SharedReplayFilter,
            keys: []const Secret,
            encoded: []const u8,
            start_gate: *std.Io.Event,
            outcome: *Outcome,
        ) std.Io.Cancelable!void {
            try start_gate.wait(shared.io);
            _ = validateAnySecretAndRememberShared(
                keys,
                .retry,
                .version_1,
                10,
                "peer",
                encoded,
                shared,
            ) catch |err| {
                outcome.* = if (err == error.TokenReplay) .replayed else .failed;
                return;
            };
            outcome.* = .accepted;
        }
    };

    var outcomes: [contender_count]Outcome = @splat(.pending);
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    for (&outcomes) |*outcome| {
        try group.concurrent(io, Contender.run, .{
            &replay,
            &secrets,
            token,
            &start,
            outcome,
        });
    }
    start.set(io);
    try group.await(io);

    var accepted: usize = 0;
    var replayed: usize = 0;
    for (outcomes) |outcome| switch (outcome) {
        .accepted => accepted += 1,
        .replayed => replayed += 1,
        .pending, .failed => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), accepted);
    try std.testing.expectEqual(@as(usize, contender_count - 1), replayed);
    try std.testing.expectEqual(@as(usize, 1), replay.entryCount());
}

test "shared QUIC address validation replay filter rejects zero capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidCapacity,
        SharedReplayFilter.init(
            std.testing.allocator,
            threaded.io(),
            0,
        ),
    );
}

test "QUIC address validation replay filter disabled remember skips fingerprints" {
    var no_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var replay = ReplayFilter.init(no_alloc.allocator(), 0);
    defer replay.deinit();

    try replay.rememberValidated(&.{});
    try replay.rememberValidated("not-a-token");
    try std.testing.expectEqual(@as(usize, 0), replay.entryCount());
    try std.testing.expectEqual(@as(usize, 0), replay.fingerprint_index.count());
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
    try std.testing.expectEqual(@as(usize, 2), replay.fingerprint_index.count());
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
    try std.testing.expectEqual(@as(usize, 2), replay.fingerprint_index.count());
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
    try std.testing.expectEqual(@as(usize, 2), restored.fingerprint_index.count());
    try std.testing.expect(!try restored.contains(a));
    try std.testing.expect(try restored.contains(b));
    try std.testing.expect(try restored.contains(c));
    try std.testing.expectError(error.TokenReplay, restored.rememberValidated(b));

    var trimmed = try ReplayFilter.initWithSnapshot(allocator, 1, snapshot);
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 1), trimmed.entryCount());
    try std.testing.expectEqual(@as(usize, 1), trimmed.fingerprint_index.count());
    try std.testing.expect(!try trimmed.contains(b));
    try std.testing.expect(try trimmed.contains(c));
}

test "QUIC address validation replay filter restores newest unique snapshot fingerprints" {
    const allocator = std.testing.allocator;
    const secret: Secret = [_]u8{0x89} ** secret_len;
    const a = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 1, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x1a} ** nonce_len });
    defer allocator.free(a);
    const b = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 2, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x1b} ** nonce_len });
    defer allocator.free(b);
    const c = try encode(allocator, secret, .{ .kind = .new_token, .issued_ns = 3, .lifetime_ns = 100, .peer_address = "peer", .nonce = [_]u8{0x1c} ** nonce_len });
    defer allocator.free(c);

    const fingerprint_a = try fingerprint(a);
    const fingerprint_b = try fingerprint(b);
    const fingerprint_c = try fingerprint(c);
    var fingerprints = [_]Fingerprint{
        fingerprint_a,
        fingerprint_b,
        fingerprint_a,
        fingerprint_c,
    };
    const snapshot = ReplayFilterSnapshot{ .fingerprints = &fingerprints };

    var restored = try ReplayFilter.initWithSnapshot(allocator, 3, snapshot);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.entryCount());
    try std.testing.expectEqual(@as(usize, 3), restored.fingerprint_index.count());
    try std.testing.expect(try restored.contains(a));
    try std.testing.expect(try restored.contains(b));
    try std.testing.expect(try restored.contains(c));
    try std.testing.expectEqualSlices(u8, &fingerprint_b, &restored.fingerprints.items[0]);
    try std.testing.expectEqualSlices(u8, &fingerprint_a, &restored.fingerprints.items[1]);
    try std.testing.expectEqualSlices(u8, &fingerprint_c, &restored.fingerprints.items[2]);

    var trimmed = try ReplayFilter.initWithSnapshot(allocator, 2, snapshot);
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 2), trimmed.entryCount());
    try std.testing.expectEqual(@as(usize, 2), trimmed.fingerprint_index.count());
    try std.testing.expect(!try trimmed.contains(b));
    try std.testing.expect(try trimmed.contains(a));
    try std.testing.expect(try trimmed.contains(c));
}
