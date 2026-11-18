const std = @import("std");
const address_validation_token_root = @import("../address_validation_token.zig");

const quic = @import("../mod.zig");

const Fingerprint = address_validation_token_root.Fingerprint;
const Kind = address_validation_token_root.Kind;
const Nonce = address_validation_token_root.Nonce;
const ReplayFilter = address_validation_token_root.ReplayFilter;
const ReplayFilterSnapshot = address_validation_token_root.ReplayFilterSnapshot;
const Secret = address_validation_token_root.Secret;
const SharedReplayFilter = address_validation_token_root.SharedReplayFilter;
const encode = address_validation_token_root.encode;
const encodeInto = address_validation_token_root.encodeInto;
const encodeRetry = address_validation_token_root.encodeRetry;
const encodeRetryInto = address_validation_token_root.encodeRetryInto;
const fingerprint = address_validation_token_root.fingerprint;
const nonce_len = address_validation_token_root.nonce_len;
const secret_len = address_validation_token_root.secret_len;
const token_len = address_validation_token_root.token_len;
const validate = address_validation_token_root.validate;
const validateAnySecret = address_validation_token_root.validateAnySecret;
const validateAnySecretAndRemember = address_validation_token_root.validateAnySecretAndRemember;
const validateAnySecretAndRememberShared = address_validation_token_root.validateAnySecretAndRememberShared;
const validateRetry = address_validation_token_root.validateRetry;
const validateRetryAnySecret = address_validation_token_root.validateRetryAnySecret;

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
