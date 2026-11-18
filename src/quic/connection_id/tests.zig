const std = @import("std");
const connection_id_root = @import("../connection_id.zig");

const quic = @import("../mod.zig");

const LocalPool = connection_id_root.LocalPool;
const PeerPool = connection_id_root.PeerPool;
const max_pool_size = connection_id_root.max_pool_size;
const max_retire_queue_len = connection_id_root.max_retire_queue_len;

test "QUIC peer CID pool stores retires and consumes IDs" {
    var pool = PeerPool{};
    try pool.add(1, "cid-one", [_]u8{1} ** 16);
    try pool.add(2, "cid-two", [_]u8{2} ** 16);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retirePriorTo(2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.pendingRetireCount());
    try std.testing.expectEqual(@as(u64, 1), pool.peekRetireFrame().?.retire_connection_id.sequence_number);
    try std.testing.expectEqual(@as(usize, 0), pool.in_use_count);
    const entry = pool.consumeUnused().?;
    try std.testing.expectEqual(@as(u64, 2), entry.sequence_number);
    try std.testing.expectEqualStrings("cid-two", entry.slice());
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expect(pool.consumeUnused() == null);
}

test "QUIC peer CID rotation retires and releases the previous ID" {
    var pool = PeerPool{};
    try pool.addInitial("initial");
    try pool.add(1, "replacement", [_]u8{1} ** 16);

    const replacement = (try pool.rotateToUnused("initial")) orelse
        return error.UnknownConnectionId;
    try std.testing.expectEqual(@as(u64, 1), replacement.sequence_number);
    try std.testing.expectEqualStrings("replacement", replacement.slice());
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expectEqual(@as(usize, 1), pool.pendingRetireCount());
    try std.testing.expectEqual(
        @as(u64, 0),
        pool.peekRetireFrame().?.retire_connection_id.sequence_number,
    );
    try std.testing.expectError(
        error.UnknownConnectionId,
        pool.rotateToUnused("initial"),
    );
}

test "QUIC peer CID rotation rolls back when retirement queue is full" {
    var pool = PeerPool{};
    try pool.addInitial("initial");
    try pool.add(1, "replacement", [_]u8{1} ** 16);
    for (0..max_retire_queue_len) |sequence_number| {
        try pool.queueRetire(@intCast(sequence_number + 10));
    }

    try std.testing.expectError(
        error.RetireQueueFull,
        pool.rotateToUnused("initial"),
    );
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expectEqualStrings("initial", pool.entries[0].slice());
    try std.testing.expect(!pool.entries[1].in_use);
}

test "QUIC peer CID pool permits only the initial ID to be empty" {
    var pool = PeerPool{};
    try pool.addInitial("");
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expectEqualStrings("", pool.entries[0].slice());

    // RFC 9000 section 19.15 requires connection_id_length to be non-zero in
    // NEW_CONNECTION_ID, so the ordinary add path must stay strict.
    try std.testing.expectError(
        error.InvalidConnectionId,
        pool.add(1, "", [_]u8{1} ** 16),
    );
}

test "QUIC peer CID pool detects stateless reset token" {
    const allocator = std.testing.allocator;
    var pool = PeerPool{};
    const token = [_]u8{0x44} ** 16;
    try pool.add(7, "reset-cid", token);

    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try quic.stateless_reset.encode(&datagram, allocator, &.{ 0x40, 9, 8, 7, 6 }, token);
    // RFC 9000 §10.3.1: only check tokens for connection IDs the endpoint has
    // actually used.  A peer can issue a CID before we switch to it; that token
    // must not be accepted until the CID is active.
    try std.testing.expectEqual(@as(?u64, null), pool.detectStatelessReset(datagram.items));
    try pool.markInUse(7);
    try pool.markInUse(7);
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expectEqual(@as(?u64, 7), pool.detectStatelessReset(datagram.items));
    try std.testing.expectEqual(@as(?u64, null), pool.detectStatelessReset(&.{ 0x40, 1, 2 }));
    try std.testing.expectEqual(
        @as(?u64, null),
        pool.detectStatelessReset(datagram.items[1..]),
    );
    try pool.retirePriorTo(8);
    try std.testing.expectEqual(@as(usize, 0), pool.in_use_count);
    try std.testing.expectEqual(@as(?u64, null), pool.detectStatelessReset(datagram.items));
}

test "QUIC peer CID pool enables initial reset token after negotiation" {
    var pool = PeerPool{};
    const token = [_]u8{0x45} ** quic.stateless_reset.token_len;
    try pool.addInitial("initial-peer-cid");

    var datagram = [_]u8{0x40} ** quic.stateless_reset.min_datagram_len;
    @memcpy(datagram[datagram.len - token.len ..], &token);
    try std.testing.expectEqual(
        @as(?u64, null),
        pool.detectStatelessReset(&datagram),
    );

    try pool.setInitialStatelessResetToken(token);
    try std.testing.expectEqual(
        @as(?u64, 0),
        pool.detectStatelessReset(&datagram),
    );
    try std.testing.expectError(
        error.DuplicateResetToken,
        pool.add(1, "other-cid", token),
    );
}

test "QUIC peer CID pool selects replacement when preferred CID was retired" {
    var pool = PeerPool{};
    try pool.addInitial("initial");
    try pool.add(1, "replacement", [_]u8{1} ** 16);
    try pool.retirePriorTo(1);

    const selected = pool.selectForPath("initial") orelse
        return error.UnknownConnectionId;
    try std.testing.expectEqualStrings("replacement", selected);
    try std.testing.expectEqual(@as(usize, 1), pool.in_use_count);
    try std.testing.expectEqualStrings(
        "replacement",
        pool.selectForPath("initial").?,
    );
}

test "QUIC peer CID pool validates duplicate IDs tokens and active limit" {
    var pool = PeerPool{};
    const token_a = [_]u8{0xaa} ** 16;
    const token_b = [_]u8{0xbb} ** 16;
    try pool.addWithLimit(0, "cid-a", token_a, 2);

    // Repeated delivery of the same NEW_CONNECTION_ID is idempotent.
    try pool.addWithLimit(0, "cid-a", token_a, 2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    try std.testing.expectError(error.DuplicateConnectionId, pool.addWithLimit(1, "cid-a", token_b, 2));
    try std.testing.expectError(error.DuplicateResetToken, pool.addWithLimit(1, "cid-b", token_a, 2));
    try pool.addWithLimit(1, "cid-b", token_b, 2);
    // When both a CID and another reset token would collide, the single-pass
    // scan must preserve the historical DuplicateConnectionId priority.
    try std.testing.expectError(error.DuplicateConnectionId, pool.addWithLimit(2, "cid-a", token_b, 3));
    try std.testing.expectError(error.ActiveConnectionIdLimit, pool.addWithLimit(2, "cid-c", [_]u8{0xcc} ** 16, 2));
}

test "QUIC peer CID pool rejects retire_prior_to above sequence" {
    var pool = PeerPool{};
    try std.testing.expectError(error.RetirePriorToTooLarge, pool.addWithRetirePriorTo(
        3,
        4,
        "cid-three",
        [_]u8{3} ** 16,
        4,
    ));
    try std.testing.expectEqual(@as(usize, 0), pool.count());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingRetireCount());
}

test "QUIC peer CID pool queues retire frames for retire_prior_to" {
    var pool = PeerPool{};
    try pool.addWithRetirePriorTo(0, 0, "cid-zero", [_]u8{0} ** 16, 4);
    try pool.addWithRetirePriorTo(2, 1, "cid-two", [_]u8{2} ** 16, 4);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.pendingRetireCount());
    try std.testing.expectEqual(@as(u64, 0), pool.peekRetireFrame().?.retire_connection_id.sequence_number);

    // A reordered NEW_CONNECTION_ID below the largest Retire Prior To is not
    // reactivated; a matching RETIRE_CONNECTION_ID is queued once instead.
    try pool.addWithRetirePriorTo(0, 0, "cid-zero-again", [_]u8{3} ** 16, 4);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.pendingRetireCount());

    pool.discardRetireFrame();
    try std.testing.expectEqual(@as(usize, 0), pool.pendingRetireCount());
}

test "QUIC peer CID retire queue reuses consumed slots after wrap" {
    var pool = PeerPool{};

    for (0..max_retire_queue_len) |sequence_number| {
        try pool.queueRetire(@intCast(sequence_number));
    }
    try std.testing.expectError(
        error.RetireQueueFull,
        pool.queueRetire(max_retire_queue_len),
    );
    pool.discardRetireFrame();
    pool.discardRetireFrame();
    try std.testing.expectEqual(@as(usize, 2), pool.retire_queue_head);

    // Reusing freed head slots keeps FIFO retirement delivery without the
    // per-discard memmove that would otherwise run when several CIDs are
    // retired by one Retire Prior To update.
    try pool.queueRetire(max_retire_queue_len);
    try pool.queueRetire(max_retire_queue_len + 1);
    try std.testing.expectEqual(max_retire_queue_len, pool.pendingRetireCount());

    try pool.queueRetire(max_retire_queue_len + 1);
    try std.testing.expectEqual(max_retire_queue_len, pool.pendingRetireCount());
    for (2..max_retire_queue_len + 2) |expected| {
        try std.testing.expectEqual(
            @as(u64, @intCast(expected)),
            pool.peekRetireFrame().?.retire_connection_id.sequence_number,
        );
        pool.discardRetireFrame();
    }
    try std.testing.expectEqual(@as(usize, 0), pool.pendingRetireCount());
    try std.testing.expectEqual(@as(usize, 0), pool.retire_queue_head);
}

test "QUIC local CID pool rejects retiring packet DCID" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    const frame = try pool.issue("new-cid", [_]u8{1} ** 16);
    try std.testing.expectError(error.InvalidConnectionId, pool.retireExceptPacketDestination(1, frame.new_connection_id.connection_id));
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retireExceptPacketDestination(1, "other-cid");
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}

test "QUIC local CID pool accepts repeated retirement" {
    var pool = LocalPool{};
    try std.testing.expectEqual(@as(u64, 0), pool.activeRevision());
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    try std.testing.expectEqual(@as(u64, 1), pool.activeRevision());
    _ = try pool.issue("new-cid", [_]u8{1} ** 16);
    try std.testing.expectEqual(@as(u64, 2), pool.activeRevision());

    try pool.retire(0);
    try std.testing.expectEqual(@as(u64, 3), pool.activeRevision());
    try pool.retire(0);
    try std.testing.expectEqual(@as(u64, 3), pool.activeRevision());
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectError(error.UnknownConnectionId, pool.retire(2));
    try std.testing.expectEqual(@as(u64, 3), pool.activeRevision());
}

test "QUIC local CID pool issues and retires NEW_CONNECTION_ID frames" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    const frame = try pool.issue("new-cid", [_]u8{3} ** 16);
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.sequence_number);
    try std.testing.expectEqualStrings("new-cid", frame.new_connection_id.connection_id);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retire(0);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}

test "QUIC local CID pool rejects sequence numbers outside varint range before mutation" {
    var pool = LocalPool{};
    pool.next_sequence_number = @as(u64, quic.varint.max_value) + 1;
    const revision = pool.activeRevision();

    try std.testing.expectError(error.ConnectionIdSequenceLimit, pool.issue("new-cid", [_]u8{3} ** 16));
    try std.testing.expectEqual(@as(u64, quic.varint.max_value) + 1, pool.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
    try std.testing.expectEqual(revision, pool.activeRevision());
}

test "QUIC local CID pool issues replacement with retire_prior_to" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);

    const frame = try pool.issueWithRetirePriorTo("new-cid", [_]u8{3} ** 16, 1);
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.retire_prior_to);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.countAfterRetirePriorTo(1));
}

test "QUIC local CID pool rejects invalid retire_prior_to before mutation" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    pool.retire_prior_to = 2;

    try std.testing.expectError(error.RetirePriorToTooLarge, pool.issue("new-cid", [_]u8{3} ** 16));
    try std.testing.expectEqual(@as(u64, 1), pool.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(u64, 1), pool.activeRevision());
}

test "QUIC local CID pool keeps retire_prior_to monotonic across issuance" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);

    const replacement = try pool.issueWithRetirePriorTo(
        "replacement",
        [_]u8{1} ** 16,
        1,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        replacement.new_connection_id.retire_prior_to,
    );
    const later = try pool.issue("later-cid", [_]u8{2} ** 16);
    try std.testing.expectEqual(
        @as(u64, 1),
        later.new_connection_id.retire_prior_to,
    );
    const lower = try pool.issueWithRetirePriorTo(
        "lower-request",
        [_]u8{3} ** 16,
        0,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        lower.new_connection_id.retire_prior_to,
    );
}

test "QUIC local CID pool rejects duplicate IDs and reset tokens before mutation" {
    var pool = LocalPool{};
    const initial_token = [_]u8{0} ** 16;
    try pool.registerInitial("init-cid", initial_token);

    const issued = try pool.issue("issued-cid", [_]u8{1} ** 16);
    try std.testing.expectEqual(@as(u64, 1), issued.new_connection_id.sequence_number);

    try std.testing.expectError(error.DuplicateConnectionId, pool.issue("init-cid", [_]u8{2} ** 16));
    try std.testing.expectError(error.DuplicateResetToken, pool.issue("new-cid", initial_token));
    // If a candidate duplicates both a CID and another reset token, the
    // single-pass validator must preserve the historical error priority:
    // duplicate connection IDs are reported before duplicate reset tokens.
    try std.testing.expectError(error.DuplicateConnectionId, pool.issue("init-cid", [_]u8{1} ** 16));
    try std.testing.expectEqual(@as(u64, 2), pool.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try std.testing.expectEqual(@as(u64, 2), pool.activeRevision());
}

test "QUIC local CID pool derives stateless reset tokens from static key" {
    const key = [_]u8{0x42} ** quic.stateless_reset.static_key_len;
    var pool = LocalPool{};
    try pool.registerInitialWithStaticKey("init-cid", key);
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(key, "init-cid"),
        &pool.entries[0].stateless_reset_token,
    );

    const frame = try pool.issueWithStaticKey("new-cid", key);
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(key, "new-cid"),
        &frame.new_connection_id.stateless_reset_token,
    );
}

test "QUIC local CID pool registers preferred address at sequence one" {
    var pool = LocalPool{};
    const initial_token = [_]u8{0x31} ** 16;
    const preferred_token = [_]u8{0x32} ** 16;
    try pool.registerInitial("initial-cid", initial_token);
    try pool.registerPreferredAddress("preferred-cid", preferred_token);

    var storage: [max_pool_size]LocalPool.ActiveId = undefined;
    const active = try pool.activeIdsInto(&storage);
    try std.testing.expectEqual(@as(usize, 2), active.len);
    try std.testing.expectEqual(@as(u64, 0), active[0].sequence_number);
    try std.testing.expectEqualStrings(
        "initial-cid",
        active[0].connection_id,
    );
    try std.testing.expectEqual(@as(u64, 1), active[1].sequence_number);
    try std.testing.expectEqualStrings(
        "preferred-cid",
        active[1].connection_id,
    );
    try std.testing.expectEqual(@as(u64, 2), pool.next_sequence_number);

    const before = pool;
    try std.testing.expectError(
        error.ConnectionIdSequenceLimit,
        pool.registerPreferredAddress("second-preferred", [_]u8{0x33} ** 16),
    );
    try std.testing.expectEqualDeep(before, pool);

    var duplicate = LocalPool{};
    try duplicate.registerInitial("initial-cid", initial_token);
    try std.testing.expectError(
        error.DuplicateConnectionId,
        duplicate.registerPreferredAddress("initial-cid", preferred_token),
    );
    try std.testing.expectEqual(@as(u64, 1), duplicate.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 1), duplicate.count());
}

test "QUIC local CID pool exposes every active route into caller storage" {
    var pool = LocalPool{};
    try pool.registerInitial("initial", [_]u8{0} ** 16);
    _ = try pool.issue("next", [_]u8{1} ** 16);

    var storage: [max_pool_size]LocalPool.ActiveId = undefined;
    const active = try pool.activeIdsInto(&storage);
    try std.testing.expectEqual(@as(usize, 2), active.len);
    try std.testing.expectEqual(@as(u64, 0), active[0].sequence_number);
    try std.testing.expectEqualStrings("initial", active[0].connection_id);
    try std.testing.expectEqual(@as(u64, 1), active[1].sequence_number);
    try std.testing.expectEqualStrings("next", active[1].connection_id);
    try std.testing.expectError(
        error.BufferTooShort,
        pool.activeIdsInto(storage[0..1]),
    );
}

test "QUIC local CID pool issues draft-21 QUIC-LB IDs with reset tokens" {
    const config = quic.quic_lb.Config{
        .config_rotation = 2,
        .server_id_len = 3,
        .nonce_len = 4,
        .key = .{
            0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
            0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
        },
    };
    const reset_key = [_]u8{0x42} ** quic.stateless_reset.static_key_len;
    var pool = LocalPool{};
    try pool.registerInitialWithStaticKey("initial", reset_key);

    const frame = try pool.issueQuicLbRetirePriorTo(
        config,
        &.{ 0xed, 0x79, 0x3a },
        &.{ 0xee, 0x08, 0x0d, 0xbf },
        0,
        reset_key,
        1,
    );
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.retire_prior_to);
    try std.testing.expectEqual(@as(u3, 2), quic.quic_lb.extractConfigRotation(
        frame.new_connection_id.connection_id[0],
    ));
    var server_id: [3]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xed, 0x79, 0x3a },
        try quic.quic_lb.decodeServerId(
            config,
            frame.new_connection_id.connection_id,
            &server_id,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(
            reset_key,
            frame.new_connection_id.connection_id,
        ),
        &frame.new_connection_id.stateless_reset_token,
    );
    // The frame borrows stable pool storage, not the stack scratch used by
    // issueQuicLbRetirePriorTo.
    try std.testing.expectEqualSlices(
        u8,
        pool.entries[1].slice(),
        frame.new_connection_id.connection_id,
    );
}

test "QUIC local CID pool QUIC-LB issuance is transactional on failure" {
    const config = quic.quic_lb.Config{
        .config_rotation = 1,
        .server_id_len = 2,
        .nonce_len = 4,
    };
    const reset_key = [_]u8{0x24} ** quic.stateless_reset.static_key_len;
    var pool = LocalPool{};
    try pool.registerInitialWithStaticKey("initial", reset_key);
    const before = pool;

    try std.testing.expectError(
        error.InvalidNonceLength,
        pool.issueQuicLb(
            config,
            "id",
            "bad",
            0,
            reset_key,
        ),
    );
    try std.testing.expectEqualDeep(before, pool);

    try std.testing.expectError(
        error.RetirePriorToTooLarge,
        pool.issueQuicLbRetirePriorTo(
            config,
            "id",
            "good",
            0,
            reset_key,
            2,
        ),
    );
    try std.testing.expectEqualDeep(before, pool);
}
