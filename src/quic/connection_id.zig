const std = @import("std");
const quic = @import("mod.zig");

pub const max_pool_size: usize = 8;
pub const max_connection_id_len: usize = 20;

pub const Error = error{
    InvalidConnectionId,
    DuplicateConnectionId,
    DuplicateResetToken,
    ActiveConnectionIdLimit,
    PoolFull,
    UnknownConnectionId,
    RetireQueueFull,
    RetirePriorToTooLarge,
    ConnectionIdSequenceLimit,
} || quic.quic_lb.Error || std.mem.Allocator.Error;

pub const Entry = struct {
    sequence_number: u64 = 0,
    connection_id: [max_connection_id_len]u8 = .{0} ** max_connection_id_len,
    connection_id_len: u8 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    in_use: bool = false,
    occupied: bool = false,

    pub fn slice(self: *const Entry) []const u8 {
        return self.connection_id[0..self.connection_id_len];
    }
};

pub const max_retire_queue_len: usize = max_pool_size * 4;

pub const PeerPool = struct {
    entries: [max_pool_size]Entry = .{Entry{}} ** max_pool_size,
    retire_queue: [max_retire_queue_len]u64 = .{0} ** max_retire_queue_len,
    retire_queue_len: usize = 0,
    largest_retire_prior_to: u64 = 0,

    pub fn add(self: *PeerPool, sequence_number: u64, connection_id: []const u8, token: [16]u8) Error!void {
        try self.addWithLimit(sequence_number, connection_id, token, max_pool_size);
    }

    pub fn addWithRetirePriorTo(
        self: *PeerPool,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: []const u8,
        token: [16]u8,
        active_limit: usize,
    ) Error!void {
        if (retire_prior_to > sequence_number) return error.RetirePriorToTooLarge;
        try self.retirePriorTo(retire_prior_to);
        // RFC 9000 §19.15: if a NEW_CONNECTION_ID arrives below a previously
        // advertised Retire Prior To, the endpoint sends RETIRE_CONNECTION_ID
        // rather than making the stale CID active again.  Keeping this in the
        // pool layer lets receive preflight use a value-copy shadow pool without
        // committing partial CID lifecycle changes.
        if (sequence_number < self.largest_retire_prior_to) {
            try self.queueRetire(sequence_number);
            return;
        }
        try self.addWithLimit(sequence_number, connection_id, token, active_limit);
    }

    pub fn addWithLimit(self: *PeerPool, sequence_number: u64, connection_id: []const u8, token: [16]u8, active_limit: usize) Error!void {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        if (self.find(sequence_number)) |entry| {
            if (!std.mem.eql(u8, entry.slice(), connection_id)) return error.DuplicateConnectionId;
            if (!std.mem.eql(u8, &entry.stateless_reset_token, &token)) return error.DuplicateResetToken;
            entry.connection_id_len = @intCast(connection_id.len);
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            entry.stateless_reset_token = token;
            entry.occupied = true;
            return;
        }
        if (self.findByConnectionId(connection_id) != null) return error.DuplicateConnectionId;
        if (self.findByResetToken(token) != null) return error.DuplicateResetToken;
        if (self.count() >= active_limit) return error.ActiveConnectionIdLimit;
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.* = .{ .sequence_number = sequence_number, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
                @memcpy(entry.connection_id[0..connection_id.len], connection_id);
                return;
            }
        }
        return error.PoolFull;
    }

    pub fn retirePriorTo(self: *PeerPool, sequence_number: u64) Error!void {
        if (sequence_number <= self.largest_retire_prior_to) return;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number < sequence_number) {
                try self.queueRetire(entry.sequence_number);
                entry.* = .{};
            }
        }
        self.largest_retire_prior_to = sequence_number;
    }

    pub fn pendingRetireCount(self: *const PeerPool) usize {
        return self.retire_queue_len;
    }

    pub fn peekRetireFrame(self: *const PeerPool) ?quic.Frame {
        if (self.retire_queue_len == 0) return null;
        return .{ .retire_connection_id = .{ .sequence_number = self.retire_queue[0] } };
    }

    pub fn discardRetireFrame(self: *PeerPool) void {
        if (self.retire_queue_len == 0) return;
        if (self.retire_queue_len > 1) {
            std.mem.copyForwards(u64, self.retire_queue[0 .. self.retire_queue_len - 1], self.retire_queue[1..self.retire_queue_len]);
        }
        self.retire_queue_len -= 1;
        self.retire_queue[self.retire_queue_len] = 0;
    }

    fn queueRetire(self: *PeerPool, sequence_number: u64) Error!void {
        for (self.retire_queue[0..self.retire_queue_len]) |queued| {
            if (queued == sequence_number) return;
        }
        if (self.retire_queue_len >= self.retire_queue.len) return error.RetireQueueFull;
        self.retire_queue[self.retire_queue_len] = sequence_number;
        self.retire_queue_len += 1;
    }

    pub fn consumeUnused(self: *PeerPool) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.in_use) {
                entry.in_use = true;
                return entry;
            }
        }
        return null;
    }

    pub fn markInUse(self: *PeerPool, sequence_number: u64) Error!void {
        const entry = self.find(sequence_number) orelse return error.UnknownConnectionId;
        entry.in_use = true;
    }

    pub fn detectStatelessReset(self: *const PeerPool, datagram: []const u8) ?u64 {
        for (&self.entries) |*entry| {
            if (!entry.occupied or !entry.in_use) continue;
            if (quic.stateless_reset.matches(datagram, entry.stateless_reset_token)) return entry.sequence_number;
        }
        return null;
    }

    pub fn count(self: *const PeerPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }

    fn find(self: *PeerPool, sequence_number: u64) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number == sequence_number) return entry;
        }
        return null;
    }

    fn findByConnectionId(self: *PeerPool, connection_id: []const u8) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and std.mem.eql(u8, entry.slice(), connection_id)) return entry;
        }
        return null;
    }

    fn findByResetToken(self: *PeerPool, token: [16]u8) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and std.mem.eql(u8, &entry.stateless_reset_token, &token)) return entry;
        }
        return null;
    }
};

pub const LocalPool = struct {
    entries: [max_pool_size]Entry = .{Entry{}} ** max_pool_size,
    next_sequence_number: u64 = 0,
    retire_prior_to: u64 = 0,

    pub fn registerInitial(self: *LocalPool, connection_id: []const u8, token: [16]u8) Error!void {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        self.entries[0] = .{ .sequence_number = 0, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
        @memcpy(self.entries[0].connection_id[0..connection_id.len], connection_id);
        self.next_sequence_number = 1;
    }

    pub fn registerInitialWithStaticKey(
        self: *LocalPool,
        connection_id: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
    ) Error!void {
        try self.registerInitial(connection_id, quic.stateless_reset.tokenForConnectionId(static_key, connection_id));
    }

    pub fn issue(self: *LocalPool, connection_id: []const u8, token: [16]u8) Error!quic.Frame {
        return try self.issueWithRetirePriorTo(connection_id, token, self.retire_prior_to);
    }

    pub fn issueWithRetirePriorTo(
        self: *LocalPool,
        connection_id: []const u8,
        token: [16]u8,
        retire_prior_to: u64,
    ) Error!quic.Frame {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        // NEW_CONNECTION_ID sequence numbers are encoded as QUIC varints.
        // Reject exhaustion before looking for a slot or advancing the counter
        // so callers can observe and handle a stable pool state.
        if (self.next_sequence_number > quic.varint.max_value) return error.ConnectionIdSequenceLimit;
        if (retire_prior_to > self.next_sequence_number) return error.RetirePriorToTooLarge;
        const slot = try self.availableIssueSlot(connection_id, token);
        if (slot) |entry| {
            const seq = self.next_sequence_number;
            self.next_sequence_number += 1;
            entry.* = .{ .sequence_number = seq, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            return .{ .new_connection_id = .{
                .sequence_number = seq,
                .retire_prior_to = retire_prior_to,
                .connection_id = entry.slice(),
                .stateless_reset_token = token,
            } };
        }
        return error.PoolFull;
    }

    fn availableIssueSlot(
        self: *LocalPool,
        connection_id: []const u8,
        token: [16]u8,
    ) Error!?*Entry {
        var first_empty: ?*Entry = null;
        var duplicate_token = false;
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                if (first_empty == null) first_empty = entry;
                continue;
            }
            if (std.mem.eql(u8, entry.slice(), connection_id)) {
                return error.DuplicateConnectionId;
            }
            if (std.mem.eql(u8, &entry.stateless_reset_token, &token)) {
                duplicate_token = true;
            }
        }
        if (duplicate_token) return error.DuplicateResetToken;
        return first_empty;
    }

    pub fn countAfterRetirePriorTo(self: *const LocalPool, retire_prior_to: u64) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number >= retire_prior_to) n += 1;
        }
        return n;
    }

    pub fn issueWithStaticKey(
        self: *LocalPool,
        connection_id: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
    ) Error!quic.Frame {
        return try self.issue(connection_id, quic.stateless_reset.tokenForConnectionId(static_key, connection_id));
    }

    pub fn issueWithStaticKeyRetirePriorTo(
        self: *LocalPool,
        connection_id: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
        retire_prior_to: u64,
    ) Error!quic.Frame {
        return try self.issueWithRetirePriorTo(connection_id, quic.stateless_reset.tokenForConnectionId(static_key, connection_id), retire_prior_to);
    }

    /// Generate, register, and advertise a QUIC-LB CID as one transaction.
    ///
    /// The encoded CID is first built in stack storage. `issueWithStaticKey`
    /// then performs duplicate, pool-capacity, sequence, and retire-prior-to
    /// validation before copying it into stable pool storage. No caller-owned
    /// nonce or temporary CID slice escapes this function.
    pub fn issueQuicLb(
        self: *LocalPool,
        config: quic.quic_lb.Config,
        server_id: []const u8,
        nonce: []const u8,
        first_octet_random_bits: u5,
        static_reset_key: [quic.stateless_reset.static_key_len]u8,
    ) Error!quic.Frame {
        return self.issueQuicLbRetirePriorTo(
            config,
            server_id,
            nonce,
            first_octet_random_bits,
            static_reset_key,
            self.retire_prior_to,
        );
    }

    pub fn issueQuicLbRetirePriorTo(
        self: *LocalPool,
        config: quic.quic_lb.Config,
        server_id: []const u8,
        nonce: []const u8,
        first_octet_random_bits: u5,
        static_reset_key: [quic.stateless_reset.static_key_len]u8,
        retire_prior_to: u64,
    ) Error!quic.Frame {
        var cid_storage: [max_connection_id_len]u8 = undefined;
        const connection_id = try quic.quic_lb.encode(
            config,
            server_id,
            nonce,
            first_octet_random_bits,
            &cid_storage,
        );
        return self.issueWithStaticKeyRetirePriorTo(
            connection_id,
            static_reset_key,
            retire_prior_to,
        );
    }

    pub fn retire(self: *LocalPool, sequence_number: u64) Error!void {
        try self.retireExceptPacketDestination(sequence_number, null);
    }

    pub fn retireExceptPacketDestination(self: *LocalPool, sequence_number: u64, packet_destination_connection_id: ?[]const u8) Error!void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number == sequence_number) {
                if (packet_destination_connection_id) |dcid| {
                    if (std.mem.eql(u8, entry.slice(), dcid)) return error.InvalidConnectionId;
                }
                entry.* = .{};
                return;
            }
        }
        return error.UnknownConnectionId;
    }

    pub fn count(self: *const LocalPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }
};

test "QUIC peer CID pool stores retires and consumes IDs" {
    var pool = PeerPool{};
    try pool.add(1, "cid-one", [_]u8{1} ** 16);
    try pool.add(2, "cid-two", [_]u8{2} ** 16);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retirePriorTo(2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    try std.testing.expectEqual(@as(usize, 1), pool.pendingRetireCount());
    try std.testing.expectEqual(@as(u64, 1), pool.peekRetireFrame().?.retire_connection_id.sequence_number);
    const entry = pool.consumeUnused().?;
    try std.testing.expectEqual(@as(u64, 2), entry.sequence_number);
    try std.testing.expectEqualStrings("cid-two", entry.slice());
    try std.testing.expect(pool.consumeUnused() == null);
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
    try std.testing.expectEqual(@as(?u64, 7), pool.detectStatelessReset(datagram.items));
    try std.testing.expectEqual(@as(?u64, null), pool.detectStatelessReset(&.{ 0x40, 1, 2 }));
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

test "QUIC local CID pool rejects retiring packet DCID" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    const frame = try pool.issue("new-cid", [_]u8{1} ** 16);
    try std.testing.expectError(error.InvalidConnectionId, pool.retireExceptPacketDestination(1, frame.new_connection_id.connection_id));
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retireExceptPacketDestination(1, "other-cid");
    try std.testing.expectEqual(@as(usize, 1), pool.count());
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

    try std.testing.expectError(error.ConnectionIdSequenceLimit, pool.issue("new-cid", [_]u8{3} ** 16));
    try std.testing.expectEqual(@as(u64, quic.varint.max_value) + 1, pool.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
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
