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
} || std.mem.Allocator.Error;

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
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        // NEW_CONNECTION_ID sequence numbers are encoded as QUIC varints.
        // Reject exhaustion before looking for a slot or advancing the counter
        // so callers can observe and handle a stable pool state.
        if (self.next_sequence_number > quic.varint.max_value) return error.ConnectionIdSequenceLimit;
        if (self.retire_prior_to > self.next_sequence_number) return error.RetirePriorToTooLarge;
        if (self.containsConnectionId(connection_id)) return error.DuplicateConnectionId;
        if (self.containsResetToken(token)) return error.DuplicateResetToken;
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                const seq = self.next_sequence_number;
                self.next_sequence_number += 1;
                entry.* = .{ .sequence_number = seq, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
                @memcpy(entry.connection_id[0..connection_id.len], connection_id);
                return .{ .new_connection_id = .{
                    .sequence_number = seq,
                    .retire_prior_to = self.retire_prior_to,
                    .connection_id = entry.slice(),
                    .stateless_reset_token = token,
                } };
            }
        }
        return error.PoolFull;
    }

    fn containsConnectionId(self: *const LocalPool, connection_id: []const u8) bool {
        for (&self.entries) |*entry| {
            if (entry.occupied and std.mem.eql(u8, entry.slice(), connection_id)) return true;
        }
        return false;
    }

    fn containsResetToken(self: *const LocalPool, token: [16]u8) bool {
        for (&self.entries) |*entry| {
            if (entry.occupied and std.mem.eql(u8, &entry.stateless_reset_token, &token)) return true;
        }
        return false;
    }

    pub fn issueWithStaticKey(
        self: *LocalPool,
        connection_id: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
    ) Error!quic.Frame {
        return try self.issue(connection_id, quic.stateless_reset.tokenForConnectionId(static_key, connection_id));
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

    try std.testing.expectError(error.DuplicateConnectionId, pool.issue("init-cid", [_]u8{1} ** 16));
    try std.testing.expectError(error.DuplicateResetToken, pool.issue("new-cid", initial_token));
    try std.testing.expectEqual(@as(u64, 1), pool.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    _ = try pool.issue("new-cid", [_]u8{2} ** 16);
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
