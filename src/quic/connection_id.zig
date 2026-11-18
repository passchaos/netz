const std = @import("std");
const quic = @import("mod.zig");

pub const max_pool_size: usize = 8;
pub const max_connection_id_len: usize = 20;

pub const Error = error{
    BufferTooShort,
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
    /// Initial peer CIDs have no token until a client authenticates the
    /// server's stateless_reset_token transport parameter. NEW_CONNECTION_ID
    /// and local CIDs always set this field when they install their token.
    stateless_reset_token_available: bool = false,
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
    retire_queue_head: usize = 0,
    retire_queue_len: usize = 0,
    largest_retire_prior_to: u64 = 0,
    in_use_count: usize = 0,

    pub fn add(self: *PeerPool, sequence_number: u64, connection_id: []const u8, token: [16]u8) Error!void {
        try self.addWithLimit(sequence_number, connection_id, token, max_pool_size);
    }

    /// Register the peer's Initial Source Connection ID. Unlike a
    /// NEW_CONNECTION_ID value, RFC 9000 permits this initial CID to be empty.
    /// A zero-length peer CID disables migration/stateless-reset rotation but
    /// remains the active sequence-zero destination for short packets.
    pub fn addInitial(
        self: *PeerPool,
        connection_id: []const u8,
    ) Error!void {
        if (connection_id.len > max_connection_id_len) {
            return error.InvalidConnectionId;
        }
        const entry = &self.entries[0];
        entry.* = .{
            .sequence_number = 0,
            .connection_id_len = @intCast(connection_id.len),
            .occupied = true,
            .in_use = true,
        };
        @memcpy(entry.connection_id[0..connection_id.len], connection_id);
        self.in_use_count = 1;
    }

    /// Attach the server's transport-parameter reset token to the peer's
    /// already-active Initial connection ID. Clients learn this token outside
    /// NEW_CONNECTION_ID, so it must become matchable without changing CID
    /// occupancy or use counts.
    pub fn setInitialStatelessResetToken(
        self: *PeerPool,
        token: [quic.stateless_reset.token_len]u8,
    ) Error!void {
        const entry = self.find(0) orelse return error.UnknownConnectionId;
        for (&self.entries) |*other| {
            if (!other.occupied or other == entry) continue;
            if (other.stateless_reset_token_available and
                std.mem.eql(u8, &other.stateless_reset_token, &token))
            {
                return error.DuplicateResetToken;
            }
        }
        entry.stateless_reset_token = token;
        entry.stateless_reset_token_available = true;
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
            if (!entry.stateless_reset_token_available or
                !std.mem.eql(u8, &entry.stateless_reset_token, &token))
            {
                return error.DuplicateResetToken;
            }
            entry.connection_id_len = @intCast(connection_id.len);
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            entry.stateless_reset_token = token;
            entry.stateless_reset_token_available = true;
            entry.occupied = true;
            return;
        }
        const slot = try self.availableAddSlot(connection_id, token, active_limit);
        if (slot) |entry| {
            entry.* = .{ .sequence_number = sequence_number, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .stateless_reset_token_available = true, .occupied = true };
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            return;
        }
        return error.PoolFull;
    }

    pub fn retirePriorTo(self: *PeerPool, sequence_number: u64) Error!void {
        if (sequence_number <= self.largest_retire_prior_to) return;
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number < sequence_number) {
                try self.queueRetire(entry.sequence_number);
                if (entry.in_use) self.in_use_count -|= 1;
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
        return .{ .retire_connection_id = .{
            .sequence_number = self.retire_queue[self.retireQueueIndex(0)],
        } };
    }

    pub fn discardRetireFrame(self: *PeerPool) void {
        if (self.retire_queue_len == 0) return;
        const head = self.retireQueueIndex(0);
        self.retire_queue[head] = 0;
        self.retire_queue_len -= 1;
        if (self.retire_queue_len == 0) {
            self.retire_queue_head = 0;
        } else {
            self.retire_queue_head = self.retireQueueIndex(1);
        }
    }

    pub fn queueRetire(self: *PeerPool, sequence_number: u64) Error!void {
        for (0..self.retire_queue_len) |offset| {
            const queued = self.retire_queue[self.retireQueueIndex(offset)];
            if (queued == sequence_number) return;
        }
        if (self.retire_queue_len >= self.retire_queue.len) return error.RetireQueueFull;
        const tail = self.retireQueueIndex(self.retire_queue_len);
        self.retire_queue[tail] = sequence_number;
        self.retire_queue_len += 1;
    }

    fn retireQueueIndex(self: *const PeerPool, offset: usize) usize {
        return (self.retire_queue_head + offset) % self.retire_queue.len;
    }

    pub fn consumeUnused(self: *PeerPool) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.in_use) {
                entry.in_use = true;
                self.in_use_count += 1;
                return entry;
            }
        }
        return null;
    }

    /// Rotate one active path to a fresh peer CID and queue retirement of the
    /// previous identifier as one transaction. Failure to reserve the bounded
    /// retirement queue leaves both CID entries and use counts unchanged.
    pub fn rotateToUnused(
        self: *PeerPool,
        current_connection_id: []const u8,
    ) Error!?*Entry {
        var current: ?*Entry = null;
        var replacement: ?*Entry = null;
        for (&self.entries) |*entry| {
            if (!entry.occupied) continue;
            if (entry.in_use and
                std.mem.eql(u8, entry.slice(), current_connection_id))
            {
                current = entry;
            } else if (!entry.in_use and replacement == null) {
                replacement = entry;
            }
        }
        const old = current orelse return error.UnknownConnectionId;
        const next = replacement orelse return null;
        try self.queueRetire(old.sequence_number);
        old.* = .{};
        self.in_use_count -|= 1;
        next.in_use = true;
        self.in_use_count += 1;
        return next;
    }

    pub fn markInUse(self: *PeerPool, sequence_number: u64) Error!void {
        const entry = self.find(sequence_number) orelse return error.UnknownConnectionId;
        if (!entry.in_use) self.in_use_count += 1;
        entry.in_use = true;
    }

    /// Return pool-owned storage for a peer connection ID that has actually
    /// been used. Path fallback must not retain a config slice across peer CID
    /// retirement and replacement.
    pub fn activeConnectionId(
        self: *const PeerPool,
        connection_id: []const u8,
    ) ?[]const u8 {
        for (&self.entries) |*entry| {
            if (!entry.occupied or !entry.in_use) continue;
            if (std.mem.eql(u8, entry.slice(), connection_id)) {
                return entry.slice();
            }
        }
        return null;
    }

    /// Select a usable destination CID for a path. Prefer the path's previous
    /// CID, then consume a fresh peer-issued CID, and only reuse another active
    /// CID when no unused value remains.
    pub fn selectForPath(
        self: *PeerPool,
        preferred: []const u8,
    ) ?[]const u8 {
        if (self.activeConnectionId(preferred)) |connection_id| {
            return connection_id;
        }
        var oldest_unused: ?*Entry = null;
        for (&self.entries) |*entry| {
            if (!entry.occupied or entry.in_use) continue;
            if (oldest_unused == null or
                entry.sequence_number < oldest_unused.?.sequence_number)
            {
                oldest_unused = entry;
            }
        }
        if (oldest_unused) |entry| {
            entry.in_use = true;
            self.in_use_count += 1;
            return entry.slice();
        }
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.in_use) return entry.slice();
        }
        return null;
    }

    pub fn detectStatelessReset(self: *const PeerPool, datagram: []const u8) ?u64 {
        const candidate = quic.stateless_reset.tokenCandidate(datagram) orelse
            return null;
        return self.detectStatelessResetToken(candidate);
    }

    /// Match a token copied from a datagram before an in-place decrypt.
    ///
    /// The receive pipeline does not call this until packet authentication has
    /// failed, as required by RFC 9000 section 10.3. The separate token form is
    /// necessary because AEAD plaintext output is undefined on failure; callers
    /// must not depend on the in-place crypto backend preserving any bytes.
    pub fn detectStatelessResetToken(
        self: *const PeerPool,
        candidate: [quic.stateless_reset.token_len]u8,
    ) ?u64 {
        if (self.in_use_count == 0) return null;
        for (&self.entries) |*entry| {
            if (!entry.occupied or !entry.in_use or
                !entry.stateless_reset_token_available) continue;
            if (quic.stateless_reset.matchesToken(
                candidate,
                entry.stateless_reset_token,
            )) return entry.sequence_number;
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

    fn availableAddSlot(
        self: *PeerPool,
        connection_id: []const u8,
        token: [16]u8,
        active_limit: usize,
    ) Error!?*Entry {
        var first_empty: ?*Entry = null;
        var occupied_count: usize = 0;
        var duplicate_token = false;
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                if (first_empty == null) first_empty = entry;
                continue;
            }
            occupied_count += 1;
            if (std.mem.eql(u8, entry.slice(), connection_id)) {
                return error.DuplicateConnectionId;
            }
            if (entry.stateless_reset_token_available and
                std.mem.eql(u8, &entry.stateless_reset_token, &token))
            {
                duplicate_token = true;
            }
        }
        if (duplicate_token) return error.DuplicateResetToken;
        if (occupied_count >= active_limit) return error.ActiveConnectionIdLimit;
        return first_empty;
    }
};

pub const LocalPool = struct {
    entries: [max_pool_size]Entry = .{Entry{}} ** max_pool_size,
    next_sequence_number: u64 = 0,
    retire_prior_to: u64 = 0,
    /// Monotonic structural generation for endpoint CID-route mirrors. Only
    /// successful active-set changes advance it; value-copy transaction
    /// rollback restores it with the rest of the fixed-size pool.
    active_revision: u64 = 0,

    pub fn registerInitial(self: *LocalPool, connection_id: []const u8, token: [16]u8) Error!void {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        self.entries[0] = .{ .sequence_number = 0, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .stateless_reset_token_available = true, .occupied = true };
        @memcpy(self.entries[0].connection_id[0..connection_id.len], connection_id);
        self.next_sequence_number = 1;
        self.advanceActiveRevision();
    }

    pub fn registerInitialWithStaticKey(
        self: *LocalPool,
        connection_id: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
    ) Error!void {
        try self.registerInitial(connection_id, quic.stateless_reset.tokenForConnectionId(static_key, connection_id));
    }

    /// Register the server CID carried by preferred_address as sequence 1.
    /// Unlike `issue`, this CID has already been advertised in transport
    /// parameters and therefore must not produce NEW_CONNECTION_ID.
    pub fn registerPreferredAddress(
        self: *LocalPool,
        connection_id: []const u8,
        token: [16]u8,
    ) Error!void {
        if (self.next_sequence_number != 1 or self.count() != 1) {
            return error.ConnectionIdSequenceLimit;
        }
        _ = try self.issue(connection_id, token);
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
        const effective_retire_prior_to = @max(
            self.retire_prior_to,
            retire_prior_to,
        );
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        // NEW_CONNECTION_ID sequence numbers are encoded as QUIC varints.
        // Reject exhaustion before looking for a slot or advancing the counter
        // so callers can observe and handle a stable pool state.
        if (self.next_sequence_number > quic.varint.max_value) return error.ConnectionIdSequenceLimit;
        if (effective_retire_prior_to > self.next_sequence_number) return error.RetirePriorToTooLarge;
        const slot = try self.availableIssueSlot(connection_id, token);
        if (slot) |entry| {
            const seq = self.next_sequence_number;
            self.next_sequence_number += 1;
            self.retire_prior_to = effective_retire_prior_to;
            entry.* = .{ .sequence_number = seq, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .stateless_reset_token_available = true, .occupied = true };
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            self.advanceActiveRevision();
            return .{ .new_connection_id = .{
                .sequence_number = seq,
                .retire_prior_to = effective_retire_prior_to,
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
            if (entry.stateless_reset_token_available and
                std.mem.eql(u8, &entry.stateless_reset_token, &token))
            {
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

    pub fn effectiveRetirePriorTo(
        self: *const LocalPool,
        requested: u64,
    ) u64 {
        return @max(self.retire_prior_to, requested);
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
                self.advanceActiveRevision();
                return;
            }
        }
        // RETIRE_CONNECTION_ID is retransmittable. Since local sequence
        // numbers are issued contiguously, a missing value below the next
        // sequence was previously issued and retired; accept it idempotently.
        // A value at or beyond next_sequence_number was never provided.
        if (sequence_number < self.next_sequence_number) return;
        return error.UnknownConnectionId;
    }

    pub fn count(self: *const LocalPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }

    pub fn activeRevision(self: *const LocalPool) u64 {
        return self.active_revision;
    }

    fn advanceActiveRevision(self: *LocalPool) void {
        // CID sequence numbers are QUIC varints and every issued ID can be
        // retired at most once, so a connection cannot reach 2^64 structural
        // changes and wrap this generation within the protocol's lifetime.
        self.active_revision +%= 1;
    }

    pub const ActiveId = struct {
        sequence_number: u64,
        connection_id: []const u8,
    };

    /// Copy borrowed views of every currently accepted local CID into caller
    /// storage. The slices remain valid until the pool is mutated. Endpoint
    /// dispatchers use this to mirror NEW_CONNECTION_ID/RETIRE_CONNECTION_ID
    /// state without exposing stateless-reset keys or mutable pool entries.
    pub fn activeIdsInto(
        self: *const LocalPool,
        out: []ActiveId,
    ) Error![]ActiveId {
        var written: usize = 0;
        for (&self.entries) |*entry| {
            if (!entry.occupied) continue;
            if (written == out.len) return error.BufferTooShort;
            out[written] = .{
                .sequence_number = entry.sequence_number,
                .connection_id = entry.slice(),
            };
            written += 1;
        }
        return out[0..written];
    }
};

test {
    _ = @import("connection_id/tests.zig");
}
