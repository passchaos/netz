//! Bounded owning server-side store for issued TLS 1.3 session tickets.
//!
//! Ticket identities and PSKs are copied into stable storage. Lookups return an
//! owning lease so concurrent eviction or ticket rotation cannot invalidate a
//! resumed handshake. Expired entries are removed eagerly on issue/lookup.

const std = @import("std");
const vail = @import("vail");
const codec = @import("vail").tls.ticket;

const CipherSuite = vail.tls.cipher_suite.Suite;
const Secret = vail.tls.secret.Secret;

const IdentityIndex = std.StringHashMapUnmanaged(usize);

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapacity,
    InvalidTicket,
    InvalidTicketLifetime,
};

pub const Issued = struct {
    identity: []const u8,
    secret: [32]u8,
    secret_value: ?Secret = null,
    age_add: u32,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
    issued_at_ms: u64,
    lifetime_seconds: u32,
};

pub const Lease = struct {
    allocator: std.mem.Allocator,
    identity: []u8,
    secret: [32]u8,
    secret_value: Secret,
    age_add: u32,
    cipher_suite: CipherSuite,
    issued_at_ms: u64,
    lifetime_seconds: u32,

    pub fn deinit(self: *Lease) void {
        vail.crypto.memory.zero(self.identity);
        self.allocator.free(self.identity);
        vail.crypto.memory.zeroValue(&self.secret);
        self.secret_value.deinit();
        self.* = undefined;
    }
};

const Entry = struct {
    identity: []u8,
    secret: [32]u8,
    secret_value: Secret,
    age_add: u32,
    cipher_suite: CipherSuite,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    sequence: u64,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        vail.crypto.memory.zero(self.identity);
        allocator.free(self.identity);
        vail.crypto.memory.zeroValue(&self.secret);
        self.secret_value.deinit();
        self.* = undefined;
    }

    fn expired(self: Entry, now_ms: u64) bool {
        if (now_ms < self.issued_at_ms) return true;
        const lifetime_ms = @as(u64, self.lifetime_seconds) *
            std.time.ms_per_s;
        return now_ms - self.issued_at_ms > lifetime_ms;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    max_entries: usize,
    entries: std.ArrayList(Entry) = .empty,
    /// Maps ticket identities to their current physical slot in `entries`.
    /// The map keys borrow entry-owned identity slices, so replacement must
    /// retarget the stored key before freeing old identity bytes and every
    /// swap-remove path must repair the moved entry's slot.
    identity_index: IdentityIndex = .empty,
    oldest_index: ?usize = null,
    next_sequence: u64 = 1,
    mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
    ) Error!Store {
        if (max_entries == 0 or max_entries > @as(usize, std.math.maxInt(IdentityIndex.Size))) {
            return error.InvalidCapacity;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.identity_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn issue(self: *Store, issued: Issued) Error!void {
        try validateIssued(issued);
        const secret_value =
            issued.secret_value orelse Secret.fromSha256(issued.secret);
        const identity = try self.allocator.dupe(u8, issued.identity);
        errdefer self.allocator.free(identity);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpired(issued.issued_at_ms);

        const slot = try self.identity_index.getOrPut(
            self.allocator,
            issued.identity,
        );
        if (slot.found_existing) {
            const index = slot.value_ptr.*;
            self.replaceEntryAt(index, .{
                .identity = identity,
                .secret = issued.secret,
                .secret_value = secret_value,
                .age_add = issued.age_add,
                .cipher_suite = issued.cipher_suite,
                .issued_at_ms = issued.issued_at_ms,
                .lifetime_seconds = issued.lifetime_seconds,
                .sequence = self.nextSequence(),
            });
            return;
        }
        errdefer _ = self.identity_index.remove(issued.identity);

        if (self.entries.items.len < self.max_entries) {
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
            self.appendEntryAssumeCapacity(.{
                .identity = identity,
                .secret = issued.secret,
                .secret_value = secret_value,
                .age_add = issued.age_add,
                .cipher_suite = issued.cipher_suite,
                .issued_at_ms = issued.issued_at_ms,
                .lifetime_seconds = issued.lifetime_seconds,
                .sequence = self.nextSequence(),
            }, slot.key_ptr, slot.value_ptr);
        } else {
            var evicted = self.removeEntryAt(self.oldestIndex());
            evicted.deinit(self.allocator);
            // `removeEntryAt` mutates the string map, so the pointers returned
            // by the earlier getOrPut may no longer be stable on the eviction
            // path. Reacquire them after the old ticket has been removed; the
            // common non-evicting issue path above still performs one map
            // lookup.
            self.appendEntryAssumeCapacity(.{
                .identity = identity,
                .secret = issued.secret,
                .secret_value = secret_value,
                .age_add = issued.age_add,
                .cipher_suite = issued.cipher_suite,
                .issued_at_ms = issued.issued_at_ms,
                .lifetime_seconds = issued.lifetime_seconds,
                .sequence = self.nextSequence(),
            }, self.identity_index.getKeyPtr(issued.identity).?, self.identity_index.getPtr(issued.identity).?);
        }
    }

    pub fn lookup(
        self: *Store,
        identity: []const u8,
        now_ms: u64,
    ) Error!?Lease {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpired(now_ms);
        const index = self.identity_index.get(identity) orelse return null;
        var entry = &self.entries.items[index];
        const identity_copy = try self.allocator.dupe(u8, entry.identity);
        entry.sequence = self.nextSequence();
        if (self.oldest_index == index) self.recomputeOldest();
        return .{
            .allocator = self.allocator,
            .identity = identity_copy,
            .secret = entry.secret,
            .secret_value = entry.secret_value,
            .age_add = entry.age_add,
            .cipher_suite = entry.cipher_suite,
            .issued_at_ms = entry.issued_at_ms,
            .lifetime_seconds = entry.lifetime_seconds,
        };
    }

    pub fn count(self: *Store, now_ms: u64) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpired(now_ms);
        return self.entries.items.len;
    }

    fn pruneExpired(self: *Store, now_ms: u64) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (!self.entries.items[index].expired(now_ms)) {
                index += 1;
                continue;
            }
            var expired = self.removeEntryAt(index);
            expired.deinit(self.allocator);
        }
    }

    fn appendEntryAssumeCapacity(
        self: *Store,
        entry: Entry,
        key_slot: *[]const u8,
        index_slot: *usize,
    ) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        key_slot.* = self.entries.items[index].identity;
        index_slot.* = index;
        self.considerOldest(index);
    }

    fn replaceEntryAt(self: *Store, index: usize, replacement: Entry) void {
        var replaced = self.entries.items[index];
        self.entries.items[index] = replacement;
        const key_ptr = self.identity_index.getKeyPtr(replaced.identity) orelse
            unreachable;
        key_ptr.* = self.entries.items[index].identity;
        if (self.oldest_index == index) self.recomputeOldest() else self.considerOldest(index);
        replaced.deinit(self.allocator);
    }

    fn removeEntryAt(self: *Store, index: usize) Entry {
        const old_len = self.entries.items.len;
        const oldest = self.oldest_index;
        const removed = self.entries.swapRemove(index);
        _ = self.identity_index.remove(removed.identity);
        if (index != old_len - 1) {
            const moved = self.entries.items[index];
            self.identity_index.getPtr(moved.identity).?.* = index;
        }
        if (self.entries.items.len == 0) {
            self.oldest_index = null;
        } else if (oldest == index) {
            self.recomputeOldest();
        } else if (oldest == old_len - 1) {
            self.oldest_index = index;
        }
        return removed;
    }

    fn oldestIndex(self: *Store) usize {
        return self.oldest_index.?;
    }

    fn considerOldest(self: *Store, index: usize) void {
        const oldest = self.oldest_index orelse {
            self.oldest_index = index;
            return;
        };
        if (self.entries.items[index].sequence < self.entries.items[oldest].sequence) {
            self.oldest_index = index;
        }
    }

    fn recomputeOldest(self: *Store) void {
        if (self.entries.items.len == 0) {
            self.oldest_index = null;
            return;
        }
        var oldest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.sequence < self.entries.items[oldest].sequence) {
                oldest = index;
            }
        }
        self.oldest_index = oldest;
    }

    fn nextSequence(self: *Store) u64 {
        const current = self.next_sequence;
        self.next_sequence +%= 1;
        if (self.next_sequence == 0) self.next_sequence = 1;
        return current;
    }
};

fn validateIssued(issued: Issued) Error!void {
    if (issued.identity.len == 0) return error.InvalidTicket;
    if (issued.lifetime_seconds == 0 or
        issued.lifetime_seconds > codec.max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    const secret_value =
        issued.secret_value orelse Secret.fromSha256(issued.secret);
    if (secret_value.hash != issued.cipher_suite.hash()) {
        return error.InvalidTicket;
    }
}
