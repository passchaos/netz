//! Owning, bounded session-ticket cache for QUIC resumption.
//!
//! Cache entries own every byte slice. Callers receive an owned lease copy, so
//! later LRU eviction or array relocation cannot invalidate TLS inputs. Early
//! data uses an explicit single-consumer lease to prevent concurrent reuse of
//! one ticket.

const std = @import("std");
const vail = @import("vail");
const parameters = @import("parameters.zig");

const CipherSuite = vail.tls.cipher_suite.Suite;
const Secret = vail.tls.secret.Secret;

const OriginAlpnKey = struct {
    server_id: []const u8,
    alpn: []const u8,
};

const OriginAlpnContext = struct {
    pub fn hash(_: @This(), key: OriginAlpnKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        // Prefix the variable-length fields with their lengths so concatenated
        // byte strings cannot alias across the server_id/ALPN boundary.
        std.hash.autoHash(&hasher, key.server_id.len);
        hasher.update(key.server_id);
        std.hash.autoHash(&hasher, key.alpn.len);
        hasher.update(key.alpn);
        return hasher.final();
    }

    pub fn eql(_: @This(), lhs: OriginAlpnKey, rhs: OriginAlpnKey) bool {
        return std.mem.eql(u8, lhs.server_id, rhs.server_id) and
            std.mem.eql(u8, lhs.alpn, rhs.alpn);
    }
};

const OriginAlpnIndex = std.HashMapUnmanaged(
    OriginAlpnKey,
    usize,
    OriginAlpnContext,
    std.hash_map.default_max_load_percentage,
);

pub const max_ticket_lifetime_seconds: u32 = 7 * 24 * 60 * 60;
pub const quic_early_data_size: u32 = std.math.maxInt(u32);

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapacity,
    InvalidTicket,
    InvalidTicketLifetime,
    InvalidEarlyDataSize,
    CacheBusy,
    UnknownLease,
    LeaseAlreadyFinished,
};

pub const Ticket = struct {
    server_id: []const u8,
    alpn: []const u8,
    ticket: []const u8,
    psk: [32]u8,
    /// Canonical PSK for SHA-384 suites. When absent, `psk` is interpreted as
    /// the source-compatible SHA-256 value.
    psk_secret: ?Secret = null,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
    max_early_data_size: ?u32 = null,
    transport_parameters: parameters.Snapshot,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    server_id: []u8,
    alpn: []u8,
    ticket: []u8,
    psk: [32]u8,
    psk_secret: Secret,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    cipher_suite: CipherSuite,
    max_early_data_size: ?u32,
    transport_parameters: parameters.Snapshot,

    pub fn deinit(self: *Session) void {
        self.allocator.free(self.server_id);
        self.allocator.free(self.alpn);
        wipeAndFree(self.allocator, self.ticket);
        vail.crypto.memory.zeroValue(&self.psk);
        self.psk_secret.deinit();
        self.* = undefined;
    }

    /// TLS 1.3 obfuscated_ticket_age in milliseconds modulo 2^32.
    pub fn obfuscatedTicketAge(self: Session, now_ms: u64) u32 {
        const age = now_ms -| self.issued_at_ms;
        return @as(u32, @truncate(age)) +% self.age_add;
    }

    pub fn permitsEarlyData(self: Session) bool {
        return self.max_early_data_size == quic_early_data_size;
    }
};

pub const EarlyDataLease = struct {
    /// The cache must outlive the lease. `deinit` automatically releases an
    /// unused reservation so ordinary error cleanup cannot strand an entry.
    owner: *Cache,
    session: Session,
    lease_id: u64,
    state: enum {
        active,
        consumed,
        released,
    } = .active,

    pub fn deinit(self: *EarlyDataLease) void {
        if (self.state == .active) {
            self.owner.releaseEarlyData(self) catch {};
        }
        self.session.deinit();
        self.* = undefined;
    }
};

pub const CacheStats = struct {
    entries: usize,
    capacity: usize,
    active_early_data_leases: usize,
    consumed_early_data_tickets: usize,
    reusable_early_data_tickets: usize,
};

const Entry = struct {
    server_id: []u8,
    alpn: []u8,
    ticket: []u8,
    psk: [32]u8,
    psk_secret: Secret,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    cipher_suite: CipherSuite,
    max_early_data_size: ?u32,
    transport_parameters: parameters.Snapshot,
    last_used: u64,
    lease_id: ?u64 = null,
    early_data_consumed: bool = false,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.alpn);
        wipeAndFree(allocator, self.ticket);
        vail.crypto.memory.zeroValue(&self.psk);
        self.psk_secret.deinit();
        self.* = undefined;
    }

    fn expired(self: Entry, now_ms: u64) bool {
        if (now_ms < self.issued_at_ms) return true;
        const lifetime_ms = @as(u64, self.lifetime_seconds) *
            std.time.ms_per_s;
        return now_ms - self.issued_at_ms > lifetime_ms;
    }

    fn matches(self: Entry, server_id: []const u8, alpn: []const u8) bool {
        return std.mem.eql(u8, self.server_id, server_id) and
            std.mem.eql(u8, self.alpn, alpn);
    }

    fn allowsEarlyData(self: Entry) bool {
        return self.max_early_data_size == quic_early_data_size and
            !self.early_data_consumed and self.lease_id == null;
    }

    fn originAlpnKey(self: Entry) OriginAlpnKey {
        return .{
            .server_id = self.server_id,
            .alpn = self.alpn,
        };
    }
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// Exact origin+ALPN index for the single live ticket per tuple. Keys point
    /// into entry-owned `server_id`/`alpn` buffers; replacement refreshes the
    /// key before freeing the old entry, and swap-remove paths repair moved
    /// indexes so hot acquire/store/beginEarlyData paths avoid linear scans.
    origin_index: OriginAlpnIndex = .empty,
    /// Active early-data lease IDs map back to their owning entry. This keeps
    /// lease finish/ownership checks independent of cache size while preserving
    /// the existing lease ID wraparound semantics.
    lease_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// Cached hot-path state: LRU eviction and public stats are queried by
    /// connection setup/recovery code, so maintain them transactionally instead
    /// of rescanning the bounded ticket list on each read.
    evictable_lru_index: ?usize = null,
    active_early_data_leases: usize = 0,
    consumed_early_data_tickets: usize = 0,
    reusable_early_data_tickets: usize = 0,
    max_entries: usize,
    access_clock: u64 = 0,
    next_lease_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) Error!Cache {
        if (max_entries == 0 or max_entries > std.math.maxInt(OriginAlpnIndex.Size)) {
            return error.InvalidCapacity;
        }
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Cache) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.origin_index.deinit(self.allocator);
        self.lease_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const Cache) usize {
        return self.entries.items.len;
    }

    pub fn stats(self: *const Cache) CacheStats {
        return .{
            .entries = self.entries.items.len,
            .capacity = self.max_entries,
            .active_early_data_leases = self.active_early_data_leases,
            .consumed_early_data_tickets = self.consumed_early_data_tickets,
            .reusable_early_data_tickets = self.reusable_early_data_tickets,
        };
    }

    pub fn getStats(self: *const Cache) CacheStats {
        return self.stats();
    }

    /// Return an owned session copy suitable for a normal PSK resumption.
    /// Unlike early data, TLS resumption itself does not require an exclusive
    /// one-shot lease.
    pub fn acquire(
        self: *Cache,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!?Session {
        const index = self.findUsable(server_id, alpn, now_ms) orelse
            return null;
        const session = try self.copySession(self.entries.items[index]);
        self.entries.items[index].last_used = self.nextAccess();
        if (self.evictable_lru_index == index) self.recomputeEvictableLru();
        return session;
    }

    /// Deep-copy a ticket into the cache. Replacing an origin+ALPN entry is
    /// transactional and forbidden while an early-data lease is outstanding.
    pub fn store(self: *Cache, ticket: Ticket) Error!void {
        try validateTicket(ticket);
        const replacement_index = self.find(ticket.server_id, ticket.alpn);
        if (replacement_index) |index| {
            if (self.entries.items[index].lease_id != null) {
                return error.CacheBusy;
            }
        } else {
            if (self.entries.items.len < self.max_entries) {
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
                try self.origin_index.ensureUnusedCapacity(self.allocator, 1);
            } else {
                // swapRemove below creates the slot used by append, so a full
                // cache never grows merely to replace its LRU entry.
                if (self.lruEvictableIndex() == null) return error.CacheBusy;
            }
        }

        var owned = try self.copyEntry(ticket);
        errdefer owned.deinit(self.allocator);
        owned.last_used = self.nextAccess();

        if (replacement_index) |index| {
            self.replaceEntryAt(index, owned);
            return;
        }
        if (self.entries.items.len >= self.max_entries) {
            const index = self.lruEvictableIndex() orelse unreachable;
            var evicted = self.removeEntryAt(index);
            evicted.deinit(self.allocator);
        }
        self.appendEntryAssumeCapacity(owned);
    }

    /// Reserve one early-data use and return an owned ticket copy. The cache
    /// cannot hand the same ticket to another connection until this lease is
    /// consumed or released.
    pub fn beginEarlyData(
        self: *Cache,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!?EarlyDataLease {
        const index = self.findUsable(server_id, alpn, now_ms) orelse
            return null;
        var entry = &self.entries.items[index];
        if (!entry.allowsEarlyData()) return null;

        const lease_id = self.nextLeaseId();
        const lease_slot = try self.lease_index.getOrPut(
            self.allocator,
            lease_id,
        );
        std.debug.assert(!lease_slot.found_existing);
        errdefer _ = self.lease_index.remove(lease_id);

        var session = try self.copySession(entry.*);
        errdefer session.deinit();
        self.removeEntryStats(entry.*);
        entry.lease_id = lease_id;
        entry.last_used = self.nextAccess();
        lease_slot.value_ptr.* = index;
        self.addEntryStats(entry.*);
        if (self.evictable_lru_index == index) self.recomputeEvictableLru();
        return .{
            .owner = self,
            .session = session,
            .lease_id = lease_id,
        };
    }

    /// Mark a ticket as offered on the wire. It remains unavailable for 0-RTT
    /// even when the connection later fails or the server rejects early data.
    pub fn consumeEarlyData(
        self: *Cache,
        lease: *EarlyDataLease,
    ) Error!void {
        try self.finishLease(lease, true);
    }

    /// Release a reservation only when no 0-RTT bytes were offered.
    pub fn releaseEarlyData(
        self: *Cache,
        lease: *EarlyDataLease,
    ) Error!void {
        try self.finishLease(lease, false);
    }

    pub fn pruneExpired(self: *Cache, now_ms: u64) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = &self.entries.items[index];
            if (!entry.expired(now_ms) or entry.lease_id != null) {
                index += 1;
                continue;
            }
            var expired = self.removeEntryAt(index);
            expired.deinit(self.allocator);
            removed += 1;
        }
        return removed;
    }

    pub fn ownsActiveLease(
        self: *const Cache,
        lease: EarlyDataLease,
    ) bool {
        if (lease.owner != self) return false;
        if (lease.state != .active) return false;
        if (self.lease_index.count() == 0) return false;
        const index = self.lease_index.get(lease.lease_id) orelse return false;
        return self.entries.items[index].lease_id == lease.lease_id;
    }

    fn finishLease(
        self: *Cache,
        lease: *EarlyDataLease,
        consumed: bool,
    ) Error!void {
        if (lease.state != .active) return error.LeaseAlreadyFinished;
        if (lease.owner != self) return error.UnknownLease;
        if (self.lease_index.count() == 0) return error.UnknownLease;
        const index = self.lease_index.get(lease.lease_id) orelse
            return error.UnknownLease;
        var entry = &self.entries.items[index];
        if (entry.lease_id != lease.lease_id) return error.UnknownLease;
        self.removeEntryStats(entry.*);
        entry.lease_id = null;
        _ = self.lease_index.remove(lease.lease_id);
        entry.early_data_consumed = consumed;
        entry.last_used = self.nextAccess();
        self.addEntryStats(entry.*);
        self.considerEvictableLru(index);
        lease.state = if (consumed) .consumed else .released;
    }

    fn findUsable(
        self: *Cache,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) ?usize {
        const index = self.find(server_id, alpn) orelse return null;
        if (self.entries.items[index].expired(now_ms)) return null;
        return index;
    }

    fn find(self: *const Cache, server_id: []const u8, alpn: []const u8) ?usize {
        if (self.origin_index.count() == 0) return null;
        return self.origin_index.get(.{
            .server_id = server_id,
            .alpn = alpn,
        });
    }

    fn lruEvictableIndex(self: *const Cache) ?usize {
        return self.evictable_lru_index;
    }

    fn copyEntry(self: *const Cache, ticket: Ticket) Error!Entry {
        const server_id = try self.allocator.dupe(u8, ticket.server_id);
        errdefer self.allocator.free(server_id);
        const alpn = try self.allocator.dupe(u8, ticket.alpn);
        errdefer self.allocator.free(alpn);
        const ticket_data = try self.allocator.dupe(u8, ticket.ticket);
        errdefer wipeAndFree(self.allocator, ticket_data);
        const psk_secret = effectiveTicketSecret(ticket);
        return .{
            .server_id = server_id,
            .alpn = alpn,
            .ticket = ticket_data,
            .psk = ticket.psk,
            .psk_secret = psk_secret,
            .issued_at_ms = ticket.issued_at_ms,
            .lifetime_seconds = ticket.lifetime_seconds,
            .age_add = ticket.age_add,
            .cipher_suite = ticket.cipher_suite,
            .max_early_data_size = ticket.max_early_data_size,
            .transport_parameters = ticket.transport_parameters,
            .last_used = 0,
        };
    }

    fn copySession(self: *const Cache, entry: Entry) Error!Session {
        const server_id = try self.allocator.dupe(u8, entry.server_id);
        errdefer self.allocator.free(server_id);
        const alpn = try self.allocator.dupe(u8, entry.alpn);
        errdefer self.allocator.free(alpn);
        const ticket_data = try self.allocator.dupe(u8, entry.ticket);
        return .{
            .allocator = self.allocator,
            .server_id = server_id,
            .alpn = alpn,
            .ticket = ticket_data,
            .psk = entry.psk,
            .psk_secret = entry.psk_secret,
            .issued_at_ms = entry.issued_at_ms,
            .lifetime_seconds = entry.lifetime_seconds,
            .age_add = entry.age_add,
            .cipher_suite = entry.cipher_suite,
            .max_early_data_size = entry.max_early_data_size,
            .transport_parameters = entry.transport_parameters,
        };
    }

    fn nextAccess(self: *Cache) u64 {
        self.access_clock +%= 1;
        return self.access_clock;
    }

    fn nextLeaseId(self: *Cache) u64 {
        while (true) {
            const id = self.next_lease_id;
            self.next_lease_id +%= 1;
            if (self.next_lease_id == 0) self.next_lease_id = 1;
            if (id != 0 and !self.leaseIdActive(id)) return id;
        }
    }

    fn leaseIdActive(self: *const Cache, id: u64) bool {
        return self.lease_index.count() != 0 and
            self.lease_index.contains(id);
    }

    fn appendEntryAssumeCapacity(self: *Cache, entry: Entry) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        self.origin_index.putAssumeCapacityNoClobber(
            self.entries.items[index].originAlpnKey(),
            index,
        );
        self.addEntryStats(self.entries.items[index]);
        self.considerEvictableLru(index);
    }

    fn replaceEntryAt(self: *Cache, index: usize, replacement: Entry) void {
        var replaced = self.entries.items[index];
        std.debug.assert(replaced.lease_id == null);
        self.removeEntryStats(replaced);
        self.entries.items[index] = replacement;
        const key_ptr = self.origin_index.getKeyPtr(replaced.originAlpnKey()) orelse
            unreachable;
        key_ptr.* = self.entries.items[index].originAlpnKey();
        self.addEntryStats(self.entries.items[index]);
        if (self.evictable_lru_index == index) self.recomputeEvictableLru() else self.considerEvictableLru(index);
        replaced.deinit(self.allocator);
    }

    fn removeEntryAt(self: *Cache, index: usize) Entry {
        const old_len = self.entries.items.len;
        const lru = self.evictable_lru_index;
        const removed = self.entries.swapRemove(index);
        self.removeEntryStats(removed);
        _ = self.origin_index.remove(removed.originAlpnKey());
        if (removed.lease_id) |lease_id| {
            _ = self.lease_index.remove(lease_id);
        }
        if (index != old_len - 1) {
            self.reindexMovedEntry(index);
        }
        if (self.entries.items.len == 0) {
            self.evictable_lru_index = null;
        } else if (lru == index) {
            self.recomputeEvictableLru();
        } else if (lru == old_len - 1) {
            self.evictable_lru_index = index;
        }
        return removed;
    }

    fn addEntryStats(self: *Cache, entry: Entry) void {
        if (entry.lease_id != null) self.active_early_data_leases += 1;
        if (entry.early_data_consumed) self.consumed_early_data_tickets += 1;
        if (entry.allowsEarlyData()) self.reusable_early_data_tickets += 1;
    }

    fn removeEntryStats(self: *Cache, entry: Entry) void {
        if (entry.lease_id != null) self.active_early_data_leases -|= 1;
        if (entry.early_data_consumed) self.consumed_early_data_tickets -|= 1;
        if (entry.allowsEarlyData()) self.reusable_early_data_tickets -|= 1;
    }

    fn reindexMovedEntry(self: *Cache, index: usize) void {
        const moved = self.entries.items[index];
        self.origin_index.getPtr(moved.originAlpnKey()).?.* = index;
        if (moved.lease_id) |lease_id| {
            self.lease_index.getPtr(lease_id).?.* = index;
        }
    }

    fn considerEvictableLru(self: *Cache, index: usize) void {
        if (self.entries.items[index].lease_id != null) return;
        const current = self.evictable_lru_index orelse {
            self.evictable_lru_index = index;
            return;
        };
        if (self.entries.items[index].last_used < self.entries.items[current].last_used) {
            self.evictable_lru_index = index;
        }
    }

    fn recomputeEvictableLru(self: *Cache) void {
        self.evictable_lru_index = null;
        for (self.entries.items, 0..) |entry, index| {
            if (entry.lease_id != null) continue;
            self.considerEvictableLru(index);
        }
    }
};

fn validateTicket(ticket: Ticket) Error!void {
    if (ticket.server_id.len == 0 or
        ticket.alpn.len == 0 or
        ticket.ticket.len == 0)
    {
        return error.InvalidTicket;
    }
    if (ticket.lifetime_seconds == 0 or
        ticket.lifetime_seconds > max_ticket_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
    if (effectiveTicketSecret(ticket).hash != ticket.cipher_suite.hash()) {
        return error.InvalidTicket;
    }
    // RFC 9001 Section 4.6.1 requires QUIC NewSessionTicket early_data to
    // advertise exactly 0xffffffff. Any other present value is a TLS error,
    // not a signal to silently downgrade this cached ticket.
    if (ticket.max_early_data_size) |size| {
        if (size != quic_early_data_size) return error.InvalidEarlyDataSize;
    }
}

fn effectiveTicketSecret(ticket: Ticket) Secret {
    return ticket.psk_secret orelse Secret.fromSha256(ticket.psk);
}

fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    vail.crypto.memory.zero(bytes);
    allocator.free(bytes);
}
