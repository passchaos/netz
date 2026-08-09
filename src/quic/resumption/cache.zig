//! Owning, bounded session-ticket cache for QUIC resumption.
//!
//! Cache entries own every byte slice. Callers receive an owned lease copy, so
//! later LRU eviction or array relocation cannot invalidate TLS inputs. Early
//! data uses an explicit single-consumer lease to prevent concurrent reuse of
//! one ticket.

const std = @import("std");
const parameters = @import("parameters.zig");

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
    issued_at_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    max_early_data_size: ?u32 = null,
    transport_parameters: parameters.Snapshot,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    ticket: []u8,
    psk: [32]u8,
    issued_at_ms: u64,
    age_add: u32,
    max_early_data_size: ?u32,
    transport_parameters: parameters.Snapshot,

    pub fn deinit(self: *Session) void {
        wipeAndFree(self.allocator, self.ticket);
        std.crypto.secureZero(u8, &self.psk);
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

const Entry = struct {
    server_id: []u8,
    alpn: []u8,
    ticket: []u8,
    psk: [32]u8,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    max_early_data_size: ?u32,
    transport_parameters: parameters.Snapshot,
    last_used: u64,
    lease_id: ?u64 = null,
    early_data_consumed: bool = false,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.alpn);
        wipeAndFree(allocator, self.ticket);
        std.crypto.secureZero(u8, &self.psk);
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
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_entries: usize,
    access_clock: u64 = 0,
    next_lease_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) Error!Cache {
        if (max_entries == 0) return error.InvalidCapacity;
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Cache) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Cache) usize {
        return self.entries.items.len;
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
            var replaced = self.entries.items[index];
            self.entries.items[index] = owned;
            replaced.deinit(self.allocator);
            return;
        }
        if (self.entries.items.len >= self.max_entries) {
            const index = self.lruEvictableIndex() orelse unreachable;
            var evicted = self.entries.swapRemove(index);
            evicted.deinit(self.allocator);
        }
        self.entries.appendAssumeCapacity(owned);
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

        var session = try self.copySession(entry.*);
        errdefer session.deinit();
        const lease_id = self.nextLeaseId();
        entry.lease_id = lease_id;
        entry.last_used = self.nextAccess();
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
            var expired = self.entries.swapRemove(index);
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
        for (self.entries.items) |entry| {
            if (entry.lease_id == lease.lease_id) return true;
        }
        return false;
    }

    fn finishLease(
        self: *Cache,
        lease: *EarlyDataLease,
        consumed: bool,
    ) Error!void {
        if (lease.state != .active) return error.LeaseAlreadyFinished;
        for (self.entries.items) |*entry| {
            if (entry.lease_id != lease.lease_id) continue;
            entry.lease_id = null;
            entry.early_data_consumed = consumed;
            entry.last_used = self.nextAccess();
            lease.state = if (consumed) .consumed else .released;
            return;
        }
        return error.UnknownLease;
    }

    fn findUsable(
        self: *Cache,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (!entry.matches(server_id, alpn) or entry.expired(now_ms)) {
                continue;
            }
            return index;
        }
        return null;
    }

    fn find(self: Cache, server_id: []const u8, alpn: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.matches(server_id, alpn)) return index;
        }
        return null;
    }

    fn lruEvictableIndex(self: Cache) ?usize {
        var best: ?usize = null;
        for (self.entries.items, 0..) |entry, index| {
            if (entry.lease_id != null) continue;
            if (best == null or
                entry.last_used < self.entries.items[best.?].last_used)
            {
                best = index;
            }
        }
        return best;
    }

    fn copyEntry(self: Cache, ticket: Ticket) Error!Entry {
        const server_id = try self.allocator.dupe(u8, ticket.server_id);
        errdefer self.allocator.free(server_id);
        const alpn = try self.allocator.dupe(u8, ticket.alpn);
        errdefer self.allocator.free(alpn);
        const ticket_data = try self.allocator.dupe(u8, ticket.ticket);
        errdefer wipeAndFree(self.allocator, ticket_data);
        return .{
            .server_id = server_id,
            .alpn = alpn,
            .ticket = ticket_data,
            .psk = ticket.psk,
            .issued_at_ms = ticket.issued_at_ms,
            .lifetime_seconds = ticket.lifetime_seconds,
            .age_add = ticket.age_add,
            .max_early_data_size = ticket.max_early_data_size,
            .transport_parameters = ticket.transport_parameters,
            .last_used = 0,
        };
    }

    fn copySession(self: Cache, entry: Entry) Error!Session {
        return .{
            .allocator = self.allocator,
            .ticket = try self.allocator.dupe(u8, entry.ticket),
            .psk = entry.psk,
            .issued_at_ms = entry.issued_at_ms,
            .age_add = entry.age_add,
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

    fn leaseIdActive(self: Cache, id: u64) bool {
        for (self.entries.items) |entry| {
            if (entry.lease_id == id) return true;
        }
        return false;
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
    // RFC 9001 Section 4.6.1 requires QUIC NewSessionTicket early_data to
    // advertise exactly 0xffffffff. Any other present value is a TLS error,
    // not a signal to silently downgrade this cached ticket.
    if (ticket.max_early_data_size) |size| {
        if (size != quic_early_data_size) return error.InvalidEarlyDataSize;
    }
}

fn wipeAndFree(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}
