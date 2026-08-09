//! Bounded owning server-side store for issued TLS 1.3 session tickets.
//!
//! Ticket identities and PSKs are copied into stable storage. Lookups return an
//! owning lease so concurrent eviction or ticket rotation cannot invalidate a
//! resumed handshake. Expired entries are removed eagerly on issue/lookup.

const std = @import("std");
const codec = @import("vail").tls.ticket;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapacity,
    InvalidTicket,
    InvalidTicketLifetime,
};

pub const Issued = struct {
    identity: []const u8,
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
};

pub const Lease = struct {
    allocator: std.mem.Allocator,
    identity: []u8,
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,

    pub fn deinit(self: *Lease) void {
        std.crypto.secureZero(u8, self.identity);
        self.allocator.free(self.identity);
        std.crypto.secureZero(u8, &self.secret);
        self.* = undefined;
    }
};

const Entry = struct {
    identity: []u8,
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    sequence: u64,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.identity);
        allocator.free(self.identity);
        std.crypto.secureZero(u8, &self.secret);
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
    next_sequence: u64 = 1,
    mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
    ) Error!Store {
        if (max_entries == 0) return error.InvalidCapacity;
        return .{
            .allocator = allocator,
            .io = io,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn issue(self: *Store, issued: Issued) Error!void {
        try validateIssued(issued);
        const identity = try self.allocator.dupe(u8, issued.identity);
        errdefer self.allocator.free(identity);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpired(issued.issued_at_ms);

        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, entry.identity, issued.identity)) continue;
            const replacement = Entry{
                .identity = identity,
                .secret = issued.secret,
                .age_add = issued.age_add,
                .issued_at_ms = issued.issued_at_ms,
                .lifetime_seconds = issued.lifetime_seconds,
                .sequence = self.nextSequence(),
            };
            const replaced = entry.*;
            entry.* = replacement;
            var old = replaced;
            old.deinit(self.allocator);
            return;
        }

        if (self.entries.items.len < self.max_entries) {
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
        } else {
            var oldest: usize = 0;
            for (self.entries.items[1..], 1..) |entry, index| {
                if (entry.sequence < self.entries.items[oldest].sequence) {
                    oldest = index;
                }
            }
            var evicted = self.entries.swapRemove(oldest);
            evicted.deinit(self.allocator);
        }
        self.entries.appendAssumeCapacity(.{
            .identity = identity,
            .secret = issued.secret,
            .age_add = issued.age_add,
            .issued_at_ms = issued.issued_at_ms,
            .lifetime_seconds = issued.lifetime_seconds,
            .sequence = self.nextSequence(),
        });
    }

    pub fn lookup(
        self: *Store,
        identity: []const u8,
        now_ms: u64,
    ) Error!?Lease {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpired(now_ms);
        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, entry.identity, identity)) continue;
            const identity_copy = try self.allocator.dupe(u8, entry.identity);
            entry.sequence = self.nextSequence();
            return .{
                .allocator = self.allocator,
                .identity = identity_copy,
                .secret = entry.secret,
                .age_add = entry.age_add,
                .issued_at_ms = entry.issued_at_ms,
                .lifetime_seconds = entry.lifetime_seconds,
            };
        }
        return null;
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
            var expired = self.entries.swapRemove(index);
            expired.deinit(self.allocator);
        }
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
}
