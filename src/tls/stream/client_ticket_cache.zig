//! Thread-safe, bounded client cache for TLS 1.2 RFC 5077 tickets.
//!
//! Entries are isolated by server identity and port. Callers receive an owned
//! clone so a concurrent replacement or eviction cannot invalidate handshake
//! input while a connection is being established.

const std = @import("std");
const vail = @import("vail");

pub const Ticket = vail.tls.tls12_ticket.Cached;
pub const Error = vail.tls.tls12_ticket.Error;

const Entry = struct {
    server_identity: []u8,
    port: u16,
    ticket: Ticket,
    last_used: u64,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.server_identity);
        self.ticket.deinit();
        self.* = undefined;
    }

    fn matches(
        self: Entry,
        server_identity: []const u8,
        port: u16,
    ) bool {
        return self.port == port and std.mem.eql(
            u8,
            self.server_identity,
            server_identity,
        );
    }

    fn expired(self: Entry, now_seconds: u64) bool {
        const session = self.ticket.session;
        return now_seconds < session.created_at_seconds or
            now_seconds - session.created_at_seconds >= session.lifetime_seconds;
    }
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    max_entries: usize,
    mutex: std.Io.Mutex = .init,
    entries: std.ArrayList(Entry) = .empty,
    access_clock: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        max_entries: usize,
    ) Cache {
        return .{
            .allocator = allocator,
            .io = io,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Cache) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
    }

    pub fn count(self: *Cache) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.entries.items.len;
    }

    pub fn cloneFor(
        self: *Cache,
        server_identity: []const u8,
        port: u16,
        now_seconds: u64,
    ) Error!?Ticket {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(now_seconds);
        const index = self.find(server_identity, port) orelse return null;
        var ticket = try self.entries.items[index].ticket.clone(self.allocator);
        errdefer ticket.deinit();
        self.entries.items[index].last_used = self.nextAccess();
        return ticket;
    }

    /// Consume `ticket`. Allocation failure disables caching for this ticket
    /// without failing the already-authenticated connection that produced it.
    pub fn store(
        self: *Cache,
        server_identity: []const u8,
        port: u16,
        ticket_value: Ticket,
        now_seconds: u64,
    ) void {
        var ticket = ticket_value;
        if (self.max_entries == 0) {
            ticket.deinit();
            return;
        }
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(now_seconds);
        if (self.find(server_identity, port)) |index| {
            self.entries.items[index].ticket.deinit();
            self.entries.items[index].ticket = ticket;
            self.entries.items[index].last_used = self.nextAccess();
            return;
        }
        if (self.entries.items.len < self.max_entries) {
            self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
                ticket.deinit();
                return;
            };
        }
        const owned_identity = self.allocator.dupe(
            u8,
            server_identity,
        ) catch {
            ticket.deinit();
            return;
        };
        if (self.entries.items.len == self.max_entries) {
            var evicted = self.entries.swapRemove(self.oldestIndex());
            evicted.deinit(self.allocator);
        }
        self.entries.appendAssumeCapacity(.{
            .server_identity = owned_identity,
            .port = port,
            .ticket = ticket,
            .last_used = self.nextAccess(),
        });
    }

    pub fn remove(
        self: *Cache,
        server_identity: []const u8,
        port: u16,
    ) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const index = self.find(server_identity, port) orelse return false;
        var removed = self.entries.swapRemove(index);
        removed.deinit(self.allocator);
        return true;
    }

    fn pruneExpiredLocked(self: *Cache, now_seconds: u64) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (!self.entries.items[index].expired(now_seconds)) {
                index += 1;
                continue;
            }
            var expired = self.entries.swapRemove(index);
            expired.deinit(self.allocator);
        }
    }

    fn find(
        self: *const Cache,
        server_identity: []const u8,
        port: u16,
    ) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.matches(server_identity, port)) return index;
        }
        return null;
    }

    fn oldestIndex(self: *const Cache) usize {
        std.debug.assert(self.entries.items.len != 0);
        var oldest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.last_used < self.entries.items[oldest].last_used) {
                oldest = index;
            }
        }
        return oldest;
    }

    fn nextAccess(self: *Cache) u64 {
        self.access_clock +|= 1;
        return self.access_clock;
    }
};

fn testTicket(
    allocator: std.mem.Allocator,
    identity: []const u8,
    created_at_seconds: u64,
) !Ticket {
    return Ticket.init(
        allocator,
        "opaque-ticket",
        &.{},
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        [_]u8{0x42} ** vail.tls.tls12.master_secret_len,
        identity,
        "h2",
        created_at_seconds,
        60,
    );
}

test "TLS 1.2 client ticket cache isolates authorities and evicts LRU" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = Cache.init(std.testing.allocator, threaded.io(), 2);
    defer cache.deinit();

    cache.store("First.EXAMPLE", 443, try testTicket(
        std.testing.allocator,
        "First.EXAMPLE",
        100,
    ), 100);
    cache.store("second.example", 443, try testTicket(
        std.testing.allocator,
        "second.example",
        100,
    ), 100);
    try std.testing.expect((try cache.cloneFor(
        "first.example",
        443,
        101,
    )) == null);
    try std.testing.expect((try cache.cloneFor(
        "First.EXAMPLE",
        8443,
        101,
    )) == null);
    var first = (try cache.cloneFor("First.EXAMPLE", 443, 101)).?;
    defer first.deinit();
    cache.store("third.example", 443, try testTicket(
        std.testing.allocator,
        "third.example",
        100,
    ), 100);
    try std.testing.expect((try cache.cloneFor(
        "second.example",
        443,
        101,
    )) == null);
    var third = (try cache.cloneFor("third.example", 443, 101)).?;
    defer third.deinit();
    try std.testing.expectEqual(@as(usize, 2), cache.count());
}

test "TLS 1.2 client ticket cache drops expired and disabled entries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = Cache.init(std.testing.allocator, threaded.io(), 1);
    defer cache.deinit();
    cache.store("expired.example", 443, try testTicket(
        std.testing.allocator,
        "expired.example",
        100,
    ), 100);
    try std.testing.expect((try cache.cloneFor(
        "expired.example",
        443,
        160,
    )) == null);

    var disabled = Cache.init(std.testing.allocator, threaded.io(), 0);
    defer disabled.deinit();
    disabled.store("disabled.example", 443, try testTicket(
        std.testing.allocator,
        "disabled.example",
        100,
    ), 100);
    try std.testing.expectEqual(@as(usize, 0), disabled.count());
}
