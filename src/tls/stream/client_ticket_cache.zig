//! Thread-safe, bounded client caches for TLS 1.2 and TLS 1.3 tickets.
//!
//! Entries are isolated by exact server identity and port. Callers receive an
//! owned clone so concurrent replacement or eviction cannot invalidate
//! handshake input while a connection is being established.

const std = @import("std");
const vail = @import("vail");
const Guard = @import("../../internal/mutex_guard.zig").Guard;
const deadline_policy = @import("../../internal/deadline.zig");

const Tls12Ops = struct {
    const Ticket = vail.tls.tls12_ticket.Cached;

    fn clone(ticket: *const Ticket, allocator: std.mem.Allocator) !Ticket {
        return ticket.clone(allocator);
    }

    fn expired(ticket: *const Ticket, now_seconds: u64) bool {
        const session = ticket.session;
        return now_seconds < session.created_at_seconds or
            now_seconds - session.created_at_seconds >= session.lifetime_seconds;
    }

    fn ticketAlpn(ticket: *const Ticket) []const u8 {
        return ticket.alpn();
    }
};

const Tls13Ops = struct {
    const Ticket = vail.tls.ticket.Cached;

    fn clone(ticket: *const Ticket, allocator: std.mem.Allocator) !Ticket {
        var psk = ticket.psk;
        errdefer psk.deinit();
        const identity = try allocator.dupe(u8, ticket.identity);
        errdefer allocator.free(identity);
        const server_name = try allocator.dupe(u8, ticket.server_name);
        errdefer allocator.free(server_name);
        const alpn = try allocator.dupe(u8, ticket.alpn);
        errdefer allocator.free(alpn);
        const local_settings = if (ticket.local_application_settings) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (local_settings) |value| allocator.free(value);
        const peer_settings = if (ticket.peer_application_settings) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (peer_settings) |value| allocator.free(value);
        return .{
            .allocator = allocator,
            .identity = identity,
            .psk = psk,
            .suite = ticket.suite,
            .server_name = server_name,
            .alpn = alpn,
            .age_add = ticket.age_add,
            .received_at_ms = ticket.received_at_ms,
            .lifetime_seconds = ticket.lifetime_seconds,
            .max_early_data_size = ticket.max_early_data_size,
            .application_settings_codepoint = ticket.application_settings_codepoint,
            .local_application_settings = local_settings,
            .peer_application_settings = peer_settings,
        };
    }

    fn expired(ticket: *const Ticket, now_ms: u64) bool {
        _ = ticket.obfuscatedTicketAge(now_ms) catch return true;
        return false;
    }

    fn ticketAlpn(ticket: *const Ticket) []const u8 {
        return ticket.alpn;
    }
};

fn TicketCache(comptime Ops: type) type {
    return struct {
        const Self = @This();
        pub const Ticket = Ops.Ticket;

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
        };

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
        ) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .max_entries = max_entries,
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.entries.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            for (self.entries.items) |*entry| entry.deinit(self.allocator);
            self.entries.clearRetainingCapacity();
        }

        pub fn count(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.entries.items.len;
        }

        pub fn cloneFor(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            now: u64,
        ) !?Ticket {
            return self.cloneForBefore(server_identity, port, now, null);
        }

        /// Preserve one awake-clock deadline through cache admission and clone.
        pub fn cloneForBefore(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            now: u64,
            deadline: ?std.Io.Clock.Timestamp,
        ) !?Ticket {
            var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
            defer guard.unlock();
            self.pruneExpiredLocked(now);
            const index = self.find(server_identity, port) orelse return null;
            var ticket = try Ops.clone(
                &self.entries.items[index].ticket,
                self.allocator,
            );
            errdefer ticket.deinit();
            if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
            self.entries.items[index].last_used = self.nextAccess();
            return ticket;
        }

        /// Clone only a ticket issued for the exact application protocol.
        /// A unified HTTP pool may negotiate HTTP/1.1 or HTTP/2 for the same
        /// origin, so origin-only lookup is insufficient for safe resumption.
        pub fn cloneForAlpn(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            alpn: []const u8,
            now: u64,
        ) !?Ticket {
            return self.cloneForAlpnBefore(server_identity, port, alpn, now, null);
        }

        /// Preserve one awake-clock deadline through cache admission and clone.
        pub fn cloneForAlpnBefore(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            alpn: []const u8,
            now: u64,
            deadline: ?std.Io.Clock.Timestamp,
        ) !?Ticket {
            var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
            defer guard.unlock();
            self.pruneExpiredLocked(now);
            const index = self.findAlpn(
                server_identity,
                port,
                alpn,
            ) orelse return null;
            var ticket = try Ops.clone(
                &self.entries.items[index].ticket,
                self.allocator,
            );
            errdefer ticket.deinit();
            if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
            self.entries.items[index].last_used = self.nextAccess();
            return ticket;
        }

        /// Consume `ticket`. Allocation failure disables caching for this
        /// ticket without failing the authenticated connection that issued it.
        pub fn store(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            ticket_value: Ticket,
            now: u64,
        ) void {
            var ticket = ticket_value;
            if (self.max_entries == 0) {
                ticket.deinit();
                return;
            }
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.storeLocked(server_identity, port, ticket, now);
        }

        /// Consume a ticket after the caller acquired this cache's mutex.
        pub fn storeLocked(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            ticket_value: Ticket,
            now: u64,
        ) void {
            var ticket = ticket_value;
            if (self.max_entries == 0) {
                ticket.deinit();
                return;
            }
            self.pruneExpiredLocked(now);
            if (self.findAlpn(
                server_identity,
                port,
                Ops.ticketAlpn(&ticket),
            )) |index| {
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
            self: *Self,
            server_identity: []const u8,
            port: u16,
        ) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.removeLocked(server_identity, port);
        }

        /// Remove an entry while the caller owns this cache's mutex.
        pub fn removeLocked(self: *Self, server_identity: []const u8, port: u16) bool {
            const index = self.find(server_identity, port) orelse return false;
            var removed = self.entries.swapRemove(index);
            removed.deinit(self.allocator);
            return true;
        }

        pub fn removeForAlpn(
            self: *Self,
            server_identity: []const u8,
            port: u16,
            alpn: []const u8,
        ) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.removeForAlpnLocked(server_identity, port, alpn);
        }

        /// Exact-ALPN removal while the caller owns this cache's mutex.
        pub fn removeForAlpnLocked(self: *Self, server_identity: []const u8, port: u16, alpn: []const u8) bool {
            const index = self.findAlpn(
                server_identity,
                port,
                alpn,
            ) orelse return false;
            var removed = self.entries.swapRemove(index);
            removed.deinit(self.allocator);
            return true;
        }

        fn pruneExpiredLocked(self: *Self, now: u64) void {
            var index: usize = 0;
            while (index < self.entries.items.len) {
                if (!Ops.expired(&self.entries.items[index].ticket, now)) {
                    index += 1;
                    continue;
                }
                var expired = self.entries.swapRemove(index);
                expired.deinit(self.allocator);
            }
        }

        fn find(
            self: *const Self,
            server_identity: []const u8,
            port: u16,
        ) ?usize {
            for (self.entries.items, 0..) |entry, index| {
                if (entry.matches(server_identity, port)) return index;
            }
            return null;
        }

        fn findAlpn(
            self: *const Self,
            server_identity: []const u8,
            port: u16,
            alpn: []const u8,
        ) ?usize {
            for (self.entries.items, 0..) |entry, index| {
                if (entry.matches(server_identity, port) and
                    std.mem.eql(u8, Ops.ticketAlpn(&entry.ticket), alpn))
                {
                    return index;
                }
            }
            return null;
        }

        fn oldestIndex(self: *const Self) usize {
            std.debug.assert(self.entries.items.len != 0);
            var oldest: usize = 0;
            for (self.entries.items[1..], 1..) |entry, index| {
                if (entry.last_used < self.entries.items[oldest].last_used) {
                    oldest = index;
                }
            }
            return oldest;
        }

        fn nextAccess(self: *Self) u64 {
            self.access_clock +|= 1;
            return self.access_clock;
        }
    };
}

pub const Cache = TicketCache(Tls12Ops);
pub const Tls13Cache = TicketCache(Tls13Ops);

fn testTls12Ticket(
    allocator: std.mem.Allocator,
    identity: []const u8,
    created_at_seconds: u64,
) !Tls12Ops.Ticket {
    return Tls12Ops.Ticket.init(
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

fn testTls13Ticket(
    allocator: std.mem.Allocator,
    identity: []const u8,
    received_at_ms: u64,
) !Tls13Ops.Ticket {
    const owned_identity = try allocator.dupe(u8, "opaque-ticket");
    errdefer allocator.free(owned_identity);
    const server_name = try allocator.dupe(u8, identity);
    errdefer allocator.free(server_name);
    const alpn = try allocator.dupe(u8, "h2");
    errdefer allocator.free(alpn);
    return .{
        .allocator = allocator,
        .identity = owned_identity,
        .psk = .fromSha256([_]u8{0x43} ** 32),
        .suite = .aes_128_gcm_sha256,
        .server_name = server_name,
        .alpn = alpn,
        .age_add = 7,
        .received_at_ms = received_at_ms,
        .lifetime_seconds = 60,
        .max_early_data_size = null,
        .application_settings_codepoint = null,
        .local_application_settings = null,
        .peer_application_settings = null,
    };
}

fn exerciseCache(comptime Ops: type, now: u64, expired_at: u64) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = TicketCache(Ops).init(std.testing.allocator, threaded.io(), 2);
    defer cache.deinit();

    const make = if (Ops == Tls12Ops) testTls12Ticket else testTls13Ticket;
    cache.store("First.EXAMPLE", 443, try make(
        std.testing.allocator,
        "First.EXAMPLE",
        now,
    ), now);
    cache.store("second.example", 443, try make(
        std.testing.allocator,
        "second.example",
        now,
    ), now);
    try std.testing.expect((try cache.cloneFor(
        "first.example",
        443,
        now + 1,
    )) == null);
    try std.testing.expect((try cache.cloneFor(
        "First.EXAMPLE",
        8443,
        now + 1,
    )) == null);
    var first = (try cache.cloneFor("First.EXAMPLE", 443, now + 1)).?;
    defer first.deinit();
    cache.store("third.example", 443, try make(
        std.testing.allocator,
        "third.example",
        now,
    ), now);
    try std.testing.expect((try cache.cloneFor(
        "second.example",
        443,
        now + 1,
    )) == null);
    var third = (try cache.cloneFor("third.example", 443, now + 1)).?;
    defer third.deinit();
    try std.testing.expectEqual(@as(usize, 2), cache.count());

    cache.store("expired.example", 443, try make(
        std.testing.allocator,
        "expired.example",
        now,
    ), now);
    try std.testing.expect((try cache.cloneFor(
        "expired.example",
        443,
        expired_at,
    )) == null);
}

test "TLS 1.2 client ticket cache isolates authorities and evicts LRU" {
    try exerciseCache(Tls12Ops, 100, 160);
}

test "TLS 1.3 client ticket cache isolates authorities and evicts LRU" {
    try exerciseCache(Tls13Ops, 100_000, 160_001);
}

test "TLS 1.3 client ticket cache deep-clones owned session context" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = Tls13Cache.init(std.testing.allocator, threaded.io(), 1);
    defer cache.deinit();

    var ticket = try testTls13Ticket(
        std.testing.allocator,
        "settings.example",
        100_000,
    );
    ticket.local_application_settings = try std.testing.allocator.dupe(
        u8,
        "local-settings",
    );
    ticket.peer_application_settings = std.testing.allocator.dupe(
        u8,
        "peer-settings",
    ) catch |err| {
        ticket.deinit();
        return err;
    };
    cache.store("settings.example", 443, ticket, 100_000);

    var cloned = (try cache.cloneFor(
        "settings.example",
        443,
        100_001,
    )).?;
    defer cloned.deinit();
    try std.testing.expect(cache.remove("settings.example", 443));
    try std.testing.expectEqualStrings("opaque-ticket", cloned.identity);
    try std.testing.expectEqualStrings("settings.example", cloned.server_name);
    try std.testing.expectEqualStrings("h2", cloned.alpn);
    try std.testing.expectEqualStrings(
        "local-settings",
        cloned.local_application_settings.?,
    );
    try std.testing.expectEqualStrings(
        "peer-settings",
        cloned.peer_application_settings.?,
    );
    var expected_psk = vail.tls.secret.Secret.fromSha256([_]u8{0x43} ** 32);
    defer expected_psk.deinit();
    try std.testing.expect(cloned.psk.eql(&expected_psk));
}

test "client ticket cache isolates application protocols for one origin" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var cache = Tls13Cache.init(allocator, threaded.io(), 2);
    defer cache.deinit();

    const h2 = try testTls13Ticket(allocator, "same.example", 100_000);
    cache.store("same.example", 443, h2, 100_000);
    var h1 = try testTls13Ticket(allocator, "same.example", 100_001);
    const h1_alpn = try allocator.dupe(u8, "http/1.1");
    allocator.free(h1.alpn);
    h1.alpn = h1_alpn;
    cache.store("same.example", 443, h1, 100_001);

    try std.testing.expectEqual(@as(usize, 2), cache.count());
    var cloned_h2 = (try cache.cloneForAlpn(
        "same.example",
        443,
        "h2",
        100_002,
    )).?;
    defer cloned_h2.deinit();
    var cloned_h1 = (try cache.cloneForAlpn(
        "same.example",
        443,
        "http/1.1",
        100_002,
    )).?;
    defer cloned_h1.deinit();
    try std.testing.expectEqualStrings("h2", cloned_h2.alpn);
    try std.testing.expectEqualStrings("http/1.1", cloned_h1.alpn);
    try std.testing.expect(cache.removeForAlpn(
        "same.example",
        443,
        "h2",
    ));
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    try std.testing.expect((try cache.cloneForAlpn(
        "same.example",
        443,
        "h2",
        100_003,
    )) == null);
}

test "client ticket caches discard entries when disabled" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var tls12 = Cache.init(std.testing.allocator, threaded.io(), 0);
    defer tls12.deinit();
    tls12.store("disabled.example", 443, try testTls12Ticket(
        std.testing.allocator,
        "disabled.example",
        100,
    ), 100);
    try std.testing.expectEqual(@as(usize, 0), tls12.count());

    var tls13 = Tls13Cache.init(std.testing.allocator, threaded.io(), 0);
    defer tls13.deinit();
    tls13.store("disabled.example", 443, try testTls13Ticket(
        std.testing.allocator,
        "disabled.example",
        100_000,
    ), 100_000);
    try std.testing.expectEqual(@as(usize, 0), tls13.count());
}
