//! Bounded origin-scoped memory of peer HTTP/3 SETTINGS.
//!
//! QUIC tickets remember transport parameters, but HTTP/3 0-RTT also needs
//! the application SETTINGS from the connection that issued the ticket. This
//! cache deliberately remains separate from Alt-Svc routing and TLS ticket
//! ownership so none of those authorities can be confused across origins.

const std = @import("std");
const http3 = @import("../../http3/mod.zig");

pub const Stats = struct {
    entries: usize,
    capacity: usize,
    evictions: u64,
};

pub const Cache = struct {
    const Entry = struct {
        key: http3.OriginKey,
        settings: http3.Settings,
        last_used: u64,

        fn deinit(self: *Entry) void {
            self.key.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    max_entries: usize,
    entries: std.ArrayList(Entry) = .empty,
    sequence: u64 = 0,
    evictions: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        max_entries: usize,
    ) std.mem.Allocator.Error!Cache {
        var self = Cache{
            .allocator = allocator,
            .max_entries = max_entries,
        };
        errdefer self.deinit();
        try self.entries.ensureTotalCapacity(allocator, max_entries);
        return self;
    }

    pub fn deinit(self: *Cache) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Cache) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.clearRetainingCapacity();
    }

    pub fn stats(self: *const Cache) Stats {
        return .{
            .entries = self.entries.items.len,
            .capacity = self.max_entries,
            .evictions = self.evictions,
        };
    }

    pub fn lookup(
        self: *Cache,
        origin: http3.Origin,
    ) ?http3.Settings {
        const index = self.find(origin) orelse return null;
        self.entries.items[index].last_used = self.nextSequence();
        return self.entries.items[index].settings;
    }

    pub fn remember(
        self: *Cache,
        origin: http3.Origin,
        settings: http3.Settings,
    ) (http3.Error || std.mem.Allocator.Error)!void {
        if (self.max_entries == 0) return;
        if (self.find(origin)) |index| {
            self.entries.items[index].settings = settings;
            self.entries.items[index].last_used = self.nextSequence();
            return;
        }

        var key = try http3.originKeyFromOrigin(self.allocator, origin);
        errdefer key.deinit();
        const entry = Entry{
            .key = key,
            .settings = settings,
            .last_used = self.nextSequence(),
        };
        if (self.entries.items.len < self.max_entries) {
            self.entries.appendAssumeCapacity(entry);
            return;
        }

        const oldest = self.oldestIndex();
        self.entries.items[oldest].deinit();
        self.entries.items[oldest] = entry;
        self.evictions +%= 1;
    }

    fn find(self: *const Cache, origin: http3.Origin) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (http3.sameOrigin(entry.key.origin(), origin)) return index;
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

    fn nextSequence(self: *Cache) u64 {
        self.sequence +%= 1;
        if (self.sequence == 0) {
            // Preserve a deterministic ordering across the practically
            // unreachable wrap without allowing a new entry to look oldest.
            for (self.entries.items, 1..) |*entry, index| {
                entry.last_used = index;
            }
            self.sequence = self.entries.items.len + 1;
        }
        return self.sequence;
    }
};

test "HTTP/3 remembered SETTINGS are origin scoped and bounded" {
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    const first = http3.Origin{
        .scheme = "https",
        .host = "first.example",
        .port = 443,
    };
    const second = http3.Origin{
        .scheme = "https",
        .host = "second.example",
        .port = 443,
    };
    const third = http3.Origin{
        .scheme = "https",
        .host = "third.example",
        .port = 8443,
    };
    try cache.remember(first, .{ .qpack_max_table_capacity = 1 });
    try cache.remember(second, .{ .qpack_max_table_capacity = 2 });
    try std.testing.expectEqual(
        @as(u64, 1),
        cache.lookup(.{
            .scheme = "HTTPS",
            .host = "FIRST.EXAMPLE",
            .port = 443,
        }).?.qpack_max_table_capacity,
    );
    try cache.remember(third, .{ .qpack_max_table_capacity = 3 });
    try std.testing.expect(cache.lookup(second) == null);
    try std.testing.expectEqual(
        @as(u64, 1),
        cache.lookup(first).?.qpack_max_table_capacity,
    );
    try std.testing.expectEqual(
        @as(u64, 3),
        cache.lookup(third).?.qpack_max_table_capacity,
    );
    try std.testing.expectEqual(@as(usize, 2), cache.stats().entries);
    try std.testing.expectEqual(@as(u64, 1), cache.stats().evictions);
}
