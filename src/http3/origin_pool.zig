//! Origin-keyed HTTP/3 idle connection pool metadata.
//!
//! The pool is intentionally generic over the stored connection handle.  HTTP/3
//! has multiple runtime layers (`ProtectedClient`, `HandshakeClient`, and
//! embedders with their own wrappers); this helper owns only normalized origin
//! keys and caller handles, while the caller supplies a drop callback for
//! handles that expire or exceed capacity.

const std = @import("std");
const http3 = @import("mod.zig");

pub const Config = struct {
    max_idle_per_origin: usize = 4,
    max_idle_total: usize = 16,
    idle_timeout_ms: u64 = 30_000,
};

pub const Stats = struct {
    idle: usize,
    total_reused: u64,
    total_misses: u64,
    total_dropped: u64,

    pub fn hitRate(self: Stats) f64 {
        const total = self.total_reused + self.total_misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_reused)) /
            @as(f64, @floatFromInt(total));
    }
};

pub fn Pool(comptime Handle: type) type {
    return struct {
        allocator: std.mem.Allocator,
        config: Config,
        drop_fn: *const fn (std.mem.Allocator, Handle) void,
        entries: std.ArrayList(Entry) = .empty,
        total_reused: u64 = 0,
        total_misses: u64 = 0,
        total_dropped: u64 = 0,

        const Self = @This();

        const Entry = struct {
            key: http3.OriginKey,
            handle: Handle,
            pooled_at_ms: u64,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            config: Config,
            drop_fn: *const fn (std.mem.Allocator, Handle) void,
        ) Self {
            return .{
                .allocator = allocator,
                .config = config,
                .drop_fn = drop_fn,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.entries.items) |*entry| self.destroyEntry(entry);
            self.entries.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn idleCount(self: Self) usize {
            return self.entries.items.len;
        }

        pub fn stats(self: Self) Stats {
            return .{
                .idle = self.entries.items.len,
                .total_reused = self.total_reused,
                .total_misses = self.total_misses,
                .total_dropped = self.total_dropped,
            };
        }

        pub fn getStats(self: Self) Stats {
            return self.stats();
        }

        pub fn hitRate(self: Self) f64 {
            return self.stats().hitRate();
        }

        pub fn idleCountForOrigin(self: Self, origin: http3.Origin) usize {
            var count: usize = 0;
            for (self.entries.items) |entry| {
                if (http3.sameOrigin(entry.key.origin(), origin)) count += 1;
            }
            return count;
        }

        pub fn pruneExpired(self: *Self, now_ms: u64) usize {
            var removed: usize = 0;
            var index: usize = 0;
            while (index < self.entries.items.len) {
                if (!self.expired(self.entries.items[index], now_ms)) {
                    index += 1;
                    continue;
                }
                var expired_entry = self.entries.swapRemove(index);
                self.destroyEntry(&expired_entry);
                removed += 1;
            }
            return removed;
        }

        pub fn acquire(self: *Self, origin: http3.Origin, now_ms: u64) ?Handle {
            var index: usize = 0;
            while (index < self.entries.items.len) {
                const entry = &self.entries.items[index];
                if (self.expired(entry.*, now_ms)) {
                    var expired_entry = self.entries.swapRemove(index);
                    self.destroyEntry(&expired_entry);
                    continue;
                }
                if (http3.sameOrigin(entry.key.origin(), origin)) {
                    var pooled = self.entries.swapRemove(index);
                    const handle = pooled.handle;
                    pooled.key.deinit();
                    self.total_reused +|= 1;
                    return handle;
                }
                index += 1;
            }
            self.total_misses +|= 1;
            return null;
        }

        pub fn release(
            self: *Self,
            handle: Handle,
            origin: http3.Origin,
            now_ms: u64,
        ) !void {
            const key = try originKeyFromOrigin(self.allocator, origin);
            try self.releaseKey(handle, key, now_ms);
        }

        /// Return a handle to the pool using an already-owned canonical key.
        ///
        /// On success, the pool takes ownership of `key`.  If capacity policy
        /// drops the handle or appending fails, this function deinitializes
        /// `key` before returning so callers can use `errdefer key.deinit()`
        /// only until this call starts.
        pub fn releaseKey(
            self: *Self,
            handle: Handle,
            key: http3.OriginKey,
            now_ms: u64,
        ) !void {
            var owned_key = key;
            errdefer owned_key.deinit();
            _ = self.pruneExpired(now_ms);
            if (self.config.max_idle_per_origin == 0 or
                self.config.max_idle_total == 0)
            {
                self.dropHandle(handle);
                owned_key.deinit();
                return;
            }
            if (self.idleCountForOrigin(owned_key.origin()) >= self.config.max_idle_per_origin) {
                self.dropHandle(handle);
                owned_key.deinit();
                return;
            }
            if (self.entries.items.len < self.config.max_idle_total) {
                // Reserve the new slot before any capacity eviction below.
                // If allocation fails, neither an existing pooled handle nor
                // the caller's handle has been dropped.
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
            } else {
                // Idle pool entries are interchangeable for reuse decisions;
                // avoid preserving insertion order so capacity eviction stays
                // O(1) instead of memmoving the rest of the pool.
                var evicted = self.entries.swapRemove(0);
                self.destroyEntry(&evicted);
            }

            self.entries.appendAssumeCapacity(.{
                .key = owned_key,
                .handle = handle,
                .pooled_at_ms = now_ms,
            });
            owned_key = undefined;
        }

        fn expired(self: Self, entry: Entry, now_ms: u64) bool {
            return now_ms >= entry.pooled_at_ms and
                now_ms - entry.pooled_at_ms > self.config.idle_timeout_ms;
        }

        fn destroyEntry(self: *Self, entry: *Entry) void {
            entry.key.deinit();
            self.dropHandle(entry.handle);
        }

        fn dropHandle(self: *Self, handle: Handle) void {
            self.drop_fn(self.allocator, handle);
            self.total_dropped +|= 1;
        }
    };
}

fn originKeyFromOrigin(
    allocator: std.mem.Allocator,
    origin: http3.Origin,
) !http3.OriginKey {
    const scheme = try asciiLowerAlloc(allocator, origin.scheme);
    errdefer allocator.free(scheme);
    const host = try asciiLowerAlloc(allocator, origin.host);
    errdefer allocator.free(host);
    return .{
        .allocator = allocator,
        .scheme = scheme,
        .host = host,
        .port = origin.port,
    };
}

fn asciiLowerAlloc(
    allocator: std.mem.Allocator,
    value: []const u8,
) std.mem.Allocator.Error![]u8 {
    const owned = try allocator.dupe(u8, value);
    for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
    return owned;
}

fn dropInt(_: std.mem.Allocator, _: usize) void {}

fn countDrop(_: std.mem.Allocator, counter: *usize) void {
    counter.* += 1;
}

test "HTTP/3 origin pool releases and acquires by normalized origin" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{}, dropInt);
    defer pool.deinit();

    const origin = try http3.requestOrigin("https", "Example.COM");
    try pool.release(42, origin, 1000);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(
        try http3.requestOrigin("HTTPS", "example.com:443"),
    ));

    try std.testing.expectEqual(@as(?usize, 42), pool.acquire(
        try http3.requestOrigin("https", "example.com:443"),
        1500,
    ));
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    const stats = pool.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.total_reused);
    try std.testing.expectEqual(@as(f64, 1.0), stats.hitRate());
    try std.testing.expectEqual(@as(f64, 1.0), pool.hitRate());
}

test "HTTP/3 origin pool accepts owned origin keys" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{}, dropInt);
    defer pool.deinit();

    const key = try http3.requestOriginKey(allocator, "HTTPS", "Owned.EXAMPLE:443");
    try pool.releaseKey(7, key, 10);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(?usize, 7), pool.acquire(
        try http3.requestOrigin("https", "owned.example"),
        11,
    ));

    const disabled_key = try http3.requestOriginKey(allocator, "https", "drop.example");
    var disabled = IntPool.init(allocator, .{ .max_idle_total = 0 }, dropInt);
    defer disabled.deinit();
    try disabled.releaseKey(9, disabled_key, 0);
    try std.testing.expectEqual(@as(usize, 0), disabled.idleCount());
    try std.testing.expectEqual(@as(u64, 1), disabled.stats().total_dropped);
}

test "HTTP/3 origin pool releaseKey is transactional on allocation failure" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const CounterPool = Pool(*usize);
    var pool = CounterPool.init(failing.allocator(), .{}, countDrop);
    defer pool.deinit();

    var drops: usize = 0;
    const key = try http3.requestOriginKey(allocator, "https", "oom.example");
    try std.testing.expectError(
        error.OutOfMemory,
        pool.releaseKey(&drops, key, 0),
    );
    try std.testing.expectEqual(@as(usize, 0), drops);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 0), pool.stats().total_dropped);
}

test "HTTP/3 origin pool enforces expiry and capacity" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 1,
        .max_idle_total = 2,
        .idle_timeout_ms = 10,
    }, dropInt);
    defer pool.deinit();

    const a = try http3.requestOrigin("https", "a.example");
    const b = try http3.requestOrigin("https", "b.example");
    const c = try http3.requestOrigin("https", "c.example");
    try pool.release(1, a, 0);
    try pool.release(2, a, 1); // per-origin overflow: dropped.
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try pool.release(3, b, 2);
    try pool.release(4, c, 3); // total overflow evicts oldest.
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expect(pool.acquire(a, 4) == null);
    try std.testing.expectEqual(@as(u64, 1), pool.getStats().total_misses);

    // Expired b is removed while searching, then c is returned before its own
    // idle timeout elapses.
    try std.testing.expectEqual(@as(?usize, 4), pool.acquire(c, 13));
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 3), pool.stats().total_dropped);
}

test "HTTP/3 origin pool prunes expired idle handles explicitly" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{ .idle_timeout_ms = 10 }, dropInt);
    defer pool.deinit();

    try pool.release(1, try http3.requestOrigin("https", "a.example"), 0);
    try pool.release(2, try http3.requestOrigin("https", "b.example"), 5);
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());

    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired(11));
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try std.testing.expectEqual(@as(?usize, 2), pool.acquire(
        try http3.requestOrigin("https", "b.example"),
        12,
    ));
}

test "HTTP/3 origin pool release ignores expired capacity occupants" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 1,
        .max_idle_total = 1,
        .idle_timeout_ms = 10,
    }, dropInt);
    defer pool.deinit();

    const origin = try http3.requestOrigin("https", "slot.example");
    try pool.release(1, origin, 0);
    try pool.release(2, origin, 11);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try std.testing.expectEqual(@as(?usize, 2), pool.acquire(origin, 12));
}
