//! Origin-keyed HTTP/3 idle connection pool metadata.
//!
//! The pool is intentionally generic over the stored connection handle.  HTTP/3
//! has multiple runtime layers (`ProtectedClient`, `HandshakeClient`, and
//! embedders with their own wrappers); this helper owns only normalized origin
//! keys and caller handles, while the caller supplies a drop callback for
//! handles that expire or exceed capacity.

const std = @import("std");
const authority = @import("../http/authority/mod.zig");
const http3 = @import("mod.zig");

const OriginIndexKey = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
};

const OriginIndexContext = struct {
    pub fn hash(_: @This(), key: OriginIndexKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, key.scheme.len);
        updateLower(&hasher, key.scheme);
        std.hash.autoHash(&hasher, authority.hostHash(key.host) catch 0);
        std.hash.autoHash(&hasher, key.port);
        return hasher.final();
    }

    pub fn eql(_: @This(), lhs: OriginIndexKey, rhs: OriginIndexKey) bool {
        return lhs.port == rhs.port and
            std.ascii.eqlIgnoreCase(lhs.scheme, rhs.scheme) and
            authority.hostEquivalent(lhs.host, rhs.host);
    }

    fn updateLower(hasher: *std.hash.Wyhash, bytes: []const u8) void {
        var lowered: [64]u8 = undefined;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(lowered.len, bytes.len - offset);
            for (bytes[offset..][0..chunk_len], lowered[0..chunk_len]) |byte, *out| {
                out.* = std.ascii.toLower(byte);
            }
            hasher.update(lowered[0..chunk_len]);
            offset += chunk_len;
        }
    }
};

const OriginBucket = struct {
    head: usize,
    tail: usize,
    count: usize,
};

const OriginIndex = std.HashMapUnmanaged(
    OriginIndexKey,
    OriginBucket,
    OriginIndexContext,
    std.hash_map.default_max_load_percentage,
);

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
        /// Per-origin linked-list index. Entries remain in `entries` for cheap
        /// global capacity eviction, while this map makes origin counts and
        /// reuse selection independent of total idle pool size.
        origin_index: OriginIndex = .empty,
        total_reused: u64 = 0,
        total_misses: u64 = 0,
        total_dropped: u64 = 0,
        release_sequence: u64 = 0,

        const Self = @This();

        const Entry = struct {
            key: http3.OriginKey,
            handle: Handle,
            pooled_at_ms: u64,
            /// Monotonic insertion order breaks equal-timestamp ties and keeps
            /// global capacity eviction independent of `swapRemove` layout.
            release_sequence: u64,
            origin_prev: ?usize = null,
            origin_next: ?usize = null,
        };

        /// One idle handle removed for reuse while preserving the origin that
        /// authenticated and created the underlying connection. Cross-origin
        /// HTTP reuse must not replace this key with the latest request origin.
        pub const Acquired = struct {
            key: http3.OriginKey,
            handle: Handle,
            exact_origin: bool,
        };

        pub const ReusePolicy = struct {
            context: *const anyopaque,
            allows: *const fn (
                context: *const anyopaque,
                connection_origin: http3.Origin,
                requested_origin: http3.Origin,
                handle: *const Handle,
            ) bool,
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
            self.origin_index.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn idleCount(self: *const Self) usize {
            return self.entries.items.len;
        }

        pub fn stats(self: *const Self) Stats {
            return .{
                .idle = self.entries.items.len,
                .total_reused = self.total_reused,
                .total_misses = self.total_misses,
                .total_dropped = self.total_dropped,
            };
        }

        pub fn getStats(self: *const Self) Stats {
            return self.stats();
        }

        pub fn hitRate(self: *const Self) f64 {
            return self.stats().hitRate();
        }

        pub fn idleCountForOrigin(self: *const Self, origin: http3.Origin) usize {
            if (self.entries.items.len == 0) return 0;
            const bucket = self.origin_index.get(originIndexKey(origin)) orelse return 0;
            return bucket.count;
        }

        pub fn pruneExpired(self: *Self, now_ms: u64) usize {
            var removed: usize = 0;
            var index: usize = 0;
            while (index < self.entries.items.len) {
                if (!self.expired(self.entries.items[index], now_ms)) {
                    index += 1;
                    continue;
                }
                var expired_entry = self.removeEntryAt(index);
                self.destroyEntry(&expired_entry);
                removed += 1;
            }
            return removed;
        }

        pub fn acquire(self: *Self, origin: http3.Origin, now_ms: u64) ?Handle {
            if (self.entries.items.len == 0) {
                self.total_misses +|= 1;
                return null;
            }
            _ = self.pruneExpired(now_ms);
            if (self.entries.items.len == 0) {
                self.total_misses +|= 1;
                return null;
            }
            const bucket = self.origin_index.get(originIndexKey(origin)) orelse {
                self.total_misses +|= 1;
                return null;
            };
            var pooled = self.removeEntryAt(bucket.head);
            const handle = pooled.handle;
            pooled.key.deinit();
            self.total_reused +|= 1;
            return handle;
        }

        /// Acquire the oldest eligible idle handle, preferring the exact
        /// origin's FIFO before considering cross-origin candidates.
        ///
        /// The policy runs while the owning pool is locked and therefore must
        /// be bounded and nonblocking. On success, ownership of both the handle
        /// and its original connection key transfers to the caller.
        pub fn acquireMatching(
            self: *Self,
            requested_origin: http3.Origin,
            now_ms: u64,
            policy: ReusePolicy,
        ) ?Acquired {
            if (self.entries.items.len == 0) {
                self.total_misses +|= 1;
                return null;
            }
            _ = self.pruneExpired(now_ms);
            if (self.entries.items.len == 0) {
                self.total_misses +|= 1;
                return null;
            }

            var selected: ?usize = null;
            if (self.origin_index.get(originIndexKey(requested_origin))) |bucket| {
                var candidate: ?usize = bucket.head;
                while (candidate) |index| {
                    const entry = &self.entries.items[index];
                    const next = entry.origin_next;
                    if (policy.allows(
                        policy.context,
                        entry.key.origin(),
                        requested_origin,
                        &entry.handle,
                    )) {
                        selected = index;
                        break;
                    }
                    candidate = next;
                }
            }

            if (selected == null) {
                for (self.entries.items, 0..) |*entry, index| {
                    if (http3.sameOrigin(
                        entry.key.origin(),
                        requested_origin,
                    )) continue;
                    if (!policy.allows(
                        policy.context,
                        entry.key.origin(),
                        requested_origin,
                        &entry.handle,
                    )) continue;
                    if (selected) |current| {
                        if (!olderThan(entry.*, self.entries.items[current])) {
                            continue;
                        }
                    }
                    selected = index;
                }
            }

            const index = selected orelse {
                self.total_misses +|= 1;
                return null;
            };
            const exact_origin = http3.sameOrigin(
                self.entries.items[index].key.origin(),
                requested_origin,
            );
            const pooled = self.removeEntryAt(index);
            self.total_reused +|= 1;
            return .{
                .key = pooled.key,
                .handle = pooled.handle,
                .exact_origin = exact_origin,
            };
        }

        /// Remove the globally least-recently-released idle handle. This is
        /// used by owning pools when a new origin needs to replace idle
        /// capacity without temporarily exceeding their total connection cap.
        pub fn takeOldest(self: *Self) ?Handle {
            if (self.entries.items.len == 0) return null;
            var entry = self.removeEntryAt(self.oldestEntryIndex());
            const handle = entry.handle;
            entry.key.deinit();
            return handle;
        }

        fn removeEntryAt(self: *Self, index: usize) Entry {
            const old_len = self.entries.items.len;
            self.detachOriginIndex(index);
            const removed = self.entries.swapRemove(index);
            if (index != old_len - 1) {
                self.reindexMovedEntry(index);
            }
            return removed;
        }

        pub fn release(
            self: *Self,
            handle: Handle,
            origin: http3.Origin,
            now_ms: u64,
        ) !void {
            _ = self.pruneExpired(now_ms);
            if (self.config.max_idle_per_origin == 0 or
                self.config.max_idle_total == 0)
            {
                self.dropHandle(handle);
                return;
            }
            if (self.idleCountForOrigin(origin) >= self.config.max_idle_per_origin) {
                self.dropHandle(handle);
                return;
            }
            const key = try http3.originKeyFromOrigin(self.allocator, origin);
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
            const origin_key = originIndexKey(owned_key.origin());
            const existing_bucket = self.origin_index.getPtr(origin_key);
            if (existing_bucket) |bucket| {
                if (bucket.count >= self.config.max_idle_per_origin) {
                    self.dropHandle(handle);
                    owned_key.deinit();
                    return;
                }
            }
            const new_origin = existing_bucket == null;
            if (self.entries.items.len < self.config.max_idle_total) {
                // Reserve the new slot before any capacity eviction below.
                // If allocation fails, neither an existing pooled handle nor
                // the caller's handle has been dropped.
                try self.entries.ensureUnusedCapacity(self.allocator, 1);
                if (existing_bucket) |bucket| {
                    self.appendEntryToBucketAssumeCapacity(.{
                        .key = owned_key,
                        .handle = handle,
                        .pooled_at_ms = now_ms,
                        .release_sequence = self.nextReleaseSequence(),
                    }, bucket);
                    owned_key = undefined;
                    return;
                }
                try self.origin_index.ensureUnusedCapacity(self.allocator, 1);
                self.appendEntryToNewBucketAssumeCapacity(.{
                    .key = owned_key,
                    .handle = handle,
                    .pooled_at_ms = now_ms,
                    .release_sequence = self.nextReleaseSequence(),
                });
                owned_key = undefined;
                return;
            } else {
                if (new_origin) try self.origin_index.ensureUnusedCapacity(self.allocator, 1);
                // `swapRemove` intentionally does not preserve array order, so
                // index zero is not necessarily the oldest surviving socket.
                // Capacity is small and explicit; scan it once to retain true
                // global LRU semantics without a second intrusive list.
                var evicted = self.removeEntryAt(
                    self.oldestEntryIndex(),
                );
                self.destroyEntry(&evicted);
                if (new_origin) {
                    self.appendEntryToNewBucketAssumeCapacity(.{
                        .key = owned_key,
                        .handle = handle,
                        .pooled_at_ms = now_ms,
                        .release_sequence = self.nextReleaseSequence(),
                    });
                    owned_key = undefined;
                    return;
                }
            }

            self.appendEntryAssumeCapacity(.{
                .key = owned_key,
                .handle = handle,
                .pooled_at_ms = now_ms,
                .release_sequence = self.nextReleaseSequence(),
            });
            owned_key = undefined;
        }

        fn expired(self: *const Self, entry: Entry, now_ms: u64) bool {
            return now_ms >= entry.pooled_at_ms and
                now_ms - entry.pooled_at_ms > self.config.idle_timeout_ms;
        }

        fn destroyEntry(self: *Self, entry: *Entry) void {
            entry.key.deinit();
            self.dropHandle(entry.handle);
        }

        fn nextReleaseSequence(self: *Self) u64 {
            const value = self.release_sequence;
            self.release_sequence +%= 1;
            return value;
        }

        fn oldestEntryIndex(self: *const Self) usize {
            std.debug.assert(self.entries.items.len != 0);
            var oldest: usize = 0;
            for (self.entries.items[1..], 1..) |entry, index| {
                const selected = self.entries.items[oldest];
                if (olderThan(entry, selected)) {
                    oldest = index;
                }
            }
            return oldest;
        }

        fn olderThan(candidate: Entry, selected: Entry) bool {
            return candidate.pooled_at_ms < selected.pooled_at_ms or
                (candidate.pooled_at_ms == selected.pooled_at_ms and
                    candidate.release_sequence < selected.release_sequence);
        }

        fn dropHandle(self: *Self, handle: Handle) void {
            self.drop_fn(self.allocator, handle);
            self.total_dropped +|= 1;
        }

        fn appendEntryAssumeCapacity(self: *Self, entry: Entry) void {
            const index = self.entries.items.len;
            self.entries.appendAssumeCapacity(entry);
            const key = originIndexKey(self.entries.items[index].key.origin());
            if (self.origin_index.getPtr(key)) |bucket| {
                self.entries.items[index].origin_prev = bucket.tail;
                self.entries.items[bucket.tail].origin_next = index;
                bucket.tail = index;
                bucket.count += 1;
            } else {
                self.origin_index.putAssumeCapacityNoClobber(key, .{
                    .head = index,
                    .tail = index,
                    .count = 1,
                });
            }
        }

        fn appendEntryToNewBucketAssumeCapacity(
            self: *Self,
            entry: Entry,
        ) void {
            const index = self.entries.items.len;
            self.entries.appendAssumeCapacity(entry);
            const key = originIndexKey(self.entries.items[index].key.origin());
            self.origin_index.putAssumeCapacityNoClobber(key, .{
                .head = index,
                .tail = index,
                .count = 1,
            });
        }

        fn appendEntryToBucketAssumeCapacity(
            self: *Self,
            entry: Entry,
            bucket: *OriginBucket,
        ) void {
            const index = self.entries.items.len;
            self.entries.appendAssumeCapacity(entry);
            self.entries.items[index].origin_prev = bucket.tail;
            self.entries.items[bucket.tail].origin_next = index;
            bucket.tail = index;
            bucket.count += 1;
        }

        fn detachOriginIndex(self: *Self, index: usize) void {
            const entry = self.entries.items[index];
            const key = originIndexKey(entry.key.origin());
            var bucket = self.origin_index.getPtr(key).?;
            if (entry.origin_prev) |prev| {
                self.entries.items[prev].origin_next = entry.origin_next;
            } else {
                bucket.head = entry.origin_next orelse index;
            }
            if (entry.origin_next) |next| {
                self.entries.items[next].origin_prev = entry.origin_prev;
            } else {
                bucket.tail = entry.origin_prev orelse index;
            }
            bucket.count -= 1;
            if (bucket.count == 0) {
                _ = self.origin_index.remove(key);
                return;
            }
            self.origin_index.getKeyPtr(key).?.* = originIndexKey(
                self.entries.items[bucket.head].key.origin(),
            );
        }

        fn reindexMovedEntry(self: *Self, index: usize) void {
            const moved = self.entries.items[index];
            const key = originIndexKey(moved.key.origin());
            const bucket = self.origin_index.getPtr(key).?;
            if (moved.origin_prev) |prev| {
                self.entries.items[prev].origin_next = index;
            } else {
                bucket.head = index;
            }
            if (moved.origin_next) |next| {
                self.entries.items[next].origin_prev = index;
            } else {
                bucket.tail = index;
            }
        }
    };
}

fn originIndexKey(origin: http3.Origin) OriginIndexKey {
    return .{
        .scheme = origin.scheme,
        .host = origin.host,
        .port = origin.port,
    };
}

pub fn dropInt(_: std.mem.Allocator, _: usize) void {}

pub fn countDrop(_: std.mem.Allocator, counter: *usize) void {
    counter.* += 1;
}

test {
    _ = @import("origin_pool/tests.zig");
}
