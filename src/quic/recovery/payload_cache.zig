const std = @import("std");

pub const Stats = struct {
    blocks: usize,
    bytes: usize,
    hits: u64,
    misses: u64,
};

pub const Cache = struct {
    pub const inline_depth: usize = 4;
    pub const max_cacheable_payload: usize = 1024 * 1024;
    pub const max_cached_bytes: usize = 1024 * 1024;
    const class_count: usize = @ctz(max_cacheable_payload) + 1;
    const link_size = @sizeOf(usize);

    allocator: std.mem.Allocator,
    /// Four direct slots cover tiny/control payloads. Larger bursts use an
    /// intrusive free list whose next pointer occupies otherwise-dead cached
    /// payload bytes, so a dominant class can use the complete byte budget
    /// without per-block metadata allocation or a large connection object.
    slots: [class_count][inline_depth]?[]u8 =
        .{.{null} ** inline_depth} ** class_count,
    class_counts: [class_count]u8 = .{0} ** class_count,
    overflow_heads: [class_count]?[*]u8 = .{null} ** class_count,
    block_count: usize = 0,
    byte_count: usize = 0,
    hits: u64 = 0,
    misses: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Cache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Cache) void {
        for (self.slots) |size_class| {
            for (size_class) |maybe_storage| {
                if (maybe_storage) |storage| {
                    self.allocator.free(storage);
                }
            }
        }
        for (self.overflow_heads, 0..) |maybe_head, size_class| {
            var head = maybe_head;
            const storage_len = @as(usize, 1) << @intCast(size_class);
            while (head) |ptr| {
                const storage = ptr[0..storage_len];
                const next_address = std.mem.readInt(
                    usize,
                    storage[0..link_size],
                    .native,
                );
                head = if (next_address == 0)
                    null
                else
                    @ptrFromInt(next_address);
                self.allocator.free(storage);
            }
        }
        self.* = undefined;
    }

    pub fn stats(self: Cache) Stats {
        return .{
            .blocks = self.block_count,
            .bytes = self.byte_count,
            .hits = self.hits,
            .misses = self.misses,
        };
    }

    pub fn acquire(self: *Cache, payload_len: usize) ![]u8 {
        std.debug.assert(payload_len != 0);
        const storage_len = if (payload_len <= max_cacheable_payload)
            try std.math.ceilPowerOfTwo(usize, payload_len)
        else
            payload_len;
        if (storage_len <= max_cacheable_payload) {
            const size_class = sizeClass(storage_len);
            const count = self.class_counts[size_class];
            if (count != 0) {
                const slot_index = count - 1;
                const storage = self.slots[size_class][slot_index].?;
                self.slots[size_class][slot_index] = null;
                self.class_counts[size_class] = slot_index;
                self.hits +|= 1;
                self.block_count -= 1;
                self.byte_count -= storage.len;
                return storage;
            }
            if (self.overflow_heads[size_class]) |ptr| {
                const storage = ptr[0..storage_len];
                const next_address = std.mem.readInt(
                    usize,
                    storage[0..link_size],
                    .native,
                );
                self.overflow_heads[size_class] = if (next_address == 0)
                    null
                else
                    @ptrFromInt(next_address);
                self.hits +|= 1;
                self.block_count -= 1;
                self.byte_count -= storage.len;
                return storage;
            }
        }
        self.misses +|= 1;
        return self.allocator.alloc(u8, storage_len);
    }

    pub fn release(self: *Cache, storage: []u8) void {
        if (storage.len <= max_cacheable_payload) {
            const size_class = sizeClass(storage.len);
            const count = self.class_counts[size_class];
            if (count < inline_depth and
                storage.len <= max_cached_bytes -
                    @min(max_cached_bytes, self.byte_count))
            {
                self.slots[size_class][count] = storage;
                self.class_counts[size_class] = count + 1;
                self.block_count += 1;
                self.byte_count += storage.len;
                return;
            }
            if (storage.len >= link_size and
                storage.len <= max_cached_bytes -
                    @min(max_cached_bytes, self.byte_count))
            {
                const next_address = if (self.overflow_heads[size_class]) |head|
                    @intFromPtr(head)
                else
                    0;
                std.mem.writeInt(
                    usize,
                    storage[0..link_size],
                    next_address,
                    .native,
                );
                self.overflow_heads[size_class] = storage.ptr;
                self.block_count += 1;
                self.byte_count += storage.len;
                return;
            }
        }
        self.allocator.free(storage);
    }

    fn sizeClass(storage_len: usize) usize {
        std.debug.assert(storage_len != 0);
        std.debug.assert(storage_len <= max_cacheable_payload);
        std.debug.assert(std.math.isPowerOfTwo(storage_len));
        return @ctz(storage_len);
    }
};

test "recovery payload cache reuses logical prefixes" {
    var counting = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var cache = Cache.init(counting.allocator());
    defer cache.deinit();

    const first = try cache.acquire(8);
    const allocations_after_first = counting.allocations;
    cache.release(first);
    const second = try cache.acquire(7);
    defer cache.release(second);
    try std.testing.expectEqual(@as(usize, 8), second.len);
    try std.testing.expectEqual(allocations_after_first, counting.allocations);
    try std.testing.expectEqual(@as(u64, 1), cache.stats().hits);
    try std.testing.expectEqual(@as(u64, 1), cache.stats().misses);
}

test "recovery payload cache spills by class and is byte bounded" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator);
    defer cache.deinit();

    const small_blocks = Cache.inline_depth + 2;
    for (0..small_blocks) |_| {
        cache.release(try allocator.alloc(u8, 8));
    }
    try std.testing.expectEqual(small_blocks, cache.stats().blocks);
    try std.testing.expectEqual(small_blocks * 8, cache.stats().bytes);
    var acquired: [small_blocks][]u8 = undefined;
    for (&acquired) |*storage| storage.* = try cache.acquire(7);
    try std.testing.expectEqual(@as(usize, 0), cache.stats().blocks);
    try std.testing.expectEqual(
        @as(u64, small_blocks),
        cache.stats().hits,
    );
    for (acquired) |storage| cache.release(storage);

    var large = Cache.init(allocator);
    defer large.deinit();
    for (0..3) |_| {
        large.release(try allocator.alloc(u8, Cache.max_cacheable_payload));
    }
    const large_blocks = Cache.max_cached_bytes /
        Cache.max_cacheable_payload;
    try std.testing.expectEqual(large_blocks, large.stats().blocks);
    try std.testing.expectEqual(Cache.max_cached_bytes, large.stats().bytes);
}

test "recovery payload cache lets one class use the byte budget" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator);
    defer cache.deinit();

    const block_len: usize = 4096;
    const block_count = Cache.max_cached_bytes / block_len;
    for (0..block_count + 2) |_| {
        cache.release(try allocator.alloc(u8, block_len));
    }
    try std.testing.expectEqual(block_count, cache.stats().blocks);
    try std.testing.expectEqual(Cache.max_cached_bytes, cache.stats().bytes);

    var acquired: [block_count][]u8 = undefined;
    for (&acquired) |*storage| storage.* = try cache.acquire(3000);
    try std.testing.expectEqual(@as(usize, 0), cache.stats().blocks);
    try std.testing.expectEqual(@as(u64, block_count), cache.stats().hits);
    for (acquired) |storage| cache.release(storage);
}

test "recovery payload cache keeps size classes isolated" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator);
    defer cache.deinit();

    cache.release(try allocator.alloc(u8, 4096));
    cache.release(try allocator.alloc(u8, 8192));
    const small = try cache.acquire(3000);
    const large = try cache.acquire(6000);
    try std.testing.expectEqual(@as(usize, 4096), small.len);
    try std.testing.expectEqual(@as(usize, 8192), large.len);
    cache.release(small);
    cache.release(large);
}
