const std = @import("std");

pub const Stats = struct {
    blocks: usize,
    bytes: usize,
    hits: u64,
    misses: u64,
};

pub const Cache = struct {
    pub const depth: usize = 4;
    pub const max_cacheable_payload: usize = 1024 * 1024;
    pub const max_cached_bytes: usize = 1024 * 1024;
    const class_count: usize = @ctz(max_cacheable_payload) + 1;

    allocator: std.mem.Allocator,
    /// Four fixed slots per power-of-two size class make ACK-time recycling
    /// allocation-free and O(1). The shallow depth covers common delayed-ACK
    /// bursts while the independent byte cap prevents large payload classes
    /// from retaining several MiB merely because their slot count is unused.
    slots: [class_count][depth]?[]u8 =
        .{.{null} ** depth} ** class_count,
    class_counts: [class_count]u8 = .{0} ** class_count,
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
        }
        self.misses +|= 1;
        return self.allocator.alloc(u8, storage_len);
    }

    pub fn release(self: *Cache, storage: []u8) void {
        if (storage.len <= max_cacheable_payload) {
            const size_class = sizeClass(storage.len);
            const count = self.class_counts[size_class];
            if (count < depth and
                storage.len <= max_cached_bytes -
                    @min(max_cached_bytes, self.byte_count))
            {
                self.slots[size_class][count] = storage;
                self.class_counts[size_class] = count + 1;
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

test "recovery payload cache is depth and byte bounded" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator);
    defer cache.deinit();

    for (0..Cache.depth + 2) |_| {
        cache.release(try allocator.alloc(u8, 8));
    }
    try std.testing.expectEqual(Cache.depth, cache.stats().blocks);
    try std.testing.expectEqual(Cache.depth * 8, cache.stats().bytes);

    var large = Cache.init(allocator);
    defer large.deinit();
    for (0..3) |_| {
        large.release(try allocator.alloc(u8, Cache.max_cacheable_payload));
    }
    try std.testing.expectEqual(@as(usize, 1), large.stats().blocks);
    try std.testing.expectEqual(Cache.max_cached_bytes, large.stats().bytes);
}
