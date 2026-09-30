//! Bounded power-of-two storage reuse for MQTT state machines.
//!
//! The cache stores its free-list link inside each released block, avoiding
//! metadata allocations. Callers remain responsible for synchronization; the
//! broker and reconnect Session stores already serialize their own mutation.

const std = @import("std");

pub const Cache = struct {
    pub const max_cacheable_storage: usize = 64 * 1024;
    pub const max_cached_bytes: usize = 1024 * 1024;
    const class_count: usize = @ctz(max_cacheable_storage) + 1;
    const link_size = @sizeOf(usize);

    allocator: std.mem.Allocator,
    max_blocks: usize,
    heads: [class_count]?[*]u8 = .{null} ** class_count,
    block_count: usize = 0,
    byte_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        max_blocks: usize,
    ) Cache {
        return .{ .allocator = allocator, .max_blocks = max_blocks };
    }

    pub fn deinit(self: *Cache) void {
        for (self.heads, 0..) |maybe_head, size_class| {
            var head = maybe_head;
            const storage_len = @as(usize, 1) << @intCast(size_class);
            while (head) |pointer| {
                const storage = pointer[0..storage_len];
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

    pub fn acquire(
        self: *Cache,
        required_len: usize,
    ) std.mem.Allocator.Error![]u8 {
        if (required_len == 0) return self.allocator.alloc(u8, 0);
        const storage_len = if (required_len <= max_cacheable_storage)
            std.math.ceilPowerOfTwo(usize, required_len) catch unreachable
        else
            required_len;
        if (storage_len <= max_cacheable_storage) {
            const size_class: usize = @ctz(storage_len);
            if (self.heads[size_class]) |pointer| {
                const storage = pointer[0..storage_len];
                const next_address = std.mem.readInt(
                    usize,
                    storage[0..link_size],
                    .native,
                );
                self.heads[size_class] = if (next_address == 0)
                    null
                else
                    @ptrFromInt(next_address);
                self.block_count -= 1;
                self.byte_count -= storage.len;
                return storage;
            }
        }
        return self.allocator.alloc(u8, storage_len);
    }

    pub fn release(self: *Cache, storage: []u8) void {
        if (storage.len >= link_size and
            storage.len <= max_cacheable_storage and
            std.math.isPowerOfTwo(storage.len) and
            self.block_count < self.max_blocks and
            storage.len <= max_cached_bytes -
                @min(max_cached_bytes, self.byte_count))
        {
            const size_class: usize = @ctz(storage.len);
            const next_address = if (self.heads[size_class]) |head|
                @intFromPtr(head)
            else
                0;
            std.mem.writeInt(
                usize,
                storage[0..link_size],
                next_address,
                .native,
            );
            self.heads[size_class] = storage.ptr;
            self.block_count += 1;
            self.byte_count += storage.len;
            return;
        }
        self.allocator.free(storage);
    }

    pub fn cachedBlockCount(self: Cache) usize {
        return self.block_count;
    }

    pub fn cachedByteCount(self: Cache) usize {
        return self.byte_count;
    }
};

test "bounded storage cache respects block and byte limits" {
    const allocator = std.testing.allocator;
    {
        var cache = Cache.init(allocator, 2);
        defer cache.deinit();

        const first = try cache.acquire(80);
        const second = try cache.acquire(80);
        const excess = try cache.acquire(80);
        cache.release(first);
        cache.release(second);
        cache.release(excess);
        try std.testing.expectEqual(@as(usize, 2), cache.cachedBlockCount());
        try std.testing.expectEqual(@as(usize, 256), cache.cachedByteCount());
    }
    {
        var cache = Cache.init(allocator, std.math.maxInt(usize));
        defer cache.deinit();
        const block_count = Cache.max_cached_bytes /
            Cache.max_cacheable_storage;
        var blocks: [block_count + 1][]u8 = undefined;
        for (&blocks) |*storage| {
            storage.* = try cache.acquire(Cache.max_cacheable_storage);
        }
        for (blocks) |storage| cache.release(storage);
        try std.testing.expectEqual(block_count, cache.cachedBlockCount());
        try std.testing.expectEqual(
            Cache.max_cached_bytes,
            cache.cachedByteCount(),
        );
    }
}

test "bounded storage cache reuses matching size class" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var cache = Cache.init(failing.allocator(), 1);
    defer cache.deinit();
    const first = try cache.acquire(80);
    const first_pointer = first.ptr;
    cache.release(first);
    const allocations = failing.allocations;
    failing.fail_index = failing.alloc_index;

    const second = try cache.acquire(100);
    try std.testing.expectEqual(allocations, failing.allocations);
    try std.testing.expectEqual(first_pointer, second.ptr);
    cache.release(second);
}

test "bounded storage cache releases oversized blocks" {
    var cache = Cache.init(std.testing.allocator, std.math.maxInt(usize));
    defer cache.deinit();
    const oversized = try cache.acquire(Cache.max_cacheable_storage + 1);
    cache.release(oversized);
    try std.testing.expectEqual(@as(usize, 0), cache.cachedBlockCount());
    try std.testing.expectEqual(@as(usize, 0), cache.cachedByteCount());
}
