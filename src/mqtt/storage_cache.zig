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
    alignment: std.mem.Alignment = .@"1",
    mutex: std.atomic.Mutex = .unlocked,
    heads: [class_count]?[*]u8 = .{null} ** class_count,
    block_count: usize = 0,
    byte_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        max_blocks: usize,
    ) Cache {
        return .{ .allocator = allocator, .max_blocks = max_blocks };
    }

    pub fn initAligned(
        allocator: std.mem.Allocator,
        max_blocks: usize,
        alignment: std.mem.Alignment,
    ) Cache {
        return .{
            .allocator = allocator,
            .max_blocks = max_blocks,
            .alignment = alignment,
        };
    }

    /// Expose the cache as a thread-safe allocator whose returned slice keeps
    /// the caller-requested length while the cache retains its rounded
    /// capacity. Direct `acquire`/`release` remain lock-free for owners that
    /// already serialize access.
    pub fn asAllocator(self: *Cache) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &allocator_vtable };
    }

    pub fn acquireThreadSafe(
        self: *Cache,
        required_len: usize,
    ) std.mem.Allocator.Error![]u8 {
        self.lock();
        defer self.mutex.unlock();
        return self.acquire(required_len);
    }

    pub fn releaseThreadSafe(self: *Cache, storage: []u8) void {
        self.lock();
        defer self.mutex.unlock();
        self.release(storage);
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
                self.allocator.rawFree(
                    storage,
                    self.alignment,
                    @returnAddress(),
                );
            }
        }
        self.* = undefined;
    }

    pub fn acquire(
        self: *Cache,
        required_len: usize,
    ) std.mem.Allocator.Error![]u8 {
        if (required_len == 0) return self.allocator.alloc(u8, 0);
        const storage_len = storageLength(required_len);
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
        const pointer = self.allocator.rawAlloc(
            storage_len,
            self.alignment,
            @returnAddress(),
        ) orelse return error.OutOfMemory;
        return pointer[0..storage_len];
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
        self.allocator.rawFree(
            storage,
            self.alignment,
            @returnAddress(),
        );
    }

    pub fn cachedBlockCount(self: Cache) usize {
        return self.block_count;
    }

    pub fn cachedByteCount(self: Cache) usize {
        return self.byte_count;
    }

    const allocator_vtable: std.mem.Allocator.VTable = .{
        .alloc = allocatorAlloc,
        .resize = allocatorResize,
        .remap = allocatorRemap,
        .free = allocatorFree,
    };

    fn allocatorAlloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        _: usize,
    ) ?[*]u8 {
        const self: *Cache = @ptrCast(@alignCast(context));
        if (alignment.compare(.gt, self.alignment)) return null;
        const storage = self.acquireThreadSafe(len) catch return null;
        return storage.ptr;
    }

    fn allocatorResize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        _: usize,
    ) bool {
        const self: *Cache = @ptrCast(@alignCast(context));
        if (alignment.compare(.gt, self.alignment)) return false;
        return storageLength(memory.len) == storageLength(new_len);
    }

    fn allocatorRemap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        if (!allocatorResize(
            context,
            memory,
            alignment,
            new_len,
            return_address,
        )) return null;
        return memory.ptr;
    }

    fn allocatorFree(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        _: usize,
    ) void {
        const self: *Cache = @ptrCast(@alignCast(context));
        std.debug.assert(!alignment.compare(.gt, self.alignment));
        const storage = memory.ptr[0..storageLength(memory.len)];
        self.releaseThreadSafe(storage);
    }

    fn storageLength(required_len: usize) usize {
        if (required_len == 0) return 0;
        return if (required_len <= max_cacheable_storage)
            std.math.ceilPowerOfTwo(usize, required_len) catch unreachable
        else
            required_len;
    }

    fn lock(self: *Cache) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
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

test "bounded storage cache allocator preserves aligned rounded backing" {
    var cache = Cache.initAligned(
        std.testing.allocator,
        1,
        .@"16",
    );
    defer cache.deinit();
    const allocator = cache.asAllocator();

    const first = try allocator.alignedAlloc(u8, .@"16", 80);
    try std.testing.expectEqual(@as(usize, 80), first.len);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(first.ptr) % 16);
    allocator.free(first);
    try std.testing.expectEqual(@as(usize, 1), cache.cachedBlockCount());
    try std.testing.expectEqual(@as(usize, 128), cache.cachedByteCount());

    const second = try allocator.alloc(u8, 100);
    try std.testing.expectEqual(first.ptr, second.ptr);
    allocator.free(second);
    try std.testing.expectEqual(@as(usize, 1), cache.cachedBlockCount());
    try std.testing.expectEqual(@as(usize, 128), cache.cachedByteCount());
}

test "bounded storage cache allocator serializes concurrent owners" {
    var cache = Cache.initAligned(
        std.testing.allocator,
        8,
        .@"16",
    );
    defer cache.deinit();
    const allocator = cache.asAllocator();
    const Worker = struct {
        fn run(shared: std.mem.Allocator, byte: u8) void {
            for (0..1000) |_| {
                const memory = shared.alignedAlloc(
                    u8,
                    .@"16",
                    80,
                ) catch @panic("allocation failed");
                @memset(memory, byte);
                shared.free(memory);
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(
            .{},
            Worker.run,
            .{ allocator, @as(u8, @intCast(index)) },
        );
    }
    for (threads) |thread| thread.join();
    try std.testing.expect(cache.cachedBlockCount() <= 4);
    try std.testing.expectEqual(
        cache.cachedBlockCount() * 128,
        cache.cachedByteCount(),
    );
}
