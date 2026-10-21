//! Thread-safe hard limit for broker-owned heap allocations.
//!
//! The limit follows Mosquitto's `memory_limit` convention: zero means
//! unlimited. Lowering the limit below the current live allocation total does
//! not reclaim memory, but every growth request is denied until enough memory
//! has been released.

const std = @import("std");

pub const Snapshot = struct {
    limit_bytes: usize,
    current_bytes: usize,
    peak_bytes: usize,
    denied_growths: usize,
};

pub const MemoryLimiter = struct {
    backing: std.mem.Allocator,
    limit_bytes: std.atomic.Value(usize),
    current_bytes: std.atomic.Value(usize) = .init(0),
    peak_bytes: std.atomic.Value(usize) = .init(0),
    denied_growths: std.atomic.Value(usize) = .init(0),

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(
        backing: std.mem.Allocator,
        limit_bytes: usize,
    ) MemoryLimiter {
        return .{
            .backing = backing,
            .limit_bytes = .init(limit_bytes),
        };
    }

    pub fn allocator(self: *MemoryLimiter) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Update the hard limit without disturbing live allocations. A value of
    /// zero disables the limit. If the new limit is below the live total,
    /// future growth remains denied until releases bring the total below it.
    pub fn setLimit(self: *MemoryLimiter, limit_bytes: usize) void {
        self.limit_bytes.store(limit_bytes, .seq_cst);
    }

    pub fn snapshot(self: *const MemoryLimiter) Snapshot {
        return .{
            .limit_bytes = self.limit_bytes.load(.seq_cst),
            .current_bytes = self.current_bytes.load(.seq_cst),
            .peak_bytes = self.peak_bytes.load(.seq_cst),
            .denied_growths = self.denied_growths.load(.seq_cst),
        };
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *MemoryLimiter = @ptrCast(@alignCast(context));
        if (!self.reserve(len)) return null;
        return self.backing.rawAlloc(
            len,
            alignment,
            return_address,
        ) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *MemoryLimiter = @ptrCast(@alignCast(context));
        if (new_len == memory.len) return true;
        if (new_len > memory.len) {
            const growth = new_len - memory.len;
            if (!self.reserve(growth)) return false;
            if (!self.backing.rawResize(
                memory,
                alignment,
                new_len,
                return_address,
            )) {
                self.release(growth);
                return false;
            }
            return true;
        }
        if (!self.backing.rawResize(
            memory,
            alignment,
            new_len,
            return_address,
        )) return false;
        self.release(memory.len - new_len);
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *MemoryLimiter = @ptrCast(@alignCast(context));
        if (new_len == memory.len) return memory.ptr;
        if (new_len > memory.len) {
            const growth = new_len - memory.len;
            if (!self.reserve(growth)) return null;
            return self.remapBacking(
                memory,
                alignment,
                new_len,
                return_address,
            ) orelse {
                self.release(growth);
                return null;
            };
        }
        const pointer = self.remapBacking(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse return null;
        self.release(memory.len - new_len);
        return pointer;
    }

    fn remapBacking(
        self: *MemoryLimiter,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        return self.backing.rawRemap(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse {
            const pointer = self.backing.rawAlloc(
                new_len,
                alignment,
                return_address,
            ) orelse return null;
            @memcpy(
                pointer[0..@min(memory.len, new_len)],
                memory[0..@min(memory.len, new_len)],
            );
            self.backing.rawFree(memory, alignment, return_address);
            return pointer;
        };
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *MemoryLimiter = @ptrCast(@alignCast(context));
        self.backing.rawFree(memory, alignment, return_address);
        self.release(memory.len);
    }

    fn reserve(self: *MemoryLimiter, additional: usize) bool {
        var current = self.current_bytes.load(.seq_cst);
        while (true) {
            const next = std.math.add(
                usize,
                current,
                additional,
            ) catch return self.denyGrowth();
            const limit = self.limit_bytes.load(.seq_cst);
            if (limit != 0 and next > limit) return self.denyGrowth();
            current = self.current_bytes.cmpxchgWeak(
                current,
                next,
                .seq_cst,
                .seq_cst,
            ) orelse {
                // Linearize a concurrent limit reduction: a reservation that
                // committed before the new limit remains valid, while one
                // that observes the new limit rolls itself back.
                const committed_limit = self.limit_bytes.load(.seq_cst);
                if (committed_limit != 0 and next > committed_limit) {
                    self.release(additional);
                    return self.denyGrowth();
                }
                _ = self.peak_bytes.fetchMax(next, .seq_cst);
                return true;
            };
        }
    }

    fn denyGrowth(self: *MemoryLimiter) bool {
        _ = self.denied_growths.fetchAdd(1, .monotonic);
        return false;
    }

    fn release(self: *MemoryLimiter, bytes: usize) void {
        const previous = self.current_bytes.fetchSub(bytes, .seq_cst);
        std.debug.assert(previous >= bytes);
    }
};

test "memory limiter enforces allocations, resize, and live limit changes" {
    var limiter = MemoryLimiter.init(std.testing.allocator, 12);
    const allocator = limiter.allocator();

    var first = try allocator.alloc(u8, 8);
    defer allocator.free(first);
    @memset(first, 0xa5);
    try std.testing.expectError(
        error.OutOfMemory,
        allocator.alloc(u8, 5),
    );
    first = try allocator.realloc(first, 12);
    const expected_prefix = [_]u8{0xa5} ** 8;
    try std.testing.expectEqualSlices(
        u8,
        &expected_prefix,
        first[0..8],
    );
    try std.testing.expectError(
        error.OutOfMemory,
        allocator.realloc(first, 13),
    );

    limiter.setLimit(4);
    try std.testing.expectError(
        error.OutOfMemory,
        allocator.alloc(u8, 1),
    );
    first = try allocator.realloc(first, 4);
    try std.testing.expectError(
        error.OutOfMemory,
        allocator.alloc(u8, 1),
    );

    limiter.setLimit(0);
    const unlimited = try allocator.alloc(u8, 32);
    allocator.free(unlimited);

    const snapshot = limiter.snapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.limit_bytes);
    try std.testing.expectEqual(@as(usize, 4), snapshot.current_bytes);
    try std.testing.expect(snapshot.peak_bytes >= 36);
    try std.testing.expect(snapshot.denied_growths >= 3);
}

test "memory limiter never admits concurrent allocations beyond the limit" {
    var limiter = MemoryLimiter.init(std.heap.page_allocator, 256);
    const Worker = struct {
        fn run(shared: *MemoryLimiter) void {
            const allocator = shared.allocator();
            for (0..4_000) |_| {
                const memory = allocator.alloc(u8, 32) catch continue;
                const snapshot = shared.snapshot();
                std.debug.assert(snapshot.current_bytes <= 256);
                allocator.free(memory);
            }
        }
    };

    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{&limiter});
    }
    for (threads) |thread| thread.join();

    const snapshot = limiter.snapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.current_bytes);
    try std.testing.expect(snapshot.peak_bytes <= snapshot.limit_bytes);
}
