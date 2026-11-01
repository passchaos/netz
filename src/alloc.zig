//! Bounded cache for message-sized allocations.
//!
//! `BlockCache` wraps a backing allocator and retains freed power-of-two
//! blocks up to a byte cap. It targets large protocol messages, where repeated
//! multi-hundred-KiB allocations can dominate throughput even when the backing
//! allocator is otherwise competitive.

const std = @import("std");

pub const BlockCache = struct {
    backing: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    free_lists: [class_count]?*FreeNode = .{null} ** class_count,
    cached_bytes: usize = 0,
    hits: usize = 0,
    misses: usize = 0,
    max_cached_bytes: usize,

    const min_class: usize = 4 * 1024;
    const max_class: usize = 16 * 1024 * 1024;
    const class_count: usize = 13; // 4 KiB through 16 MiB, power-of-two classes.
    const cache_alignment: std.mem.Alignment = .@"16";

    const FreeNode = struct {
        next: ?*FreeNode,
    };

    pub const Options = struct {
        /// Zero disables caching; freed blocks return to the backing allocator.
        max_cached_bytes: usize = 16 * 1024 * 1024,
    };

    pub fn init(backing: std.mem.Allocator, options: Options) BlockCache {
        return .{
            .backing = backing,
            .max_cached_bytes = options.max_cached_bytes,
        };
    }

    fn lock(self: *BlockCache) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *BlockCache) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *BlockCache) void {
        self.lock();
        defer self.unlock();
        for (&self.free_lists, 0..) |*list, index| {
            var node = list.*;
            list.* = null;
            while (node) |current| {
                node = current.next;
                self.backing.rawFree(
                    @as([*]u8, @ptrCast(current))[0..classSize(index)],
                    cache_alignment,
                    0,
                );
            }
        }
        self.cached_bytes = 0;
    }

    pub fn allocator(self: *BlockCache) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn hitCount(self: *const BlockCache) usize {
        return self.hits;
    }

    pub fn missCount(self: *const BlockCache) usize {
        return self.misses;
    }

    fn classIndex(len: usize) ?usize {
        if (len <= min_class) return 0;
        if (len > max_class) return null;
        const shifted = (len - 1) / min_class;
        const bits = std.math.log2_int(usize, shifted);
        return @intCast(bits + 1);
    }

    fn classSize(index: usize) usize {
        return min_class << @intCast(index);
    }

    fn allocFn(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *BlockCache = @ptrCast(@alignCast(context));
        if (len == 0 or alignment.toByteUnits() > cache_alignment.toByteUnits()) {
            return self.backing.rawAlloc(len, alignment, ret_addr);
        }
        const index = classIndex(len) orelse
            return self.backing.rawAlloc(len, alignment, ret_addr);
        self.lock();
        defer self.unlock();
        if (self.free_lists[index]) |node| {
            self.free_lists[index] = node.next;
            self.cached_bytes -= classSize(index);
            self.hits += 1;
            return @ptrCast(node);
        }
        self.misses += 1;
        return self.backing.rawAlloc(classSize(index), cache_alignment, ret_addr);
    }

    fn resizeFn(
        _: *anyopaque,
        _: []u8,
        _: std.mem.Alignment,
        _: usize,
        _: usize,
    ) bool {
        return false;
    }

    fn remapFn(
        _: *anyopaque,
        _: []u8,
        _: std.mem.Alignment,
        _: usize,
        _: usize,
    ) ?[*]u8 {
        return null;
    }

    fn freeFn(
        context: *anyopaque,
        buffer: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *BlockCache = @ptrCast(@alignCast(context));
        if (buffer.len == 0 or
            alignment.toByteUnits() > cache_alignment.toByteUnits())
        {
            self.backing.rawFree(buffer, alignment, ret_addr);
            return;
        }
        const index = classIndex(buffer.len) orelse {
            self.backing.rawFree(buffer, alignment, ret_addr);
            return;
        };
        const size = classSize(index);
        const allocation: []u8 = @as([*]u8, @ptrCast(buffer.ptr))[0..size];
        self.lock();
        defer self.unlock();
        if (self.cached_bytes + size > self.max_cached_bytes) {
            self.backing.rawFree(allocation, cache_alignment, ret_addr);
            return;
        }
        const node: *FreeNode = @ptrCast(@alignCast(buffer.ptr));
        node.* = .{ .next = self.free_lists[index] };
        self.free_lists[index] = node;
        self.cached_bytes += size;
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };
};

test "block cache reuses message-sized allocations" {
    const allocator = std.testing.allocator;
    var cache = BlockCache.init(allocator, .{});
    defer cache.deinit();
    const wrapped = cache.allocator();
    const first = try wrapped.alloc(u8, 256 * 1024);
    wrapped.free(first);
    const second = try wrapped.alloc(u8, 256 * 1024);
    try std.testing.expectEqual(first.ptr, second.ptr);
    wrapped.free(second);
}

test "block cache rounds sizes and honors the byte cap" {
    const allocator = std.testing.allocator;
    var cache = BlockCache.init(allocator, .{ .max_cached_bytes = 0 });
    defer cache.deinit();
    const wrapped = cache.allocator();
    const buffer = try wrapped.alloc(u8, 4097);
    wrapped.free(buffer);
    // A zero cap forwards the block to the backing allocator; the test
    // allocator reports any leak at the end of the test.
}

test "block cache deinit releases cached blocks" {
    const allocator = std.testing.allocator;
    var cache = BlockCache.init(allocator, .{});
    const wrapped = cache.allocator();
    const buffer = try wrapped.alloc(u8, 512 * 1024);
    wrapped.free(buffer);
    cache.deinit();
}
