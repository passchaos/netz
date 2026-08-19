//! Thread-safe allocation telemetry for multi-threaded runtime benchmarks.

const std = @import("std");

pub const bucket_count = 7;
pub const exact_size_capacity = 128;
pub const bucket_labels = [_][]const u8{
    "<=64", "<=256", "<=1K", "<=4K", "<=16K", "<=64K", ">64K",
};

pub const Snapshot = struct {
    current_bytes: usize,
    peak_bytes: usize,
    total_allocated: usize,
    total_freed: usize,
    alloc_count: usize,
    free_count: usize,
    resize_count: usize,
    remap_count: usize,
    alloc_buckets: [bucket_count]usize,
    alloc_bucket_bytes: [bucket_count]usize,
    exact_sizes: [exact_size_capacity]ExactSize,
    exact_size_len: usize,

    pub fn print(self: Snapshot) void {
        std.debug.print(
            "allocator stats\n" ++
                "  alloc count: {d}\n" ++
                "  free count: {d}\n" ++
                "  resize count: {d}\n" ++
                "  remap count: {d}\n" ++
                "  total allocated bytes: {d}\n" ++
                "  total freed bytes: {d}\n" ++
                "  live bytes: {d}\n" ++
                "  peak live bytes: {d}\n",
            .{
                self.alloc_count,   self.free_count,      self.resize_count,
                self.remap_count,   self.total_allocated, self.total_freed,
                self.current_bytes, self.peak_bytes,
            },
        );
        std.debug.print("  allocation buckets:\n", .{});
        for (bucket_labels, 0..) |label, index| {
            std.debug.print(
                "    {s}: count={d}, bytes={d}\n",
                .{
                    label,
                    self.alloc_buckets[index],
                    self.alloc_bucket_bytes[index],
                },
            );
        }
        std.debug.print("  top exact allocation sizes:\n", .{});
        var emitted: usize = 0;
        var ceiling: usize = std.math.maxInt(usize);
        while (emitted < 12) : (emitted += 1) {
            var best: ?ExactSize = null;
            for (self.exact_sizes[0..self.exact_size_len]) |entry| {
                if (entry.count >= ceiling) continue;
                if (best == null or entry.count > best.?.count) best = entry;
            }
            const entry = best orelse break;
            std.debug.print("    {d} bytes: {d}\n", .{ entry.size, entry.count });
            ceiling = entry.count;
        }
    }
};

pub const ExactSize = struct { size: usize = 0, count: usize = 0 };

pub const CountingAllocator = struct {
    backing: std.mem.Allocator,
    current_bytes: std.atomic.Value(usize) = .init(0),
    peak_bytes: std.atomic.Value(usize) = .init(0),
    total_allocated: std.atomic.Value(usize) = .init(0),
    total_freed: std.atomic.Value(usize) = .init(0),
    alloc_count: std.atomic.Value(usize) = .init(0),
    free_count: std.atomic.Value(usize) = .init(0),
    resize_count: std.atomic.Value(usize) = .init(0),
    remap_count: std.atomic.Value(usize) = .init(0),
    alloc_buckets: [bucket_count]std.atomic.Value(usize) =
        .{std.atomic.Value(usize).init(0)} ** bucket_count,
    alloc_bucket_bytes: [bucket_count]std.atomic.Value(usize) =
        .{std.atomic.Value(usize).init(0)} ** bucket_count,
    exact_mutex: std.Io.Mutex = .init,
    exact_sizes: [exact_size_capacity]ExactSize =
        .{ExactSize{}} ** exact_size_capacity,
    exact_size_len: usize = 0,

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(backing: std.mem.Allocator) CountingAllocator {
        return .{ .backing = backing };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn snapshot(self: *const CountingAllocator) Snapshot {
        var result: Snapshot = .{
            .current_bytes = self.current_bytes.load(.monotonic),
            .peak_bytes = self.peak_bytes.load(.monotonic),
            .total_allocated = self.total_allocated.load(.monotonic),
            .total_freed = self.total_freed.load(.monotonic),
            .alloc_count = self.alloc_count.load(.monotonic),
            .free_count = self.free_count.load(.monotonic),
            .resize_count = self.resize_count.load(.monotonic),
            .remap_count = self.remap_count.load(.monotonic),
            .alloc_buckets = undefined,
            .alloc_bucket_bytes = undefined,
            .exact_sizes = undefined,
            .exact_size_len = 0,
        };
        for (0..bucket_count) |index| {
            result.alloc_buckets[index] =
                self.alloc_buckets[index].load(.monotonic);
            result.alloc_bucket_bytes[index] =
                self.alloc_bucket_bytes[index].load(.monotonic);
        }
        const mutable: *CountingAllocator = @constCast(self);
        const io = std.Io.Threaded.global_single_threaded.io();
        mutable.exact_mutex.lockUncancelable(io);
        defer mutable.exact_mutex.unlock(io);
        result.exact_size_len = self.exact_size_len;
        @memcpy(
            result.exact_sizes[0..self.exact_size_len],
            self.exact_sizes[0..self.exact_size_len],
        );
        return result;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse
            return null;
        _ = self.alloc_count.fetchAdd(1, .monotonic);
        self.recordAlloc(len);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.backing.rawResize(memory, alignment, new_len, ret_addr)) {
            return false;
        }
        _ = self.resize_count.fetchAdd(1, .monotonic);
        self.recordResize(memory.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.backing.rawRemap(
            memory,
            alignment,
            new_len,
            ret_addr,
        ) orelse return null;
        _ = self.remap_count.fetchAdd(1, .monotonic);
        self.recordResize(memory.len, new_len);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.free_count.fetchAdd(1, .monotonic);
        _ = self.total_freed.fetchAdd(memory.len, .monotonic);
        _ = self.current_bytes.fetchSub(memory.len, .monotonic);
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    fn recordAlloc(self: *CountingAllocator, len: usize) void {
        const bucket = bucketIndex(len);
        _ = self.alloc_buckets[bucket].fetchAdd(1, .monotonic);
        _ = self.alloc_bucket_bytes[bucket].fetchAdd(len, .monotonic);
        self.recordExactSize(len);
        _ = self.total_allocated.fetchAdd(len, .monotonic);
        const current = self.current_bytes.fetchAdd(len, .monotonic) + len;
        _ = self.peak_bytes.fetchMax(current, .monotonic);
    }

    fn recordExactSize(self: *CountingAllocator, len: usize) void {
        const io = std.Io.Threaded.global_single_threaded.io();
        self.exact_mutex.lockUncancelable(io);
        defer self.exact_mutex.unlock(io);
        for (self.exact_sizes[0..self.exact_size_len]) |*entry| {
            if (entry.size != len) continue;
            entry.count += 1;
            return;
        }
        if (self.exact_size_len == self.exact_sizes.len) return;
        self.exact_sizes[self.exact_size_len] = .{
            .size = len,
            .count = 1,
        };
        self.exact_size_len += 1;
    }

    fn recordResize(self: *CountingAllocator, old_len: usize, new_len: usize) void {
        if (new_len > old_len) {
            const delta = new_len - old_len;
            _ = self.total_allocated.fetchAdd(delta, .monotonic);
            const current = self.current_bytes.fetchAdd(delta, .monotonic) +
                delta;
            _ = self.peak_bytes.fetchMax(current, .monotonic);
        } else {
            const delta = old_len - new_len;
            _ = self.total_freed.fetchAdd(delta, .monotonic);
            _ = self.current_bytes.fetchSub(delta, .monotonic);
        }
    }

    fn bucketIndex(len: usize) usize {
        if (len <= 64) return 0;
        if (len <= 256) return 1;
        if (len <= 1024) return 2;
        if (len <= 4096) return 3;
        if (len <= 16 * 1024) return 4;
        if (len <= 64 * 1024) return 5;
        return 6;
    }
};
