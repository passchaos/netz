//! Minimal thread-safe live-byte telemetry for the endpoint soak gate.

const std = @import("std");

pub const Allocator = struct {
    backing: std.mem.Allocator,
    current_bytes: std.atomic.Value(usize) = .init(0),
    peak_bytes: std.atomic.Value(usize) = .init(0),

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(backing: std.mem.Allocator) Allocator {
        return .{ .backing = backing };
    }

    pub fn allocator(self: *Allocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn liveBytes(self: *const Allocator) usize {
        return self.current_bytes.load(.monotonic);
    }

    pub fn peakBytes(self: *const Allocator) usize {
        return self.peak_bytes.load(.monotonic);
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(context));
        const pointer = self.backing.rawAlloc(
            len,
            alignment,
            return_address,
        ) orelse return null;
        const current = self.current_bytes.fetchAdd(len, .monotonic) + len;
        _ = self.peak_bytes.fetchMax(current, .monotonic);
        return pointer;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *Allocator = @ptrCast(@alignCast(context));
        if (!self.backing.rawResize(
            memory,
            alignment,
            new_len,
            return_address,
        )) return false;
        self.recordResize(memory.len, new_len);
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *Allocator = @ptrCast(@alignCast(context));
        const pointer = self.backing.rawRemap(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse return null;
        self.recordResize(memory.len, new_len);
        return pointer;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *Allocator = @ptrCast(@alignCast(context));
        _ = self.current_bytes.fetchSub(memory.len, .monotonic);
        self.backing.rawFree(memory, alignment, return_address);
    }

    fn recordResize(self: *Allocator, old_len: usize, new_len: usize) void {
        if (new_len > old_len) {
            const delta = new_len - old_len;
            const current = self.current_bytes.fetchAdd(delta, .monotonic) +
                delta;
            _ = self.peak_bytes.fetchMax(current, .monotonic);
        } else {
            _ = self.current_bytes.fetchSub(old_len - new_len, .monotonic);
        }
    }
};
