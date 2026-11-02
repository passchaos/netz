const std = @import("std");

pub const Faults = struct {
    caller: std.Thread.Id,
    base: std.Io,
    tracking: std.atomic.Value(bool) = .init(false),
    deny: std.atomic.Value(bool) = .init(false),
    attempts: std.atomic.Value(usize) = .init(0),
    mutex: ?*std.Io.Mutex = null,
    unbounded: usize = 0,
    released: bool = false,
    pub var active: ?*Faults = null;

    fn allocation(self: *Faults) bool {
        if (std.Thread.getCurrentId() != self.caller or !self.tracking.load(.acquire)) return false;
        _ = self.attempts.fetchAdd(1, .acq_rel);
        return self.deny.load(.acquire);
    }
    pub fn allocator(self: *Faults) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.allocation()) return null;
        return std.testing.allocator.rawAlloc(len, alignment, ra);
    }
    fn resize(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.allocation()) return false;
        return std.testing.allocator.rawResize(bytes, alignment, len, ra);
    }
    fn remap(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.allocation()) return null;
        return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
    }
    fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        std.testing.allocator.rawFree(bytes, alignment, ra);
    }
    pub fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (self.mutex) |mutex| {
            if (std.Thread.getCurrentId() == self.caller and pointer == @as(*const u32, @ptrCast(&mutex.state.raw))) {
                // An older cleanup implementation must fail instead of
                // hanging while trying to reacquire the caller-held mutex.
                self.unbounded += 1;
                self.released = true;
                mutex.state.store(.unlocked, .release);
                return;
            }
        }
        self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};
