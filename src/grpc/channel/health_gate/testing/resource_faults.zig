const std = @import("std");

pub const Kind = enum { memory, executor };

pub const Faults = struct {
    kind: Kind,
    base: std.Io,
    enabled: std.atomic.Value(bool) = .init(false),
    hits: std.atomic.Value(usize) = .init(0),
    first_failed: std.atomic.Value(bool) = .init(false),
    owner_thread: std.atomic.Value(std.Thread.Id) = .init(0),
    address: std.Io.net.IpAddress,
    rpc_entered: std.Io.Event = .unset,
    rpc_permitted: std.Io.Event = .unset,
    local_entered: [2]std.Io.Event = .{ .unset, .unset },
    local_permitted: [2]std.Io.Event = .{ .unset, .unset },
    local_sleeps: std.atomic.Value(usize) = .init(0),
    delays_ns: [2]i96 = .{ 0, 0 },
    pub var active: ?*Faults = null;

    pub fn allocator(self: *Faults) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.kind == .memory and self.enabled.load(.acquire)) {
            _ = self.hits.fetchAdd(1, .acq_rel);
            return null;
        }
        return std.testing.allocator.rawAlloc(len, alignment, ra);
    }
    fn resize(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.kind == .memory and self.enabled.load(.acquire)) return false;
        return std.testing.allocator.rawResize(bytes, alignment, len, ra);
    }
    fn remap(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *Faults = @ptrCast(@alignCast(context));
        if (self.kind == .memory and self.enabled.load(.acquire)) return null;
        return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
    }
    fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        std.testing.allocator.rawFree(bytes, alignment, ra);
    }

    pub fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        // Only the Watch owner runs retry sleep. Timed output also creates
        // timer tasks with this I/O table; those must retain normal behavior.
        if (self.owner_thread.load(.acquire) != std.Thread.getCurrentId()) return self.base.vtable.sleep(userdata, timeout);
        if (self.first_failed.load(.acquire) and self.hits.load(.acquire) == 0) {
            self.rpc_entered.set(self.base);
            try self.rpc_permitted.wait(self.base);
        } else if (self.enabled.load(.acquire) and self.hits.load(.acquire) != 0) {
            const index = self.local_sleeps.fetchAdd(1, .acq_rel);
            std.debug.assert(index < self.local_entered.len);
            self.delays_ns[index] = timeout.deadline.durationFromNow(self.base).raw.nanoseconds;
            self.local_entered[index].set(self.base);
            try self.local_permitted[index].wait(self.base);
        }
        return self.base.vtable.sleep(userdata, timeout);
    }
};
