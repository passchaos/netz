//! Bounded input retained while a proxy destination is connecting.

const std = @import("std");

pub const Buffer = struct {
    inline_storage: [2048]u8 = undefined,
    heap: []u8 = &.{},
    len: usize = 0,

    pub fn bytes(self: *Buffer) []u8 {
        return if (self.heap.len == 0)
            self.inline_storage[0..self.len]
        else
            self.heap[0..self.len];
    }

    pub fn append(self: *Buffer, allocator: std.mem.Allocator, maximum: usize, input: []const u8) !void {
        if (self.len > maximum or input.len > maximum - self.len) return error.PendingBufferFull;
        const required = self.len + input.len;
        const capacity = if (self.heap.len == 0) self.inline_storage.len else self.heap.len;
        if (required > capacity) {
            const doubled = std.math.mul(usize, capacity, 2) catch maximum;
            const next = try allocator.alloc(u8, @min(maximum, @max(required, doubled)));
            @memcpy(next[0..self.len], self.bytes());
            if (self.heap.len != 0) allocator.free(self.heap);
            self.heap = next;
        }
        const storage = if (self.heap.len == 0) &self.inline_storage else self.heap;
        @memcpy(storage[self.len..][0..input.len], input);
        self.len = required;
    }

    pub fn deinit(self: *Buffer, allocator: std.mem.Allocator) void {
        if (self.heap.len != 0) allocator.free(self.heap);
        self.heap = &.{};
        self.len = 0;
    }
};

test {
    _ = @import("pending_input_tests.zig");
}
