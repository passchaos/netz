const std = @import("std");

pub const stack_capacity: usize = 16;

pub fn acquire(
    comptime T: type,
    allocator: std.mem.Allocator,
    stack: []T,
    count: usize,
) std.mem.Allocator.Error![]T {
    if (count <= stack.len) return stack[0..count];
    return allocator.alloc(T, count);
}

pub fn release(
    comptime T: type,
    allocator: std.mem.Allocator,
    stack: []T,
    fields: []T,
) void {
    if (fields.ptr != stack.ptr) allocator.free(fields);
}

test "WebSocket handshake header storage is stack-first with exact fallback" {
    var stack: [stack_capacity]usize = undefined;
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    const common = try acquire(usize, failing.allocator(), &stack, stack.len);
    defer release(usize, failing.allocator(), &stack, common);
    try std.testing.expectEqual(stack[0..].ptr, common.ptr);
    try std.testing.expect(!failing.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        acquire(usize, failing.allocator(), &stack, stack.len + 1),
    );
}
