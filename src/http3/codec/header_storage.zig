const std = @import("std");
const Qpack = @import("../qpack/mod.zig");

pub const stack_capacity: usize = 16;

pub fn capacity(base: usize, extra: usize) error{IntegerOverflow}!usize {
    return std.math.add(usize, base, extra) catch error.IntegerOverflow;
}

pub fn acquire(
    allocator: std.mem.Allocator,
    stack: []Qpack.HeaderField,
    required: usize,
) std.mem.Allocator.Error![]Qpack.HeaderField {
    if (required <= stack.len) return stack[0..required];
    return allocator.alloc(Qpack.HeaderField, required);
}

pub fn release(
    allocator: std.mem.Allocator,
    stack: []Qpack.HeaderField,
    fields: []Qpack.HeaderField,
) void {
    if (fields.ptr != stack.ptr) allocator.free(fields);
}
