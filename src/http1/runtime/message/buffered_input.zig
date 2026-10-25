//! Allocation boundaries for connection-owned HTTP/1 input.
const std = @import("std");

pub fn Reader(comptime Context: type) type {
    return struct {
        /// Reserve before reading, then commit exactly the returned prefix.
        /// An allocator failure leaves socket input untouched; an I/O failure
        /// leaves the already-owned message prefix intact.
        pub fn append(allocator: std.mem.Allocator, transport: Context.TransportType, input: *std.ArrayList(u8), maximum: usize, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!usize {
            std.debug.assert(maximum != 0);
            if (input.items.len == input.capacity) try input.ensureUnusedCapacity(allocator, maximum);
            const output = input.unusedCapacitySlice()[0..@min(maximum, input.capacity - input.items.len)];
            const count = try Context.readUntil(transport, output, deadline);
            input.items.len += count;
            return count;
        }
    };
}

/// Restore a complete message detached just before a decoder's local OOM.
/// The suffix's allocation still has room for the previous prefix, or the
/// entire allocation was transferred and can be adopted directly.
pub fn restore(allocator: std.mem.Allocator, input: *std.ArrayList(u8), bytes: []u8) void {
    if (input.capacity == 0) {
        std.debug.assert(input.items.len == 0);
        input.* = .fromOwnedSlice(bytes);
        return;
    }
    const old_len = input.items.len;
    std.debug.assert(bytes.len + old_len <= input.capacity);
    input.items.len += bytes.len;
    @memmove(input.items[bytes.len..], input.items[0..old_len]);
    @memcpy(input.items[0..bytes.len], bytes);
    allocator.free(bytes);
}
