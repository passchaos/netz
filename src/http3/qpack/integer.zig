//! QPACK variable-length prefix integer codec (RFC 9204 Section 4.1.1).

const std = @import("std");
const wire = @import("../../internal/wire.zig");

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime prefix_bits: u4, first_prefix: u8, value: u64) !void {
    try list.ensureUnusedCapacity(allocator, encodedLen(prefix_bits, value));
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    if (value < max_prefix) {
        list.appendAssumeCapacity(first_prefix | @as(u8, @intCast(value)));
        return;
    }
    list.appendAssumeCapacity(first_prefix | max_prefix);
    var remaining = value - max_prefix;
    while (remaining >= 128) {
        list.appendAssumeCapacity(@as(u8, @intCast(remaining & 0x7f)) | 0x80);
        remaining >>= 7;
    }
    list.appendAssumeCapacity(@intCast(remaining));
}

pub fn encodedLen(comptime prefix_bits: u4, value: u64) usize {
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    if (value < max_prefix) return 1;
    var len: usize = 2;
    var remaining = value - max_prefix;
    while (remaining >= 128) : (remaining >>= 7) {
        len += 1;
    }
    return len;
}

pub fn decode(cursor: *wire.Cursor, comptime prefix_bits: u4, first: u8) !usize {
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value: usize = first & max_prefix;
    if (value < max_prefix) return value;
    var shift: u6 = 0;
    while (true) {
        const byte = try cursor.readByte();
        value = std.math.add(usize, value, (@as(usize, byte & 0x7f) << shift)) catch return error.IntegerOverflow;
        if ((byte & 0x80) == 0) return value;
        shift += 7;
        if (shift >= @bitSizeOf(usize)) return error.IntegerOverflow;
    }
}
