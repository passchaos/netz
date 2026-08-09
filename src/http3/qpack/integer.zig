//! QPACK variable-length prefix integer codec (RFC 9204 Section 4.1.1).

const std = @import("std");
const wire = @import("../../internal/wire.zig");

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime prefix_bits: u4, first_prefix: u8, value: u64) !void {
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    if (value < max_prefix) {
        try list.append(allocator, first_prefix | @as(u8, @intCast(value)));
        return;
    }
    try list.append(allocator, first_prefix | max_prefix);
    var remaining = value - max_prefix;
    while (remaining >= 128) {
        try list.append(allocator, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
        remaining >>= 7;
    }
    try list.append(allocator, @intCast(remaining));
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
