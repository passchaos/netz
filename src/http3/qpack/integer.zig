//! QPACK variable-length prefix integer codec (RFC 9204 Section 4.1.1).

const std = @import("std");
const wire = @import("../../internal/wire.zig");

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime prefix_bits: u4, first_prefix: u8, value: u64) !void {
    try list.ensureUnusedCapacity(allocator, encodedLen(prefix_bits, value));
    encodeAssumeCapacity(list, prefix_bits, first_prefix, value);
}

pub fn encodeAssumeCapacity(list: *std.ArrayList(u8), comptime prefix_bits: u4, first_prefix: u8, value: u64) void {
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
    var shift: usize = 0;
    while (true) {
        const byte = try cursor.readByte();
        if (shift >= @bitSizeOf(usize)) return error.IntegerOverflow;
        const increment = std.math.shlExact(
            usize,
            @as(usize, byte & 0x7f),
            @intCast(shift),
        ) catch return error.IntegerOverflow;
        value = std.math.add(usize, value, increment) catch
            return error.IntegerOverflow;
        if ((byte & 0x80) == 0) return value;
        if (shift > @bitSizeOf(usize) - 7) {
            return error.IntegerOverflow;
        }
        shift += 7;
    }
}

test "QPACK prefix integer accepts maximum usize without wrapping" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encode(
        &encoded,
        allocator,
        5,
        0,
        std.math.maxInt(usize),
    );

    var cursor = wire.Cursor.init(encoded.items[1..]);
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        try decode(&cursor, 5, encoded.items[0]),
    );
    try std.testing.expect(cursor.eof());
}

test "QPACK prefix integer rejects values wider than usize" {
    const continued = [_]u8{0x80} ** 10;
    var unterminated = wire.Cursor.init(&continued);
    try std.testing.expectError(
        error.IntegerOverflow,
        decode(&unterminated, 5, 0x1f),
    );

    const terminal_overflow = [_]u8{0x80} ** 9 ++ [_]u8{0x02};
    var terminated = wire.Cursor.init(&terminal_overflow);
    try std.testing.expectError(
        error.IntegerOverflow,
        decode(&terminated, 5, 0x1f),
    );
}
