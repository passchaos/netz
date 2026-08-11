const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const Error = wire.Error;
pub const max_value: u62 = (1 << 62) - 1;

pub fn length(value: u64) Error!u8 {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_value) return 8;
    return error.VarIntTooLarge;
}

pub fn prefixForLength(len: u8) u8 {
    return switch (len) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        else => unreachable,
    };
}

pub fn encodedLen(first: u8) u8 {
    return @as(u8, 1) << @intCast(first >> 6);
}

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    const len = try length(value);
    var tmp: [8]u8 = undefined;
    encodeIntoWithLen(&tmp, value, len);
    try list.appendSlice(allocator, tmp[0..len]);
}

pub fn encodeInto(out: []u8, value: u64) Error![]u8 {
    const len = try length(value);
    if (out.len < len) return error.BufferTooShort;
    encodeIntoWithLen(out, value, len);
    return out[0..len];
}

fn encodeIntoWithLen(out: []u8, value: u64, len: u8) void {
    switch (len) {
        1 => out[0] = @truncate(value),
        2 => {
            std.mem.writeInt(u16, out[0..2], @as(u16, @intCast(value)) | 0x4000, .big);
        },
        4 => {
            std.mem.writeInt(u32, out[0..4], @as(u32, @intCast(value)) | 0x80000000, .big);
        },
        8 => {
            std.mem.writeInt(u64, out[0..8], value | 0xc000000000000000, .big);
        },
        else => unreachable,
    }
}

pub fn decode(cursor: *wire.Cursor) Error!u64 {
    const first = try cursor.peekByte();
    const len = encodedLen(first);
    const bytes = try cursor.readSlice(len);
    return switch (len) {
        1 => bytes[0] & 0x3f,
        2 => std.mem.readInt(u16, bytes[0..2], .big) & 0x3fff,
        4 => std.mem.readInt(u32, bytes[0..4], .big) & 0x3fffffff,
        8 => std.mem.readInt(u64, bytes[0..8], .big) & 0x3fffffffffffffff,
        else => unreachable,
    };
}

pub fn decodeSlice(bytes: []const u8) Error!struct { value: u64, len: u8 } {
    var cursor = wire.Cursor.init(bytes);
    const value = try decode(&cursor);
    return .{ .value = value, .len = @intCast(cursor.pos) };
}

test "QUIC varint roundtrips" {
    const allocator = std.testing.allocator;
    const values = [_]u64{ 0, 63, 64, 15293, 16383, 16384, 1073741823, 1073741824, max_value };
    for (values) |value| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encode(&encoded, allocator, value);
        var cursor = wire.Cursor.init(encoded.items);
        try std.testing.expectEqual(value, try decode(&cursor));
        try std.testing.expect(cursor.eof());
    }
}

test "QUIC varint encodes into caller storage" {
    const values = [_]u64{ 0, 63, 64, 15293, 16383, 16384, 1073741823, 1073741824, max_value };
    for (values) |value| {
        var direct: [8]u8 = undefined;
        const encoded = try encodeInto(&direct, value);

        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        try encode(&list, std.testing.allocator, value);
        try std.testing.expectEqualSlices(u8, list.items, encoded);
    }

    var too_small: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooShort, encodeInto(&too_small, 64));
}
