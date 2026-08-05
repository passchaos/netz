const std = @import("std");

pub const Error = error{
    BufferTooShort,
    IntegerOverflow,
    VarIntTooLarge,
    MalformedVarInt,
    InvalidEncoding,
};

pub const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Cursor {
        return .{ .buf = buf };
    }

    pub fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }

    pub fn eof(self: Cursor) bool {
        return self.pos == self.buf.len;
    }

    pub fn readByte(self: *Cursor) Error!u8 {
        if (self.remaining() < 1) return error.BufferTooShort;
        const value = self.buf[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn peekByte(self: Cursor) Error!u8 {
        if (self.remaining() < 1) return error.BufferTooShort;
        return self.buf[self.pos];
    }

    pub fn readSlice(self: *Cursor, len: usize) Error![]const u8 {
        if (self.remaining() < len) return error.BufferTooShort;
        const out = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }

    pub fn readInt(self: *Cursor, comptime T: type, endian: std.builtin.Endian) Error!T {
        const bytes = try self.readSlice(@divExact(@typeInfo(T).int.bits, 8));
        return std.mem.readInt(T, bytes[0..@divExact(@typeInfo(T).int.bits, 8)], endian);
    }

    pub fn skip(self: *Cursor, len: usize) Error!void {
        _ = try self.readSlice(len);
    }
};

pub fn appendInt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T, endian: std.builtin.Endian) !void {
    var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &tmp, value, endian);
    try list.appendSlice(allocator, &tmp);
}

pub fn appendU24(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u24) !void {
    try list.append(allocator, @truncate(value >> 16));
    try list.append(allocator, @truncate(value >> 8));
    try list.append(allocator, @truncate(value));
}

pub fn readU24(cursor: *Cursor) Error!u24 {
    const b = try cursor.readSlice(3);
    return (@as(u24, b[0]) << 16) | (@as(u24, b[1]) << 8) | @as(u24, b[2]);
}

pub fn eqlAsciiIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn trimOws(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

pub const Header = struct {
    name: []const u8,
    value: []const u8,

    pub fn eqlName(self: Header, name: []const u8) bool {
        return eqlAsciiIgnoreCase(self.name, name);
    }
};

pub fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (header.eqlName(name)) return header.value;
    }
    return null;
}

pub fn containsToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(trimOws(part), token)) return true;
    }
    return false;
}

test "wire cursor and helpers" {
    var cursor = Cursor.init(&.{ 0x12, 0x34, 0xab, 0xcd, 0xef });
    try std.testing.expectEqual(@as(u16, 0x1234), try cursor.readInt(u16, .big));
    try std.testing.expectEqual(@as(u24, 0xabcdef), try readU24(&cursor));
    try std.testing.expect(cursor.eof());
    try std.testing.expect(containsToken("keep-alive, Upgrade", "upgrade"));
}
