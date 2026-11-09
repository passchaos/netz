//! Bounded little-endian/big-endian byte helpers shared by mesh wire codecs.
//!
//! Every parser in this package reads through `Reader`, which rejects reads
//! past the supplied slice. Callers still enforce semantic limits (frame size,
//! endpoint count, name length) before allocating or retaining data.

const std = @import("std");

pub const Error = error{
    Truncated,
    InvalidLength,
    ValueTooLarge,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clearRetainingCapacity(self: *Writer) void {
        self.bytes.clearRetainingCapacity();
    }

    pub fn slice(self: *const Writer) []const u8 {
        return self.bytes.items;
    }

    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.bytes.toOwnedSlice(self.allocator);
    }

    pub fn writeU8(self: *Writer, value: u8) !void {
        try self.bytes.append(self.allocator, value);
    }

    pub fn writeU16(self: *Writer, value: u16) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(value >> 8),
            @truncate(value),
        });
    }

    pub fn writeU32(self: *Writer, value: u32) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(value >> 24),
            @truncate(value >> 16),
            @truncate(value >> 8),
            @truncate(value),
        });
    }

    pub fn writeU64(self: *Writer, value: u64) !void {
        try self.bytes.appendSlice(self.allocator, &.{
            @truncate(value >> 56),
            @truncate(value >> 48),
            @truncate(value >> 40),
            @truncate(value >> 32),
            @truncate(value >> 24),
            @truncate(value >> 16),
            @truncate(value >> 8),
            @truncate(value),
        });
    }

    pub fn writeSlice(self: *Writer, value: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, value);
    }

    /// Write a `u16` byte length followed by the bytes. `max_len` bounds the
    /// payload so a caller cannot accidentally emit an unparseable field.
    pub fn writeBoundedSlice(
        self: *Writer,
        value: []const u8,
        max_len: usize,
    ) (std.mem.Allocator.Error || Error)!void {
        if (value.len > max_len or value.len > std.math.maxInt(u16)) {
            return error.ValueTooLarge;
        }
        try self.writeU16(@intCast(value.len));
        try self.writeSlice(value);
    }
};

pub const Reader = struct {
    input: []const u8,
    index: usize = 0,

    pub fn init(input: []const u8) Reader {
        return .{ .input = input };
    }

    pub fn remainingLen(self: *const Reader) usize {
        return self.input.len - self.index;
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.index == self.input.len;
    }

    pub fn readU8(self: *Reader) Error!u8 {
        if (self.remainingLen() < 1) return error.Truncated;
        const value = self.input[self.index];
        self.index += 1;
        return value;
    }

    pub fn readU16(self: *Reader) Error!u16 {
        const bytes = try self.readFixed(2);
        return (@as(u16, bytes[0]) << 8) | bytes[1];
    }

    pub fn readU32(self: *Reader) Error!u32 {
        const bytes = try self.readFixed(4);
        return (@as(u32, bytes[0]) << 24) |
            (@as(u32, bytes[1]) << 16) |
            (@as(u32, bytes[2]) << 8) |
            bytes[3];
    }

    pub fn readU64(self: *Reader) Error!u64 {
        const bytes = try self.readFixed(8);
        var value: u64 = 0;
        for (bytes) |byte| value = (value << 8) | byte;
        return value;
    }

    pub fn readFixed(self: *Reader, comptime len: usize) Error![len]u8 {
        if (self.remainingLen() < len) return error.Truncated;
        const start = self.index;
        self.index += len;
        return self.input[start..][0..len].*;
    }

    pub fn readSlice(self: *Reader, len: usize) Error![]const u8 {
        if (self.remainingLen() < len) return error.Truncated;
        const start = self.index;
        self.index += len;
        return self.input[start..self.index];
    }

    pub fn readBoundedSlice(self: *Reader, max_len: usize) Error![]const u8 {
        const len = try self.readU16();
        if (len > max_len) return error.ValueTooLarge;
        return self.readSlice(len);
    }

    pub fn expectEnd(self: *const Reader) Error!void {
        if (!self.atEnd()) return error.InvalidLength;
    }
};

test "writer and reader round trip" {
    var writer = Writer.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeU8(0xab);
    try writer.writeU16(0x1234);
    try writer.writeU32(0xdeadbeef);
    try writer.writeU64(0x0123456789abcdef);
    try writer.writeBoundedSlice("meshz", 16);

    var reader = Reader.init(writer.slice());
    try std.testing.expectEqual(@as(u8, 0xab), try reader.readU8());
    try std.testing.expectEqual(@as(u16, 0x1234), try reader.readU16());
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), try reader.readU32());
    try std.testing.expectEqual(@as(u64, 0x0123456789abcdef), try reader.readU64());
    try std.testing.expectEqualStrings("meshz", try reader.readBoundedSlice(16));
    try reader.expectEnd();
}

test "reader rejects truncation and oversized bounded slices" {
    var writer = Writer.init(std.testing.allocator);
    defer writer.deinit();
    try writer.writeU16(5);
    try writer.writeSlice("hello");

    var reader = Reader.init(writer.slice());
    try std.testing.expectError(error.ValueTooLarge, reader.readBoundedSlice(4));

    var short = Reader.init(&.{0x12});
    try std.testing.expectError(error.Truncated, short.readU16());
}
