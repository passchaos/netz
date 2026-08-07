const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    InvalidCryptoRange,
    CryptoBufferTooLarge,
    ConflictingCryptoData,
    NothingAvailable,
} || quic.Error || std.mem.Allocator.Error;

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8) = .empty,
    received: std.ArrayList(bool) = .empty,
    read_offset: usize = 0,
    contiguous_end: usize = 0,
    max_buffered: usize,

    pub fn init(allocator: std.mem.Allocator, max_buffered: usize) Reassembler {
        return .{ .allocator = allocator, .max_buffered = max_buffered };
    }

    pub fn deinit(self: *Reassembler) void {
        self.buffer.deinit(self.allocator);
        self.received.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn insert(self: *Reassembler, frame: quic.CryptoFrame) Error!void {
        if (frame.data.len == 0) return;
        const offset = std.math.cast(usize, frame.offset) orelse return error.InvalidCryptoRange;
        const end = std.math.add(usize, offset, frame.data.len) catch return error.InvalidCryptoRange;
        if (end > self.max_buffered) return error.CryptoBufferTooLarge;
        for (frame.data, 0..) |byte, i| {
            const absolute = offset + i;
            if (absolute >= self.received.items.len) break;
            if (!self.received.items[absolute]) continue;
            if (self.buffer.items[absolute] != byte) return error.ConflictingCryptoData;
        }
        if (end > self.buffer.items.len) {
            const old_len = self.buffer.items.len;
            try self.buffer.resize(self.allocator, end);
            @memset(self.buffer.items[old_len..end], 0);
            try self.received.resize(self.allocator, end);
            @memset(self.received.items[old_len..end], false);
        }
        @memcpy(self.buffer.items[offset..end], frame.data);
        @memset(self.received.items[offset..end], true);
        while (self.contiguous_end < self.received.items.len and self.received.items[self.contiguous_end]) {
            self.contiguous_end += 1;
        }
    }

    pub fn available(self: Reassembler) []const u8 {
        return self.buffer.items[self.read_offset..self.contiguous_end];
    }

    pub fn consume(self: *Reassembler, len: usize) Error!void {
        if (len > self.available().len) return error.NothingAvailable;
        self.read_offset += len;
    }

    pub fn readAllAvailable(self: *Reassembler, allocator: std.mem.Allocator) Error![]u8 {
        const data = self.available();
        if (data.len == 0) return error.NothingAvailable;
        const out = try allocator.dupe(u8, data);
        self.read_offset += data.len;
        return out;
    }
};

pub fn writeCryptoFrames(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    offset: u64,
    bytes: []const u8,
    max_frame_data_len: usize,
) Error!void {
    if (max_frame_data_len == 0) return error.InvalidCryptoRange;
    var written: usize = 0;
    while (written < bytes.len) {
        const chunk_len = @min(max_frame_data_len, bytes.len - written);
        try (quic.Frame{ .crypto = .{
            .offset = offset + written,
            .data = bytes[written .. written + chunk_len],
        } }).write(list, allocator);
        written += chunk_len;
    }
}

test "QUIC CRYPTO stream frames split and reassemble out of order" {
    const allocator = std.testing.allocator;
    const handshake = "client hello bytes";

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCryptoFrames(&encoded, allocator, 0, handshake, 5);

    var frames: std.ArrayList(quic.CryptoFrame) = .empty;
    defer frames.deinit(allocator);
    var pos: usize = 0;
    while (pos < encoded.items.len) {
        const parsed = try quic.parseFrame(encoded.items[pos..]);
        try std.testing.expect(parsed.frame == .crypto);
        try frames.append(allocator, parsed.frame.crypto);
        pos += parsed.consumed;
    }
    try std.testing.expect(frames.items.len > 1);

    var reassembler = Reassembler.init(allocator, 1024);
    defer reassembler.deinit();

    var i = frames.items.len;
    while (i > 0) {
        i -= 1;
        try reassembler.insert(frames.items[i]);
    }

    try std.testing.expectEqualStrings(handshake, reassembler.available());
    const copied = try reassembler.readAllAvailable(allocator);
    defer allocator.free(copied);
    try std.testing.expectEqualStrings(handshake, copied);
    try std.testing.expectEqual(@as(usize, 0), reassembler.available().len);
}

test "QUIC CRYPTO reassembler exposes only contiguous bytes" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 32);
    defer reassembler.deinit();

    try reassembler.insert(.{ .offset = 5, .data = "world" });
    try std.testing.expectEqual(@as(usize, 0), reassembler.available().len);
    try reassembler.insert(.{ .offset = 0, .data = "hello" });
    try std.testing.expectEqualStrings("helloworld", reassembler.available());
    try reassembler.consume(5);
    try std.testing.expectEqualStrings("world", reassembler.available());
}

test "QUIC CRYPTO reassembler ignores empty no-op frames" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 8);
    defer reassembler.deinit();

    try reassembler.insert(.{ .offset = 8, .data = &.{} });
    try std.testing.expectEqual(@as(usize, 0), reassembler.available().len);
    try std.testing.expectEqual(@as(usize, 0), reassembler.buffer.items.len);

    try reassembler.insert(.{ .offset = 0, .data = "hello" });
    try std.testing.expectEqualStrings("hello", reassembler.available());
}

test "QUIC CRYPTO reassembler rejects conflicting duplicate bytes" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 32);
    defer reassembler.deinit();

    try reassembler.insert(.{ .offset = 0, .data = "abcdef" });
    // Identical retransmission overlap is harmless.
    try reassembler.insert(.{ .offset = 2, .data = "cde" });
    try std.testing.expectEqualStrings("abcdef", reassembler.available());

    // A proven byte conflict is a protocol error; the old data remains intact.
    try std.testing.expectError(error.ConflictingCryptoData, reassembler.insert(.{ .offset = 3, .data = "XYZ" }));
    try std.testing.expectEqualStrings("abcdef", reassembler.available());
}
