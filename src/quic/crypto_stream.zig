const std = @import("std");
const quic = @import("mod.zig");
const ReceivedBitmap = @import("stream/received_bitmap.zig").Bitmap;

pub const Error = error{
    InvalidCryptoRange,
    CryptoBufferTooLarge,
    ConflictingCryptoData,
    NothingAvailable,
} || quic.Error || std.mem.Allocator.Error;

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8) = .empty,
    received: ReceivedBitmap = .{},
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
        const old_len = self.received.len();
        std.debug.assert(old_len == self.buffer.items.len);
        if (end <= old_len and end <= self.contiguous_end) {
            if (!std.mem.eql(u8, self.buffer.items[offset..end], frame.data)) {
                return error.ConflictingCryptoData;
            }
            return;
        }
        for (frame.data, 0..) |byte, i| {
            const absolute = offset + i;
            if (absolute >= old_len) break;
            if (!self.received.isSet(absolute)) continue;
            if (self.buffer.items[absolute] != byte) return error.ConflictingCryptoData;
        }
        if (end > old_len) {
            const fills_extension = offset <= old_len;
            try self.buffer.ensureTotalCapacity(self.allocator, end);
            try self.received.ensureResizeCapacity(
                self.allocator,
                end,
                fills_extension,
            );
            self.buffer.items.len = end;
            self.received.resizeAssumeCapacity(end, fills_extension);
            if (offset > old_len) {
                @memset(self.buffer.items[old_len..offset], 0);
            }
        }
        @memcpy(self.buffer.items[offset..end], frame.data);
        if (offset != old_len or end <= old_len) {
            self.received.setRangeValue(
                .{ .start = offset, .end = end },
                true,
            );
        }
        self.contiguous_end = self.received.firstUnsetFrom(
            self.contiguous_end,
        );
    }

    pub fn available(self: Reassembler) []const u8 {
        return self.buffer.items[self.read_offset..self.contiguous_end];
    }

    pub fn consume(self: *Reassembler, len: usize) Error!void {
        if (len == 0) return;
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
    if (bytes.len == 0) return;
    if (max_frame_data_len == 0) return error.InvalidCryptoRange;
    try list.ensureUnusedCapacity(
        allocator,
        try cryptoFramesWireLen(offset, bytes.len, max_frame_data_len),
    );
    var written: usize = 0;
    while (written < bytes.len) {
        const chunk_len = @min(max_frame_data_len, bytes.len - written);
        const frame_offset = std.math.add(u64, offset, written) catch
            return error.InvalidCryptoRange;
        list.appendAssumeCapacity(@intFromEnum(quic.FrameType.crypto));
        try appendVarintAssumeCapacity(list, frame_offset);
        try appendVarintAssumeCapacity(list, chunk_len);
        list.appendSliceAssumeCapacity(bytes[written .. written + chunk_len]);
        written += chunk_len;
    }
}

pub fn cryptoFramesWireLen(offset: u64, bytes_len: usize, max_frame_data_len: usize) Error!usize {
    if (max_frame_data_len == 0) return error.InvalidCryptoRange;
    var len: usize = 0;
    var written: usize = 0;
    while (written < bytes_len) {
        const chunk_len = @min(max_frame_data_len, bytes_len - written);
        const frame_offset = std.math.add(u64, offset, written) catch return error.InvalidCryptoRange;
        const chunk_len_u64 = std.math.cast(u64, chunk_len) orelse return error.InvalidCryptoRange;
        const frame_end = std.math.add(u64, frame_offset, chunk_len_u64) catch return error.InvalidCryptoRange;
        if (frame_end > quic.varint.max_value) return error.InvalidCryptoRange;

        len = std.math.add(usize, len, 1) catch return error.InvalidFrameLength;
        len = std.math.add(usize, len, try quic.varint.length(frame_offset)) catch return error.InvalidFrameLength;
        len = std.math.add(usize, len, try quic.varint.length(chunk_len)) catch return error.InvalidFrameLength;
        len = std.math.add(usize, len, chunk_len) catch return error.InvalidFrameLength;
        written += chunk_len;
    }
    return len;
}

fn appendVarintAssumeCapacity(list: *std.ArrayList(u8), value: u64) Error!void {
    try quic.varint.encodeAssumeCapacity(list, value);
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
    try reassembler.consume(0);
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

test "QUIC ordered CRYPTO reassembly keeps an implicit dense prefix" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 16);
    defer reassembler.deinit();
    try reassembler.buffer.ensureTotalCapacity(allocator, 16);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    reassembler.allocator = no_alloc.allocator();
    try reassembler.insert(.{ .offset = 0, .data = "abcdefgh" });
    try reassembler.insert(.{ .offset = 6, .data = "ghijklmnop" });
    reassembler.allocator = allocator;

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        reassembler.received.materializedCapacity(),
    );
    try std.testing.expectEqual(@as(usize, 16), reassembler.received.len());
    try std.testing.expectEqualStrings(
        "abcdefghijklmnop",
        reassembler.available(),
    );
}

test "QUIC CRYPTO gap bitmap materialization is transactional" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 16);
    defer reassembler.deinit();
    try reassembler.buffer.ensureTotalCapacity(allocator, 16);
    try reassembler.insert(.{ .offset = 0, .data = "abcd" });

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    reassembler.allocator = fail.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        reassembler.insert(.{ .offset = 8, .data = "ijkl" }),
    );
    reassembler.allocator = allocator;

    try std.testing.expect(fail.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), reassembler.buffer.items.len);
    try std.testing.expectEqual(@as(usize, 4), reassembler.received.len());
    try std.testing.expectEqual(
        @as(usize, 0),
        reassembler.received.materializedCapacity(),
    );
    try std.testing.expectEqualStrings("abcd", reassembler.available());

    try reassembler.insert(.{ .offset = 8, .data = "ijkl" });
    try std.testing.expect(
        reassembler.received.materializedCapacity() != 0,
    );
    try std.testing.expectEqualStrings("abcd", reassembler.available());
    try reassembler.insert(.{ .offset = 4, .data = "efgh" });
    try std.testing.expectEqualStrings("abcdefghijkl", reassembler.available());
}

test "QUIC CRYPTO reassembler rejects conflicting duplicate bytes" {
    const allocator = std.testing.allocator;
    var reassembler = Reassembler.init(allocator, 32);
    defer reassembler.deinit();

    try reassembler.insert(.{ .offset = 0, .data = "abcdef" });
    // Identical retransmission overlap is harmless.
    try reassembler.insert(.{ .offset = 2, .data = "cde" });
    try reassembler.insert(.{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqualStrings("abcdef", reassembler.available());

    // A proven byte conflict is a protocol error; the old data remains intact.
    try std.testing.expectError(error.ConflictingCryptoData, reassembler.insert(.{ .offset = 3, .data = "XYZ" }));
    try std.testing.expectEqualStrings("abcdef", reassembler.available());
}

test "QUIC CRYPTO stream writer skips empty payloads" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeCryptoFrames(&encoded, allocator, 10, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
}
