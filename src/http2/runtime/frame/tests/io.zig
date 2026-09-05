const std = @import("std");
const http2 = @import("../../../mod.zig");
const frame_io = @import("../io.zig");
const frame_wire = @import("../wire.zig");

test "HTTP/2 frame reader coalesces small frames in bounded storage" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try frame_wire.appendFrame(
        &encoded,
        allocator,
        .ping,
        0x1,
        0,
        "12345678",
    );
    try frame_wire.appendFrame(
        &encoded,
        allocator,
        .data,
        0x1,
        1,
        "payload",
    );

    var offset: usize = 0;
    var reads: usize = 0;
    const source = SliceSource{
        .bytes = encoded.items,
        .offset = &offset,
        .reads = &reads,
    };
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);

    const first = try reader.readFrom(
        allocator,
        source,
        16 * 1024,
    );
    try std.testing.expectEqual(http2.FrameType.ping, first.frame.header.frame_type);
    try std.testing.expectEqualStrings("12345678", first.frame.payload);
    const second = try reader.readFrom(
        allocator,
        source,
        16 * 1024,
    );
    try std.testing.expectEqual(http2.FrameType.data, second.frame.header.frame_type);
    try std.testing.expectEqualStrings("payload", second.frame.payload);
    try std.testing.expectEqual(@as(usize, 1), reads);
    try std.testing.expectEqual(frame_io.default_read_size, reader.buffer.capacity);
}

test "HTTP/2 frame reader grows exactly beyond default read-ahead" {
    const allocator = std.testing.allocator;
    const payload_len = frame_io.default_read_size + 123;
    const bytes = try allocator.alloc(
        u8,
        http2.FrameHeader.encoded_len + payload_len,
    );
    defer allocator.free(bytes);
    const header: *[http2.FrameHeader.encoded_len]u8 = @ptrCast(bytes.ptr);
    try frame_wire.encodeHeader(header, .data, 0x1, 1, payload_len);
    @memset(bytes[http2.FrameHeader.encoded_len..], 'x');

    var offset: usize = 0;
    var reads: usize = 0;
    const source = SliceSource{
        .bytes = bytes,
        .offset = &offset,
        .reads = &reads,
        .max_chunk = http2.FrameHeader.encoded_len,
    };
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);

    const borrowed = try reader.readFrom(
        allocator,
        source,
        payload_len,
    );
    try std.testing.expectEqual(payload_len, borrowed.frame.payload.len);
    try std.testing.expectEqual(
        http2.FrameHeader.encoded_len + payload_len,
        reader.buffer.capacity,
    );
    try std.testing.expect(reads > 1);
}

const SliceSource = struct {
    bytes: []const u8,
    offset: *usize,
    reads: *usize,
    max_chunk: usize = std.math.maxInt(usize),

    pub fn read(self: @This(), output: []u8) error{}!usize {
        self.reads.* += 1;
        const remaining = self.bytes[self.offset.*..];
        const count = @min(output.len, remaining.len, self.max_chunk);
        @memcpy(output[0..count], remaining[0..count]);
        self.offset.* += count;
        return count;
    }
};
