const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const datagram_queue = @import("../datagram_queue.zig");
const send = @import("../send.zig");

test {
    _ = @import("../data_error_tests.zig");
}

test "HTTP/3 development send splits STREAM offsets and final FIN exactly" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send.appendStreamMessageFrames(
        &frames,
        allocator,
        4,
        "abcdefgh",
        3,
    );
    try std.testing.expectEqual(@as(usize, 3), frames.items.len);
    var next_offset: u64 = 0;
    for (frames.items, 0..) |frame, index| {
        try std.testing.expect(frame == .stream);
        try std.testing.expectEqual(@as(u64, 4), frame.stream.stream_id);
        try std.testing.expectEqual(next_offset, frame.stream.offset);
        next_offset += frame.stream.data.len;
        try std.testing.expectEqual(index + 1 == frames.items.len, frame.stream.fin);
    }
    try std.testing.expectEqual(@as(u64, 8), next_offset);
}

test "HTTP/3 development DATAGRAM retention is transactional on OOM" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (quic.Frame{ .datagram = .{ .data = "payload" } }).write(
        &encoded,
        allocator,
    );
    const bytes = try allocator.dupe(u8, encoded.items);
    const frames = try allocator.alloc(quic.Frame, 1);
    var parsed = try quic.parseFrameOwned(allocator, bytes);
    frames[0] = parsed.frame;
    parsed.frame = undefined;
    var packet: quic.runtime.OwnedDatagram = .{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = bytes,
        .frames = frames,
    };
    defer packet.deinit(allocator);

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var queue = datagram_queue.Queue.init(fail.allocator(), 1, 1024);
    defer queue.deinit();
    try std.testing.expectError(
        error.OutOfMemory,
        send.retainDatagramFrames(&queue, packet),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.count());
    try std.testing.expectEqualStrings("payload", packet.frames[0].datagram.data);
}

test "HTTP/3 development datagram routing splits coalesced frames" {
    const allocator = std.testing.allocator;
    var queue = datagram_queue.Queue.init(allocator, 4, 1024);
    defer queue.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (quic.Frame{ .datagram = .{ .data = "first" } }).write(
        &encoded,
        allocator,
    );
    try (quic.Frame{ .datagram = .{ .data = "second" } }).write(
        &encoded,
        allocator,
    );
    const packet_bytes = try allocator.dupe(u8, encoded.items);
    const packet_frames = try allocator.alloc(quic.Frame, 2);
    var cursor: usize = 0;
    for (packet_frames) |*slot| {
        const parsed = try quic.parseFrame(packet_bytes[cursor..]);
        slot.* = parsed.frame;
        cursor += parsed.consumed;
    }
    var packet: quic.runtime.OwnedDatagram = .{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = packet_bytes,
        .frames = packet_frames,
    };
    defer packet.deinit(allocator);

    try send.retainDatagramFrames(&queue, packet);
    var first = queue.pop() orelse return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    var second = queue.pop() orelse return error.TestUnexpectedResult;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings(
        "first",
        first.frames[0].datagram.data,
    );
    try std.testing.expectEqualStrings(
        "second",
        second.frames[0].datagram.data,
    );
    try std.testing.expect(queue.pop() == null);
}
