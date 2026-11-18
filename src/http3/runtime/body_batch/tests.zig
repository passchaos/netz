const std = @import("std");
const body_batch_root = @import("../body_batch.zig");

const quic = @import("../../../quic/mod.zig");

const Prefix = body_batch_root.Prefix;
const appendDataStreamFrames = body_batch_root.appendDataStreamFrames;
const appendDataStreamPartFrames = body_batch_root.appendDataStreamPartFrames;
const prefix_capacity = body_batch_root.prefix_capacity;

test "HTTP/3 body batch keeps DATA prefixes isolated" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var first_prefix: Prefix = undefined;
    var second_prefix: Prefix = undefined;
    var first = quic.stream_state.SendState.init(0);
    var second = quic.stream_state.SendState.init(4);

    try std.testing.expect(try appendDataStreamFrames(
        &first,
        &frames,
        allocator,
        &first_prefix,
        "first-body",
        false,
        8,
        8,
    ));
    const second_start = frames.items.len;
    try std.testing.expect(try appendDataStreamFrames(
        &second,
        &frames,
        allocator,
        &second_prefix,
        "second-body",
        true,
        8,
        8,
    ));

    try std.testing.expectEqual(@as(u64, 0), frames.items[0].stream.stream_id);
    try std.testing.expectEqual(
        @as(u64, 4),
        frames.items[second_start].stream.stream_id,
    );
    try std.testing.expect(frames.items[frames.items.len - 1].stream.fin);
    try std.testing.expect(!std.mem.eql(
        u8,
        frames.items[0].stream.data,
        frames.items[second_start].stream.data,
    ));
}

test "HTTP/3 body batch borrows complete body behind DATA prefix" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(8);
    const body = "borrowed-body";

    try std.testing.expect(try appendDataStreamFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        body,
        true,
        8,
        4,
    ));

    try std.testing.expectEqual(@as(usize, 3), frames.items.len);
    const encoded_prefix = [_]u8{ 0, @intCast(body.len) };
    try std.testing.expectEqualSlices(
        u8,
        &encoded_prefix,
        frames.items[0].stream.data,
    );
    try std.testing.expectEqual(@as(usize, 2), frames.items[0].stream.data.len);
    try std.testing.expectEqual(body.ptr, frames.items[1].stream.data.ptr);
    try std.testing.expectEqualSlices(u8, body[0..8], frames.items[1].stream.data);
    try std.testing.expectEqualSlices(u8, body[8..], frames.items[2].stream.data);
    try std.testing.expectEqual(@as(u64, 0), frames.items[0].stream.offset);
    try std.testing.expectEqual(@as(u64, 2), frames.items[1].stream.offset);
    try std.testing.expectEqual(@as(u64, 10), frames.items[2].stream.offset);
    try std.testing.expect(!frames.items[0].stream.fin);
    try std.testing.expect(!frames.items[1].stream.fin);
    try std.testing.expect(frames.items[2].stream.fin);
    try std.testing.expectEqual(@as(u64, 2 + body.len), send.next_offset);
    try std.testing.expect(send.fin_sent);
}

test "HTTP/3 body parts borrow slices in one DATA frame" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(4);
    const first = "first";
    const second = "second-part";

    try std.testing.expect(try appendDataStreamPartFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        &.{ first, &.{}, second },
        true,
        8,
        4,
    ));
    try std.testing.expectEqual(@as(usize, 4), frames.items.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, first.len + second.len },
        frames.items[0].stream.data,
    );
    try std.testing.expectEqual(first.ptr, frames.items[1].stream.data.ptr);
    try std.testing.expectEqual(second.ptr, frames.items[2].stream.data.ptr);
    try std.testing.expect(!frames.items[0].stream.fin);
    try std.testing.expect(!frames.items[2].stream.fin);
    try std.testing.expect(frames.items[3].stream.fin);
    try std.testing.expectEqual(
        @as(u64, 2 + first.len + second.len),
        send.next_offset,
    );
}

test "HTTP/3 body parts compact only the minimum leading slice prefix" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(4);

    try std.testing.expect(try appendDataStreamPartFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        &.{ "a", "b", "c", "d", "e", "f", "g", "h" },
        true,
        64,
        8,
    ));
    try std.testing.expectEqual(@as(usize, 8), frames.items.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 8, 'a' },
        frames.items[0].stream.data,
    );
    try std.testing.expectEqualStrings("b", frames.items[1].stream.data);
    try std.testing.expectEqualStrings("h", frames.items[7].stream.data);
    try std.testing.expect(frames.items[7].stream.fin);
    try std.testing.expectEqual(@as(u64, 10), send.next_offset);
}

test "HTTP/3 body parts reject a required copy larger than prefix scratch" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(0);

    const payload = [_]u8{0xaa} ** (prefix_capacity + 1);
    var parts: [prefix_capacity + 1][]const u8 = undefined;
    for (&parts, 0..) |*part, index| part.* = payload[index..][0..1];
    try std.testing.expect(!try appendDataStreamPartFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        &parts,
        true,
        prefix_capacity + 16,
        1,
    ));
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqual(@as(u64, 0), send.next_offset);
    try std.testing.expect(!send.fin_sent);
}

test "HTTP/3 body batch copies only packet-boundary body prefix" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(0);
    const body = "123456789";

    // A prefix-only plan would need three descriptors. Copying one byte,
    // rather than filling the whole first STREAM frame, preserves the two
    // descriptors that the contiguous DATA representation used.
    try std.testing.expect(try appendDataStreamFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        body,
        false,
        8,
        2,
    ));

    try std.testing.expectEqual(@as(usize, 2), frames.items.len);
    const encoded_prefix = [_]u8{ 0, @intCast(body.len), body[0] };
    try std.testing.expectEqualSlices(
        u8,
        &encoded_prefix,
        frames.items[0].stream.data,
    );
    try std.testing.expectEqual(body.ptr + 1, frames.items[1].stream.data.ptr);
    try std.testing.expectEqualSlices(u8, body[1..], frames.items[1].stream.data);
}

test "HTTP/3 body batch accepts exact prefix frame and rejects smaller limit" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var exact = quic.stream_state.SendState.init(0);
    const short_body = [_]u8{'x'} ** 63;

    try std.testing.expect(try appendDataStreamFrames(
        &exact,
        &frames,
        allocator,
        &prefix,
        &short_body,
        true,
        2,
        64,
    ));
    try std.testing.expectEqual(@as(usize, 2), frames.items[0].stream.data.len);
    try std.testing.expectEqual(@as(u64, 65), exact.next_offset);
    try std.testing.expect(exact.fin_sent);

    frames.clearRetainingCapacity();
    var too_small = quic.stream_state.SendState.init(4);
    const previous = too_small;
    const long_body = [_]u8{'y'} ** 64;
    try std.testing.expect(!try appendDataStreamFrames(
        &too_small,
        &frames,
        allocator,
        &prefix,
        &long_body,
        true,
        2,
        64,
    ));
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqualDeep(previous, too_small);
}

test "HTTP/3 body batch leaves empty DATA and FIN to fallback" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(0);
    const previous = send;

    try std.testing.expect(!try appendDataStreamFrames(
        &send,
        &frames,
        allocator,
        &prefix,
        &.{},
        true,
        8,
        2,
    ));
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqualDeep(previous, send);
}

test "HTTP/3 body batch allocation failure is transactional" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(12);
    send.next_offset = 37;
    const previous = send;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        appendDataStreamFrames(
            &send,
            &frames,
            fail_first.allocator(),
            &prefix,
            "borrowed-body",
            true,
            8,
            4,
        ),
    );
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqualDeep(previous, send);
}

test "HTTP/3 body batch rejects an overflowing final stream offset" {
    const allocator = std.testing.allocator;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var prefix: Prefix = undefined;
    var send = quic.stream_state.SendState.init(0);
    send.next_offset = quic.varint.max_value;
    const previous = send;

    try std.testing.expectError(
        error.InvalidStreamRange,
        appendDataStreamFrames(
            &send,
            &frames,
            allocator,
            &prefix,
            "x",
            true,
            8,
            2,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
    try std.testing.expectEqualDeep(previous, send);
}
