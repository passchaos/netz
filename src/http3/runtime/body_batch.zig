const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

/// One HTTP/3 DATA contribution intended to become one protected QUIC packet.
///
/// A batch may contain each stream at most once. Keeping that invariant at the
/// public API boundary makes application body offsets transactional with the
/// socket-visible packet prefix returned by QUIC's stateful batch sender.
pub const Chunk = struct {
    stream_id: u62,
    data: []const u8,
    fin: bool = false,
};

/// A complete response body owned by the caller for the duration of a
/// priority-aware blocking send.
///
/// Unlike `Chunk`, one value may span many QUIC packets. The runtime chooses
/// packet-sized slices according to the request's effective RFC 9218 priority
/// and retries after processing ACK, flow-control, and PRIORITY_UPDATE input.
pub const ResponseBody = struct {
    stream_id: u62,
    data: []const u8,
};

/// Storage for an encoded DATA frame prefix and, only at a packet-frame
/// boundary, the minimum body prefix needed to avoid adding another packet.
///
/// Most sends use only the at-most-nine-byte DATA prefix and borrow every body
/// byte from the caller. The larger capacity preserves the single-packet path
/// for boundary sizes without materializing the complete DATA frame.
pub const prefix_capacity: usize = 4096;
pub const Prefix = [prefix_capacity]u8;

pub const Scratch = struct {
    pub const FrameRange = struct {
        start: usize,
        len: usize,
    };

    frames: std.ArrayList(quic.Frame) = .empty,
    frame_ranges: std.ArrayList(FrameRange) = .empty,
    prefixes: std.ArrayList(Prefix) = .empty,

    pub fn deinit(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) void {
        self.prefixes.deinit(allocator);
        self.frame_ranges.deinit(allocator);
        self.frames.deinit(allocator);
        self.* = undefined;
    }

    pub fn begin(
        self: *Scratch,
        allocator: std.mem.Allocator,
        packet_count: usize,
    ) !void {
        try self.prefixes.resize(allocator, packet_count);
        try self.frame_ranges.resize(allocator, packet_count);
        self.frames.clearRetainingCapacity();
    }
};

/// Append STREAM-frame views for one HTTP/3 DATA frame.
///
/// `prefix` is unique to this DATA frame and must remain alive through the QUIC
/// send call. Body STREAM frames normally borrow all of `data`; only enough of
/// its beginning to keep the same packet count as a coalesced DATA frame is
/// copied when the extra prefix descriptor crosses a `max_frames_per_packet`
/// boundary. Stateful QUIC recovery copies the encoded packet payload before
/// returning, so the caller only needs to preserve the body slice for the
/// duration of the call.
pub fn appendDataStreamFrames(
    send: *quic.stream_state.SendState,
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    prefix: *Prefix,
    data: []const u8,
    fin: bool,
    max_stream_frame_data: usize,
    max_frames_per_packet: usize,
) !bool {
    if (data.len == 0 or max_stream_frame_data == 0) return false;
    if (send.fin_sent) return error.FinalSizeMismatch;
    const payload_len_u64 = std.math.cast(u64, data.len) orelse
        return error.IntegerOverflow;
    var prefix_len: usize = 0;
    const type_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        http3.FrameType.data,
    );
    prefix_len += type_bytes.len;
    const len_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        payload_len_u64,
    );
    prefix_len += len_bytes.len;
    // A prefix that exactly fills a STREAM frame is valid. A larger prefix
    // falls back to the ordinary contiguous encoder, which can split it.
    if (prefix_len > max_stream_frame_data) return false;

    const combined_len = std.math.add(
        usize,
        prefix_len,
        data.len,
    ) catch return error.InvalidFrameLength;
    const combined_len_u64 = std.math.cast(u64, combined_len) orelse
        return error.IntegerOverflow;
    const final_next_offset = std.math.add(
        u64,
        send.next_offset,
        combined_len_u64,
    ) catch return error.InvalidStreamRange;
    if (final_next_offset > quic.varint.max_value) {
        return error.InvalidStreamRange;
    }
    const coalesced_frame_count = std.math.divCeil(
        usize,
        combined_len,
        max_stream_frame_data,
    ) catch return error.InvalidFrameLength;
    const packet_frame_budget = @max(
        @as(usize, 1),
        max_frames_per_packet,
    );
    const coalesced_packet_count = std.math.divCeil(
        usize,
        coalesced_frame_count,
        packet_frame_budget,
    ) catch return error.InvalidFrameLength;
    // Saturation is intentional: an unrepresentably large descriptor budget
    // can certainly cover every body byte addressable by this process.
    const descriptor_capacity =
        coalesced_packet_count *| packet_frame_budget;
    const borrowed_body_capacity =
        (descriptor_capacity - 1) *| max_stream_frame_data;
    const first_body_len = data.len -| borrowed_body_capacity;
    if (first_body_len > max_stream_frame_data - prefix_len or
        first_body_len > prefix.len - prefix_len)
    {
        return false;
    }
    if (first_body_len != 0) {
        @memcpy(
            prefix[prefix_len..][0..first_body_len],
            data[0..first_body_len],
        );
    }
    const first_len = prefix_len + first_body_len;
    const remaining = data[first_body_len..];
    const additional = if (remaining.len == 0)
        @as(usize, 0)
    else
        std.math.divCeil(
            usize,
            remaining.len,
            max_stream_frame_data,
        ) catch return error.InvalidFrameLength;
    const frame_count = std.math.add(
        usize,
        1,
        additional,
    ) catch return error.InvalidFrameLength;
    try frames.ensureUnusedCapacity(allocator, frame_count);
    var next_offset = send.next_offset;
    frames.appendAssumeCapacity(.{ .stream = .{
        .stream_id = send.stream_id,
        .offset = next_offset,
        .data = prefix[0..first_len],
        .fin = fin and remaining.len == 0,
    } });
    next_offset += first_len;
    var written: usize = 0;
    while (written < remaining.len) {
        const chunk_len = @min(
            max_stream_frame_data,
            remaining.len - written,
        );
        const is_last = written + chunk_len == remaining.len;
        frames.appendAssumeCapacity(.{ .stream = .{
            .stream_id = send.stream_id,
            .offset = next_offset,
            .data = remaining[written .. written + chunk_len],
            .fin = fin and is_last,
        } });
        next_offset += chunk_len;
        written += chunk_len;
    }
    std.debug.assert(next_offset == final_next_offset);
    send.next_offset = final_next_offset;
    if (fin) send.fin_sent = true;
    return true;
}

/// Append one HTTP/3 DATA frame whose payload is borrowed from several caller
/// slices. The DATA prefix gets its own STREAM frame; non-empty payload parts
/// are split only at `max_stream_frame_data`, without joining them. When slice
/// boundaries alone would increase the packet count, the minimum leading body
/// prefix is copied into the bounded DATA-prefix scratch to recover the same
/// descriptor budget as a contiguous body.
///
/// It returns `false` when the descriptor count cannot fit the caller's frame
/// budget even after the bounded prefix copy, leaving `send` unchanged so the
/// exact same parts can be retried. Nonblocking callers separately require the
/// resulting descriptors to fit one actual QUIC packet.
pub fn appendDataStreamPartFrames(
    send: *quic.stream_state.SendState,
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    prefix: *Prefix,
    parts: []const []const u8,
    fin: bool,
    max_stream_frame_data: usize,
    max_frames_per_packet: usize,
) !bool {
    if (max_stream_frame_data == 0) return false;
    if (send.fin_sent) return error.FinalSizeMismatch;

    var payload_len: usize = 0;
    var payload_frame_count: usize = 0;
    for (parts) |part| {
        payload_len = std.math.add(usize, payload_len, part.len) catch
            return error.InvalidFrameLength;
        if (part.len != 0) {
            payload_frame_count = std.math.add(
                usize,
                payload_frame_count,
                std.math.divCeil(usize, part.len, max_stream_frame_data) catch
                    return error.InvalidFrameLength,
            ) catch return error.InvalidFrameLength;
        }
    }
    if (payload_len == 0) return false;

    var prefix_len: usize = 0;
    const type_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        http3.FrameType.data,
    );
    prefix_len += type_bytes.len;
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse
        return error.IntegerOverflow;
    const length_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        payload_len_u64,
    );
    prefix_len += length_bytes.len;
    if (prefix_len > max_stream_frame_data) return false;

    const encoded_len = std.math.add(usize, prefix_len, payload_len) catch
        return error.InvalidFrameLength;
    const encoded_len_u64 = std.math.cast(u64, encoded_len) orelse
        return error.IntegerOverflow;
    const final_next_offset = std.math.add(
        u64,
        send.next_offset,
        encoded_len_u64,
    ) catch return error.InvalidStreamRange;
    if (final_next_offset > quic.varint.max_value) {
        return error.InvalidStreamRange;
    }
    const packet_frame_budget = @max(
        @as(usize, 1),
        max_frames_per_packet,
    );
    const coalesced_frame_count = std.math.divCeil(
        usize,
        encoded_len,
        max_stream_frame_data,
    ) catch return error.InvalidFrameLength;
    const coalesced_packet_count = std.math.divCeil(
        usize,
        coalesced_frame_count,
        packet_frame_budget,
    ) catch return error.InvalidFrameLength;
    const descriptor_capacity =
        coalesced_packet_count *| packet_frame_budget;

    var copied_body_len: usize = 0;
    var remaining_payload_frames = payload_frame_count;
    const max_copied_body = @min(
        payload_len,
        @min(
            max_stream_frame_data - prefix_len,
            prefix.len - prefix_len,
        ),
    );
    for (parts) |part| {
        var remaining_part = part.len;
        while (remaining_part != 0 and
            1 + remaining_payload_frames > descriptor_capacity)
        {
            const part_frames = std.math.divCeil(
                usize,
                remaining_part,
                max_stream_frame_data,
            ) catch return error.InvalidFrameLength;
            const bytes_to_remove_frame = remaining_part -
                (part_frames - 1) * max_stream_frame_data;
            if (bytes_to_remove_frame > max_copied_body - copied_body_len) {
                return false;
            }
            copied_body_len += bytes_to_remove_frame;
            remaining_part -= bytes_to_remove_frame;
            remaining_payload_frames -= 1;
        }
        if (1 + remaining_payload_frames <= descriptor_capacity) break;
    }
    if (1 + remaining_payload_frames > descriptor_capacity) return false;
    if (copied_body_len == payload_len) return false;

    var copy_remaining = copied_body_len;
    var copy_part_index: usize = 0;
    var copy_part_offset: usize = 0;
    var copied: usize = 0;
    while (copy_remaining != 0) {
        while (copy_part_index < parts.len and
            copy_part_offset == parts[copy_part_index].len)
        {
            copy_part_index += 1;
            copy_part_offset = 0;
        }
        std.debug.assert(copy_part_index < parts.len);
        const count = @min(
            copy_remaining,
            parts[copy_part_index].len - copy_part_offset,
        );
        @memcpy(
            prefix[prefix_len + copied ..][0..count],
            parts[copy_part_index][copy_part_offset..][0..count],
        );
        copied += count;
        copy_remaining -= count;
        copy_part_offset += count;
    }

    const frame_count = 1 + remaining_payload_frames;
    try frames.ensureUnusedCapacity(allocator, frame_count);
    var next_offset = send.next_offset;
    frames.appendAssumeCapacity(.{ .stream = .{
        .stream_id = send.stream_id,
        .offset = next_offset,
        .data = prefix[0 .. prefix_len + copied_body_len],
        .fin = fin and remaining_payload_frames == 0,
    } });
    next_offset += prefix_len + copied_body_len;
    var remaining_frames = remaining_payload_frames;
    for (parts[copy_part_index..], 0..) |part, relative_index| {
        var part_offset = if (relative_index == 0) copy_part_offset else 0;
        while (part_offset < part.len) {
            const chunk_len = @min(
                max_stream_frame_data,
                part.len - part_offset,
            );
            remaining_frames -= 1;
            frames.appendAssumeCapacity(.{ .stream = .{
                .stream_id = send.stream_id,
                .offset = next_offset,
                .data = part[part_offset..][0..chunk_len],
                .fin = fin and remaining_frames == 0,
            } });
            next_offset += chunk_len;
            part_offset += chunk_len;
        }
    }
    std.debug.assert(remaining_frames == 0);
    std.debug.assert(next_offset == final_next_offset);
    send.next_offset = final_next_offset;
    if (fin) send.fin_sent = true;
    return true;
}

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
