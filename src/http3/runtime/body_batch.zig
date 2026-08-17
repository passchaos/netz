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

/// The DATA prefix and first body fragment share storage so a packet can borrow
/// the remainder directly from the caller without allocating a full encoded
/// HTTP/3 payload. The normal paced body budget keeps this comfortably below
/// the cap; callers fall back to the copying path if it does not fit.
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
/// send call. Remaining STREAM frames borrow `data`; stateful QUIC recovery
/// copies the encoded packet payload before returning, so the caller only needs
/// to preserve the body slice for the duration of the call.
pub fn appendDataStreamFrames(
    send: *quic.stream_state.SendState,
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    prefix: *Prefix,
    data: []const u8,
    fin: bool,
    max_stream_frame_data: usize,
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
    if (prefix_len >= max_stream_frame_data) return false;
    const first_body_len = @min(
        data.len,
        @min(
            max_stream_frame_data - prefix_len,
            prefix.len - prefix_len,
        ),
    );
    if (first_body_len == 0) return false;
    @memcpy(
        prefix[prefix_len..][0..first_body_len],
        data[0..first_body_len],
    );
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
    try frames.ensureUnusedCapacity(allocator, 1 + additional);
    frames.appendAssumeCapacity(.{ .stream = .{
        .stream_id = send.stream_id,
        .offset = send.next_offset,
        .data = prefix[0..first_len],
        .fin = fin and remaining.len == 0,
    } });
    send.next_offset += first_len;
    var written: usize = 0;
    while (written < remaining.len) {
        const chunk_len = @min(
            max_stream_frame_data,
            remaining.len - written,
        );
        const is_last = written + chunk_len == remaining.len;
        frames.appendAssumeCapacity(.{ .stream = .{
            .stream_id = send.stream_id,
            .offset = send.next_offset,
            .data = remaining[written .. written + chunk_len],
            .fin = fin and is_last,
        } });
        send.next_offset += chunk_len;
        written += chunk_len;
    }
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
