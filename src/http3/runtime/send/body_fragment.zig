//! Resumable DATA framing when one contribution cannot fit one QUIC packet.
//! Each call commits one bounded STREAM fragment and its body offset together.

const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const outbound_body = @import("../stream/outbound_body.zig");
const Error = @import("../error.zig").Error;

pub const State = struct {
    stream_id: u62 = 0,
    start_offset: u64 = 0,
    data_len: usize = 0,
    wire_sent: usize = 0,
    header_len: u8 = 0,
    fin_requested: bool = false,
    initialized: bool = false,
    complete: bool = false,

    pub fn dataSent(self: State) usize {
        return @min(self.data_len, self.wire_sent -| self.header_len);
    }
};

/// `data` must retain the same contents until completion. Interleaving another
/// writer on this stream is rejected; writes on other streams remain independent.
pub fn write(connection: *quic.one_rtt.Connection, bodies: *outbound_body.Set, stream_id: u62, data: []const u8, fin: bool, state: *State, options: anytype) Error!void {
    if (state.initialized and (state.stream_id != stream_id or state.data_len != data.len or state.fin_requested != fin)) return error.UnexpectedStream;
    if (state.complete) return;
    if (options.max_stream_frame_data == 0) return error.InvalidStreamRange;
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    var staged = entry.*;
    var prefix: [16]u8 = undefined;
    const prefix_len: u8 = if (data.len == 0) 0 else blk: {
        prefix[0] = 0; // HTTP/3 DATA type.
        const length = try quic.varint.encodeInto(prefix[1..], data.len);
        break :blk @intCast(1 + length.len);
    };
    if (!state.initialized) {
        try bodies.prepareChunkForEntry(&staged, data.len, fin);
        state.* = .{ .stream_id = stream_id, .start_offset = entry.send.next_offset, .data_len = data.len, .header_len = prefix_len, .fin_requested = fin, .initialized = true };
    }
    const expected_offset = std.math.add(u64, state.start_offset, state.wire_sent) catch return error.InvalidStreamRange;
    if (entry.send.next_offset != expected_offset or entry.send.fin_sent) return error.UnexpectedStream;
    staged = entry.*;
    const wire_len = std.math.add(usize, prefix_len, data.len) catch return error.InvalidFrameLength;
    const remaining = wire_len - state.wire_sent;
    const credit = @min(connection.connectionSendAvailable(), connection.streamSendAvailable(stream_id));
    var length = @min(remaining, @min(options.max_stream_frame_data, connection.currentSendDatagramSize()));
    length = @min(length, std.math.cast(usize, credit) orelse std.math.maxInt(usize));
    if (length == 0 and remaining != 0) return error.FlowControlBlocked;
    var frame: quic.Frame = undefined;
    while (true) {
        try bodies.payload_scratch.resize(connection.endpoint.allocator, length);
        const output = bodies.payload_scratch.items;
        const prefix_bytes = @min(length, prefix_len -| state.wire_sent);
        if (prefix_bytes != 0) @memcpy(output[0..prefix_bytes], prefix[state.wire_sent..][0..prefix_bytes]);
        const body_offset = state.wire_sent -| prefix_len;
        if (length > prefix_bytes) @memcpy(output[prefix_bytes..], data[body_offset..][0 .. length - prefix_bytes]);
        frame = .{ .stream = .{ .stream_id = stream_id, .offset = expected_offset, .data = output, .fin = fin and state.wire_sent + length == wire_len } };
        if (try connection.packetLenForFramesAtOffset(0, &.{frame}) <= connection.currentSendDatagramSize()) break;
        if (length <= 1) return error.DatagramTooLarge;
        length /= 2;
    }
    const next_wire_sent = state.wire_sent + length;
    const next_data_sent = @min(data.len, next_wire_sent -| prefix_len);
    staged.written = std.math.add(usize, staged.written, next_data_sent - state.dataSent()) catch return error.InvalidContentLength;
    staged.send.next_offset = std.math.add(u64, expected_offset, length) catch return error.InvalidStreamRange;
    staged.send.fin_sent = frame.stream.fin;
    try connection.trySend(&.{frame});
    entry.* = staged;
    state.wire_sent = next_wire_sent;
    state.complete = next_wire_sent == wire_len;
    if (frame.stream.fin) _ = bodies.finish(stream_id);
}
