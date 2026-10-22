//! Critical-stream preface progress for dispatcher-owned CONNECT. All cursors
//! advance only after one packet submission; small frame budgets retain retry.

const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");

pub const State = struct {
    payload: std.ArrayList(u8) = .empty,
    ends: [3]usize = .{ 0, 0, 0 },
    committed: [3]usize = .{ 0, 0, 0 },
    prepared: bool = false,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.payload.deinit(allocator);
        self.* = .{};
    }

    pub fn poll(self: *State, h3: *http3.runtime.HandshakeClient) http3.runtime.Error!bool {
        if (h3.control.settings.sent) return true;
        if (!self.prepared) {
            var payload: std.ArrayList(u8) = .empty;
            errdefer payload.deinit(h3.allocator);
            try http3.writeControlStreamPrefix(&payload, h3.allocator);
            try http3.writeSettingsFrame(&payload, h3.allocator, h3.options.local_settings);
            const control_end = payload.items.len;
            if (!h3.qpack_encoder_prefix_sent) try http3.writeQpackEncoderStreamPrefix(&payload, h3.allocator);
            const encoder_end = payload.items.len;
            if (!h3.qpack_decoder_prefix_sent) try http3.writeQpackDecoderStreamPrefix(&payload, h3.allocator);
            self.ends = .{ control_end, encoder_end, payload.items.len };
            self.payload = payload;
            self.prepared = true;
        }
        const connection = &h3.established.connection;
        const states = [_]*quic.stream_state.SendState{ &h3.control_send, &h3.qpack_encoder_send, &h3.qpack_decoder_send };
        var frames: [3]quic.Frame = undefined;
        var indices: [3]usize = undefined;
        var frame_count: usize = 0;
        var staged_bytes: usize = 0;
        for (states, 0..) |send, index| {
            if (frame_count == @max(@as(usize, 1), h3.options.max_frames_per_packet)) break;
            const start = if (index == 0) 0 else self.ends[index - 1];
            const total = self.ends[index] - start;
            if (self.committed[index] == total) continue;
            const credit = connection.streamSendCredit(send.stream_id);
            const upper = @min(total - self.committed[index], @min(credit.stream, credit.connection -| staged_bytes));
            if (upper == 0) {
                if (frame_count == 0) return error.FlowControlBlocked;
                break;
            }
            var low: usize = 0;
            var high = upper;
            while (low < high) {
                const count = low + (high - low + 1) / 2;
                frames[frame_count] = .{ .stream = .{ .stream_id = send.stream_id, .offset = send.next_offset, .data = self.payload.items[start + self.committed[index] ..][0..count] } };
                const packet_len = connection.packetLenForFramesAtOffset(0, frames[0 .. frame_count + 1]) catch |err| switch (err) {
                    error.DatagramTooLarge => std.math.maxInt(usize),
                    else => return err,
                };
                var wire_len: usize = 0;
                for (frames[0 .. frame_count + 1]) |frame| wire_len += try frame.wireLen();
                if (packet_len <= credit.max_datagram_size and wire_len <= credit.congestion) low = count else high = count - 1;
            }
            if (low == 0) {
                if (frame_count == 0) return error.CongestionLimited;
                break;
            }
            frames[frame_count] = .{ .stream = .{ .stream_id = send.stream_id, .offset = send.next_offset, .data = self.payload.items[start + self.committed[index] ..][0..low] } };
            indices[frame_count] = index;
            frame_count += 1;
            staged_bytes += low;
            if (low != total - self.committed[index]) break;
        }
        if (frame_count != 0) {
            try connection.trySend(frames[0..frame_count]);
            for (frames[0..frame_count], indices[0..frame_count]) |frame, index| {
                self.committed[index] += frame.stream.data.len;
                states[index].next_offset += frame.stream.data.len;
            }
        }
        var start: usize = 0;
        for (self.ends, self.committed) |end, committed| {
            if (committed != end - start) return false;
            start = end;
        }
        h3.control.settings.markSent(h3.options.local_settings);
        h3.qpack_encoder_prefix_sent = true;
        h3.qpack_decoder_prefix_sent = true;
        return true;
    }
};
