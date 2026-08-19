//! Cross-stream WebTransport writes backed by QUIC's stateful packet batch.
//!
//! Each input contributes at most one packet-sized application slice. The
//! transport may accept only a prefix of the staged packet array; registry
//! offsets and caller counts commit exactly that socket-visible prefix.

const std = @import("std");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const stream_runtime = @import("stream.zig");

pub const Error = stream_runtime.Error;

pub const Write = struct {
    stream_id: u62,
    data: []const u8,
};

pub const Result = struct {
    /// Number of writes with a nonzero committed application prefix.
    progressed: usize,
    /// Socket error observed after an accepted packet prefix, if any.
    send_error: ?std.Io.net.Socket.SendError = null,
};

/// Write one fair packet-sized slice to every immediately sendable stream.
///
/// The output slice must have at least as many elements as `writes`. It is
/// cleared first and records application bytes committed for each input. Empty
/// writes are ignored. A stream ID may occur at most once per call.
pub fn write(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
) Error!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    if (writes.len == 0) return .{ .progressed = 0 };

    const packet_limit = @min(writes.len, quic.one_rtt.max_batch_packets);
    var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    var input_indices: [quic.one_rtt.max_batch_packets]usize = undefined;
    var stream_ids: [quic.one_rtt.max_batch_packets]u62 = undefined;
    var byte_counts: [quic.one_rtt.max_batch_packets]usize = undefined;

    while (true) {
        var packet_count: usize = 0;
        for (writes, 0..) |item, input_index| {
            if (packet_count == packet_limit) break;
            if (item.data.len == 0) continue;
            var previous: usize = 0;
            while (previous < input_index) : (previous += 1) {
                if (writes[previous].stream_id == item.stream_id) {
                    return error.DuplicateStream;
                }
            }

            const stream = try stream_runtime.prepare(
                connection,
                registry,
                session_id,
                item.stream_id,
            );
            const credit = connection.streamSendCredit(item.stream_id);
            const packet_payload = credit.max_datagram_size -| 128;
            const count = @min(
                item.data.len,
                @min(packet_payload, credit.available()),
            );
            if (count == 0) continue;

            frames[packet_count][0] = .{ .stream = .{
                .stream_id = item.stream_id,
                .offset = stream.send_offset,
                .data = item.data[0..count],
                .fin = false,
            } };
            packets[packet_count] = &frames[packet_count];
            input_indices[packet_count] = input_index;
            stream_ids[packet_count] = item.stream_id;
            byte_counts[packet_count] = count;
            packet_count += 1;
        }

        if (packet_count == 0) {
            var has_data = false;
            for (writes) |item| has_data = has_data or item.data.len != 0;
            if (!has_data) return .{ .progressed = 0 };
            try stream_runtime.receiveSendProgress(connection);
            continue;
        }

        const sent = connection.sendManyProgress(packets[0..packet_count]) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try stream_runtime.receiveSendProgress(connection);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
        if (sent.sent_count > packet_count or
            sent.sent_count > sent.protected_count)
        {
            return error.Unexpected;
        }

        for (0..sent.sent_count) |packet_index| {
            const stream_id = stream_ids[packet_index];
            const count = byte_counts[packet_index];
            const stream = registry.get(stream_id) orelse
                return error.UnknownStream;
            stream.send_offset = std.math.add(
                u64,
                stream.send_offset,
                count,
            ) catch return error.IntegerOverflow;
            try registry.recordSent(stream_id, count, false);
            counts[input_indices[packet_index]] = count;
        }
        if (sent.sent_count == 0 and sent.send_error == null) {
            return error.Unexpected;
        }
        return .{
            .progressed = sent.sent_count,
            .send_error = sent.send_error,
        };
    }
}
