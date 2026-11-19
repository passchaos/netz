//! One packet-sized relay send with exact socket-visible progress.

const std = @import("std");
const queues = @import("../relay_queue.zig");

pub const Progress = struct {
    committed_bytes: usize = 0,
    complete: bool = false,
};

pub fn send(
    comptime quic: type,
    connection: *quic.one_rtt.Connection,
    relay: *queues.Relay,
    item: queues.Outbound,
    maximum_bytes: usize,
    progress: *Progress,
) quic.one_rtt.Error!void {
    progress.* = .{};
    const remaining: []const u8 = switch (item) {
        .data => |bytes| bytes[relay.pending_data_start..],
        .fin => &.{},
    };
    if (item == .data and remaining.len == 0) {
        progress.complete = true;
        return;
    }
    var count = @min(remaining.len, maximum_bytes);
    if (remaining.len != 0) {
        count = @intCast(@min(@as(u64, count), @min(
            connection.connectionSendAvailable(),
            connection.streamSendAvailable(relay.stream_id),
        )));
        if (count == 0) return error.FlowControlBlocked;
        count = @min(count, connection.currentSendDatagramSize());
        const congestion = connection.congestionAvailable();
        const first = quic.Frame{ .stream = .{
            .stream_id = relay.stream_id,
            .offset = relay.send_offset,
            .data = remaining[0..1],
        } };
        const first_size = try connection.packetLenForFramesAtOffset(0, &.{first});
        if (first_size > connection.currentSendDatagramSize()) return error.DatagramTooLarge;
        if (first_size > congestion) return error.CongestionLimited;
        var lower: usize = 1;
        var upper = count;
        while (lower < upper) {
            const middle = lower + (upper - lower + 1) / 2;
            const candidate = quic.Frame{ .stream = .{
                .stream_id = relay.stream_id,
                .offset = relay.send_offset,
                .data = remaining[0..middle],
            } };
            const packet_size = try connection.packetLenForFramesAtOffset(0, &.{candidate});
            if (packet_size <= connection.currentSendDatagramSize() and packet_size <= congestion) {
                lower = middle;
            } else {
                upper = middle - 1;
            }
        }
        count = lower;
    }
    const next_offset = std.math.add(u64, relay.send_offset, count) catch return error.InvalidFrameLength;
    const frame = quic.Frame{ .stream = .{
        .stream_id = relay.stream_id,
        .offset = relay.send_offset,
        .data = remaining[0..count],
        .fin = item == .fin,
    } };
    const result = try connection.sendManyProgress(&.{&.{frame}});
    if (result.sent_count > 1 or result.sent_count > result.protected_count) return error.Unexpected;
    if (result.sent_count == 1) {
        progress.committed_bytes = count;
        relay.send_offset = next_offset;
        relay.pending_data_start += count;
        progress.complete = count == remaining.len;
        if (item == .fin) relay.quic_fin_sent = true;
        relay.touch();
    }
    if (result.send_error) |err| return err;
    if (result.sent_count == 0) return error.Unexpected;
}
