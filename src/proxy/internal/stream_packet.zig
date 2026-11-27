//! One packet-sized STREAM attempt with exact committed prefix and FIN state.
const std = @import("std");

pub const Progress = struct {
    committed_bytes: usize = 0,
    complete: bool = false,
    fin_committed: bool = false,
};

pub fn send(
    comptime quic: type,
    connection: *quic.one_rtt.Connection,
    stream_id: u64,
    offset: u64,
    bytes: []const u8,
    finish: bool,
    maximum_bytes: usize,
    progress: *Progress,
) quic.one_rtt.Error!void {
    progress.* = .{};
    if (bytes.len == 0 and !finish) {
        progress.complete = true;
        return;
    }
    var count = @min(bytes.len, maximum_bytes);
    if (bytes.len != 0) {
        count = @intCast(@min(@as(u64, count), @min(
            connection.connectionSendAvailable(),
            connection.streamSendAvailable(stream_id),
        )));
        if (count == 0) return error.FlowControlBlocked;
        count = @min(count, connection.currentSendDatagramSize());
        const congestion = connection.congestionAvailable();
        const first = quic.Frame{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = bytes[0..1],
            .fin = finish and bytes.len == 1,
        } };
        const first_size = try connection.packetLenForFramesAtOffset(0, &.{first});
        if (first_size > connection.currentSendDatagramSize()) return error.DatagramTooLarge;
        if (first_size > congestion) return error.CongestionLimited;
        var lower: usize = 1;
        var upper = count;
        while (lower < upper) {
            const middle = lower + (upper - lower + 1) / 2;
            const candidate = quic.Frame{ .stream = .{
                .stream_id = stream_id,
                .offset = offset,
                .data = bytes[0..middle],
                .fin = finish and middle == bytes.len,
            } };
            const packet_size = try connection.packetLenForFramesAtOffset(0, &.{candidate});
            if (packet_size <= connection.currentSendDatagramSize() and
                packet_size <= congestion)
            {
                lower = middle;
            } else {
                upper = middle - 1;
            }
        }
        count = lower;
    }
    _ = std.math.add(u64, offset, count) catch return error.InvalidFrameLength;
    const final = finish and count == bytes.len;
    const frame = quic.Frame{ .stream = .{
        .stream_id = stream_id,
        .offset = offset,
        .data = bytes[0..count],
        .fin = final,
    } };
    const result = try connection.sendManyProgress(&.{&.{frame}});
    if (result.sent_count > 1 or result.sent_count > result.protected_count) return error.Unexpected;
    if (result.sent_count == 1) {
        progress.* = .{
            .committed_bytes = count,
            .complete = count == bytes.len,
            .fin_committed = final,
        };
    }
    if (result.send_error) |err| return err;
    if (result.sent_count == 0) return error.Unexpected;
}
