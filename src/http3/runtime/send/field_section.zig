//! Flow-aware borrowed HEADERS fragments for complete and streaming sends.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const Error = @import("../error.zig").Error;
const ReceiveTimeoutError = @import("../error.zig").ReceiveTimeoutError;

pub fn sendProgress(connection: *quic.one_rtt.Connection, id: u62, encoded: []const u8, base_offset: u64, fin: bool, committed: *usize, max_frame_data: usize, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
    while (committed.* < encoded.len) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        writeFragment(connection, id, encoded, fin, base_offset, committed, max_frame_data) catch |err| switch (err) {
            error.PacingLimited => {
                if (deadline) |absolute| try connection.waitForPacingAvailabilityWithDeadline(absolute) else try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
    }
}

fn writeFragment(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    encoded: []const u8,
    fin: bool,
    base_offset: u64,
    committed: *usize,
    max_frame_data: usize,
) Error!void {
    if (max_frame_data == 0 or committed.* > encoded.len) return error.InvalidStreamRange;
    const credit = @min(connection.connectionSendAvailable(), connection.streamSendAvailable(stream_id));
    const limit = @min(encoded.len - committed.*, @min(max_frame_data, std.math.cast(usize, credit) orelse std.math.maxInt(usize)));
    if (limit == 0) return error.FlowControlBlocked;
    var length = @min(limit, connection.currentSendDatagramSize());
    var frame = quic.Frame{ .stream = .{
        .stream_id = stream_id,
        .offset = base_offset + committed.*,
        .data = encoded[committed.*..][0..length],
        .fin = fin and committed.* + length == encoded.len,
    } };
    if (try connection.packetLenForFramesAtOffset(0, &.{frame}) > connection.currentSendDatagramSize()) {
        var low: usize = 0;
        var high = length;
        while (low < high) {
            const middle = low + (high - low + 1) / 2;
            frame.stream.data = encoded[committed.*..][0..middle];
            frame.stream.fin = fin and committed.* + middle == encoded.len;
            if (try connection.packetLenForFramesAtOffset(0, &.{frame}) <= connection.currentSendDatagramSize()) low = middle else high = middle - 1;
        }
        if (low == 0) return error.DatagramTooLarge;
        length = low;
        frame.stream.data = encoded[committed.*..][0..length];
        frame.stream.fin = fin and committed.* + length == encoded.len;
    }
    try connection.trySend(&.{frame});
    committed.* += length;
}
