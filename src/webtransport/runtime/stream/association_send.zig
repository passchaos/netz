//! Publish a STREAM association prefix only after its bounded socket commit.
const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const packets = @import("../../../quic/one_rtt/send_deadline.zig");

pub const Error = quic.one_rtt.Error || quic.runtime.ReceiveTimeoutError || error{IntegerOverflow};

pub fn prefix(connection: *quic.one_rtt.Connection, stream: *webtransport.StreamState, stream_id: u62, bytes: []const u8, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const next_offset = std.math.add(u64, stream.send_offset, bytes.len) catch return error.IntegerOverflow;
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_id,
        .offset = stream.send_offset,
        .data = bytes,
        .fin = false,
    } }};
    try packets.oneOptional(connection, &frames, deadline);
    stream.send_offset = next_offset;
    stream.prefix_sent = true;
}
