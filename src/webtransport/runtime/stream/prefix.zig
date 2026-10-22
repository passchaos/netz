//! Association bytes used by data writes and the transport's reset obligation.

const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");

pub fn header(session_id: webtransport.SessionId, direction: webtransport.StreamDirection, storage: []u8) webtransport.Error![]const u8 {
    if (session_id.value & 3 != 0) return error.InvalidSessionId;
    return switch (direction) {
        .bidirectional => webtransport.BidirectionalStreamHeader.writeInto(storage, session_id),
        .unidirectional => blk: {
            const stream_type: u64 = @intFromEnum(http3.StreamType.webtransport_unidirectional);
            const length = try quic.varint.length(stream_type) + try quic.varint.length(session_id.value);
            if (storage.len < length) return error.BufferTooShort;
            const first = try quic.varint.encodeInto(storage, stream_type);
            const second = try quic.varint.encodeInto(storage[first.len..], session_id.value);
            break :blk storage[0 .. first.len + second.len];
        },
    };
}

pub fn bind(connection: *quic.one_rtt.Connection, registry: *webtransport.StreamRegistry, stream: *webtransport.StreamState) (webtransport.Error || quic.one_rtt.Error)!void {
    if (!connection.config.reliable_reset.peer) return;
    var storage: [16]u8 = undefined;
    const bytes = if (stream.locally_initiated)
        try header(registry.session_id, stream.direction, &storage)
    else
        &.{};
    try connection.setStreamResetPrefix(stream.stream_id, bytes);
}

/// A reset can submit an otherwise unwritten association prefix itself. This
/// advances only the transport offset, never the application byte counter.
pub fn observeReset(connection: *const quic.one_rtt.Connection, stream: *webtransport.StreamState) void {
    if (!stream.locally_initiated or stream.prefix_sent) return;
    const stats = connection.sendStreamStats(stream.stream_id) orelse return;
    const reset = stats.reset orelse return;
    if (reset.reliable_size == 0) return;
    stream.send_offset = stats.highest_sent_offset;
    stream.prefix_sent = true;
}
