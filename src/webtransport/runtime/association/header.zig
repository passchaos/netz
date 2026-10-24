//! Identify a peer association prefix before any application consumes it.

const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");

pub const Header = struct {
    direction: webtransport.StreamDirection,
    session_id: ?u62,
    consumed: usize = 0,
};

/// Unknown stream types belong to the HTTP/3 router. A recognized WT type
/// waits for its Session ID until QUIC's clean final size proves truncation;
/// RESET/STOP can abort before association and must not fabricate a FIN error.
pub fn peek(connection: *quic.one_rtt.Connection, stream_id: u62) (webtransport.Error || quic.one_rtt.Error)!?Header {
    const bytes = connection.retainedReceivedStream(stream_id) orelse return null;
    const kind = quic.varint.decodeSlice(bytes) catch return null;
    const direction: webtransport.StreamDirection = if (quic.StreamId.init(stream_id).direction() == .bidirectional) .bidirectional else .unidirectional;
    const expected: u64 = if (direction == .bidirectional) http3.FrameType.webtransport_stream else @intFromEnum(http3.StreamType.webtransport_unidirectional);
    if (kind.value != expected) return null;
    const session_bytes = bytes[kind.len..];
    const session = quic.varint.decodeSlice(session_bytes) catch |err| switch (err) {
        error.BufferTooShort => {
            if (connection.recvStreamStats(stream_id)) |stats| {
                if (stats.reset == null and stats.stop_sending_sent == null and stats.bytes_read == 0) {
                    if (stats.final_size) |final_size| {
                        const needed: usize = if (session_bytes.len == 0) 1 else @as(usize, 1) << @as(u3, @intCast(session_bytes[0] >> 6));
                        if (final_size < kind.len + needed) {
                            http3.runtime.closeConnectionForProtocolError(connection, error.BufferTooShort) catch {};
                            return error.BufferTooShort;
                        }
                    }
                }
            }
            return .{ .direction = direction, .session_id = null };
        },
        else => return err,
    };
    const id = webtransport.SessionId.init(@intCast(session.value));
    if (!id.isClientInitiatedBidirectional()) {
        http3.runtime.closeConnectionForProtocolError(connection, error.IdError) catch {};
        return error.InvalidSessionId;
    }
    return .{ .direction = direction, .session_id = id.value, .consumed = kind.len + session.len };
}
