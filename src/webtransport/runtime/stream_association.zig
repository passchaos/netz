//! WebTransport stream association over QUIC stream prefixes.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

pub const Error = webtransport.Error || quic.one_rtt.Error;

/// Identify/register a WebTransport stream after its association prefix is
/// contiguous. Locally-opened bidirectional reverse directions carry no
/// second prefix and are recognized from the existing registry entry.
pub fn identify(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
) Error!?*webtransport.StreamState {
    std.debug.assert(receive_mode != .unset);
    const direction: webtransport.StreamDirection =
        if (quic.StreamId.init(stream_id).direction() == .bidirectional)
            .bidirectional
        else
            .unidirectional;
    var stream = registry.get(stream_id);
    if (stream == null) {
        const available = connection.availableReceivedStream(stream_id) orelse
            return null;
        const prefix_len = switch (direction) {
            .bidirectional => blk: {
                const parsed =
                    webtransport.BidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return null,
                            // Another HTTP/3 adapter owns ordinary request or
                            // extension streams on the same QUIC connection.
                            error.InvalidStreamType => return null,
                            else => return err,
                        };
                if (parsed.session_id.value != session_id.value) {
                    return error.InvalidSessionId;
                }
                break :blk parsed.consumed;
            },
            .unidirectional => blk: {
                const parsed =
                    webtransport.UnidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return null,
                            else => return err,
                        };
                if (parsed.stream_type !=
                    http3.StreamType.webtransport_unidirectional)
                {
                    return null;
                }
                if (parsed.session_id == null or
                    parsed.session_id.?.value != session_id.value)
                {
                    return error.InvalidSessionId;
                }
                break :blk parsed.consumed;
            },
        };
        stream = try registry.registerPeer(stream_id, direction);
        stream.?.receive_mode = receive_mode;
        if (receive_mode == .incremental) {
            // Association bytes count toward QUIC credit but are never exposed
            // as WebTransport application bytes.
            connection.releaseReceivedCapacity(
                stream_id,
                prefix_len,
            ) catch |err| {
                // Registry insertion must be transactional with prefix-credit
                // consumption. Otherwise a failed MAX_* send leaves a peer
                // stream registered as incremental even though its prefix is
                // still at the front of transport storage.
                registry.removeLastPeer(stream_id);
                return err;
            };
        } else {
            // The compatibility whole-stream API consumes prefix + payload in
            // one transaction after FIN.
            stream.?.receive_prefix_len = prefix_len;
        }
        stream.?.prefix_received = true;
    } else if (stream.?.locally_initiated and
        stream.?.direction == .bidirectional and
        !stream.?.prefix_received)
    {
        // The peer's reverse direction begins directly with application data.
        stream.?.prefix_received = true;
    }
    if (stream.?.receive_mode == .unset) {
        stream.?.receive_mode = receive_mode;
    } else if (stream.?.receive_mode != receive_mode) {
        return error.InvalidStreamState;
    }
    return stream;
}
