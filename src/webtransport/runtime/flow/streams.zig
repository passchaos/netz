//! Retire associated records after QUIC has compacted the stream and every
//! terminal application notification has been delivered. QUIC's closed-ID
//! ranges retain the replay guard without per-Session lifetime tombstones.

const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");

/// Explicit release stays idempotent after automatic record reclamation.
/// Unknown live IDs still fail ownership validation before touching transport.
pub fn shouldReleasePeer(connection: *const quic.one_rtt.Connection, registry: *webtransport.StreamRegistry, stream_id: u62) webtransport.Error!bool {
    const stream = registry.get(stream_id) orelse {
        if (connection.peerStreamClosed(stream_id)) return false;
        return error.UnknownStream;
    };
    if (stream.locally_initiated) return error.InvalidStreamState;
    return true;
}

pub fn observeClosed(connection: *const quic.one_rtt.Connection, registry: *webtransport.StreamRegistry) void {
    const flow = registry.flow orelse return;
    var position: usize = 0;
    while (position < registry.streams.items.len) {
        const stream = &registry.streams.items[position];
        if (connection.sendStreamStats(stream.stream_id)) |stats| {
            if (stats.reset) |reset| stream.send_reset = .fromHttp3(reset.application_error_code);
            if (stats.stopped) |stop| {
                if (stream.stopped == null) stream.stopped = .fromHttp3(stop.application_error_code);
            }
        }
        if (connection.recvStreamStats(stream.stream_id)) |stats| {
            if (stats.reset) |reset| {
                if (reset.reliable_size == 0 or stats.bytes_read >= reset.reliable_size) {
                    if (stream.receive_reset == null) stream.receive_reset = .fromHttp3(reset.application_error_code);
                    if (stream.receive_reset_final_size == null) stream.receive_reset_final_size = reset.final_size;
                }
            }
        }
        if (connection.streamLifecycle(stream.stream_id) != .closed or !stream.readyForRetirement()) {
            position += 1;
            continue;
        }
        const removed = stream.*;
        if (!removed.locally_initiated) flow.retirePeer(removed.direction) catch unreachable;
        _ = registry.index.remove(removed.stream_id);
        _ = registry.streams.swapRemove(position);
        if (position < registry.streams.items.len) {
            registry.index.getPtr(registry.streams.items[position].stream_id).?.position = position;
        }
    }
}

test {
    _ = @import("streams/tests.zig");
}
