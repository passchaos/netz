//! Settle abandoned receive directions without losing terminal events.

const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const flow_receive = @import("../flow/receive.zig");
const association = @import("../stream_association.zig");
const std = @import("std");

pub const Error = webtransport.Error || quic.one_rtt.Error;

/// Discard bytes for every receive direction abandoned by local STOP_SENDING
/// or peer RESET_STREAM. This is shared by targeted, whichever-ready, and
/// whole-stream pollers so an application that waits only on a sibling cannot
/// leave connection flow-control credit trapped behind a terminal stream.
/// RESET metadata remains in the session registry for one later application
/// event even if QUIC can reclaim the stream immediately.
pub fn drain(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    single_attempt: bool,
) Error!bool {
    try flow_receive.observeAll(connection, registry);
    var progressed = false;
    for (registry.registered()) |*stream| {
        if (stream.peer_fin) continue;
        const before = connection.recvStreamStats(stream.stream_id) orelse
            continue;
        var fresh_reset = false;
        if (before.reset) |reset| {
            // A live reader must receive the reliable prefix before reset.
            // STOP_SENDING explicitly abandons that read contract: QUIC has
            // already settled the final-size credit and still owns overlap/
            // prefix validation, so preserve the reset event and settle the
            // Session credit even while the reliable prefix has gaps.
            if (stream.stop_sent == null and reset.reliable_size != 0 and
                before.bytes_read < reset.reliable_size)
            {
                continue;
            }
            // RESET_STREAM is application-visible. Preserve its metadata in
            // the session registry before releasing transport storage.
            if (stream.receive_reset == null) {
                stream.receive_reset = .fromHttp3(
                    reset.application_error_code,
                );
                fresh_reset = true;
            }
            if (stream.receive_reset_final_size == null) {
                stream.receive_reset_final_size = reset.final_size;
                fresh_reset = true;
            }
            _ = try connection.discardResetReceived(stream.stream_id);
            flow_receive.consumeAbandoned(registry, stream);
            try association.requestAfterSendTerminal(connection, stream);
        } else {
            if (stream.stop_sent == null) continue;
            _ = try connection.discardStoppedReceived(stream.stream_id);
            flow_receive.consumeAbandoned(registry, stream);
        }
        progressed = progressed or before.available_bytes != 0 or fresh_reset;
        const after = connection.recvStreamStats(stream.stream_id) orelse {
            if (single_attempt and progressed) return true;
            continue;
        };
        if (after.reset == null and after.final_size != null and
            after.bytes_read == after.final_size.?)
        {
            stream.peer_fin = true;
            try association.requestAfterSendTerminal(connection, stream);
            progressed = true;
        } else {
            std.debug.assert(after.bytes_read >= before.bytes_read);
        }
        // Endpoint pollers promise bounded nonblocking work. After one
        // cancelled receive direction advances, let the dispatcher service
        // timers and other connections before another sweep.
        if (single_attempt and progressed) return true;
    }
    return progressed;
}
