//! Persistent transport markers for streams rejected before Session ownership.

const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");

pub const Error = quic.one_rtt.Error;

pub fn code(connection: *const quic.one_rtt.Connection, stream_id: u62, direction: webtransport.StreamDirection) ?u64 {
    if (connection.recvStreamStats(stream_id)) |stats| {
        if (stats.stop_sending_sent) |stop| {
            if (isRejection(stop.application_error_code)) return stop.application_error_code;
        }
    }
    if (direction == .bidirectional) {
        if (connection.sendStreamStats(stream_id)) |stats| {
            if (stats.reset) |reset| {
                if (isRejection(reset.application_error_code)) return reset.application_error_code;
            }
        }
    }
    return null;
}

fn isRejection(value: u64) bool {
    return value == webtransport.ApplicationErrorCode.buffered_stream_rejected or value == webtransport.ApplicationErrorCode.session_gone;
}

pub fn advance(connection: *quic.one_rtt.Connection, stream_id: u62, direction: webtransport.StreamDirection, application_code: u64, single_attempt: bool) Error!bool {
    const existing_code = code(connection, stream_id, direction);
    const effective_code = existing_code orelse application_code;
    const already_started = existing_code != null;
    const send_needed = direction == .bidirectional and (if (connection.sendStreamStats(stream_id)) |stats| stats.reset == null and stats.final_size == null and stats.stopped == null else true);
    const stop_needed = if (connection.recvStreamStats(stream_id)) |stats| stats.stop_sending_sent == null else false;
    switch (direction) {
        .bidirectional => if (single_attempt)
            try connection.tryCancelStream(stream_id, effective_code)
        else
            try connection.cancelStream(stream_id, effective_code),
        .unidirectional => if (single_attempt)
            try connection.trySendStopSending(stream_id, effective_code)
        else
            try connection.sendStopSending(stream_id, effective_code),
    }
    if (single_attempt and (send_needed or stop_needed)) return true;
    const discarded = try connection.discardStoppedReceived(stream_id);
    if (single_attempt and discarded != 0) return true;
    _ = try connection.requestCompletedPeerStreamRelease(stream_id);
    return !already_started or discarded != 0 or connection.peerStreamClosed(stream_id);
}
