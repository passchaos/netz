const std = @import("std");
const runtime_error = @import("../../error.zig");
const control_sender = @import("../../control/send.zig");
const connection_error = @import("../../receive/connection_error.zig");

const Error = runtime_error.Error;

/// Apply push-stream failure policy without touching the parent request's
/// lifecycle. A single-attempt STOP_SENDING that cannot yet be submitted leaves
/// the reader and promise intact so the next poll/read can retry the policy.
pub fn handshake(
    client: anytype,
    stream_id: ?u62,
    err: anyerror,
    single_attempt: bool,
) Error!bool {
    if (stream_id) |id| {
        if (runtime_error.messageStreamErrorCode(err)) |code| {
            const cancel_qpack = client.qpack_decode.table.max_capacity != 0;
            if (single_attempt) {
                if (cancel_qpack) try client.qpack_decode.prepareStreamCancellation();
                client.established.connection.trySendStopSending(id, code) catch |send_err| switch (send_err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => return false,
                    else => return send_err,
                };
                if (cancel_qpack) client.qpack_decode.recordStreamCancellationAssumeCapacity(id);
            } else {
                if (cancel_qpack) client.qpack_decode.recordStreamCancellation(id) catch {};
                client.established.connection.sendStopSending(id, code) catch {};
            }
            client.qpack_decode.discardPeerUniStream(id);
            client.push_streams.failStream(id);
            if (single_attempt) {
                client.flushResponsePacketFeedbackOnce() catch {};
            } else {
                control_sender.sendConnectionQpackFeedback(
                    &client.established.connection,
                    &client.critical_stream_send_scratch,
                    &client.qpack_decode,
                    &client.qpack_decoder_send,
                    &client.qpack_decoder_prefix_sent,
                    client.options,
                ) catch {};
            }
            return true;
        }
    }
    try connection_error.closeConnection(&client.established.connection, err);
    return true;
}

/// Match the stateful policy on the preconfigured-key runtime. Preserve peer
/// provenance before failStream swap-removes and frees the active reader.
pub fn protected(
    client: anytype,
    stream_id: ?u62,
    from: ?std.Io.net.IpAddress,
    err: anyerror,
) void {
    const peer = from orelse client.quic_client.peer;
    if (stream_id) |id| {
        if (runtime_error.messageStreamErrorCode(err)) |code| {
            if (client.qpack_decode.table.max_capacity != 0) {
                client.qpack_decode.recordStreamCancellation(id) catch {};
            }
            client.protected_send.sendFrames(
                &client.quic_client.endpoint,
                peer,
                client.config.send_keys,
                client.config.peer_connection_id,
                &client.next_packet_number,
                &.{.{ .stop_sending = .{ .stream_id = id, .application_error_code = code } }},
                client.config.max_frames_per_packet,
            ) catch {};
            client.qpack_decode.discardPeerUniStream(id);
            client.push_streams.failStream(id);
            control_sender.sendProtectedQpackFeedback(
                &client.quic_client.endpoint,
                peer,
                client.config,
                &client.qpack_decode,
                &client.qpack_decoder_send,
                &client.qpack_decoder_prefix_sent,
                &client.next_packet_number,
                &client.protected_send,
            ) catch {};
            return;
        }
    }
    connection_error.sendProtectedClose(
        &client.quic_client.endpoint,
        peer,
        client.config,
        &client.next_packet_number,
        &client.protected_send,
        err,
    );
}
