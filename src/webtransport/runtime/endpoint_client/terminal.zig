//! Terminal CONNECT and associated-stream cleanup for a shared WT client.
//!
//! Keep protocol cancellation ahead of the ordinary FIN reply. Each polling
//! turn submits at most one terminal packet and retains completed progress.

const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const session_control = @import("../session_control.zig");

pub fn advanceOnce(
    h3: *http3.runtime.HandshakeClient,
    control: *session_control.Control,
    streams: *webtransport.StreamRegistry,
    close_response_pending: *bool,
) session_control.Error!session_control.TerminateProgress {
    if (try control.tryRejectPostTerminalData(&h3.established.connection)) {
        close_response_pending.* = false;
        return .submitted;
    }
    if (close_response_pending.*) {
        h3.trySendRequestBody(control.session_id.value, &.{}, true) catch |err|
            switch (err) {
                error.RequestCancelled, error.RequestRejected => {
                    control.recordLocalCloseFailure(0);
                    close_response_pending.* = false;
                    return .submitted;
                },
                else => return err,
            };
        close_response_pending.* = false;
        control.local_close_sent = true;
        return .submitted;
    }
    if (!control.state.closed) return .complete;
    return session_control.terminateStreamsOnce(
        &h3.established.connection,
        streams,
    );
}

/// Removal uses the same cancellation-before-FIN ordering, while allowing
/// QUIC to wait for credit and pacing before releasing the Session owner.
pub fn finish(
    h3: *http3.runtime.HandshakeClient,
    control: *session_control.Control,
    streams: *webtransport.StreamRegistry,
    close_response_pending: *bool,
) session_control.Error!void {
    if (try control.rejectPostTerminalData(&h3.established.connection)) {
        close_response_pending.* = false;
    }
    if (close_response_pending.*) {
        h3.sendRequestBodyPaced(control.session_id.value, &.{}, true) catch |err|
            switch (err) {
                error.RequestCancelled, error.RequestRejected => {
                    control.recordLocalCloseFailure(0);
                },
                else => return err,
            };
        close_response_pending.* = false;
        if (!control.local_close_failed) control.local_close_sent = true;
    }
    try session_control.terminateStreams(&h3.established.connection, streams);
}
