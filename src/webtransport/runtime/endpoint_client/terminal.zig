//! Terminal CONNECT and associated-stream cleanup for a shared WT client.
//!
//! Keep protocol cancellation ahead of the ordinary FIN reply. Each polling
//! turn submits at most one terminal packet and retains completed progress.

const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const session_control = @import("../session_control.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");
const close_write = @import("close.zig");
const drain_write = @import("drain.zig");

pub fn advanceOnce(
    h3: *http3.runtime.HandshakeClient,
    control: *session_control.Control,
    streams: *webtransport.StreamRegistry,
    close_response_pending: *bool,
    pending_close: *close_write.State,
    pending_drain: *drain_write.State,
) session_control.Error!session_control.TerminateProgress {
    if (connection_lifecycle.observe(control, h3, streams)) {
        close_response_pending.* = false;
        pending_close.clear();
        pending_drain.clear();
        return .complete;
    }
    observeSendTerminal(h3, control, close_response_pending);
    if (control.handledInvalidCapsule()) close_response_pending.* = false;
    if (control.capsule_error_pending) {
        if (try control.tryRejectInvalidCapsule(&h3.established.connection)) {
            close_response_pending.* = false;
            return .submitted;
        }
    }
    if (try control.tryRejectPostTerminalData(&h3.established.connection)) {
        close_response_pending.* = false;
        return .submitted;
    }
    if (pending_drain.pending()) {
        if (try pending_drain.advanceOnce(h3, control, close_response_pending) == .submitted) return .submitted;
    }
    if (pending_close.pending != null) {
        if (try pending_close.advanceOnce(h3, control, close_response_pending) == .submitted) return .submitted;
    }
    if (close_response_pending.*) {
        h3.trySendRequestBody(control.session_id.value, &.{}, true) catch |err|
            switch (err) {
                error.RequestCancelled, error.RequestRejected, error.StreamStopped => {
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
    pending_close: *close_write.State,
    pending_drain: *drain_write.State,
) session_control.Error!void {
    defer _ = connection_lifecycle.observe(control, h3, streams);
    if (connection_lifecycle.observe(control, h3, streams)) {
        close_response_pending.* = false;
        pending_close.clear();
        pending_drain.clear();
        return;
    }
    try inspectControl(h3, control, close_response_pending);
    try rejectPending(h3, control, close_response_pending);
    observeSendTerminal(h3, control, close_response_pending);
    if (pending_drain.pending()) try progressActive(h3, control, close_response_pending, pending_drain);
    if ((!control.state.closed or pending_close.pending != null) and !control.local_close_sent and !control.local_close_failed) {
        if (pending_close.pending == null) try pending_close.prepare(h3, control, 0, "");
        try progressActive(h3, control, close_response_pending, pending_close);
    }
    if (!control.local_close_sent and !control.local_close_failed) close_response_pending.* = true;
    if (close_response_pending.*) {
        h3.sendRequestBodyPaced(control.session_id.value, &.{}, true) catch |err|
            switch (err) {
                error.RequestCancelled, error.RequestRejected, error.StreamStopped => {
                    control.recordLocalCloseFailure(0);
                },
                else => return err,
            };
        close_response_pending.* = false;
        if (!control.local_close_failed) control.local_close_sent = true;
    }
    try session_control.terminateStreams(&h3.established.connection, streams);
    if (h3.established.connection.recvStreamStats(control.session_id.value)) |stats| {
        if (stats.final_size == null and stats.reset == null and stats.stop_sending_sent == null) try h3.established.connection.sendStopSending(control.session_id.value, webtransport.ApplicationErrorCode.session_gone);
    }
}

fn inspectControl(h3: *http3.runtime.HandshakeClient, control: *session_control.Control, reply: *bool) session_control.Error!void {
    while (!control.capsule_error_pending and !control.handledInvalidCapsule()) {
        const event = control.poll(&h3.established.connection) catch |err| switch (err) {
            error.InvalidCapsule, error.FlowControlViolation => {
                if (!control.handledInvalidCapsule()) control.capsule_error_pending = true;
                break;
            },
            else => {
                try http3.runtime.closeConnectionForProtocolError(&h3.established.connection, err);
                return err;
            },
        };
        if (event) |value| {
            if (value == .closed and !control.local_close_sent and !control.local_close_failed) reply.* = true;
        } else break;
    }
    if (control.handledInvalidCapsule()) reply.* = false;
}

fn rejectPending(h3: *http3.runtime.HandshakeClient, control: *session_control.Control, reply: *bool) session_control.Error!void {
    if (control.capsule_error_pending) {
        _ = try control.rejectInvalidCapsule(&h3.established.connection);
        reply.* = false;
    }
    if (try control.rejectPostTerminalData(&h3.established.connection)) reply.* = false;
    if (control.handledInvalidCapsule()) reply.* = false;
}

fn progressActive(h3: *http3.runtime.HandshakeClient, control: *session_control.Control, reply: *bool, state: anytype) session_control.Error!void {
    while (state.isPending()) {
        try inspectControl(h3, control, reply);
        try rejectPending(h3, control, reply);
        observeSendTerminal(h3, control, reply);
        _ = state.advanceOnce(h3, control, reply) catch |err| switch (err) {
            error.PacingLimited => {
                try h3.established.connection.waitForPacingAvailability();
                continue;
            },
            error.CongestionLimited, error.FlowControlBlocked => {
                try h3.receiveDetachedResponseProgress(control.session_id.value);
                continue;
            },
            else => return err,
        };
    }
}

fn observeSendTerminal(h3: *http3.runtime.HandshakeClient, control: *session_control.Control, reply: *bool) void {
    const stats = h3.established.connection.sendStreamStats(control.session_id.value) orelse return;
    if (stats.reset != null or stats.stopped != null) {
        control.recordLocalCloseFailure(0);
        reply.* = false;
    } else if (stats.final_size != null) {
        control.local_close_sent = true;
        if (!control.state.closed) control.state.close(0);
    }
}
