//! Terminal CONNECT and associated-stream cleanup for a shared WT client.
//!
//! Keep protocol cancellation ahead of the ordinary FIN reply. Each polling
//! turn submits at most one terminal packet and retains completed progress.

const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const session_control = @import("../session_control.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");
const body_fragment = @import("../../../http3/runtime/send/body_fragment.zig");

pub fn advanceOnce(
    h3: *http3.runtime.HandshakeClient,
    control: *session_control.Control,
    streams: *webtransport.StreamRegistry,
    close_response_pending: *bool,
) session_control.Error!session_control.TerminateProgress {
    if (connection_lifecycle.observe(control, h3, streams)) {
        close_response_pending.* = false;
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
    removal_close: *body_fragment.State,
) session_control.Error!void {
    defer _ = connection_lifecycle.observe(control, h3, streams);
    if (connection_lifecycle.observe(control, h3, streams)) {
        close_response_pending.* = false;
        return;
    }
    try inspectControl(h3, control, close_response_pending);
    try rejectPending(h3, control, close_response_pending);
    observeSendTerminal(h3, control, close_response_pending);
    if ((!control.state.closed or removal_close.initialized) and !control.local_close_sent and !control.local_close_failed) {
        try closeActive(h3, control, close_response_pending, removal_close);
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

fn closeActive(h3: *http3.runtime.HandshakeClient, control: *session_control.Control, reply: *bool, state: *body_fragment.State) session_control.Error!void {
    var storage: [16]u8 = undefined;
    const data = try session_control.writeCloseInto(&storage, 0, "");
    while (!state.complete) {
        try inspectControl(h3, control, reply);
        try rejectPending(h3, control, reply);
        observeSendTerminal(h3, control, reply);
        if (control.local_close_failed or control.local_close_sent) return;
        if (control.terminal_reported) {
            // A peer termination cannot leave us waiting for new data credit.
            // An unfinished DATA frame requires RESET; an unwritten one can
            // still acknowledge the peer with an empty FIN.
            if (state.wire_sent != 0) {
                while (true) {
                    h3.tryCancelRequest(control.session_id.value, webtransport.ApplicationErrorCode.session_gone) catch |err| switch (err) {
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
                    break;
                }
                control.recordLocalCloseFailure(0);
                reply.* = false;
            } else {
                control.local_close_started = false;
                reply.* = true;
            }
            return;
        }
        if (!control.local_close_started) try control.beginLocalClose();
        body_fragment.write(&h3.established.connection, &h3.outbound_bodies, control.session_id.value, data, true, state, h3.options) catch |err| switch (err) {
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
    try control.recordLocalClose(0);
    reply.* = false;
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
