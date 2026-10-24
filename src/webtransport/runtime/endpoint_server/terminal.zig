//! Ordered CONNECT and associated-stream cleanup for shared server Sessions.
//! Removal uses the same nonblocking steps as endpoint polling.

const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const control_mod = @import("../session_control.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const close_write = @import("close.zig");

pub const Error = control_mod.Error;

pub fn advanceOnce(target: anytype) Error!control_mod.TerminateProgress {
    if (lifecycle.observe(&target.control, target.h3, &target.streams)) {
        target.close_response_pending = false;
        close_write.clear(target);
        return .complete;
    }
    observeSendTerminal(target);
    if (target.control.handledInvalidCapsule()) {
        target.close_response_pending = false;
        close_write.clear(target);
    }
    if (target.control.capsule_error_pending) {
        if (try target.control.tryRejectInvalidCapsule(&target.h3.established.connection)) {
            target.close_response_pending = false;
            close_write.clear(target);
            return .submitted;
        }
    }
    if (try target.control.tryRejectPostTerminalData(&target.h3.established.connection)) {
        target.close_response_pending = false;
        close_write.clear(target);
        return .submitted;
    }
    if (target.pending_close != null) {
        if (try close_write.advanceOnce(target) == .submitted) return .submitted;
    }
    if (target.close_response_pending) {
        target.h3.trySendResponseBody(target.session_id.value, &.{}, true) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected, error.StreamStopped => target.control.recordLocalCloseFailure(0),
            else => return err,
        };
        target.close_response_pending = false;
        if (!target.control.local_close_failed) target.control.local_close_sent = true;
        return .submitted;
    }
    if (!target.control.state.closed) return .complete;
    return control_mod.terminateStreamsOnce(&target.h3.established.connection, &target.streams);
}

/// Keep the application owner until every required terminal packet has been
/// submitted. Pacing, credit and socket errors return without a second reader.
pub fn finish(target: anytype) @TypeOf(target.close(0, "")) {
    defer lifecycle.observeWithTimer(&target.control, target.h3, &target.streams, target.dispatcher, target.handle);
    if (lifecycle.observe(&target.control, target.h3, &target.streams)) return;
    target.control.bindFlow(target.streams.flow);
    while (!target.control.capsule_error_pending and !target.control.handledInvalidCapsule()) {
        const event = target.control.pollOnce(&target.h3.established.connection) catch |err| switch (err) {
            error.InvalidCapsule, error.FlowControlViolation => {
                if (!target.control.handledInvalidCapsule()) target.control.capsule_error_pending = true;
                break;
            },
            else => {
                try http3.runtime.closeConnectionForProtocolError(&target.h3.established.connection, err);
                return err;
            },
        };
        if (event) |value| {
            if (value == .closed and !target.control.local_close_sent and !target.control.local_close_failed) target.close_response_pending = true;
        } else break;
    }
    // An explicit removal also terminates a still-active Session normally.
    // Protocol rejection always precedes an ordinary CLOSE/FIN.
    while (target.control.capsule_error_pending or target.control.post_terminal_data_pending) {
        if (try advanceOnce(target) == .complete) break;
    }
    observeSendTerminal(target);
    if (!target.control.state.closed and target.pending_close == null) target.close(0, "") catch |err| switch (err) {
        error.RequestCancelled, error.RequestRejected, error.StreamStopped => target.control.recordLocalCloseFailure(0),
        else => return err,
    };
    if (!target.control.local_close_sent and !target.control.local_close_failed) target.close_response_pending = true;
    while (try advanceOnce(target) == .submitted) {}
    // Once the owner is removed, no application remains to read the CONNECT
    // direction. Abort it with the optional draft-16 termination signal.
    const connection = &target.h3.established.connection;
    if (connection.recvStreamStats(target.session_id.value)) |stats| {
        if (stats.final_size == null and stats.reset == null and stats.stop_sending_sent == null) try connection.trySendStopSending(target.session_id.value, webtransport.ApplicationErrorCode.session_gone);
    }
}

fn observeSendTerminal(target: anytype) void {
    if (target.control.observeConnectSend(&target.h3.established.connection)) target.close_response_pending = false;
}
