//! Preserve malformed-Capsule reporting through CONNECT and stream cleanup.

const std = @import("std");
const control_mod = @import("../session_control.zig");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn pending(control: *const control_mod.Control) bool {
    return control.capsule_error_pending or
        (control.capsule_error_rejected and !control.capsule_error_reported);
}

pub fn finish(
    control: *control_mod.Control,
    connection: *quic.one_rtt.Connection,
    streams: *webtransport.StreamRegistry,
) control_mod.Error!void {
    if (control.observeConnection(connection)) {
        report(control);
        return;
    }
    control.capsule_error_pending = true;
    _ = try control.rejectInvalidCapsule(connection);
    try control_mod.terminateStreams(connection, streams);
    report(control);
}

pub fn finishWithDeadline(
    control: *control_mod.Control,
    connection: *quic.one_rtt.Connection,
    streams: *webtransport.StreamRegistry,
    deadline: std.Io.Clock.Timestamp,
) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    if (control.observeConnection(connection)) {
        report(control);
        return;
    }
    control.capsule_error_pending = true;
    _ = try control.rejectInvalidCapsuleWithDeadline(connection, deadline);
    try control_mod.terminateStreamsWithDeadline(connection, streams, deadline);
    report(control);
}

/// Submit at most one terminal packet. False retains the protocol error for
/// the next dispatcher poll without consuming its eventual notification.
pub fn finishOnce(
    control: *control_mod.Control,
    connection: *quic.one_rtt.Connection,
    streams: *webtransport.StreamRegistry,
) control_mod.Error!bool {
    if (control.observeConnection(connection)) {
        report(control);
        return true;
    }
    control.capsule_error_pending = true;
    if (try control.tryRejectInvalidCapsule(connection)) return false;
    if (try control_mod.terminateStreamsOnce(connection, streams) == .submitted) {
        return false;
    }
    report(control);
    return true;
}

fn report(control: *control_mod.Control) void {
    control.capsule_error_pending = false;
    control.capsule_error_reported = true;
}
