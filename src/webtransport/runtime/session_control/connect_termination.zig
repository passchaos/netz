//! CONNECT send termination closes only its owning WebTransport Session.
//! Retain the transport notification separately from Capsule events so an
//! already-buffered peer CLOSE keeps its application code and reason.

const std = @import("std");
const quic = @import("../../../quic/mod.zig");

/// QUIC application error codes fit in 62 bits. Keep the raw reset code and
/// two out-of-range sentinels in one word; decode StreamError only on delivery.
pub const Send = enum(u64) {
    none = @as(u64, 1) << 62,
    closed,
    _,

    pub fn fromReset(code: u64) Send {
        std.debug.assert(code < @intFromEnum(Send.none));
        return @enumFromInt(code);
    }
};

pub fn observe(control: anytype, connection: *const quic.one_rtt.Connection) bool {
    const stats = connection.sendStreamStats(control.session_id.value) orelse return false;
    const code = if (stats.stopped) |stopped|
        stopped.application_error_code
    else if (stats.reset) |reset|
        reset.application_error_code
    else
        null;
    if (code) |value| {
        if (!control.terminal_reported and control.send_termination == .none) control.send_termination = .fromReset(value);
        // STOP_SENDING is already terminal even when pacing or congestion
        // delays QUIC's mandatory RESET_STREAM response.
        control.recordLocalCloseFailure(0);
        return true;
    }
    if (stats.final_size != null) {
        // A FIN committed by an explicit Session close already has its own
        // metadata. Only an otherwise-untracked FIN needs a new notification.
        if (!control.terminal_reported and !control.local_close_sent and control.send_termination == .none) control.send_termination = .closed;
        control.local_close_sent = true;
        if (!control.state.closed) control.state.close(0);
        return true;
    }
    return false;
}
