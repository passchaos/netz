//! Transport waits use the protocol's receive owner when one is bound.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const progress_mod = @import("../flow/progress.zig");

pub const Error = progress_mod.Error;

pub fn receive(connection: *quic.one_rtt.Connection, deadline: ?std.Io.Clock.Timestamp, progress: ?progress_mod.Progress) Error!void {
    if (progress) |owner| {
        if (try owner.receive(deadline)) {
            try owner.maintain(deadline);
            return;
        }
    }
    if (deadline) |absolute| return connection.servicePacketServicingTimersDeadline(absolute);
    return connection.servicePacketServicingTimers();
}

pub fn pacing(connection: *quic.one_rtt.Connection, deadline: ?std.Io.Clock.Timestamp, progress: ?progress_mod.Progress) Error!void {
    if (progress) |owner| {
        if (try owner.pacing(deadline)) return;
    }
    if (deadline) |absolute| return connection.waitForPacingAvailabilityWithDeadline(absolute);
    return connection.waitForPacingAvailability();
}
