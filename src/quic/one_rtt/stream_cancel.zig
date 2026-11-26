//! Atomic stream cancellation, reset identity, and deadline-bounded progress.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const bounded = @import("../../internal/progress_deadline.zig");

/// A committed RESET has its own immutable error identity. Canceling the
/// receive half may use another code, and a reliable-prefix downgrade must
/// preserve the reset's original code when it is retransmitted.
pub fn resetInfo(
    existing: anytype,
    highest_sent: u64,
    required_prefix: u64,
    requested_error: u64,
) error{FinalSizeMismatch}!@TypeOf(existing.?) {
    const final_size = @max(highest_sent, required_prefix);
    if (existing) |reset| {
        if (reset.final_size != final_size) return error.FinalSizeMismatch;
    }
    return .{
        .application_error_code = if (existing) |reset| reset.application_error_code else requested_error,
        .final_size = final_size,
        .reliable_size = required_prefix,
    };
}

pub fn withDeadline(
    connection: anytype,
    stream_id: u64,
    application_error_code: u64,
    deadline: std.Io.Clock.Timestamp,
) !void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    while (true) {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
        const Connection = @typeInfo(@TypeOf(connection)).pointer.child;
        bounded.runVoid(connection.endpoint.io, deadline, Connection.tryCancelStream, .{ connection, stream_id, application_error_code }) catch |err|
            switch (err) {
                error.CongestionLimited => {
                    connection.servicePacketServicingTimersDeadline(deadline) catch |progress_err|
                        switch (progress_err) {
                            error.CongestionLimited => continue,
                            error.PacingLimited => {
                                try connection.waitForPacingAvailabilityWithDeadline(deadline);
                                continue;
                            },
                            else => return progress_err,
                        };
                    continue;
                },
                error.PacingLimited => {
                    try connection.waitForPacingAvailabilityWithDeadline(deadline);
                    continue;
                },
                else => return err,
            };
        return;
    }
}
