//! Deadline-bounded atomic stream cancellation with transport progress.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn withDeadline(
    connection: anytype,
    stream_id: u64,
    application_error_code: u64,
    deadline: std.Io.Clock.Timestamp,
) !void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    while (true) {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
        connection.tryCancelStream(stream_id, application_error_code) catch |err|
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
