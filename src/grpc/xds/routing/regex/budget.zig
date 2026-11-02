//! Optional request budget for native routing evaluation.
const std = @import("std");
pub const Error = error{ Canceled, Timeout };
pub const Budget = struct {
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp = null,
    pub fn check(self: Budget) Error!void {
        try self.io.checkCancel();
        if (self.deadline) |deadline| if (deadline.clock != .awake or deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
    }
};
