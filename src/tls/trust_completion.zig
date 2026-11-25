//! Commit an owned trust result only after checking the caller's budget.
const std = @import("std");
const deadline_policy = @import("../internal/deadline.zig");

pub fn checkpoint(io: std.Io, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || std.Io.Timeout.Error)!void {
    try io.checkCancel();
    if (deadline) |until| _ = try deadline_policy.usableAwake(io, until);
}

fn ResultOf(comptime Result: type) type {
    const info = @typeInfo(Result).error_union;
    return (info.error_set || std.Io.Cancelable || std.Io.Timeout.Error)!info.payload;
}

/// Source failures retain their cause only while the caller may continue.
/// Every rejected successful value owns its deinit operation.
pub fn complete(io: std.Io, deadline: ?std.Io.Clock.Timestamp, result: anytype) ResultOf(@TypeOf(result)) {
    var value = result catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    errdefer value.deinit();
    try checkpoint(io, deadline);
    return value;
}
