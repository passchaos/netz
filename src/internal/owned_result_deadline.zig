//! Transfer owned results only within their original budget; reclaim every loser.
const std = @import("std");
const deadlines = @import("deadline.zig");

pub fn checkpoint(io: std.Io, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || std.Io.Timeout.Error)!void {
    try io.checkCancel();
    if (deadline) |until| _ = try deadlines.usableAwake(io, until);
}

fn ResultOf(comptime Result: type) type {
    const info = @typeInfo(Result).error_union;
    return (info.error_set || std.Io.Cancelable || std.Io.Timeout.Error)!info.payload;
}

fn BeforeResultOf(comptime work: anytype) type {
    const info = @typeInfo(@typeInfo(@TypeOf(work)).@"fn".return_type.?).error_union;
    return (info.error_set || std.Io.Cancelable || std.Io.Timeout.Error || std.Io.ConcurrentError)!info.payload;
}

/// Success owns a zero-argument deinit operation until transfer is accepted.
pub fn complete(io: std.Io, deadline: ?std.Io.Clock.Timestamp, result: anytype) ResultOf(@TypeOf(result)) {
    var value = result catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    errdefer value.deinit();
    try checkpoint(io, deadline);
    return value;
}

/// Admit the watcher before work and join all users of borrowed arguments.
pub fn before(io: std.Io, deadline: std.Io.Clock.Timestamp, comptime work: anytype, args: std.meta.ArgsTuple(@TypeOf(work))) BeforeResultOf(work) {
    try checkpoint(io, deadline);
    const Result = BeforeResultOf(work);
    const Wake = union(enum) { completed: Result, timeout: std.Io.Cancelable!void };
    const Worker = struct {
        fn run(run_io: std.Io, until: std.Io.Clock.Timestamp, run_args: @TypeOf(args)) Result {
            try checkpoint(run_io, until);
            return complete(run_io, until, @call(.auto, work, run_args));
        }
    };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .completed => |result| if (result) |value| {
            var owned = value;
            owned.deinit();
        } else |_| {},
        .timeout => {},
    };
    select.concurrent(.timeout, deadlines.waitUntil, .{ io, deadline }) catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    select.concurrent(.completed, Worker.run, .{ io, deadline, args }) catch |err| {
        try checkpoint(io, deadline);
        return err;
    };
    return switch (try select.await()) {
        .completed => |result| try complete(io, deadline, result),
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}

test {
    _ = @import("owned_result_deadline_tests.zig");
}
