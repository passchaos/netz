//! Bound a borrowed operation and retain every completed result after joining.
const std = @import("std");
const deadline_policy = @import("deadline.zig");

test {
    _ = @import("progress_deadline_tests.zig");
}

pub const BudgetError = std.Io.Cancelable || std.Io.Timeout.Error || std.Io.ConcurrentError;

fn ResultOf(comptime work: anytype) type {
    return @typeInfo(@TypeOf(work)).@"fn".return_type.?;
}

pub fn Outcome(comptime Result: type) type {
    return struct {
        result: ?Result = null,
        wait_error: ?BudgetError = null,
    };
}

/// The result and wait error are independent: a canceled operation can return
/// useful socket-prefix progress, and a complete send can race a timer. No user
/// of args remains alive after this call. The consumer commits that progress
/// before deciding which completion/error to expose.
pub fn before(io: std.Io, until: std.Io.Clock.Timestamp, comptime work: anytype, args: std.meta.ArgsTuple(@TypeOf(work))) Outcome(ResultOf(work)) {
    const Result = ResultOf(work);
    const Out = Outcome(Result);
    var out: Out = .{};
    io.checkCancel() catch |err| return .{ .wait_error = err };
    _ = deadline_policy.usableAwake(io, until) catch |err| return .{ .wait_error = err };
    const Operation = union(enum) { skipped: BudgetError, completed: Result };
    const Wake = union(enum) { operation: Operation, timer: std.Io.Cancelable!void };
    const Worker = struct {
        fn run(run_io: std.Io, deadline: std.Io.Clock.Timestamp, run_args: @TypeOf(args)) Operation {
            run_io.checkCancel() catch |err| return .{ .skipped = err };
            _ = deadline_policy.usableAwake(run_io, deadline) catch |err| return .{ .skipped = err };
            return .{ .completed = @call(.auto, work, run_args) };
        }
    };
    const Collector = struct {
        fn record(output: *Out, wake: Wake, winner: bool) void {
            switch (wake) {
                .operation => |operation| switch (operation) {
                    .skipped => |err| if (output.wait_error == null) {
                        output.wait_error = err;
                    },
                    .completed => |result| output.result = result,
                },
                .timer => |result| if (winner) {
                    result catch |err| {
                        output.wait_error = err;
                        return;
                    };
                    output.wait_error = error.Timeout;
                },
            }
        }
    };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    // Admit the watcher first; inability to create it must precede any I/O.
    select.concurrent(.timer, deadline_policy.waitUntil, .{ io, until }) catch |err| return .{ .wait_error = err };
    select.concurrent(.operation, Worker.run, .{ io, until, args }) catch |err| {
        out.wait_error = err;
        while (select.cancel()) |late| Collector.record(&out, late, false);
        return out;
    };
    if (select.await()) |winner| Collector.record(&out, winner, true) else |err| out.wait_error = err;
    // cancel joins the group and drains the result queue without introducing
    // a caller cancellation point. Preserve late results before returning.
    while (select.cancel()) |late| Collector.record(&out, late, false);
    return out;
}
