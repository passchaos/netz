//! Join one logical scatter/gather write before its borrowed slices expire.

const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn write(comptime Error: type, io: std.Io, context: anytype, comptime write_fn: anytype, prefix: []const u8, payload: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
    _ = try deadline_policy.usableAwake(io, deadline);
    const Task = struct {
        io: std.Io,
        context: @TypeOf(context),
        prefix: []const u8,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
        result: ?(Error!void) = null,

        fn run(self: *@This()) void {
            _ = deadline_policy.usableAwake(self.io, self.deadline) catch |err| {
                self.result = err;
                return;
            };
            self.result = write_fn(self.context, self.prefix, self.payload);
        }

        fn wait(task_io: std.Io, until: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
            try until.wait(task_io);
        }

        fn succeeded(self: @This()) bool {
            if (self.result) |result| {
                if (result) |_| return true else |_| {}
            }
            return false;
        }
    };
    const Wake = union(enum) { write: void, timeout: std.Io.Cancelable!void };
    var task = Task{ .io = io, .context = context, .prefix = prefix, .payload = payload, .deadline = deadline };
    var wakes: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wakes);
    defer select.cancelDiscard();
    try select.concurrent(.write, Task.run, .{&task});
    select.concurrent(.timeout, Task.wait, .{ io, deadline }) catch |err| {
        select.cancelDiscard();
        if (task.succeeded()) return;
        return err;
    };
    const wake = select.await() catch |err| {
        select.cancelDiscard();
        if (task.succeeded()) return;
        return err;
    };
    switch (wake) {
        .write => return task.result.?,
        .timeout => |result| {
            try result;
            // Cancellation joins the writer before its result or borrowed
            // storage is inspected. A fully completed racing write commits.
            select.cancelDiscard();
            if (task.result) |written| {
                if (written) |_| return else |err| {
                    if (err != error.Canceled) return err;
                }
            }
            return error.Timeout;
        },
    }
}
