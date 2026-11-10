//! Join the sole frame read before returning a command wake. A completed frame
//! takes precedence over a simultaneous wake, including completion during join.
const std = @import("std");

pub fn Result(comptime Frame: type) type {
    return union(enum) { frame: Frame, wake };
}

pub fn read(connection: anytype, deadline: ?std.Io.Clock.Timestamp, wake: ?*std.Io.Event, comptime Frame: type, comptime ReadError: type, comptime read_frame: anytype, comptime retain_frame: anytype) anyerror!Result(Frame) {
    const event = wake orelse {
        // No task can signal a command wake (no handler workers exist yet), so
        // the caller's own task reads directly: no select, no extra spawns.
        return .{ .frame = try read_frame(connection, deadline) };
    };
    const Selection = union(enum) {
        frame: ReadError!Frame,
        wake: std.Io.Cancelable!void,
    };
    var results: [2]Selection = undefined;
    var select: std.Io.Select(Selection) = .init(connection.io, &results);
    // Admission failure or task cancellation can race a completed read. Join
    // every task and retain that owning result for the next pump operation.
    defer while (select.cancel()) |late| switch (late) {
        .frame => |result| if (result) |frame| retain_frame(connection, frame) else |_| {},
        .wake => |result| result catch {},
    };
    try select.concurrent(.frame, read_frame, .{ connection, deadline });
    try select.concurrent(.wake, std.Io.Event.wait, .{ event, connection.io });
    switch (try select.await()) {
        .frame => |result| return .{ .frame = try result },
        .wake => |result| try result,
    }
    var completed: ?Frame = null;
    var read_error: ?anyerror = null;
    while (select.cancel()) |late| switch (late) {
        .frame => |result| {
            if (result) |frame| {
                completed = frame;
            } else |err| {
                if (err != error.Canceled and err != error.Timeout) read_error = err;
            }
        },
        .wake => |result| result catch |err| {
            if (err != error.Canceled) return err;
        },
    };
    if (completed) |frame| return .{ .frame = frame };
    if (read_error) |err| return err;
    return .wake;
}
