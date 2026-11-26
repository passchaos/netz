//! Independently race a buffered frame read with a reusable batch cancel wake.
//! Completed input wins interruption so already-consumed bytes stay observable.
const std = @import("std");

pub fn Result(comptime Frame: type) type {
    return union(enum) { frame: Frame, wake };
}

pub fn read(io: std.Io, connection: anytype, deadline: ?std.Io.Clock.Timestamp, wake: *std.Io.Event, comptime Frame: type, comptime ReadError: type, comptime read_frame: anytype) anyerror!Result(Frame) {
    const Selection = union(enum) { frame: ReadError!Frame, wake: std.Io.Cancelable!void };
    var buffer: [2]Selection = undefined;
    var select: std.Io.Select(Selection) = .init(io, &buffer);
    // Both tasks fit in the queue. cancel() joins before closing it, so a
    // read completing during cancellation can still publish its result.
    defer select.cancelDiscard();
    try select.concurrent(.frame, read_frame, .{ connection, deadline });
    var interruption: ?anyerror = null;
    select.concurrent(.wake, std.Io.Event.wait, .{ wake, io }) catch |err| {
        interruption = err;
    };
    var selected: ?Selection = null;
    if (interruption == null) {
        selected = select.await() catch |err| failed: {
            interruption = err;
            break :failed null;
        };
    }
    if (selected) |value| switch (value) {
        .frame => |frame| return .{ .frame = try frame },
        .wake => |result| result catch |err| {
            interruption = err;
        },
    };

    var completed: ?Frame = null;
    var read_error: ?anyerror = null;
    while (select.cancel()) |late| switch (late) {
        .frame => |result| {
            if (result) |frame| {
                completed = frame;
            } else |err| {
                if (err != error.Canceled) read_error = err;
            }
        },
        .wake => |result| result catch |err| {
            if (err != error.Canceled) interruption = err;
        },
    };
    if (completed) |frame| {
        if (interruption) |err| if (err == error.Canceled) std.Io.recancel(io);
        return .{ .frame = frame };
    }
    if (read_error) |err| return err;
    if (interruption) |err| return err;
    return .wake;
}
