//! Race the sole shared-endpoint receive owner against producer activity.
//!
//! A concurrently completed endpoint event is preferred so cancellation or a
//! newly queued command cannot drop an authenticated packet. Late owned events
//! are always destroyed before returning.

const std = @import("std");

pub fn beforeActivity(
    comptime Pool: type,
    comptime RequestError: type,
    pool: *Pool,
    io: std.Io,
    activity_event: *std.Io.Event,
    deadline: ?std.Io.Clock.Timestamp,
) RequestError!?Pool.Event {
    const Wake = union(enum) {
        endpoint: RequestError!Pool.Event,
        activity: std.Io.Cancelable!void,
    };
    const Task = struct {
        fn receive(
            pool_value: *Pool,
            absolute: ?std.Io.Clock.Timestamp,
        ) RequestError!Pool.Event {
            return if (absolute) |bounded|
                pool_value.receiveWithDeadline(bounded) catch |err|
                    return @errorCast(err)
            else
                pool_value.receive() catch |err| return @errorCast(err);
        }
    };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .endpoint => |result| if (result) |event_value| {
            var event = event_value;
            event.deinit(pool.allocator);
        } else |_| {},
        .activity => {},
    };
    try select.concurrent(
        .endpoint,
        Task.receive,
        .{ pool, deadline },
    );
    try select.concurrent(
        .activity,
        std.Io.Event.wait,
        .{ activity_event, io },
    );
    var endpoint_event: ?Pool.Event = null;
    var endpoint_err: ?RequestError = null;
    var activity = false;
    switch (try select.await()) {
        .endpoint => |result| if (result) |event_value| {
            endpoint_event = event_value;
        } else |err| {
            endpoint_err = err;
        },
        .activity => |result| {
            try result;
            activity = true;
        },
    }
    while (select.cancel()) |wake| switch (wake) {
        .endpoint => |result| if (result) |event_value| {
            if (endpoint_event == null) {
                endpoint_event = event_value;
            } else {
                var dropped = event_value;
                dropped.deinit(pool.allocator);
            }
        } else |err| {
            if (err != error.Canceled) endpoint_err = err;
        },
        .activity => |result| result catch |err| {
            if (err != error.Canceled) return err;
        },
    };
    if (endpoint_event) |event| return event;
    if (endpoint_err) |err| {
        if (err == error.Timeout) return null;
        return @errorCast(err);
    }
    std.debug.assert(activity);
    return null;
}
