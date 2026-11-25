//! Deadline-bounded listener acceptance with explicit race cleanup.

const std = @import("std");
const deadline_policy = @import("deadline.zig");
const waitUntil = deadline_policy.waitUntil;

const net = std.Io.net;

pub fn withDeadline(
    listener: *net.Server,
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) (net.Server.AcceptError || std.Io.Timeout.Error)!net.Stream {
    _ = try deadline_policy.usableAwake(io, deadline);
    const AcceptResult = net.Server.AcceptError!net.Stream;
    const Wake = union(enum) {
        accepted: AcceptResult,
        timeout: std.Io.Cancelable!void,
    };
    var buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &buffer);
    var selected_accept = false;
    defer while (select.cancel()) |wake| switch (wake) {
        .accepted => |result| if (result) |stream| {
            if (!selected_accept) stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    // Acceptance and its timer must overlap even when async fallback would
    // run inline. Reserve the timer before admitting a socket operation.
    select.concurrent(.timeout, waitUntil, .{ io, deadline }) catch return error.SystemResources;
    select.concurrent(.accepted, net.Server.accept, .{ listener, io }) catch return error.SystemResources;
    return switch (try select.await()) {
        .accepted => |result| blk: {
            const stream = try result;
            selected_accept = true;
            break :blk stream;
        },
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}
