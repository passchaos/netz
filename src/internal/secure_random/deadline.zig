//! Admit a timer before entropy work and join every writer of borrowed buffers.
const std = @import("std");
const deadlines = @import("../deadline.zig");
const unbounded = @import("../secure_random.zig").fill;

pub const Error = std.Io.RandomSecureError || std.Io.Timeout.Error || std.Io.ConcurrentError;

fn checkpoint(io: std.Io, deadline: std.Io.Clock.Timestamp) Error!void {
    try io.checkCancel();
    _ = try deadlines.usableAwake(io, deadline);
}

fn complete(io: std.Io, deadline: std.Io.Clock.Timestamp, result: Error!void) Error!void {
    try checkpoint(io, deadline);
    return result;
}

pub fn fill(io: std.Io, buffer: []u8, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const until = deadline orelse return unbounded(io, buffer);
    try checkpoint(io, until);
    const Wake = union(enum) { filled: Error!void, timeout: std.Io.Cancelable!void };
    const Worker = struct {
        fn run(run_io: std.Io, run_buffer: []u8, run_deadline: std.Io.Clock.Timestamp) Error!void {
            try checkpoint(run_io, run_deadline);
            return complete(run_io, run_deadline, unbounded(run_io, run_buffer));
        }
    };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    // The entropy offload may briefly block cancellation. The caller's buffer
    // must stay alive until it finishes, including after the timer wins.
    defer select.cancelDiscard();
    select.concurrent(.timeout, deadlines.waitUntil, .{ io, until }) catch |err| {
        try checkpoint(io, until);
        return err;
    };
    select.concurrent(.filled, Worker.run, .{ io, buffer, until }) catch |err| {
        try checkpoint(io, until);
        return err;
    };
    return switch (try select.await()) {
        .filled => |result| complete(io, until, result),
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}

test {
    _ = @import("deadline_tests.zig");
}
