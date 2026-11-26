//! Socket reads under an absolute deadline, with joined cancellation.
const std = @import("std");
const net = std.Io.net;
const native = @import("../../runtime/timed_socket.zig");
const ordinary_read = @import("read.zig");

pub const TimedReadError = net.Stream.Reader.Error ||
    std.Io.Operation.FileReadStreaming.UnendingError ||
    std.Io.Operation.NetReceive.Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

test {
    _ = @import("timed_read_tests.zig");
    _ = @import("windows_read_tests.zig");
}

/// Keep socket and file registrations separate. Native zio reads share the
/// socket owner with ordinary netRead; other backends and wrapped vtables use
/// their netRead operation, joined before caller-owned buffers leave scope.
pub fn readSomeWithDeadline(io: std.Io, stream: net.Stream, buffer: []u8, deadline: std.Io.Clock.Timestamp) TimedReadError!usize {
    if (buffer.len == 0) return 0;
    if (native.tryRead(io, stream, buffer, deadline)) |value| return value;
    _ = try @import("../deadline.zig").usableAwake(io, deadline);
    try io.checkCancel();
    const Task = struct {
        io: std.Io,
        stream: net.Stream,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
        result: ?TimedReadError!usize = null,

        fn read(self: *@This()) void {
            _ = @import("../deadline.zig").usableAwake(self.io, self.deadline) catch |err| {
                self.result = err;
                return;
            };
            self.result = ordinary_read.readSome(self.io, self.stream, self.buffer);
        }

        const waitUntil = @import("../deadline.zig").waitUntil;
    };
    const Wake = union(enum) { read: void, timeout: std.Io.Cancelable!void };
    var task = Task{ .io = io, .stream = stream, .buffer = buffer, .deadline = deadline };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.read, Task.read, .{&task});
    select.concurrent(.timeout, Task.waitUntil, .{ io, deadline }) catch |err| {
        select.cancelDiscard();
        if (task.result) |value| if (value) |count| return count else |read_err| {
            if (read_err != error.Canceled) return read_err;
        };
        return err;
    };
    const wake = select.await() catch |err| {
        select.cancelDiscard();
        if (task.result) |value| if (value) |count| {
            // Bytes (including EOF) already accepted cannot be discarded.
            // Preserve cancellation for the next operation instead.
            if (err == error.Canceled) std.Io.recancel(io);
            return count;
        } else |read_err| {
            if (read_err != error.Canceled) return read_err;
        };
        return err;
    };
    switch (wake) {
        .read => return task.result.?,
        .timeout => |value| {
            try value;
            select.cancelDiscard();
            if (task.result) |result| {
                if (result) |count| return count else |err| {
                    if (err != error.Canceled) return err;
                }
            }
            return error.Timeout;
        },
    }
}
