//! Reader-source waits retain borrowed storage until cancellation has joined.
const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

pub const Error = error{RequestBodyReadFailed} || std.Io.Timeout.Error || std.Io.Cancelable || std.Io.ConcurrentError;

fn readSome(reader: *std.Io.Reader, buffer: []u8) Error!usize {
    if (buffer.len == 0) return 0;
    // Return buffered progress before invoking the source again. Filling a
    // whole contribution could consume bytes, block on a later read, then
    // discard that progress when the later read is canceled.
    var slices = [_][]u8{buffer};
    while (true) {
        const count = @min(buffer.len, reader.buffered().len);
        if (count != 0) {
            @memcpy(buffer[0..count], reader.buffered()[0..count]);
            reader.toss(count);
            return count;
        }
        const read = reader.readVec(&slices) catch |err| switch (err) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.RequestBodyReadFailed,
        };
        if (read != 0) return read;
    }
}

pub fn readBefore(io: std.Io, reader: *std.Io.Reader, buffer: []u8, deadline: ?std.Io.Clock.Timestamp) Error!usize {
    const until = deadline orelse return readSome(reader, buffer);
    _ = try deadline_policy.usableAwake(io, until);
    if (buffer.len == 0 or reader.buffered().len != 0) return readSome(reader, buffer);
    const Task = struct {
        reader: *std.Io.Reader,
        buffer: []u8,
        result: ?Error!usize = null,
        fn read(self: *@This()) void {
            self.result = readSome(self.reader, self.buffer);
        }
        fn wait(task_io: std.Io, timestamp: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
            while (timestamp.durationFromNow(task_io).raw.nanoseconds > 0) try timestamp.wait(task_io);
        }
    };
    const Wake = union(enum) { read: void, timer: std.Io.Cancelable!void };
    var task = Task{ .reader = reader, .buffer = buffer };
    var results: [2]Wake = undefined;
    var selection: std.Io.Select(Wake) = .init(io, &results);
    defer selection.cancelDiscard();
    try selection.concurrent(.read, Task.read, .{&task});
    selection.concurrent(.timer, Task.wait, .{ io, until }) catch |err| {
        selection.cancelDiscard();
        if (task.result) |result| if (result) |count| return count else |_| {};
        return err;
    };
    const wake = selection.await() catch |err| {
        selection.cancelDiscard();
        if (task.result) |result| if (result) |count| {
            if (err == error.Canceled) std.Io.recancel(io);
            return count;
        } else |_| {};
        return err;
    };
    switch (wake) {
        .read => return task.result.?,
        .timer => |result| {
            try result;
            selection.cancelDiscard();
            // A Reader may wrap a canceled underlying operation as ReadFailed.
            // A timer/parent interruption owns that outcome; natural read
            // failures selected above remain RequestBodyReadFailed.
            if (task.result) |read| if (read) |count| return count else |_| {};
            return error.Timeout;
        },
    }
}

test {
    _ = @import("reader_io_tests.zig");
}
