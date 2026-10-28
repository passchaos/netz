//! Deadline-bound borrowed socket writes with joined cancellation.
const std = @import("std");
const net = std.Io.net;
const native = @import("../../runtime/timed_socket.zig");

pub const TimedWriteError = net.Stream.Writer.Error || std.Io.Timeout.Error || std.Io.ConcurrentError;

test {
    _ = @import("timed_write_tests.zig");
}

/// A natural completion racing timeout retains its known committed prefix.
pub fn writeSomeWithDeadline(io: std.Io, stream: net.Stream, bytes: []const u8, deadline: std.Io.Clock.Timestamp) TimedWriteError!usize {
    if (bytes.len == 0) return 0;
    if (native.tryWrite(io, stream, bytes, deadline)) |result| return result;
    return writeSomeUntil(io, stream, bytes, &.{""}, deadline);
}

fn writeSomePartsWithDeadline(io: std.Io, stream: net.Stream, header: []const u8, data: []const []const u8, deadline: std.Io.Clock.Timestamp) TimedWriteError!usize {
    if (data.len == 1) return writeSomeWithDeadline(io, stream, header, deadline);
    if (native.tryWriteParts(io, stream, header, data, deadline)) |result| return result;
    return writeSomeUntil(io, stream, header, data, deadline);
}

fn writeSomeUntil(
    io: std.Io,
    stream: net.Stream,
    header: []const u8,
    data: []const []const u8,
    deadline: std.Io.Clock.Timestamp,
) TimedWriteError!usize {
    _ = try @import("../deadline.zig").usableAwake(io, deadline);
    const WriteResult = TimedWriteError!usize;
    const Task = struct {
        io: std.Io,
        stream: net.Stream,
        header: []const u8,
        data: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
        result: ?WriteResult = null,

        fn write(self: *@This()) void {
            _ = @import("../deadline.zig").usableAwake(self.io, self.deadline) catch |err| {
                self.result = err;
                return;
            };
            const count = self.io.vtable.netWrite(
                self.io.userdata,
                self.stream.socket.handle,
                self.header,
                self.data,
                0,
            ) catch |err| {
                self.result = err;
                return;
            };
            self.result = if (count == 0) error.SocketUnconnected else count;
        }

        fn waitUntil(task_io: std.Io, task_deadline: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
            try task_deadline.wait(task_io);
        }
    };
    const Wake = union(enum) { write: void, timeout: std.Io.Cancelable!void };
    var task = Task{ .io = io, .stream = stream, .header = header, .data = data, .deadline = deadline };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.write, Task.write, .{&task});
    select.concurrent(.timeout, Task.waitUntil, .{ io, deadline }) catch |err| {
        select.cancelDiscard();
        if (task.result) |result| {
            if (result) |count| return count else |_| {}
        }
        return err;
    };
    const wake = select.await() catch |err| {
        select.cancelDiscard();
        if (task.result) |result| {
            if (result) |count| return count else |_| {}
        }
        return err;
    };
    switch (wake) {
        .write => return task.result.?,
        .timeout => |result| {
            try result;
            select.cancelDiscard();
            if (task.result) |written| {
                if (written) |count| return count else |err| {
                    if (err != error.Canceled) return err;
                }
            }
            return error.Timeout;
        },
    }
}

/// Write one borrowed slice under an absolute deadline while preserving the
/// exact committed prefix on every return path.
pub fn writeAllTrackedWithDeadline(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
    committed: *usize,
    deadline: std.Io.Clock.Timestamp,
) TimedWriteError!void {
    committed.* = 0;
    while (committed.* < bytes.len) {
        committed.* += try writeSomeWithDeadline(
            io,
            stream,
            bytes[committed.*..],
            deadline,
        );
    }
}

/// Write borrowed slices under one absolute deadline. A short write resumes
/// at the exact slice offset; timeout/error progress counts their total prefix.
/// Stack descriptors and payloads stay borrowed until cancellation has joined.
pub fn writeAllSlicesTrackedWithDeadline(io: std.Io, stream: net.Stream, parts: []const []const u8, committed: *usize, deadline: std.Io.Clock.Timestamp) TimedWriteError!void {
    committed.* = 0;
    var part_index: usize = 0;
    var part_offset: usize = 0;
    while (true) {
        while (part_index < parts.len and part_offset == parts[part_index].len) {
            part_index += 1;
            part_offset = 0;
        }
        if (part_index == parts.len) return;

        // std.Io reserves the last data entry for its splat pattern. Include
        // an empty terminator so the final real slice reaches the socket.
        var data: [16][]const u8 = undefined;
        var data_len: usize = 0;
        var next_index = part_index + 1;
        while (next_index < parts.len and data_len + 1 < data.len) : (next_index += 1) {
            if (parts[next_index].len == 0) continue;
            data[data_len] = parts[next_index];
            data_len += 1;
        }
        data[data_len] = "";
        data_len += 1;
        var remaining = try writeSomePartsWithDeadline(io, stream, parts[part_index][part_offset..], data[0..data_len], deadline);
        committed.* += remaining;
        while (remaining != 0) {
            const available = parts[part_index].len - part_offset;
            if (remaining < available) {
                part_offset += remaining;
                break;
            }
            remaining -= available;
            part_index += 1;
            part_offset = 0;
            while (part_index < parts.len and parts[part_index].len == 0) part_index += 1;
            if (part_index == parts.len) {
                std.debug.assert(remaining == 0);
                return;
            }
        }
    }
}
