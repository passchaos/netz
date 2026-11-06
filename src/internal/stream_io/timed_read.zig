//! One retained stream read under the caller's absolute deadline.
const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;

pub const TimedReadError = net.Stream.Reader.Error ||
    std.Io.Operation.FileReadStreaming.UnendingError ||
    std.Io.Operation.NetReceive.Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

test {
    _ = @import("timed_read_tests.zig");
}

/// Backend timeout notifications may be early. Keep the original batch and
/// timestamp until completion or actual expiry, joining cancellation before
/// caller-owned descriptors and receive buffers leave scope.
pub fn readSomeWithDeadline(io: std.Io, stream: net.Stream, buffer: []u8, deadline: std.Io.Clock.Timestamp) TimedReadError!usize {
    if (buffer.len == 0) return 0;
    _ = try @import("../deadline.zig").usableAwake(io, deadline);
    var incoming: net.IncomingMessage = .init;
    var bufs = [_][]u8{buffer};
    const operation: std.Io.Operation = if (builtin.os.tag == .windows)
        .{ .net_receive = .{
            .socket_handle = stream.socket.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = buffer,
            .flags = .{},
        } }
    else
        .{ .file_read_streaming = .{
            .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } },
            .data = &bufs,
        } };
    var storage: [1]std.Io.Operation.Storage = undefined;
    var batch: std.Io.Batch = .init(&storage);
    defer batch.cancel(io);
    batch.addAt(0, operation);
    while (true) {
        batch.awaitConcurrent(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and deadline.durationFromNow(io).raw.nanoseconds > 0) {
                if (batch.next()) |completion| return result(completion.result, &incoming);
                continue;
            }
            batch.cancel(io);
            if (batch.next()) |completion| {
                const count = try result(completion.result, &incoming);
                // Returning bytes already consumed by the socket must retain
                // cancellation for the caller's next cancellation point.
                if (err == error.Canceled) std.Io.recancel(io);
                return count;
            }
            return err;
        };
        if (batch.next()) |completion| return result(completion.result, &incoming);
    }
}

fn result(value: std.Io.Operation.Result, incoming: *const net.IncomingMessage) TimedReadError!usize {
    if (builtin.os.tag == .windows) {
        const maybe_err, const count = value.net_receive;
        if (maybe_err) |err| return err;
        std.debug.assert(count == 1);
        return incoming.data.len;
    }
    return value.file_read_streaming catch |err| switch (err) {
        error.EndOfStream => 0,
        else => return @errorCast(err),
    };
}
