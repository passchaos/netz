//! Deadline-bounded TCP writes charged only for their committed prefix.

const std = @import("std");
const ByteBucket = @import("../byte_bucket.zig").ByteBucket;
const io_helpers = @import("../io.zig");
pub const Error = io_helpers.WriteError || std.Io.Cancelable || error{Timeout};

pub fn write(
    bucket: *ByteBucket,
    io: std.Io,
    stream: std.Io.net.Stream,
    data: []const u8,
    committed: *usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    return writeUsing(bucket, io, stream, io_helpers.writeSome, data, committed, deadline);
}

pub fn writeUsing(
    bucket: *ByteBucket,
    io: std.Io,
    context: anytype,
    comptime send: anytype,
    data: []const u8,
    committed: *usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    committed.* = 0;
    while (committed.* < data.len) {
        const available = try bucket.waitAvailable(data.len - committed.*, io, deadline);
        const count = try send(io, context, data[committed.*..][0..@intCast(available)], deadline);
        if (count == 0) return error.SocketUnconnected;
        if (count > available) return error.Unexpected;
        const now: i64 = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
        const charged = bucket.tryConsume(count, now);
        std.debug.assert(charged);
        committed.* += count;
    }
}

test {
    _ = @import("stream_tests.zig");
}
