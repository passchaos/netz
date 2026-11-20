//! Cooperative Reader source waits classify errors and join borrowed storage.
const std = @import("std");
const source_io = @import("reader_io.zig");

const Gate = struct {
    reader: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    io: std.Io,
    started: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    canceled: bool = false,
    finished: bool = false,
    late_success: bool = false,
    fail: bool = false,
    offset: usize = 0,
    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Gate = @fieldParentPtr("reader", reader);
        if (self.offset == 3) return error.EndOfStream;
        self.started.set(self.io);
        defer self.finished = true;
        if (self.fail) return error.ReadFailed;
        self.release.wait(self.io) catch {
            self.canceled = true;
            if (!self.late_success) return error.ReadFailed;
        };
        const count = try writer.write("abc"[self.offset..][0..limit.minInt(3 - self.offset)]);
        self.offset += count;
        return count;
    }
};

fn deadline(io: std.Io, milliseconds: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
}

test "unified HTTP Reader deadlines expire before source I/O and retain source error classification" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var gate = Gate{ .io = io, .fail = true };
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.Timeout, source_io.readBefore(io, &gate.reader, &buffer, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expect(!gate.finished);
    try std.testing.expectError(error.RequestBodyReadFailed, source_io.readBefore(io, &gate.reader, &buffer, deadline(io, 1000)));
    try std.testing.expect(gate.finished);
}

test "unified HTTP Reader deadlines join cancellation before releasing source storage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var gate = Gate{ .io = io };
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.Timeout, source_io.readBefore(io, &gate.reader, &buffer, deadline(io, 30)));
    try std.testing.expect(gate.canceled);
    try std.testing.expect(gate.finished);
}

test "unified HTTP Reader deadlines return buffered progress before a later source wait" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var buffered = [_]u8{ 'a', 'b', 'c' };
    var gate = Gate{ .io = io };
    gate.reader.buffer = &buffered;
    gate.reader.end = buffered.len;
    var output: [8]u8 = undefined;
    const count = try source_io.readBefore(io, &gate.reader, &output, deadline(io, 1000));
    try std.testing.expectEqualStrings("abc", output[0..count]);
    try std.testing.expect(!gate.finished);
    try std.testing.expectError(error.Timeout, source_io.readBefore(io, &gate.reader, &output, deadline(io, 30)));
    try std.testing.expect(gate.canceled);
}

test "unified HTTP Reader deadlines retain late successful reads and rearm parent cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var gate = Gate{ .io = io, .late_success = true };
    const Caller = struct {
        gate: *Gate,
        buffer: [8]u8 = undefined,
        count: usize = 0,
        never: std.Io.Event = .unset,
        fn run(self: *@This()) !void {
            self.count = try source_io.readBefore(self.gate.io, &self.gate.reader, &self.buffer, deadline(self.gate.io, 5000));
            try self.never.wait(self.gate.io);
        }
    };
    var caller = Caller{ .gate = &gate };
    var reading = try io.concurrent(Caller.run, .{&caller});
    defer _ = reading.cancel(io) catch {};
    try gate.started.wait(io);
    try std.testing.expectError(error.Canceled, reading.cancel(io));
    try std.testing.expect(gate.finished);
    try std.testing.expectEqualStrings("abc", caller.buffer[0..caller.count]);
}
