const std = @import("std");
const actor = @import("inbound_actor.zig");
const Error = std.Io.Cancelable || error{ Timeout, BrokenPipe };

const Script = struct {
    entered: std.atomic.Value(bool) = .init(false),
    released: std.atomic.Value(bool) = .init(false),
    sink: [32]u8 = undefined,
    used: usize = 0,

    fn write(io: std.Io, self: *Script, bytes: []const u8, deadline: std.Io.Clock.Timestamp) Error!usize {
        self.entered.store(true, .release);
        while (!self.released.load(.acquire)) {
            if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
            try std.Io.sleep(io, .fromMilliseconds(1), .awake);
        }
        const count = @min(bytes.len, 3);
        @memcpy(self.sink[self.used..][0..count], bytes[0..count]);
        self.used += count;
        return count;
    }
};
const Writer = actor.Writer(*Script, Error, Script.write);

fn completion(writer: *Writer) !Writer.Completion {
    const deadline = std.Io.Clock.Timestamp.fromNow(writer.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (deadline.durationFromNow(writer.io).raw.nanoseconds > 0) {
        if (writer.take()) |result| return result;
        try std.Io.sleep(writer.io, .fromMilliseconds(1), .awake);
    }
    return error.TestWriterTimeout;
}

test "proxy inbound actor lends one range and returns exact partial progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var script: Script = .{};
    var writer: Writer = undefined;
    try writer.init(io, &script, .{ .maximum_bytes = 16 });
    defer _ = writer.stop();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expect(try writer.submit("abcdef", deadline));
    try std.testing.expect(!try writer.submit("second", deadline));
    try std.testing.expect(writer.take() == null);
    script.released.store(true, .release);
    const first = try completion(&writer);
    try std.testing.expectEqual(@as(usize, 6), first.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 3), first.committed_bytes);
    try std.testing.expect(first.failure == null);
    try std.testing.expect(try writer.submit("def", deadline));
    const second = try completion(&writer);
    try std.testing.expectEqual(@as(usize, 3), second.committed_bytes);
    try std.testing.expectEqualStrings("abcdef", script.sink[0..script.used]);
}

test "proxy inbound actor stop recovers a queued or blocked loan" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var script: Script = .{};
    var writer: Writer = undefined;
    try writer.init(io, &script, .{ .maximum_bytes = 16 });
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expect(try writer.submit("abcdef", deadline));
    const result = writer.stop() orelse return error.TestExpectedCompletion;
    try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), result.committed_bytes);
    try std.testing.expect(result.failure != null);
    try std.testing.expectEqual(error.Canceled, result.failure.?);
    try std.testing.expect(writer.stop() == null);
    try std.testing.expect(!try writer.submit("new", deadline));
}
