const std = @import("std");
const writer = @import("body_write.zig");

const Sender = struct {
    seen: [32]u8 = undefined,
    used: usize = 0,
    calls: usize = 0,
    fins: usize = 0,
    first_prefix: usize,
    first_error: ?anyerror,
    retryable: bool = true,
    deadline: ?std.Io.Clock.Timestamp = null,

    fn send(self: *Sender, data: []const u8, fin: bool, progress: *writer.Progress, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
        self.calls += 1;
        self.deadline = deadline;
        const first = self.calls == 1;
        const count = if (first) @min(self.first_prefix, data.len) else data.len;
        @memcpy(self.seen[self.used..][0..count], data[0..count]);
        self.used += count;
        progress.committed_bytes = count;
        progress.fin_committed = fin and count == data.len;
        progress.retryable = !first or self.retryable;
        if (progress.fin_committed) self.fins += 1;
        if (first) if (self.first_error) |err| return err;
    }
};

test "HTTP/3 concurrent DATA retry sends only the uncommitted suffix under the original budget" {
    for ([_]anyerror{ error.FlowControlBlocked, error.CongestionLimited, error.PacingLimited, error.Timeout }) |failure| {
        var sender: Sender = .{ .first_prefix = 2, .first_error = failure };
        var state: writer.State = .{};
        const deadline: std.Io.Clock.Timestamp = .{ .raw = .{ .nanoseconds = 42 }, .clock = .awake };
        try std.testing.expectError(failure, state.write("abcdef", true, deadline, &sender, Sender.send));
        try std.testing.expectEqual(@as(usize, 2), state.progress.committed_bytes);
        try std.testing.expect(!state.progress.fin_committed and state.progress.retryable);
        try state.write("abcdef", true, deadline, &sender, Sender.send);
        try std.testing.expectEqualStrings("abcdef", sender.seen[0..sender.used]);
        try std.testing.expectEqual(@as(usize, 2), sender.calls);
        try std.testing.expectEqual(@as(usize, 1), sender.fins);
        try std.testing.expectEqualDeep(deadline, sender.deadline.?);
        try std.testing.expect(state.progress.fin_committed and state.completed);
    }
}

test "HTTP/3 concurrent DATA completed FIN survives a late error without duplicate output" {
    var sender: Sender = .{ .first_prefix = 6, .first_error = error.Canceled };
    var state: writer.State = .{};
    try std.testing.expectError(error.Canceled, state.write("abcdef", true, null, &sender, Sender.send));
    try std.testing.expect(state.completed and state.progress.fin_committed);
    try state.write("abcdef", true, null, &sender, Sender.send);
    try std.testing.expectEqualStrings("abcdef", sender.seen[0..sender.used]);
    try std.testing.expectEqual(@as(usize, 1), sender.calls);
    try std.testing.expectEqual(@as(usize, 1), sender.fins);
}

test "HTTP/3 concurrent DATA unknown-prefix failure forbids a suffix retry" {
    var sender: Sender = .{ .first_prefix = 0, .first_error = error.NetworkDown, .retryable = false };
    var state: writer.State = .{};
    try std.testing.expectError(error.NetworkDown, state.write("abcdef", true, null, &sender, Sender.send));
    try std.testing.expect(!state.progress.retryable);
    try std.testing.expectError(error.ConnectionUnusable, state.write("abcdef", true, null, &sender, Sender.send));
    try std.testing.expectEqual(@as(usize, 1), sender.calls);
}

test "HTTP/3 concurrent DATA empty FIN retries once after zero-byte backpressure" {
    const EmptySender = struct {
        calls: usize = 0,
        fn send(self: *@This(), data: []const u8, fin: bool, progress: *writer.Progress, _: ?std.Io.Clock.Timestamp) !void {
            if (data.len != 0 or !fin) return error.Unexpected;
            self.calls += 1;
            if (self.calls == 1) return error.PacingLimited;
            progress.fin_committed = true;
        }
    };
    var sender: EmptySender = .{};
    var state: writer.State = .{};
    try std.testing.expectError(error.PacingLimited, state.write("", true, null, &sender, EmptySender.send));
    try state.write("", true, null, &sender, EmptySender.send);
    try state.write("", true, null, &sender, EmptySender.send);
    try std.testing.expectEqual(@as(usize, 2), sender.calls);
    try std.testing.expect(state.progress.fin_committed);
}
