//! Collect an EOF-delimited body within its byte and absolute-time budgets.

const std = @import("std");

pub fn Reader(comptime Context: type) type {
    return struct {
        /// Include bytes already coalesced after the head in the same budget
        /// as later reads. One lookahead byte detects overflow at the exact
        /// limit without growing retained storage or renewing the deadline.
        pub fn collect(
            allocator: std.mem.Allocator,
            transport: Context.TransportType,
            bytes: *std.ArrayList(u8),
            body_start: usize,
            max_body_bytes: usize,
            scratch: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Context.ErrorType!void {
            std.debug.assert(body_start <= bytes.items.len and scratch.len != 0);
            var body_len = bytes.items.len - body_start;
            if (body_len > max_body_bytes) return error.BodyTooLarge;
            while (true) {
                const available = max_body_bytes - body_len;
                const output = scratch[0..@min(scratch.len, available +| 1)];
                const count = try Context.readUntil(transport, output, deadline);
                if (count == 0) return;
                body_len = std.math.add(usize, body_len, count) catch return error.BodyTooLarge;
                if (body_len > max_body_bytes) return error.BodyTooLarge;
                try bytes.appendSlice(allocator, output[0..count]);
            }
        }
    };
}

const TestSource = struct {
    bytes: []const u8,
    offset: usize = 0,
    calls: usize = 0,

    pub const TransportType = *TestSource;
    pub const ErrorType = std.mem.Allocator.Error || error{BodyTooLarge};

    pub fn readUntil(self: *TestSource, output: []u8, _: ?std.Io.Clock.Timestamp) ErrorType!usize {
        self.calls += 1;
        const count = @min(output.len, self.bytes.len - self.offset);
        @memcpy(output[0..count], self.bytes[self.offset..][0..count]);
        self.offset += count;
        return count;
    }
};

test "HTTP/1 EOF body collector rejects overflow before retention or allocation" {
    var storage: [4]u8 = undefined;
    var buffer = std.ArrayList(u8).initBuffer(&storage);
    buffer.appendSliceAssumeCapacity("head");
    var source = TestSource{ .bytes = "oversized" };
    var scratch: [16]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.BodyTooLarge, Reader(TestSource).collect(failing.allocator(), &source, &buffer, 4, 2, &scratch, null));
    try std.testing.expectEqualStrings("head", buffer.items);
    try std.testing.expect(!failing.has_induced_failure);
    // The rejected input consumes only the quota plus one lookahead byte.
    try std.testing.expectEqual(@as(usize, 3), source.offset);
}

test "HTTP/1 EOF body collector handles exact and maximum word-sized budgets" {
    for ([_]usize{ 2, std.math.maxInt(usize) }) |maximum| {
        var storage: [6]u8 = undefined;
        var buffer = std.ArrayList(u8).initBuffer(&storage);
        buffer.appendSliceAssumeCapacity("head");
        var source = TestSource{ .bytes = "ok" };
        var scratch: [16]u8 = undefined;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try Reader(TestSource).collect(failing.allocator(), &source, &buffer, 4, maximum, &scratch, null);
        try std.testing.expectEqualStrings("headok", buffer.items);
        try std.testing.expect(!failing.has_induced_failure);
    }
}
