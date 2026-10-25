//! Collect an EOF-delimited body within its byte and absolute-time budgets.

const std = @import("std");
const buffered_input = @import("buffered_input.zig");

pub fn Reader(comptime Context: type) type {
    return struct {
        const Input = buffered_input.Reader(Context);

        /// Include bytes already coalesced after the head in the same budget
        /// as later reads. One lookahead byte detects overflow at the exact
        /// limit without growing retained storage or renewing the deadline.
        /// Below the limit, storage is reserved before reading so a local
        /// allocation failure cannot discard already-consumed body bytes.
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
                if (available == 0) {
                    // This byte can only establish EOF or exceed the limit.
                    // It never belongs in retained body storage, so probing
                    // needs neither allocation nor another byte of capacity.
                    if (try Context.readUntil(transport, scratch[0..1], deadline) != 0) return error.BodyTooLarge;
                    return;
                }
                const count = try Input.append(allocator, transport, bytes, @min(scratch.len, available), deadline);
                if (count == 0) return;
                body_len = std.math.add(usize, body_len, count) catch return error.BodyTooLarge;
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

test "HTTP/1 EOF body collector allocation failure leaves unretained input unread" {
    const allocator = std.testing.allocator;
    var buffer = std.ArrayList(u8).fromOwnedSlice(try allocator.dupe(u8, "headprefix"));
    defer buffer.deinit(allocator);
    var source = TestSource{ .bytes = "suffix" };
    var scratch: [4]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Reader(TestSource).collect(failing.allocator(), &source, &buffer, 4, 32, &scratch, null));
    try std.testing.expectEqual(@as(usize, 0), source.offset);
    try std.testing.expectEqualStrings("headprefix", buffer.items);
    var repeated = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Reader(TestSource).collect(repeated.allocator(), &source, &buffer, 4, 32, &scratch, null));
    try std.testing.expectEqual(@as(usize, 0), source.offset);
    try Reader(TestSource).collect(allocator, &source, &buffer, 4, 32, &scratch, null);
    try std.testing.expectEqualStrings("headprefixsuffix", buffer.items);
}

test "HTTP/1 EOF body collector interruptions retain progress and the original deadline" {
    const Source = struct {
        pub const TransportType = *@This();
        pub const ErrorType = std.mem.Allocator.Error || error{ BodyTooLarge, Timeout, Canceled, ConcurrencyUnavailable };
        bytes: []const u8,
        offset: usize = 0,
        fail_at: usize = 6,
        fault: ?ErrorType,
        deadline: std.Io.Clock.Timestamp,
        calls: usize = 0,

        pub fn readUntil(self: *@This(), out: []u8, deadline: ?std.Io.Clock.Timestamp) ErrorType!usize {
            std.debug.assert(deadline.?.clock == self.deadline.clock and deadline.?.raw.nanoseconds == self.deadline.raw.nanoseconds);
            self.calls += 1;
            if (self.offset == self.fail_at) {
                if (self.fault) |err| {
                    self.fault = null;
                    return err;
                }
            }
            const end = if (self.offset < self.fail_at) self.fail_at else self.bytes.len;
            const count = @min(out.len, end - self.offset);
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const allocator = std.testing.allocator;
    for ([_]Source.ErrorType{ error.Timeout, error.Canceled, error.ConcurrencyUnavailable }) |fault| {
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(allocator);
        try input.appendSlice(allocator, "head");
        const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(999) };
        var source = Source{ .bytes = "first/second", .fault = fault, .deadline = deadline };
        var scratch: [3]u8 = undefined;
        try std.testing.expectError(fault, Reader(Source).collect(allocator, &source, &input, 4, source.bytes.len, &scratch, deadline));
        try std.testing.expectEqual(@as(usize, 6), source.offset);
        try std.testing.expectEqualStrings("headfirst/", input.items);
        try Reader(Source).collect(allocator, &source, &input, 4, source.bytes.len, &scratch, deadline);
        try std.testing.expectEqualStrings("headfirst/second", input.items);
        try std.testing.expectEqual(@as(usize, 12), source.offset);
    }
}

test "HTTP/1 EOF body collector rejects overflow with one unallocated lookahead byte" {
    var storage: [6]u8 = undefined;
    var buffer = std.ArrayList(u8).initBuffer(&storage);
    buffer.appendSliceAssumeCapacity("head");
    var source = TestSource{ .bytes = "oversized" };
    var scratch: [16]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.BodyTooLarge, Reader(TestSource).collect(failing.allocator(), &source, &buffer, 4, 2, &scratch, null));
    try std.testing.expectEqualStrings("headov", buffer.items);
    try std.testing.expect(!failing.has_induced_failure);
    // The rejected input consumes only the quota plus one lookahead byte.
    try std.testing.expectEqual(@as(usize, 3), source.offset);
}

test "HTTP/1 EOF body collector handles exact and maximum word-sized budgets" {
    for ([_]usize{ 2, std.math.maxInt(usize) }) |maximum| {
        var storage: [7]u8 = undefined;
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

test "HTTP/1 EOF body collector zero budget probes EOF without allocation" {
    for ([_][]const u8{ "", "x" }) |body| {
        var storage: [4]u8 = undefined;
        var buffer = std.ArrayList(u8).initBuffer(&storage);
        buffer.appendSliceAssumeCapacity("head");
        var source = TestSource{ .bytes = body };
        var scratch: [1]u8 = undefined;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        const result = Reader(TestSource).collect(failing.allocator(), &source, &buffer, 4, 0, &scratch, null);
        if (body.len == 0) try result else try std.testing.expectError(error.BodyTooLarge, result);
        try std.testing.expectEqualStrings("head", buffer.items);
        try std.testing.expectEqual(body.len, source.offset);
        try std.testing.expect(!failing.has_induced_failure);
    }
}
