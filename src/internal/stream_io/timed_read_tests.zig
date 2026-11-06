//! A backend may report Timeout before the absolute timestamp is due.
const std = @import("std");
const builtin = @import("builtin");
const read = @import("timed_read.zig").readSomeWithDeadline;

const Outcome = enum { bytes, eof, io_error };
const Step = union(enum) {
    early_timeout,
    completed_timeout: Outcome,
    expired_timeout,
    canceled,
    executor_failure,
    complete: Outcome,
};

const Backend = struct {
    steps: []const Step,
    deadline_ns: i96 = 1_000_000,
    now_ns: i96 = 0,
    awaits: usize = 0,
    submissions: usize = 0,
    canceled_reads: usize = 0,
    rearmed: bool = false,
    cancel_completion: ?Outcome = null,
    operation: ?std.Io.Operation = null,
    batch_address: ?*std.Io.Batch = null,

    fn io(self: *Backend, table: *std.Io.VTable) std.Io {
        table.* = std.testing.io.vtable.*;
        table.now = now;
        table.batchAwaitConcurrent = awaitConcurrent;
        table.batchCancel = cancel;
        table.recancel = recancel;
        return .{ .userdata = self, .vtable = table };
    }

    fn selfFrom(context: ?*anyopaque) *Backend {
        return @ptrCast(@alignCast(context.?));
    }

    fn now(context: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        std.debug.assert(clock == .awake);
        return .{ .nanoseconds = selfFrom(context).now_ns };
    }

    fn awaitConcurrent(context: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self = selfFrom(context);
        std.debug.assert(timeout == .deadline and timeout.deadline.clock == .awake);
        std.debug.assert(timeout.deadline.raw.nanoseconds == self.deadline_ns);
        if (self.batch_address) |address| {
            std.debug.assert(address == batch);
            std.debug.assert(batch.submitted.head == .none);
        } else {
            self.batch_address = batch;
            const index = std.Io.Operation.OptionalIndex.fromIndex(0);
            std.debug.assert(batch.submitted.head == index);
            self.operation = batch.storage[0].submission.operation;
            self.submissions += 1;
            batch.storage[0] = .{ .pending = .{
                .node = .{ .prev = .none, .next = .none },
                .tag = std.meta.activeTag(self.operation.?),
                .userdata = @splat(0),
            } };
            batch.submitted = .empty;
            batch.pending = .{ .head = index, .tail = index };
        }
        std.debug.assert(self.awaits < self.steps.len);
        const step = self.steps[self.awaits];
        self.awaits += 1;
        switch (step) {
            .early_timeout => {
                self.now_ns = self.deadline_ns - 500;
                return error.Timeout;
            },
            .completed_timeout => |outcome| {
                self.finish(batch, outcome);
                return error.Timeout;
            },
            .expired_timeout => {
                self.now_ns = self.deadline_ns;
                return error.Timeout;
            },
            .canceled => return error.Canceled,
            .executor_failure => return error.ConcurrencyUnavailable,
            .complete => |outcome| self.finish(batch, outcome),
        }
    }

    fn finish(self: *Backend, batch: *std.Io.Batch, outcome: Outcome) void {
        const operation = self.operation.?;
        const buffer = if (builtin.os.tag == .windows)
            operation.net_receive.data_buffer
        else
            operation.file_read_streaming.data[0];
        const length: usize = if (outcome == .bytes) 3 else 0;
        if (length != 0) @memcpy(buffer[0..length], "abc");
        const result: std.Io.Operation.Result = if (builtin.os.tag == .windows) blk: {
            operation.net_receive.message_buffer[0].data = buffer[0..length];
            break :blk .{ .net_receive = if (outcome == .io_error) .{ error.Unexpected, 0 } else .{ null, 1 } };
        } else .{ .file_read_streaming = switch (outcome) {
            .bytes => length,
            .eof => error.EndOfStream,
            .io_error => error.Unexpected,
        } };
        batch.pending = .empty;
        batch.storage[0] = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
        const index = std.Io.Operation.OptionalIndex.fromIndex(0);
        batch.completed = .{ .head = index, .tail = index };
    }

    fn cancel(context: ?*anyopaque, batch: *std.Io.Batch) void {
        const self = selfFrom(context);
        if (batch.pending.head != .none) {
            self.canceled_reads += 1;
            if (self.cancel_completion) |outcome| {
                self.cancel_completion = null;
                self.finish(batch, outcome);
            } else {
                batch.pending = .empty;
                batch.storage[0] = .{ .unused = .{ .prev = .none, .next = .none } };
                const index = std.Io.Operation.OptionalIndex.fromIndex(0);
                batch.unused = .{ .head = index, .tail = index };
            }
        }
        batch.userdata = null;
    }

    fn recancel(context: ?*anyopaque) void {
        selfFrom(context).rearmed = true;
    }
};

fn socket() std.Io.net.Stream {
    return .{ .socket = .{ .handle = if (builtin.os.tag == .windows) @ptrFromInt(1) else 0, .address = .{ .ip4 = .loopback(0) } } };
}

fn deadline(backend: Backend) std.Io.Clock.Timestamp {
    return .{ .clock = .awake, .raw = .{ .nanoseconds = backend.deadline_ns } };
}

test "stream timed reader keeps one pending operation across early timeouts" {
    var backend = Backend{ .steps = &.{ .early_timeout, .early_timeout, .{ .complete = .bytes } } };
    var table: std.Io.VTable = undefined;
    const io = backend.io(&table);
    var buffer: [8]u8 = @splat(0xcc);
    const count = try read(io, socket(), &buffer, deadline(backend));
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("abc", buffer[0..count]);
    try std.testing.expectEqual(@as(u8, 0xcc), buffer[count]);
    try std.testing.expectEqual(@as(usize, 3), backend.awaits);
    try std.testing.expectEqual(@as(usize, 1), backend.submissions);
    try std.testing.expectEqual(@as(usize, 0), backend.canceled_reads);
}

test "stream timed reader consumes a completion accompanying early Timeout" {
    var backend = Backend{ .steps = &.{.{ .completed_timeout = .bytes }} };
    var table: std.Io.VTable = undefined;
    var buffer: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try read(backend.io(&table), socket(), &buffer, deadline(backend)));
    try std.testing.expectEqualStrings("abc", &buffer);
    try std.testing.expectEqual(@as(usize, 1), backend.awaits);
}

test "stream timed reader expires without renewing its original deadline" {
    var backend = Backend{ .steps = &.{ .early_timeout, .expired_timeout } };
    var table: std.Io.VTable = undefined;
    var buffer: [3]u8 = undefined;
    try std.testing.expectError(error.Timeout, read(backend.io(&table), socket(), &buffer, deadline(backend)));
    try std.testing.expectEqual(@as(usize, 2), backend.awaits);
    try std.testing.expectEqual(@as(usize, 1), backend.submissions);
    try std.testing.expectEqual(@as(usize, 1), backend.canceled_reads);
}

test "stream timed reader keeps bytes completing during timeout cancellation" {
    var backend = Backend{ .steps = &.{.expired_timeout}, .cancel_completion = .bytes };
    var table: std.Io.VTable = undefined;
    var buffer: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try read(backend.io(&table), socket(), &buffer, deadline(backend)));
    try std.testing.expectEqualStrings("abc", &buffer);
    try std.testing.expectEqual(@as(usize, 1), backend.canceled_reads);
}

test "stream timed reader rearms cancellation after consumed bytes" {
    var backend = Backend{ .steps = &.{.canceled}, .cancel_completion = .bytes };
    var table: std.Io.VTable = undefined;
    var buffer: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try read(backend.io(&table), socket(), &buffer, deadline(backend)));
    try std.testing.expectEqualStrings("abc", &buffer);
    try std.testing.expect(backend.rearmed);
}

test "stream timed reader joins interrupted operation without progress" {
    inline for (.{ Step.canceled, Step.executor_failure }) |step| {
        var backend = Backend{ .steps = &.{step} };
        var table: std.Io.VTable = undefined;
        var buffer: [3]u8 = undefined;
        const expected = if (step == .canceled) error.Canceled else error.ConcurrencyUnavailable;
        try std.testing.expectError(expected, read(backend.io(&table), socket(), &buffer, deadline(backend)));
        try std.testing.expectEqual(@as(usize, 1), backend.awaits);
        try std.testing.expectEqual(@as(usize, 1), backend.canceled_reads);
        try std.testing.expect(!backend.rearmed);
    }
}

test "stream timed reader preserves EOF and nested operation errors" {
    inline for (.{ Outcome.eof, Outcome.io_error }) |outcome| {
        var backend = Backend{ .steps = &.{.{ .complete = outcome }} };
        var table: std.Io.VTable = undefined;
        var buffer: [3]u8 = undefined;
        const result = read(backend.io(&table), socket(), &buffer, deadline(backend));
        if (outcome == .eof) try std.testing.expectEqual(@as(usize, 0), try result) else try std.testing.expectError(error.Unexpected, result);
        try std.testing.expectEqual(@as(usize, 1), backend.awaits);
    }
}

test "stream timed reader Threaded timeout preserves late socket bytes for reuse" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const peer = try listener.accept(io);
    var peer_open = true;
    defer if (peer_open) peer.close(io);
    var writer = peer.writer(io, &.{});
    try writer.interface.writeAll("ab");
    var buffer: [8]u8 = @splat(0xcc);
    const first = try read(io, client, &buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 2), first);
    try std.testing.expectEqualStrings("ab", buffer[0..first]);
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) });
    try std.testing.expectError(error.Timeout, read(io, client, &buffer, until));
    try std.testing.expect(until.durationFromNow(io).raw.nanoseconds <= 0);
    try writer.interface.writeAll("cd");
    try std.testing.expectError(error.Timeout, read(io, client, &buffer, until));
    const next = try read(io, client, &buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 2), next);
    try std.testing.expectEqualStrings("cd", buffer[0..next]);
    try std.testing.expectEqual(@as(u8, 0xcc), buffer[next]);
    peer.close(io);
    peer_open = false;
    try std.testing.expectEqual(@as(usize, 0), try read(io, client, &buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
}

test "stream timed reader rejects expired and foreign clock deadlines before submission" {
    var backend = Backend{ .steps = &.{}, .now_ns = 1_000_000 };
    var table: std.Io.VTable = undefined;
    const io = backend.io(&table);
    var buffer: [3]u8 = undefined;
    try std.testing.expectError(error.Timeout, read(io, socket(), &buffer, deadline(backend)));
    try std.testing.expectError(error.Timeout, read(io, socket(), &buffer, .{ .clock = .real, .raw = .{ .nanoseconds = 9_000_000 } }));
    try std.testing.expectEqual(@as(usize, 0), backend.awaits);
}
