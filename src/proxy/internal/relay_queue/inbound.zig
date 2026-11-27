//! One immutable target-write loan and separately owned incoming bytes.
const std = @import("std");
const io_helpers = @import("../io.zig");
const actor = @import("inbound_actor.zig");
const net = std.Io.net;

pub const Input = struct {
    const Writer = actor.Writer(net.Stream, io_helpers.WriteError, writeSome);
    pub const Completion = Writer.Completion;
    pub const Options = struct {
        maximum_bytes: usize,
        notify_context: ?*anyopaque = null,
        notify: ?*const fn (?*anyopaque) void = null,
    };

    allocator: std.mem.Allocator = undefined,
    io: std.Io = undefined,
    maximum_bytes: usize = 0,
    pending: std.ArrayList(u8) = .empty,
    loan: std.ArrayList(u8) = .empty,
    loan_start: usize = 0,
    reserved_bytes: usize = 0,
    in_flight: bool = false,
    terminal: bool = false,
    writer: Writer = undefined,
    started: bool = false,

    /// Keep this value at its initialized address until deinit completes.
    pub fn init(self: *Input, allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: Options) !void {
        self.* = .{ .allocator = allocator, .io = io, .maximum_bytes = options.maximum_bytes };
        try self.writer.init(io, stream, .{
            .maximum_bytes = options.maximum_bytes,
            .notify_context = options.notify_context,
            .notify = options.notify,
        });
        self.started = true;
    }

    pub fn pendingBytes(self: *const Input) usize {
        return self.pending.items.len + (self.loan.items.len - self.loan_start);
    }

    /// Neither pending growth nor append can move or modify an active loan.
    /// Each retained backing buffer is bounded by the logical input limit.
    pub fn append(self: *Input, bytes: []const u8) !void {
        if (self.terminal or !self.started) return error.RelayClosed;
        const queued = self.pendingBytes();
        if (queued > self.maximum_bytes or bytes.len > self.maximum_bytes - queued) return error.RelayBufferFull;
        const required = self.pending.items.len + bytes.len;
        if (self.pending.capacity < required) {
            const growth = self.pending.capacity +| self.pending.capacity / 2 +| 8;
            const capacity = @min(self.maximum_bytes, @max(required, growth));
            try self.pending.ensureTotalCapacityPrecise(self.allocator, capacity);
        }
        self.pending.appendSliceAssumeCapacity(bytes);
    }

    /// A rate owner reserves at most this prefix before calling submit.
    pub fn readyBytes(self: *const Input) usize {
        if (!self.started or self.terminal or self.in_flight) return 0;
        const remaining = self.loan.items.len - self.loan_start;
        return if (remaining != 0) remaining else self.pending.items.len;
    }

    /// Return the exact accepted reservation, or zero without a transport loan.
    /// The existing ten-millisecond target-write budget starts at submission.
    pub fn submit(self: *Input, maximum: usize) !usize {
        const count = @min(maximum, self.readyBytes());
        if (count == 0) return 0;
        self.prepareLoan();
        const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
        if (!try self.writer.submit(self.loan.items[self.loan_start..][0..count], deadline)) {
            if (self.writer.closed.load(.acquire)) self.terminal = true;
            return 0;
        }
        self.reserved_bytes = count;
        self.in_flight = true;
        return count;
    }

    /// Synchronous compatibility surface; shared pumps use submit/take.
    pub fn writeNow(self: *Input, maximum: usize) io_helpers.WriteError!usize {
        const count = @min(maximum, self.readyBytes());
        if (count == 0) return 0;
        self.prepareLoan();
        const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
        const written = try writeSome(self.io, self.writer.context, self.loan.items[self.loan_start..][0..count], deadline);
        self.consume(written);
        return written;
    }

    pub fn take(self: *Input) ?Completion {
        if (!self.started) return null;
        const result = self.writer.take() orelse return null;
        self.apply(result);
        return result;
    }

    /// Join the writer before its stream or either byte buffer can be released.
    /// A rate owner must collect this final reservation before retiring a relay.
    pub fn stop(self: *Input) ?Completion {
        if (!self.started) return null;
        const result = self.writer.stop();
        self.started = false;
        self.terminal = true;
        if (result) |completion| self.apply(completion);
        return result;
    }

    pub fn deinit(self: *Input) void {
        _ = self.stop();
        self.pending.deinit(self.allocator);
        self.loan.deinit(self.allocator);
        self.* = .{};
    }

    fn apply(self: *Input, result: Completion) void {
        std.debug.assert(self.in_flight);
        std.debug.assert(result.reserved_bytes == self.reserved_bytes);
        std.debug.assert(result.committed_bytes <= result.reserved_bytes);
        self.consume(result.committed_bytes);
        self.in_flight = false;
        self.reserved_bytes = 0;
        if (result.failure) |err| if (err != error.Timeout) {
            self.terminal = true;
        };
    }

    fn prepareLoan(self: *Input) void {
        if (self.loan_start != self.loan.items.len) return;
        self.loan.clearRetainingCapacity();
        self.loan_start = 0;
        std.mem.swap(std.ArrayList(u8), &self.loan, &self.pending);
    }

    fn consume(self: *Input, count: usize) void {
        std.debug.assert(count <= self.loan.items.len - self.loan_start);
        self.loan_start += count;
        if (self.loan_start == self.loan.items.len) {
            self.loan.clearRetainingCapacity();
            self.loan_start = 0;
        }
    }

    fn writeSome(io: std.Io, stream: net.Stream, bytes: []const u8, deadline: std.Io.Clock.Timestamp) io_helpers.WriteError!usize {
        return io_helpers.writeSome(io, stream, bytes, deadline);
    }
};

test {
    _ = @import("inbound_tests.zig");
}
