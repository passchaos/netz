//! Native loans, deadlines, partial progress and joined buffer retirement.
const std = @import("std");
const Input = @import("inbound.zig").Input;
const Relay = @import("../relay_queue.zig").Relay;
const io_helpers = @import("../io.zig");
const Native = @import("../../../internal/testing/deadline_send_io.zig").Native;
const forwarded = @import("../../../internal/testing/forwarded_io.zig");
const native_protocol = @import("../../../internal/testing/native_protocol_io.zig");
const net = std.Io.net;
const allocator = std.testing.allocator;

const Gate = struct {
    delegate: std.Io,
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    borrowed: []const u8 = &.{},
    maximum: usize = 3,
    writes: std.atomic.Value(usize) = .init(0),
    fn write(context: ?*anyopaque, handle: net.Socket.Handle, bytes: []const u8, _: []const []const u8, _: usize) net.Stream.Writer.Error!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.borrowed = bytes;
        self.entered.set(self.delegate);
        try self.release.wait(self.delegate);
        const result = try self.delegate.vtable.netWrite(self.delegate.userdata, handle, bytes[0..@min(bytes.len, self.maximum)], &.{""}, 0);
        _ = self.writes.fetchAdd(1, .monotonic);
        return result;
    }
};
pub const Fixture = struct {
    base: std.Io,
    sender: net.Stream,
    peer: net.Stream,
    owns_sender: bool = true,
    clock: Native,
    gate: Gate,
    input: Input = .{},
    complete: std.Io.Event = .unset,

    pub fn init(self: *@This(), base: std.Io, maximum: usize) !void {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
        defer listener.deinit(base);
        const sender = try listener.socket.address.connect(base, .{ .mode = .stream });
        const peer = listener.accept(base) catch |err| {
            sender.close(base);
            return err;
        };
        errdefer sender.close(base);
        errdefer peer.close(base);
        self.* = .{
            .base = base,
            .sender = sender,
            .peer = peer,
            .clock = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base, .now_ns = .init(@intCast(std.Io.Clock.awake.now(base).nanoseconds)) },
            .gate = .{ .delegate = undefined },
        };
        errdefer self.clock.backend.deinit();
        self.gate.delegate = self.clock.io();
        try self.input.init(allocator, self.observed(), sender, .{ .maximum_bytes = maximum, .notify_context = self, .notify = notify });
    }
    pub fn observed(self: *@This()) std.Io {
        return forwarded.observer(&self.gate, .{ .netWrite = Gate.write });
    }
    fn notify(context: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.complete.set(self.base);
    }
    fn completion(self: *@This()) !Input.Completion {
        while (true) {
            if (self.input.take()) |result| return result;
            try self.complete.waitTimeout(self.base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
            self.complete.reset();
        }
    }
    pub fn entered(self: *@This()) !void {
        try self.gate.entered.waitTimeout(self.base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    }
    pub fn readExact(self: *@This(), expected: []const u8) !void {
        var buffer: [8192]u8 = undefined;
        var offset: usize = 0;
        const deadline = std.Io.Clock.Timestamp.fromNow(self.base, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (offset < expected.len) {
            const count = try io_helpers.readSome(self.base, self.peer, buffer[offset..expected.len], deadline);
            if (count == 0) return error.EndOfStream;
            offset += count;
        }
        try std.testing.expectEqualSlices(u8, expected, buffer[0..offset]);
    }
    pub fn deinit(self: *@This()) void {
        self.input.deinit();
        if (self.owns_sender) self.sender.close(self.base);
        self.peer.close(self.base);
        self.clock.backend.deinit();
    }
};

test "proxy inbound loan survives pending growth and resumes exact FIFO suffix" {
    try native_protocol.runStream(loanGrowth);
}
fn loanGrowth(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 8192);
    defer fixture.deinit();
    try fixture.input.append("abcdef");
    try std.testing.expectEqual(@as(usize, 6), try fixture.input.submit(6));
    try fixture.entered();
    const borrowed = fixture.gate.borrowed.ptr;
    const extra = "x" ** 4096;
    {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        fixture.input.allocator = failing.allocator();
        defer fixture.input.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, fixture.input.append(extra));
        try std.testing.expectEqual(@as(usize, 6), fixture.input.pendingBytes());
        try std.testing.expectEqual(borrowed, fixture.gate.borrowed.ptr);
    }
    try fixture.input.append(extra);
    try std.testing.expectEqual(borrowed, fixture.gate.borrowed.ptr);
    try std.testing.expectEqualStrings("abcdef", fixture.gate.borrowed);
    try std.testing.expectEqual(@as(usize, 4102), fixture.input.pendingBytes());
    try std.testing.expectEqual(@as(usize, 0), fixture.input.readyBytes());
    try std.testing.expectError(error.RelayBufferFull, fixture.input.append("z" ** 4091));
    fixture.gate.release.set(base);
    const first = try fixture.completion();
    try std.testing.expectEqual(@as(usize, 6), first.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 3), first.committed_bytes);
    try std.testing.expect(first.failure == null);
    try std.testing.expectEqual(@as(usize, 3), fixture.input.readyBytes());
    try std.testing.expectEqual(@as(usize, 3), try fixture.input.submit(8192));
    const second = try fixture.completion();
    try std.testing.expectEqual(@as(usize, 3), second.committed_bytes);
    try fixture.readExact("abcdef");
    fixture.gate.maximum = 4096;
    try std.testing.expectEqual(@as(usize, 4096), try fixture.input.submit(8192));
    const third = try fixture.completion();
    try std.testing.expectEqual(@as(usize, 4096), third.committed_bytes);
    try fixture.readExact(extra);
    try std.testing.expectEqual(@as(usize, 0), fixture.input.pendingBytes());
    try std.testing.expect(fixture.input.pending.capacity <= 8192 and fixture.input.loan.capacity <= 8192);
}

test "proxy inbound actual deadline refunds zero progress and retries the same loan" {
    try native_protocol.runStream(deadlineRetry);
}
fn deadlineRetry(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 16);
    defer fixture.deinit();
    try fixture.input.append("abcdef");
    try std.testing.expectEqual(@as(usize, 6), try fixture.input.submit(6));
    try fixture.entered();
    fixture.clock.setNow(fixture.clock.now_ns.load(.acquire) + 10 * std.time.ns_per_ms);
    const expired = try fixture.completion();
    try std.testing.expectEqual(@as(usize, 6), expired.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), expired.committed_bytes);
    try std.testing.expectEqual(@as(?io_helpers.WriteError, error.Timeout), expired.failure);
    try std.testing.expectEqual(@as(usize, 0), fixture.gate.writes.load(.acquire));
    try std.testing.expectEqual(@as(usize, 6), fixture.input.pendingBytes());
    fixture.gate.maximum = 6;
    fixture.gate.release.set(base);
    try std.testing.expectEqual(@as(usize, 6), try fixture.input.submit(6));
    const completed = try fixture.completion();
    try std.testing.expectEqual(@as(usize, 6), completed.committed_bytes);
    try fixture.readExact("abcdef");
}

test "proxy inbound stop joins a blocked loan before releasing its storage" {
    try native_protocol.runStream(stopBlocked);
}
fn stopBlocked(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 16);
    defer fixture.deinit();
    try fixture.input.append("abcdef");
    _ = try fixture.input.submit(6);
    try fixture.entered();
    const result = fixture.input.stop() orelse return error.TestExpectedCompletion;
    try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 0), result.committed_bytes);
    try std.testing.expectEqual(@as(?io_helpers.WriteError, error.Canceled), result.failure);
    try std.testing.expectEqual(@as(usize, 0), fixture.gate.writes.load(.acquire));
    try std.testing.expect(fixture.input.stop() == null);
    try std.testing.expectEqual(@as(usize, 0), try fixture.input.submit(6));
}

test "proxy inbound stop collects an unobserved visible partial completion once" {
    try native_protocol.runStream(stopCompleted);
}
fn stopCompleted(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 16);
    defer fixture.deinit();
    fixture.gate.release.set(base);
    try fixture.input.append("abcdef");
    _ = try fixture.input.submit(6);
    try fixture.complete.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const result = fixture.input.stop() orelse return error.TestExpectedCompletion;
    try std.testing.expectEqual(@as(usize, 6), result.reserved_bytes);
    try std.testing.expectEqual(@as(usize, 3), result.committed_bytes);
    try std.testing.expect(result.failure == null);
    try std.testing.expect(fixture.input.stop() == null);
    try fixture.readExact("abc");
}

test "proxy relay concurrent reader and writer support zero async capacity and defer FIN" {
    try native_protocol.runStream(relayFin);
}
fn relayFin(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 16);
    defer fixture.deinit();
    _ = fixture.input.stop();
    const relay = try Relay.create(allocator, fixture.observed(), fixture.sender, 1, .fromSeconds(1), 16);
    fixture.owns_sender = false;
    defer relay.deinit();
    try std.testing.expect(!relay.tcp_done.load(.acquire));
    try relay.queueInbound("abcdef");
    relay.quic_done.store(true, .release);
    _ = relay.submitInput(6);
    try fixture.entered();
    relay.shutdownTcpSend();
    try std.testing.expect(!relay.tcp_send_shutdown);
    fixture.gate.maximum = 6;
    fixture.gate.release.set(base);
    const until = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
    const result = while (true) {
        if (relay.takeInputCompletion()) |result| break result;
        if (until.durationFromNow(base).raw.nanoseconds <= 0) return error.TestExpectedCompletion;
        try std.Io.sleep(base, .fromMilliseconds(1), .awake);
    };
    try std.testing.expectEqual(@as(usize, 6), result.committed_bytes);
    try std.testing.expect(result.failure == null);
    try std.testing.expect(relay.inputDrained());
    relay.shutdownTcpSend();
    try std.testing.expect(relay.tcp_send_shutdown);
    try fixture.readExact("abcdef");
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try io_helpers.readSome(base, fixture.peer, &byte, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
}

test "proxy relay synchronous flush preserves standalone partial write semantics" {
    try native_protocol.runStream(synchronousFlush);
}
fn synchronousFlush(base: std.Io) !void {
    var fixture: Fixture = undefined;
    try fixture.init(base, 16);
    defer fixture.deinit();
    _ = fixture.input.stop();
    const relay = try Relay.create(allocator, fixture.observed(), fixture.sender, 1, .fromSeconds(1), 16);
    fixture.owns_sender = false;
    defer relay.deinit();
    fixture.gate.release.set(base);
    try relay.queueInbound("abcdef");
    try std.testing.expectEqual(@as(usize, 3), relay.flushInboundUpTo(6));
    try std.testing.expectEqual(@as(usize, 3), relay.pendingInboundBytes());
    try std.testing.expect(!relay.input.in_flight);
    try std.testing.expect(relay.flushInbound());
    try std.testing.expect(relay.inputDrained());
    try fixture.readExact("abcdef");
}
