const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const stream_io = @import("../../../../internal/stream_io.zig");
const Fixture = @import("../../../../http2/runtime/duplex/testing.zig").Fixture;
const reconnecting = @import("../reconnecting.zig");
const allocator = std.testing.allocator;

const Pair = struct {
    value: Fixture,
    owned: bool = true,
    fn init(io: std.Io) !Pair {
        return .{ .value = try Fixture.init(io) };
    }
    fn take(self: *Pair, io: std.Io) http2.runtime.Connection {
        std.debug.assert(self.owned);
        self.owned = false;
        var result = self.value.connection;
        result.io = io;
        return result;
    }
    fn deinit(self: *Pair) void {
        if (self.owned) self.value.connection.close();
        self.value.peer.close(self.value.io);
        self.value.listener.deinit(self.value.io);
    }
    fn expectClosed(self: *Pair) !void {
        var byte: [1]u8 = undefined;
        const count = try stream_io.readSomeWithDeadline(self.value.io, self.value.peer, &byte, .fromNow(self.value.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        try std.testing.expectEqual(@as(usize, 0), count);
    }
};

const Mode = enum { publication_timeout, publication_cancellation, fast_publication_cancellation, callback_failure, owner_failure, late_owner, late_callback };

test "WebTransport HTTP2 reconnecting completion never waits beyond failed publication and recovers" {
    for (std.enums.values(Mode)) |mode| try exercise(mode);
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var first = try Pair.init(base);
    defer first.deinit();
    var next = try Pair.init(base);
    defer next.deinit();
    var third = try Pair.init(base);
    defer third.deinit();
    const Context = struct {
        base: std.Io,
        first: *Pair,
        next: *Pair,
        third: *Pair,
        mode: Mode,
        state: *reconnecting.ReconnectingEndpointClient = undefined,
        held: bool = false,
        calls: usize = 0,
        waits: usize = 0,
        unbounded: usize = 0,
        owner: std.Thread.Id = 0,
        observed_mutex: ?*std.Io.Mutex = null,
        clock_shift_ns: std.atomic.Value(i64) = .init(0),
        var active: ?*@This() = null;
        fn connect(context: ?*anyopaque, _: std.mem.Allocator, io: std.Io, _: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 2) return self.next.take(io);
            if (self.calls == 3) return self.third.take(io);
            self.owner = std.Thread.getCurrentId();
            if (self.mode == .late_callback) {
                try std.Io.sleep(self.base, .fromMilliseconds(50), .awake);
            } else if (self.mode != .fast_publication_cancellation) {
                self.state.state.mutex.lockUncancelable(self.base);
                self.held = true;
            }
            if (self.mode == .callback_failure) return error.OutOfMemory;
            return self.first.take(io);
        }
        fn checkCancel(userdata: ?*anyopaque) std.Io.Cancelable!void {
            const self = active.?;
            if (self.owner == std.Thread.getCurrentId() and
                self.mode == .fast_publication_cancellation and self.calls == 1 and !self.first.owned and
                self.state.state.mutex.state.load(.acquire) != .unlocked)
            {
                return error.Canceled;
            }
            return self.base.vtable.checkCancel(userdata);
        }
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            return self.base.vtable.now(userdata, clock).addDuration(.fromNanoseconds(self.clock_shift_ns.load(.acquire)));
        }
        fn concurrent(userdata: ?*anyopaque, group: *std.Io.Group, bytes: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            const self = active.?;
            try self.base.vtable.groupConcurrent(userdata, group, bytes, alignment, start);
            if (self.owner == std.Thread.getCurrentId() and self.mode == .late_owner and self.calls == 1) {
                // The owner has started, but construction must still enforce
                // its original deadline before returning that candidate.
                self.clock_shift_ns.store(50 * std.time.ns_per_ms, .release);
            }
        }
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (pointer == @as(*const u32, @ptrCast(&self.state.state.mutex.state.raw))) {
                self.waits += 1;
                if (self.mode == .publication_cancellation) return error.Canceled;
            }
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            if (self.owner == std.Thread.getCurrentId()) if (self.observed_mutex) |mutex| {
                if (pointer == @as(*const u32, @ptrCast(&mutex.state.raw))) {
                    self.unbounded += 1;
                    mutex.state.store(.unlocked, .release);
                    return;
                }
            };
            if (pointer == @as(*const u32, @ptrCast(&self.state.state.mutex.state.raw))) {
                self.unbounded += 1;
                self.state.state.mutex.state.store(.unlocked, .release);
                self.held = false;
                return;
            }
            self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
        fn unlock(self: *@This()) void {
            if (!self.held) return;
            self.state.state.mutex.unlock(self.base);
            self.held = false;
        }
    };
    var context = Context{ .base = base, .first = &first, .next = &next, .third = &third, .mode = mode };
    Context.active = &context;
    defer Context.active = null;
    var table = base.vtable.*;
    table.futexWait = Context.wait;
    table.futexWaitUncancelable = Context.waitUncancelable;
    table.checkCancel = Context.checkCancel;
    table.now = Context.now;
    table.groupConcurrent = Context.concurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var client = try reconnecting.ReconnectingEndpointClient.init(allocator, io, .{ .custom = .{ .context = &context, .connect_fn = Context.connect } }, .{ .backoff = .{ .initial = .fromMilliseconds(1), .maximum = .fromMilliseconds(1), .jitter = 0 } });
    defer client.deinit();
    context.state = &client;
    defer context.unlock();
    if (mode == .owner_failure) threaded.concurrent_limit = .limited(0);
    const result = client.connectAttemptWithDeadline(.{ .path = "/never-sent", .authority = "localhost" }, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(30) }));
    const expected: anyerror = switch (mode) {
        .publication_timeout, .late_owner, .late_callback => error.Timeout,
        .publication_cancellation, .fast_publication_cancellation => error.Canceled,
        .callback_failure => error.OutOfMemory,
        .owner_failure => error.ConcurrencyUnavailable,
    };
    try std.testing.expectError(expected, result);
    threaded.concurrent_limit = .unlimited;
    try std.testing.expectEqual(@as(usize, 0), context.unbounded);
    try std.testing.expectEqual(@as(usize, 0), client.state.active.load(.acquire));
    try std.testing.expect(client.state.current == null);
    if (mode != .late_callback and mode != .fast_publication_cancellation) {
        try std.testing.expect(client.state.pending_failure.ready.load(.acquire));
        try std.testing.expect(client.state.connecting);
    } else {
        try std.testing.expect(!client.state.connecting);
        try std.testing.expectEqual(@as(usize, 1), client.state.failures);
    }
    if (mode != .callback_failure) try first.expectClosed();
    if (mode == .publication_timeout or mode == .publication_cancellation) try std.testing.expect(context.waits != 0);
    context.unlock();
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try client.state.enter(until);
    defer client.state.leave();
    const generation = try client.state.acquireCurrent(until);
    defer generation.release();
    try std.testing.expectEqual(@as(u64, 2), generation.id);
    try std.testing.expectEqual(@as(usize, 2), context.calls);
    try std.testing.expect(!client.state.pending_failure.ready.load(.acquire));
    try std.testing.expect(!client.state.connecting);
    try std.testing.expectEqual(@as(usize, 0), client.state.failures);
    try std.testing.expect(client.state.next_attempt_ns == null);

    // A terminal result must not acquire the endpoint's metadata mutex or
    // wait for the reconnecting State mutex during retirement.
    generation.client.state.mutex.lockUncancelable(base);
    context.observed_mutex = &generation.client.state.mutex;
    defer context.observed_mutex = null;
    var endpoint_locked = true;
    defer if (endpoint_locked and generation.client.state.mutex.state.load(.acquire) != .unlocked) generation.client.state.mutex.unlock(base);
    try std.testing.expect(generation.client.terminalFailure() == null);
    client.state.mutex.lockUncancelable(base);
    context.held = true;
    try std.testing.expect(client.state.retireAfterError(generation, error.ConnectionClosed));
    try std.testing.expect(generation.retire_requested.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), context.unbounded);
    try std.testing.expect(client.state.current == generation);
    generation.client.requestShutdownAbortive();
    try std.testing.expect(generation.client.state.abortive_shutdown.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), context.unbounded);
    generation.client.state.mutex.unlock(base);
    endpoint_locked = false;
    context.observed_mutex = null;
    context.unlock();
    try std.testing.expectError(error.StaleConnection, client.state.acquireHandle(generation.id, until));
    const replacement = try client.state.acquireCurrent(until);
    defer replacement.release();
    try std.testing.expectEqual(@as(u64, 3), replacement.id);
    try std.testing.expectEqual(@as(usize, 3), context.calls);
    try next.expectClosed();
}
