//! Allocation and owned-result probes for shared connection competition.
const std = @import("std");
const competition = @import("../connection_race.zig");
const Error = error{ ConnectionRefused, Canceled, Timeout, Unexpected };

const Measurement = struct {
    allocated: usize,
    freed: usize,
    allocations: usize,
};

fn measure(comptime Payload: type, payload: Payload, comptime valid: fn (*const Payload) bool, count: usize) !Measurement {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const targets = try std.testing.allocator.alloc(usize, count);
    defer std.testing.allocator.free(targets);
    for (targets, 0..) |*target, index| target.* = index;
    var calls: std.atomic.Value(usize) = .init(0);
    const Context = struct {
        payload: Payload,
        calls: *std.atomic.Value(usize),
        marker: u64 = 0x123456789abcdef0,
        fn connect(self: @This(), _: std.Io, target: usize, index: usize) Error!u8 {
            if (self.marker != 0x123456789abcdef0 or target != index or !valid(&self.payload)) return error.Unexpected;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return error.ConnectionRefused;
        }
        fn close(_: @This(), _: *u8) void {
            unreachable;
        }
        fn next(err: Error) bool {
            return err == error.ConnectionRefused;
        }
    };
    var meter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try std.testing.expectError(error.ConnectionRefused, competition.race(Error, u8, meter.allocator(), io, targets, .{ .attempt_delay = .fromSeconds(5), .max_in_flight = 2 }, null, null, Context{ .payload = payload, .calls = &calls }, Context.connect, Context.close, Context.next));
    try std.testing.expectEqual(count, calls.load(.acquire));
    try std.testing.expectEqual(meter.allocated_bytes, meter.freed_bytes);
    return .{ .allocated = meter.allocated_bytes, .freed = meter.freed_bytes, .allocations = meter.alloc_index };
}

pub fn compare(comptime Payload: type, payload: Payload, comptime valid: fn (*const Payload) bool) !void {
    const Empty = struct {
        fn accept(_: *const void) bool {
            return true;
        }
    };
    var depends_on_context = false;
    for ([_]usize{ 1, 8, 9, 64 }) |count| {
        const small = try measure(void, {}, Empty.accept, count);
        const large = try measure(Payload, payload, valid, count);
        std.debug.print("race storage context_bytes={d} candidates={d} small_bytes={d} large_bytes={d} allocations={d}/{d}\n", .{ @sizeOf(Payload), count, small.allocated, large.allocated, small.allocations, large.allocations });
        if (small.allocated != large.allocated or small.allocations != large.allocations) depends_on_context = true;
    }
    try std.testing.expect(!depends_on_context);
}

pub fn ownership(comptime Payload: type, payload: Payload, comptime valid: fn (*const Payload) bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const State = struct {
        started: std.Io.Event = .unset,
        never: std.Io.Event = .unset,
        bad_payload: std.atomic.Value(bool) = .init(false),
        closed: usize = 0,
    };
    var state: State = .{};
    const Context = struct {
        payload: Payload,
        state: *State,
        fn connect(self: @This(), active_io: std.Io, _: usize, index: usize) Error!u8 {
            if (!valid(&self.payload)) return error.Unexpected;
            if (index == 0) {
                self.state.started.set(active_io);
                self.state.never.wait(active_io) catch |err| switch (err) {
                    error.Canceled => {},
                };
                if (!valid(&self.payload)) self.state.bad_payload.store(true, .release);
                return 1;
            }
            try self.state.started.wait(active_io);
            return 2;
        }
        fn close(self: @This(), result: *u8) void {
            if (!valid(&self.payload)) self.state.bad_payload.store(true, .release);
            std.debug.assert(result.* == 1);
            self.state.closed += 1;
        }
        fn next(_: Error) bool {
            return false;
        }
    };
    const targets = [_]usize{ 0, 1 };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    const winner = try competition.race(Error, u8, std.testing.allocator, io, &targets, .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2 }, deadline, error.Timeout, Context{ .payload = payload, .state = &state }, Context.connect, Context.close, Context.next);
    try std.testing.expectEqual(@as(u8, 2), winner);
    try std.testing.expectEqual(@as(usize, 1), state.closed);
    try std.testing.expect(!state.bad_payload.load(.acquire));
}
