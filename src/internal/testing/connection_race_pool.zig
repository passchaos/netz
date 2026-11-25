//! Bounded result storage, candidate identity and cancellation ownership.
const std = @import("std");
const competition = @import("../connection_race.zig");
const Error = error{ ConnectionRefused, Canceled, Timeout, Unexpected };

const Measurement = struct { bytes: usize, allocations: usize };

fn measure(comptime Connected: type, count: usize, concurrency: usize) !Measurement {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const targets = try std.testing.allocator.alloc(usize, count);
    defer std.testing.allocator.free(targets);
    const seen = try std.testing.allocator.alloc(std.atomic.Value(u8), count);
    defer std.testing.allocator.free(seen);
    for (targets, seen, 0..) |*target, *visited, index| {
        target.* = index;
        visited.* = .init(0);
    }
    const Context = struct {
        seen: []std.atomic.Value(u8),
        fn connect(self: @This(), _: std.Io, target: usize, index: usize) Error!Connected {
            if (target != index or index >= self.seen.len or self.seen[index].swap(1, .acq_rel) != 0) return error.Unexpected;
            return error.ConnectionRefused;
        }
        fn close(_: @This(), _: *Connected) void {
            unreachable;
        }
        fn next(err: Error) bool {
            return err == error.ConnectionRefused;
        }
    };
    var meter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try std.testing.expectError(error.ConnectionRefused, competition.race(Error, Connected, meter.allocator(), io, targets, .{ .attempt_delay = .fromSeconds(5), .max_in_flight = concurrency }, null, null, Context{ .seen = seen }, Context.connect, Context.close, Context.next));
    for (seen) |*visited| try std.testing.expectEqual(@as(u8, 1), visited.load(.acquire));
    try std.testing.expectEqual(meter.allocated_bytes, meter.freed_bytes);
    return .{ .bytes = meter.allocated_bytes, .allocations = meter.alloc_index };
}

pub fn bounded(comptime Connected: type) !void {
    var grows_with_candidates = false;
    for ([_]usize{ 1, 2, 8, 9 }) |concurrency| {
        const reference = try measure(Connected, concurrency, concurrency);
        const many = try measure(Connected, 64, concurrency);
        std.debug.print("race pool result_bytes={d} candidates={d}/{d} max_in_flight={d} allocated_bytes={d}/{d} allocations={d}/{d}\n", .{ @sizeOf(Connected), concurrency, @as(usize, 64), concurrency, reference.bytes, many.bytes, reference.allocations, many.allocations });
        if (reference.bytes != many.bytes or reference.allocations != many.allocations) grows_with_candidates = true;
    }
    const all = try measure(Connected, 64, 64);
    std.debug.print("race pool result_bytes={d} candidates=64/64 max_in_flight=64 allocated_bytes={d}/{d} allocations={d}/{d}\n", .{ @sizeOf(Connected), all.bytes, all.bytes, all.allocations, all.allocations });
    try std.testing.expect(!grows_with_candidates);
}

pub fn reusedOwnership(comptime fixed_array: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Connected = struct { index: usize, payload: [4096]u8 };
    const count = 32;
    const State = struct {
        started: std.Io.Event = .unset,
        never: std.Io.Event = .unset,
        seen: [count]std.atomic.Value(u8) = @splat(.init(0)),
        running: std.atomic.Value(usize) = .init(0),
        closed: usize = 0,
        invalid: bool = false,
    };
    var state: State = .{};
    const Context = struct {
        state: *State,
        fn connect(self: @This(), active_io: std.Io, target: usize, index: usize) Error!Connected {
            if (target != index or index >= count or self.state.seen[index].swap(1, .acq_rel) != 0) return error.Unexpected;
            const active = self.state.running.fetchAdd(1, .acq_rel) + 1;
            defer _ = self.state.running.fetchSub(1, .acq_rel);
            if (active > 2) return error.Unexpected;
            if (index == 0) {
                self.state.started.set(active_io);
                self.state.never.wait(active_io) catch |err| switch (err) {
                    error.Canceled => {},
                };
                return .{ .index = 0, .payload = @splat(0xa5) };
            }
            if (index + 1 != count) return error.ConnectionRefused;
            try self.state.started.wait(active_io);
            return .{ .index = index, .payload = @splat(0xa5) };
        }
        fn close(self: @This(), connection: *Connected) void {
            if (connection.index != 0) self.state.invalid = true;
            for (connection.payload) |byte| if (byte != 0xa5) {
                self.state.invalid = true;
            };
            self.state.closed += 1;
        }
        fn next(err: Error) bool {
            return err == error.ConnectionRefused;
        }
    };
    var targets: [count]usize = undefined;
    for (&targets, 0..) |*target, index| target.* = index;
    const target_slice: []const usize = &targets;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    const winner = try competition.race(Error, Connected, std.testing.allocator, io, if (fixed_array) &targets else target_slice, .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2 }, deadline, error.Timeout, Context{ .state = &state }, Context.connect, Context.close, Context.next);
    try std.testing.expectEqual(@as(usize, count - 1), winner.index);
    for (winner.payload) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    for (&state.seen) |*visited| try std.testing.expectEqual(@as(u8, 1), visited.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.running.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.closed);
    try std.testing.expect(!state.invalid);
}
