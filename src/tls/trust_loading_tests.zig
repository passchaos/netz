//! Owned root loading must reclaim late results before returning to its caller.
const std = @import("std");
const loading = @import("trust_loading.zig");
const Store = @import("vail").x509.trust.SystemStore;

test "TLS trust load rejects late success and failure and destroys owned results" {
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const ClockProbe = struct {
        delegate: std.Io,
        offset_ns: std.atomic.Value(i64) = .init(0),
        var active: ?*@This() = null;
        fn now(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            const timestamp = clock.now(self.delegate);
            return if (clock == .awake)
                timestamp.addDuration(.fromNanoseconds(self.offset_ns.load(.acquire)))
            else
                timestamp;
        }
    };
    var clock: ClockProbe = .{ .delegate = io };
    ClockProbe.active = &clock;
    defer ClockProbe.active = null;
    var table = io.vtable.*;
    table.now = ClockProbe.now;
    const observed: std.Io = .{ .userdata = io.userdata, .vtable = &table };
    const Loader = struct {
        fn run(allocator: std.mem.Allocator, run_io: std.Io, clock_probe: *ClockProbe, fail: bool) !Store {
            const old = run_io.swapCancelProtection(.blocked);
            defer _ = run_io.swapCancelProtection(old);
            // Expire the original deadline only after this loader has started.
            clock_probe.offset_ns.store(60 * std.time.ns_per_s, .release);
            if (fail) return error.OutOfMemory;
            var store = Store.initEmpty(allocator);
            errdefer store.deinit();
            try store.bundle.bytes.appendNTimes(allocator, 0, 256);
            return store;
        }
    };
    inline for (.{ false, true }) |fail| {
        clock.offset_ns.store(0, .release);
        var allocations = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const deadline: std.Io.Clock.Timestamp = .fromNow(observed, .{ .clock = .awake, .raw = .fromSeconds(30) });
        try std.testing.expectError(error.Timeout, loading.before(observed, deadline, Loader.run, .{ allocations.allocator(), observed, &clock, fail }));
        try std.testing.expectEqual(@as(i64, 60 * std.time.ns_per_s), clock.offset_ns.load(.acquire));
        if (!fail) try std.testing.expect(allocations.allocated_bytes >= 256);
        try std.testing.expectEqual(allocations.allocated_bytes, allocations.freed_bytes);
    }
}

test "TLS trust load caller cancellation joins the active loader" {
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const Worker = struct {
        io: std.Io,
        entered: std.Io.Event = .unset,
        exited: std.atomic.Value(bool) = .init(false),
        fn load(self: *@This()) !Store {
            self.entered.set(self.io);
            defer self.exited.store(true, .release);
            try std.Io.sleep(self.io, .fromSeconds(5), .awake);
            return Store.initEmpty(std.testing.allocator);
        }
        fn run(self: *@This()) !void {
            const deadline: std.Io.Clock.Timestamp = .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(5) });
            const result = loading.before(self.io, deadline, load, .{self});
            if (result) |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.TestExpectedError;
            } else |err| try std.testing.expectEqual(@as(anyerror, error.Canceled), err);
        }
    };
    var worker: Worker = .{ .io = io };
    var future = try std.Io.concurrent(io, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        future.cancel(io) catch {};
    };
    try worker.entered.wait(io);
    try future.cancel(io);
    joined = true;
    try std.testing.expect(worker.exited.load(.acquire));
}
