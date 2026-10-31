const std = @import("std");
const shared = @import("../shared.zig");

test "gRPC shared control-plane admission obeys State and Tracker deadlines" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    state.closed = false;
    defer state.closed = true;
    state.resolution_changed.reset();
    const retained = shared.SharedChannel{ .state = state };
    const endpoint_count = state.endpointCountLocked();

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (pointer == mutex) {
                self.unbounded_waits += 1;
                self.mutex.state.store(.unlocked, .release);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var table = base.vtable.*;
    table.futexWaitUncancelable = Probe.waitUncancelable;

    var state_probe = Probe{ .base = base, .mutex = &state.mutex };
    Probe.active = &state_probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    state.mutex.lockUncancelable(base);
    try std.testing.expectError(error.Timeout, retained.connectWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, retained.resetConnectionBackoffWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, retained.endpointCountWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, retained.watchEndpointConnectivityWithTimeout(0, .fromMilliseconds(1)));
    try std.testing.expectEqual(@as(usize, 0), state_probe.unbounded_waits);
    try std.testing.expect(!state.demand);
    try std.testing.expect(!state.mutex.tryLock());
    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);

    const tracker = state.tracker;
    const tracker_references = tracker.references.load(.acquire);
    var tracker_probe = Probe{ .base = base, .mutex = &tracker.mutex };
    Probe.active = &tracker_probe;
    tracker.io = .{ .userdata = base.userdata, .vtable = &table };
    tracker.mutex.lockUncancelable(base);
    try std.testing.expectError(error.Timeout, retained.connectWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, retained.connectivityStateWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, retained.watchConnectivityWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectEqual(@as(usize, 0), tracker_probe.unbounded_waits);
    try std.testing.expectEqual(tracker_references, tracker.references.load(.acquire));
    try std.testing.expect(!state.demand);
    try std.testing.expect(!tracker.mutex.tryLock());
    try std.testing.expect(state.mutex.tryLock());
    state.mutex.unlock(base);
    tracker.io = base;
    Probe.active = null;
    tracker.mutex.unlock(base);

    try std.testing.expectEqual(endpoint_count, try retained.endpointCountWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(@import("../connectivity.zig").State.shutdown, try retained.connectivityStateWithTimeout(.fromSeconds(1)));
    var watch = try retained.watchConnectivityWithTimeout(.fromSeconds(1));
    defer watch.deinit();
    try std.testing.expectEqual(@import("../connectivity.zig").State.shutdown, watch.snapshot().state);
    try std.testing.expect(!state.demand);
}
