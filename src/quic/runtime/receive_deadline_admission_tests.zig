//! Expired raw timeouts precede a backend's timed I/O capability check.
const std = @import("std");
const runtime = @import("../runtime.zig");
const dispatcher_mod = @import("../endpoint_dispatcher.zig");

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    waits: usize = 0,

    fn io(self: *@This()) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.batchAwaitConcurrent = awaitConcurrent;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn awaitConcurrent(userdata: ?*anyopaque, _: *std.Io.Batch, _: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        const self: *@This() = @fieldParentPtr("backend", backend);
        self.waits += 1;
        return error.ConcurrencyUnavailable;
    }
};

fn receive(comptime dispatch: bool, endpoint: *runtime.Endpoint, dispatcher: *dispatcher_mod.Dispatcher, storage: []u8, slots: usize, timeout: std.Io.Timeout) !usize {
    if (dispatch) {
        const Visitor = struct {
            fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{}!void {}
        };
        var events: [2]dispatcher_mod.VisitEvent = undefined;
        return dispatcher.receiveManyVisitingTimeout(&.{1}, storage, events[0..slots], timeout, {}, Visitor.visit);
    }
    var views: [2]runtime.ReceivedBytesView = undefined;
    return endpoint.receiveManyBytesIntoTimeout(storage, views[0..slots], timeout);
}

test "QUIC batch receive caller-owned deadlines reject expiry before I/O admission" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    const timeouts = [_]std.Io.Timeout{
        .{ .duration = .{ .clock = .awake, .raw = .zero } },
        .{ .duration = .{ .clock = .awake, .raw = .fromNanoseconds(-1) } },
        .{ .deadline = .{ .clock = .awake, .raw = .zero } },
        .{ .deadline = .fromNow(base, .{ .clock = .real, .raw = .fromSeconds(10) }) },
    };
    var storage: [256]u8 = @splat(0x5a);
    inline for (.{ false, true }) |dispatch| {
        for (timeouts) |timeout| {
            for ([_]usize{ 2, 0 }) |slots| {
                try std.testing.expectError(error.Timeout, receive(dispatch, &endpoint, &dispatcher, &storage, slots, timeout));
                try std.testing.expectEqual(@as(usize, 0), probe.waits);
                try std.testing.expectEqualSlices(u8, &(@as([256]u8, @splat(0x5a))), &storage);
            }
        }
    }
}

test "QUIC batch receive caller-owned deadlines preserve live-budget admission errors" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var storage: [256]u8 = undefined;
    inline for (.{ false, true }) |dispatch| {
        try std.testing.expectError(error.ConcurrencyUnavailable, receive(dispatch, &endpoint, &dispatcher, &storage, 2, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(10) } }));
    }
    try std.testing.expectEqual(@as(usize, 2), probe.waits);
}

test "QUIC batch receive caller-owned deadlines bound socket ownership admission" {
    var probe: Probe = .{ .backend = .init(std.testing.allocator, .{}) };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var endpoint = try runtime.Endpoint.bind(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer endpoint.deinit();
    endpoint.io = probe.io();
    defer endpoint.io = base;
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    endpoint.socket_receive_mutex.lockUncancelable(base);
    defer endpoint.socket_receive_mutex.unlock(base);
    var storage: [256]u8 = @splat(0x5a);
    inline for (.{ false, true }) |dispatch| {
        try std.testing.expectError(error.Timeout, receive(dispatch, &endpoint, &dispatcher, &storage, 2, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } }));
        try std.testing.expect(!endpoint.socket_receive_mutex.tryLock());
        try std.testing.expectEqual(@as(usize, 0), probe.waits);
        try std.testing.expectEqualSlices(u8, &(@as([256]u8, @splat(0x5a))), &storage);
    }
}
