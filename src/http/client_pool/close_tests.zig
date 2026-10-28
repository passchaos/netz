const std = @import("std");
const http = @import("../client_pool.zig");
const h1 = @import("../../http1/client_pool.zig");
const h2 = @import("../../http2/client_pool.zig");

test "HTTP closed pool rejects acquisition before collecting a returned TLS connection" {
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseClosedRejection(h1.Pool, false);
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseClosedRejection(h2.Pool, true);
    inline for (.{ false, true }) |prior| try @import("../../internal/pool_returns/success_test_support.zig").exerciseClosedRejection(http.Pool, prior);
}

test "HTTP pool close rejects publication by an already connecting request" {
    try @import("../../internal/pool_returns/close_race_test_support.zig").exercise(h1.Pool, false);
    try @import("../../internal/pool_returns/close_race_test_support.zig").exercise(h2.Pool, true);
    inline for (.{ false, true }) |prior_knowledge| try @import("../../internal/pool_returns/close_race_test_support.zig").exercise(http.Pool, prior_knowledge);
}

test "HTTP pool deadline close resumes after blocked admission publisher budget and ticket locks" {
    inline for (.{ h1.Pool, h2.Pool, http.Pool }) |Pool| try @import("../../internal/pool_returns/close_test_support.zig").exercise(Pool);
}

test "HTTP pool deadline close validates caller bounds before changing state" {
    inline for (.{ h1.Pool, h2.Pool, http.Pool }) |Pool| try @import("../../internal/pool_returns/close_test_support.zig").validate(Pool);
}

test "HTTP pool deadline close retires TLS resources after blocked alert output and retries" {
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseBoundedClose(h1.Pool, false);
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseBoundedClose(h2.Pool, true);
    inline for (.{ false, true }) |h2_protocol| try @import("../../internal/pool_returns/success_test_support.zig").exerciseBoundedClose(http.Pool, h2_protocol);
}

test "unified HTTP3 deadline close releases initialized drivers and remains idempotent" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try http.Pool.init(std.testing.allocator, io, .{ .http3 = .{ .handshake = .{ .handshake = .{
        .original_destination_connection_id = &.{1},
        .local_connection_id = &.{2},
    } } } });
    defer pool.deinit();
    try pool.closeWithTimeout(.fromSeconds(1));
    try pool.closeWithTimeout(.fromSeconds(1));
    try std.testing.expect(pool.http3.?.closed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
    try std.testing.expectError(error.PoolClosed, pool.requestUriWithTimeout("https://127.0.0.1/", .{}, .fromSeconds(1)));
}

const H3Gate = struct {
    base: std.Io,
    target: *const u32,
    var active: ?*H3Gate = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (pointer == self.target) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

test "unified HTTP3 deadline close retains initialized backend cleanup across cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    for (0..6) |stage| {
        var pool = try http.Pool.init(std.testing.allocator, base, .{ .http3 = .{ .shared_endpoint = true, .handshake = .{ .handshake = .{
            .original_destination_connection_id = &.{1},
            .local_connection_id = &.{2},
        } } } });
        defer pool.deinit();
        const state = pool.http3.?;
        const mutex = switch (stage) {
            0 => &state.close_mutex,
            1 => &state.shared_init_mutex,
            2 => &state.settings_mutex,
            3 => &state.cache.mutex,
            4 => &state.dispatcher.state.mutex,
            else => &state.shared_dispatcher.?.state.mutex,
        };
        mutex.lockUncancelable(base);
        var held = true;
        defer if (held) mutex.unlock(base);
        var gate = H3Gate{ .base = base, .target = @ptrCast(&mutex.state.raw) };
        var table = base.vtable.*;
        table.futexWait = H3Gate.wait;
        const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
        H3Gate.active = &gate;
        pool.io = io;
        state.io = io;
        state.cache.io = io;
        defer {
            pool.io = base;
            state.io = base;
            state.cache.io = base;
            H3Gate.active = null;
        }
        // The live dispatchers retain their original I/O context. Their
        // occupied mutexes exercise timeout; outer control/cache waits use
        // the canceling context without changing a running driver's I/O.
        try std.testing.expectError(if (stage < 4) error.Canceled else error.Timeout, pool.closeWithTimeout(.fromMilliseconds(10)));
        try std.testing.expect(pool.closed);
        try std.testing.expect(!mutex.tryLock());
        try std.testing.expect(pool.mutex.tryLock());
        pool.mutex.unlock(base);
        try std.testing.expectError(error.PoolClosed, pool.requestUriWithTimeout("https://127.0.0.1/", .{}, .fromSeconds(1)));
        mutex.unlock(base);
        held = false;
        try pool.closeWithTimeout(.fromSeconds(1));
        try std.testing.expect(state.closed.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
    }
}
