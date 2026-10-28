const std = @import("std");
const pool_mod = @import("../client_pool.zig");

test "HTTP/1 pool TLS setup ticket clone retains the original deadline" {
    try @import("../../internal/pool_returns/setup_test_support.zig").exercise(pool_mod.Pool);
}

test "HTTP/1 pool bounded collector retires TLS without extra output" {
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseCollectorRetirement(pool_mod.Pool, false);
}

test "HTTP/1 pool collector deadline retains connection and issued TLS ticket" {
    inline for (.{ false, true }) |canceled| try @import("../../internal/pool_returns/success_test_support.zig").exerciseCollector(pool_mod.Pool, false, canceled);
}

test "HTTP/1 pool closed TLS lease returns without output or waiting" {
    try @import("../../internal/pool_returns/success_test_support.zig").exerciseClosed(pool_mod.Pool, false);
}

test "HTTP/1 pool completed TLS response returns under pool and ticket contention" {
    inline for (.{ false, true }) |ticket| try @import("../../internal/pool_returns/success_test_support.zig").exerciseTls(pool_mod.Pool, false, ticket);
}

test "HTTP/1 pool returns a completed response before connection return lock" {
    try @import("../../internal/pool_returns/success_test_support.zig").exercise(pool_mod.Pool, false);
}

test "HTTP/1 pool retirement between capacity check and enqueue wakes its caller" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try @import("../../internal/retired_capacity/pool_race_test_support.zig").exercise(pool_mod.Pool, threaded.io());
}

test "HTTP/1 pool failed connection retirement returns under cleanup contention" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/retired_capacity/pool_test_support.zig").exercise(&pool, threaded.io());
}

test "HTTP/1 pool waiter allocation failures preserve admission ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try @import("../../internal/pool_waiter_allocation_test_support.zig").exercise(pool_mod.Pool, threaded.io());
}

test "HTTP/1 pool deadline bounds initial mutex admission and unused waiter cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/pool_admission_test_support.zig").exercise(&pool, threaded.io());
}

test "HTTP/1 pool queued timeout and cancellation return before waiter cleanup lock" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/pool_waiter_cleanup_test_support.zig").exercise(&pool, threaded.io());
}
