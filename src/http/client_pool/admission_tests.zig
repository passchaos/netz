const std = @import("std");
const pool_mod = @import("../client_pool.zig");

test "unified HTTP pool retirement between capacity check and enqueue wakes its caller" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try @import("../../internal/retired_capacity/pool_race_test_support.zig").exercise(pool_mod.Pool, threaded.io());
}

test "unified HTTP pool failed connection retirement returns under cleanup contention" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/retired_capacity/pool_test_support.zig").exercise(&pool, threaded.io());
}

test "unified HTTP pool waiter allocation failures preserve admission ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try @import("../../internal/pool_waiter_allocation_test_support.zig").exercise(pool_mod.Pool, threaded.io());
}

test "unified HTTP pool deadline bounds initial mutex admission and unused waiter cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/pool_admission_test_support.zig").exercise(&pool, threaded.io());
}

test "unified HTTP pool queued timeout and cancellation return before waiter cleanup lock" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/pool_waiter_cleanup_test_support.zig").exercise(&pool, threaded.io());
}
