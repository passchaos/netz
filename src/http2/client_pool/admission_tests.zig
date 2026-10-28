const std = @import("std");
const pool_mod = @import("../client_pool.zig");

test "HTTP/2 pool deadline bounds initial mutex admission and unused waiter cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(std.testing.allocator, threaded.io(), .{});
    defer pool.deinit();
    try @import("../../internal/pool_admission_test_support.zig").exercise(&pool, threaded.io());
}
