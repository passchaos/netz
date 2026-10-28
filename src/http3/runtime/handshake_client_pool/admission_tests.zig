const std = @import("std");
const runtime = @import("../../runtime.zig");

fn initPool(io: std.Io, connector: *runtime.HandshakeClientPoolDefaultConnector) !runtime.HandshakeClientPool {
    return runtime.HandshakeClientPool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .connector = connector.connector(),
    });
}

test "HTTP/3 pool deadline bounds initial mutex admission and unused waiter cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
    } };
    var pool = try initPool(threaded.io(), &connector);
    defer pool.deinit();
    try @import("../../../internal/pool_admission_test_support.zig").exerciseUri(&pool, threaded.io(), "https://127.0.0.1:1/");
}

test "HTTP/3 pool queued timeout and cancellation return before waiter cleanup lock" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
    } };
    var pool = try initPool(threaded.io(), &connector);
    defer pool.deinit();
    try @import("../../../internal/pool_waiter_cleanup_test_support.zig").exerciseUri(&pool, threaded.io(), "https://127.0.0.1:1/");
}
