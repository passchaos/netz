const std = @import("std");
const retirement = @import("retirement.zig");

test "MQTT shared writer retirement preserves fatal errors and reader precedence" {
    const Task = struct {
        result: *?anyerror,
        late: ?anyerror,
        cleanup_failed: bool = false,
    };
    const Context = struct {
        pub fn unregister(task: Task) error{AccessDenied}!?anyerror {
            if (task.cleanup_failed) return error.AccessDenied;
            return task.late;
        }
        pub fn transportClosed(err: anyerror) bool {
            return err == error.ConnectionClosed;
        }
    };
    var result: ?anyerror = null;
    retirement.settle(Context, Task{ .result = &result, .late = error.ConnectionClosed });
    try std.testing.expect(result == null);
    retirement.settle(Context, Task{ .result = &result, .late = error.OutOfMemory });
    try std.testing.expectEqual(@as(?anyerror, error.OutOfMemory), result);
    result = error.InvalidProperty;
    retirement.settle(Context, Task{ .result = &result, .late = error.OutOfMemory });
    try std.testing.expectEqual(@as(?anyerror, error.InvalidProperty), result);
    retirement.settle(Context, Task{ .result = &result, .late = error.OutOfMemory, .cleanup_failed = true });
    try std.testing.expectEqual(@as(?anyerror, error.AccessDenied), result);
}

pub fn lateErrorBeforeReuse(comptime Context: type) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |fatal| {
        var broker = try Context.BrokerType.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
        defer broker.deinit();
        const index = try Context.claim(&broker);
        broker.slots[index].state.generation = 1;
        const id = Context.id(index, 1);
        try std.testing.expect(broker.session_delivery_writers.takeError(io, index) == null);
        broker.session_delivery_writers.recordError(io, index, if (fatal) error.OutOfMemory else error.ConnectionClosed);
        const result = try Context.unregister(&broker, index, id, null);
        try std.testing.expectEqual(@as(?anyerror, if (fatal) error.OutOfMemory else error.ConnectionClosed), result);
        try std.testing.expect(broker.session_delivery_writers.takeError(io, index) == null);
        const replacement = try Context.claim(&broker);
        defer Context.release(&broker, replacement);
        try std.testing.expectEqual(index, replacement);
        try std.testing.expect(broker.session_delivery_writers.takeError(io, replacement) == null);
    }
}
