//! Preserve reader/cleanup error precedence while retiring a shared writer.
pub fn settle(comptime Context: type, task: anytype) void {
    const late_error = Context.unregister(task) catch |err| blk: {
        // Durable cleanup errors retain their existing precedence.
        task.result.* = err;
        break :blk null;
    };
    if (late_error) |err| {
        if (!Context.transportClosed(err) and task.result.* == null) task.result.* = err;
    }
}
