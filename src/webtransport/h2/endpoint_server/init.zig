//! Transactional server connection adoption and fixed owner table allocation.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn create(comptime Server: type, comptime State: type, comptime PendingSlot: type, comptime SessionSlot: type, comptime run: anytype, allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: anytype, deadline: ?std.Io.Clock.Timestamp) !Server {
    var connection = connection_value;
    var connection_owned = true;
    errdefer if (connection_owned) {
        if (deadline != null) connection.closeWithoutCloseNotify() else connection.close();
    };
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(connection.io, until);
        try connection.io.checkCancel();
    }
    try options.validate();
    const state = try allocator.create(State);
    var state_owned = true;
    errdefer if (state_owned) allocator.destroy(state);
    const pending = try allocator.alloc(PendingSlot, options.max_pending_sessions);
    var pending_owned = true;
    errdefer if (pending_owned) allocator.free(pending);
    const sessions = try allocator.alloc(SessionSlot, options.max_sessions);
    var sessions_owned = true;
    errdefer if (sessions_owned) allocator.free(sessions);
    @memset(pending, .{});
    @memset(sessions, .{});
    state.* = .{ .allocator = allocator, .io = connection.io, .options = options, .connection = connection, .pending = pending, .sessions = sessions };
    connection_owned = false;
    state_owned = false;
    pending_owned = false;
    sessions_owned = false;
    return @import("../endpoint/initialization.zig").start(Server, run, state, deadline);
}
