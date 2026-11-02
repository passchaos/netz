//! Transactional client owner admission and unpublished-transport cleanup.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn create(comptime Client: type, comptime State: type, comptime Slot: type, comptime start: anytype, allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: anytype, deadline: ?std.Io.Clock.Timestamp) !Client {
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
    const slots = try allocator.alloc(Slot, options.max_sessions);
    var slots_owned = true;
    errdefer if (slots_owned) allocator.free(slots);
    @memset(slots, .{});
    state.* = .{ .allocator = allocator, .io = connection.io, .options = options, .connection = connection, .slots = slots };
    connection_owned = false;
    state_owned = false;
    slots_owned = false;
    state.retain();
    state.group.concurrent(state.io, start, .{state}) catch |err| {
        state.closed = true;
        state.worker_stopped = true;
        if (deadline != null) state.connection.closeWithoutCloseNotify() else state.connection.close();
        state.release();
        state.release();
        return err;
    };
    var client = Client{ .state = state };
    if (deadline) |until| {
        _ = deadline_policy.usableAwake(state.io, until) catch |err| {
            client.deinitAbortive();
            return err;
        };
        state.io.checkCancel() catch |err| {
            client.deinitAbortive();
            return err;
        };
    }
    return client;
}
