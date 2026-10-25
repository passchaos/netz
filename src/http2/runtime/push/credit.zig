//! Return only DATA credit still owned by a buffered push.
const std = @import("std");

pub fn release(connection: anytype, id: u31, extra: usize, deadline: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) Hooks.ErrorType!void {
    const state = connection.push_state.state orelse return;
    const amount = std.math.add(usize, state.received.takeConnectionCredit(id), extra) catch return error.MessageTooLarge;
    if (amount == 0) return;
    if (connection.terminal_write_failed) return error.ConnectionClosed;
    Hooks.returnCredit(connection, amount, deadline) catch |err| switch (err) {
        error.SocketUnconnected, error.ConnectionResetByPeer => {
            // Complete siblings can still be read from memory after peer close.
            try connection.recv_connection_window.update(@intCast(amount));
            connection.terminal_write_failed = true;
        },
        else => {
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
            return err;
        },
    };
}
