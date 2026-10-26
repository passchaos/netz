//! Bounded, final output for an owned client stream. Local ownership is always
//! retired; a failed write must never be retried by an adapter destructor.
const std = @import("std");

pub fn reset(connection: anytype, id: u31, code: anytype, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) !void {
    defer retire(connection, id, Hooks);
    try usableOutput(connection, before);
    if (!Hooks.active(connection.*, id)) return error.InvalidStreamId;
    Hooks.reset(connection, id, code, before) catch |err| {
        failOutput(connection);
        return err;
    };
}

/// The response has already committed its terminal result. Only an empty
/// request-half FIN remains, and failure cannot invalidate that result.
pub fn finish(connection: anytype, id: u31, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) !void {
    defer retire(connection, id, Hooks);
    try usableOutput(connection, before);
    if (!Hooks.active(connection.*, id)) return error.InvalidStreamId;
    Hooks.emptyData(connection.allocator, Hooks.transport(connection), id, true, before) catch |err| {
        failOutput(connection);
        return err;
    };
}

fn usableOutput(connection: anytype, before: ?std.Io.Clock.Timestamp) !void {
    if (connection.aggregate_timeout_unusable or connection.terminal_write_failed) {
        failOutput(connection);
        return error.ConnectionClosed;
    }
    if (connection.callback_reader_active) {
        failOutput(connection);
        return error.UnexpectedFrame;
    }
    if (before == null) {
        // Zero cleanup budget deliberately skips transport work.
        failOutput(connection);
        return error.Timeout;
    }
}

fn failOutput(connection: anytype) void {
    connection.aggregate_timeout_unusable = true;
    connection.terminal_write_failed = true;
}

fn retire(connection: anytype, id: u31, comptime Hooks: anytype) void {
    Hooks.releaseLocal(connection, id);
    Hooks.releasePeer(connection, id);
    Hooks.forgetWindows(connection, id);
}
