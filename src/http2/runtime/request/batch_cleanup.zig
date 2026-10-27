const http2 = @import("../../mod.zig");
const std = @import("std");
const cleanup = @import("cleanup.zig");

pub const Failure = struct {
    cause: anyerror,
    stream_id: ?u31,
    stream_code: ?http2.ErrorCode,
    uninitialized_stream_id: ?u31,
    read_lost_state: bool,
    callback_failed: bool,
    before: ?std.Io.Clock.Timestamp,
};

/// Batch outputs are owned until every member completes. Abort all response
/// halves with one precise error for the rejected member, CANCEL for remaining
/// members, or a connection GOAWAY when shared decoding cannot continue.
pub fn abort(connection: anytype, requests: anytype, failure: Failure, comptime Hooks: anytype) void {
    if (connection.serve_read_connection_error != null) {
        Hooks.sendConnectionError(connection, failure.cause, failure.before);
    }
    const connection_failed = connection.serve_read_connection_error != null or
        (connection.aggregate_timeout_unusable and !failure.read_lost_state);
    if (failure.read_lost_state) connection.aggregate_timeout_unusable = true;
    var resets_possible = !connection_failed and !connection.terminal_write_failed and failure.before != null;
    if (failure.before == null) {
        connection.aggregate_timeout_unusable = true;
        connection.terminal_write_failed = true;
    }

    const stream_code = if (!connection_failed and !failure.callback_failed and !failure.read_lost_state and failure.stream_id != null)
        failure.stream_code orelse Hooks.streamErrorCode(failure.cause)
    else
        null;
    if (stream_code) |code| if (resets_possible) {
        if (code == .refused_stream) {
            Hooks.reset(connection, failure.stream_id.?, code, failure.before) catch {
                resets_possible = false;
            };
        } else {
            Hooks.errorReset(connection, failure.stream_id.?, code, failure.before) catch {
                resets_possible = false;
            };
        }
    };

    // Admission can succeed before a header error prevents initialization of
    // its output slot. The inner admission guard may already have released the
    // stream, but its peer still needs the appropriate terminal frame.
    if (failure.uninitialized_stream_id) |id| {
        if (resets_possible and (stream_code == null or failure.stream_id.? != id)) {
            resets_possible = cancel(connection, id, failure.read_lost_state, failure.before, Hooks);
        }
        release(connection, id, Hooks);
    }
    for (requests) |*request| {
        if (resets_possible and (stream_code == null or failure.stream_id.? != request.stream_id)) {
            resets_possible = cancel(connection, request.stream_id, failure.read_lost_state, failure.before, Hooks);
        }
        release(connection, request.stream_id, Hooks);
        request.deinit(connection.allocator);
    }
    if (!resets_possible) {
        connection.aggregate_timeout_unusable = true;
        connection.terminal_write_failed = true;
    }
    if (connection.aggregate_timeout_unusable) {
        cleanup.discardPending(connection, resets_possible, failure.before, .{
            .reset = Hooks.terminalReset,
            .releasePeer = Hooks.releasePeer,
            .forgetWindows = Hooks.forgetWindows,
            .pendingId = Hooks.pendingId,
            .deinitPending = Hooks.deinitPending,
        });
    }
}

fn cancel(connection: anytype, id: u31, terminal: bool, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) bool {
    if (terminal) {
        Hooks.terminalReset(connection, id, .cancel, before) catch return false;
    } else {
        Hooks.reset(connection, id, .cancel, before) catch return false;
    }
    return true;
}

fn release(connection: anytype, id: u31, comptime Hooks: anytype) void {
    Hooks.releasePeer(connection, id);
    Hooks.forgetWindows(connection, id);
}
