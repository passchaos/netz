const http2 = @import("../../mod.zig");

pub const Failure = struct {
    cause: anyerror,
    stream_id: ?u31,
    stream_code: ?http2.ErrorCode,
    uninitialized_stream_id: ?u31,
    read_timed_out: bool,
    callback_failed: bool,
};

/// Batch outputs are owned until every member completes. Abort all response
/// halves with one precise error for the rejected member, CANCEL for remaining
/// members, or a connection GOAWAY when shared decoding cannot continue.
pub fn abort(connection: anytype, requests: anytype, failure: Failure, comptime Hooks: anytype) void {
    if (connection.serve_read_connection_error != null) {
        Hooks.sendConnectionError(connection, failure.cause);
    }
    const connection_failed = connection.serve_read_connection_error != null or
        (connection.aggregate_timeout_unusable and !failure.read_timed_out);
    if (failure.read_timed_out) connection.aggregate_timeout_unusable = true;

    const stream_code = if (!connection_failed and !failure.callback_failed and !failure.read_timed_out and failure.stream_id != null)
        failure.stream_code orelse Hooks.streamErrorCode(failure.cause)
    else
        null;
    if (stream_code) |code| {
        if (code == .refused_stream) {
            Hooks.reset(connection, failure.stream_id.?, code) catch {};
        } else {
            Hooks.errorReset(connection, failure.stream_id.?, code) catch {};
        }
    }

    // Admission can succeed before a header error prevents initialization of
    // its output slot. The inner admission guard may already have released the
    // stream, but its peer still needs the appropriate terminal frame.
    if (failure.uninitialized_stream_id) |id| {
        if (!connection_failed and (stream_code == null or failure.stream_id.? != id)) {
            Hooks.reset(connection, id, .cancel) catch {};
        }
        release(connection, id, Hooks);
    }
    for (requests) |*request| {
        if (!connection_failed and (stream_code == null or failure.stream_id.? != request.stream_id)) {
            Hooks.reset(connection, request.stream_id, .cancel) catch {};
        }
        release(connection, request.stream_id, Hooks);
        request.deinit(connection.allocator);
    }
}

fn release(connection: anytype, id: u31, comptime Hooks: anytype) void {
    Hooks.releasePeer(connection, id);
    Hooks.forgetWindows(connection, id);
}
