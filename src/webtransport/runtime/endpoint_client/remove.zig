//! Keep Session ownership through every terminal submission and bounded retry.
const std = @import("std");
const webtransport = @import("../../mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const terminal = @import("terminal.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Client = Context.ClientType;

        pub fn removeSession(client: *Client, session_id: webtransport.SessionId) Context.ErrorType!bool {
            return run(client, session_id, null);
        }

        pub fn removeSessionWithTimeout(client: *Client, session_id: webtransport.SessionId, timeout: std.Io.Duration) Context.TimeoutErrorType!bool {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return removeSessionWithDeadline(client, session_id, .fromNow(client.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
        }

        pub fn removeSessionWithDeadline(client: *Client, session_id: webtransport.SessionId, deadline: std.Io.Clock.Timestamp) Context.TimeoutErrorType!bool {
            _ = try deadline_policy.usableAwake(client.h3.established.connection.endpoint.io, deadline);
            return run(client, session_id, deadline);
        }

        fn run(client: *Client, session_id: webtransport.SessionId, deadline: ?std.Io.Clock.Timestamp) Context.TimeoutErrorType!bool {
            const current = client.sessions.get(session_id.value) orelse return false;
            if (client.h3.dispatcherBound()) return error.InvalidDispatcherState;
            if (client.h3.callback_reader_active) return error.ConcurrentRead;
            if (!Context.observeConnection(client)) try client.pending_open_cleanup.advance(&client.h3);
            current.control.bindFlow(current.streams.flow);
            if (deadline) |absolute| {
                try terminal.finishWithDeadline(&client.h3, &current.control, &current.streams, &current.close_response_pending, &current.close_state, &current.drain_state, absolute);
            } else {
                try terminal.finish(&client.h3, &current.control, &current.streams, &current.close_response_pending, &current.close_state, &current.drain_state);
            }
            const removed = client.sessions.fetchRemove(session_id.value).?.value;
            Context.deinitSession(removed, client);
            client.allocator.destroy(removed);
            if (client.last_ready_session_id == session_id.value) client.last_ready_session_id = null;
            return true;
        }
    };
}
