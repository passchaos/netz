/// A request reader has discarded its only copy of admitted message state.
/// Retire connection reuse and every request made unreachable by that loss.
pub fn failClosed(connection: anytype, stream_id: u31, comptime Hooks: anytype) void {
    connection.aggregate_timeout_unusable = true;
    // Inner ownership guards may already have removed the active marker, but
    // the admitted wire stream still needs cancellation when it can be sent.
    var resets_possible = true;
    Hooks.reset(connection, stream_id, .cancel) catch {
        resets_possible = false;
    };
    Hooks.releasePeer(connection, stream_id);
    Hooks.forgetWindows(connection, stream_id);
    discardPending(connection, resets_possible, Hooks);
}

pub fn discardPending(connection: anytype, can_reset: bool, comptime Hooks: anytype) void {
    var resets_possible = can_reset;
    // Entries before the head transferred to callers and no longer belong to
    // the connection. Cancel and free only requests that remain queued.
    for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
        const id = Hooks.pendingId(pending.*);
        if (resets_possible and connection.active_peer_index.contains(id)) {
            Hooks.reset(connection, id, .cancel) catch {
                // A failed write can have committed an incomplete frame.
                // Continue freeing owners without appending further frames.
                resets_possible = false;
            };
        }
        Hooks.releasePeer(connection, id);
        Hooks.forgetWindows(connection, id);
        Hooks.deinitPending(pending, connection.allocator);
    }
    connection.pending_requests.items.len = 0;
    connection.pending_request_head = 0;
    connection.pending_accept_reset_streams = 0;
}
