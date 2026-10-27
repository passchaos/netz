const std = @import("std");
const response_cleanup = @import("../response/cleanup.zig");

/// Capture once so refunds and every terminal frame share the same budget,
/// including the explicit zero-budget opt-out represented by null.
pub const Budget = struct {
    captured: bool = false,
    before: ?std.Io.Clock.Timestamp = null,

    pub fn get(self: *Budget, connection: anytype, operation: ?std.Io.Clock.Timestamp, timed_out: bool) ?std.Io.Clock.Timestamp {
        if (!self.captured) {
            self.captured = true;
            self.before = response_cleanup.cleanupDeadline(connection, if (timed_out) null else operation);
        }
        return self.before;
    }
};

pub fn refundBefore(connection: anytype, amount: usize, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    if (amount == 0) return;
    var remaining = amount;
    if (!connection.terminal_write_failed) {
        if (before) |deadline| {
            const initial = connection.recv_connection_window.value;
            Hooks.refund(connection, amount, deadline) catch {
                connection.aggregate_timeout_unusable = true;
                connection.terminal_write_failed = true;
                const credited: usize = @intCast(@max(connection.recv_connection_window.value - initial, 0));
                remaining -= @min(credited, amount);
            };
            if (!connection.terminal_write_failed) return;
        } else {
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
        }
    }
    {
        connection.aggregate_timeout_unusable = true;
        connection.terminal_write_failed = true;
        while (remaining != 0) {
            const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
            connection.recv_connection_window.update(increment) catch return;
            remaining -= increment;
        }
    }
}

/// A request reader has discarded its only copy of admitted message state.
/// Retire connection reuse and every request made unreachable by that loss.
pub fn failClosed(connection: anytype, stream_id: u31, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    connection.aggregate_timeout_unusable = true;
    // Inner ownership guards may already have removed the active marker, but
    // the admitted wire stream still needs cancellation when it can be sent.
    var resets_possible = before != null and !connection.terminal_write_failed;
    if (resets_possible) Hooks.reset(connection, stream_id, .cancel, before) catch {
        connection.terminal_write_failed = true;
        resets_possible = false;
    } else connection.terminal_write_failed = true;
    Hooks.releasePeer(connection, stream_id);
    Hooks.forgetWindows(connection, stream_id);
    discardPending(connection, resets_possible, before, Hooks);
}

pub fn discardPending(connection: anytype, can_reset: bool, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    var resets_possible = can_reset;
    // Entries before the head transferred to callers and no longer belong to
    // the connection. Cancel and free only requests that remain queued.
    for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
        const id = Hooks.pendingId(pending.*);
        if (resets_possible and connection.active_peer_index.contains(id)) {
            Hooks.reset(connection, id, .cancel, before) catch {
                // A failed write can have committed an incomplete frame.
                // Continue freeing owners without appending further frames.
                resets_possible = false;
                connection.terminal_write_failed = true;
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
