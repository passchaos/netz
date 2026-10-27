const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn cleanupDeadline(connection: anytype, operation_deadline: ?std.Io.Clock.Timestamp) ?std.Io.Clock.Timestamp {
    // An expired read deadline cannot be used to send the cancellation. Give
    // terminal control writes their own bounded budget. When the
    // operation still has time (e.g. OOM), retain its earlier absolute bound.
    const timeout = connection.limits.terminal_cleanup_timeout;
    if (timeout.nanoseconds > 0) {
        const cleanup_deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = timeout, .clock = .awake });
        return if (operation_deadline) |outer|
            if (deadline_policy.usableAwake(connection.io, outer)) |valid|
                deadline_policy.earlier(valid, cleanup_deadline).?
            else |_|
                cleanup_deadline
        else
            cleanup_deadline;
    }
    return null;
}

/// Bound terminal output while preserving a supplied absolute deadline even
/// after expiry. Never renew a refund/reset budget already captured by a caller.
pub fn limitDeadline(connection: anytype, existing: ?std.Io.Clock.Timestamp) ?std.Io.Clock.Timestamp {
    const cap = cleanupDeadline(connection, null) orelse return null;
    if (existing) |deadline| {
        if (deadline.clock != .awake) return null;
        return deadline_policy.earlier(deadline, cap);
    }
    return cap;
}

/// Refund and reset share one absolute cleanup deadline. Expiry during the
/// refund never renews the budget or permits a reset after a partial write.
pub fn returnCapacity(connection: anytype, amount: usize, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    connection.aggregate_timeout_unusable = true;
    if (connection.terminal_write_failed or amount == 0) return;
    if (before) |deadline| {
        Hooks.refund(connection, amount, deadline) catch {
            connection.terminal_write_failed = true;
        };
    } else {
        // Opting out of transport cleanup still retires local ownership.
        var remaining = amount;
        while (remaining != 0) {
            const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
            connection.recv_connection_window.update(increment) catch {
                connection.terminal_write_failed = true;
                return;
            };
            remaining -= increment;
        }
    }
}

/// Retire discarded parser state without allocating reset history, even when
/// the bounded control write fails or the caller opted out of cleanup writes.
pub fn failClosedBefore(connection: anytype, id: u31, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    connection.aggregate_timeout_unusable = true;
    if (before) |deadline| Hooks.reset(connection, id, .cancel, deadline) catch {} else connection.terminal_write_failed = true;
    Hooks.releaseLocal(connection, id);
    Hooks.releasePeer(connection, id);
    Hooks.forgetWindows(connection, id);
}

/// Application rejection is stream-local after a complete frame is delivered.
/// A failed refund/reset makes further byte-stream writes unsafe, while the
/// original callback error remains the error reported to the application.
pub fn callbackRejected(connection: anytype, id: u31, remote_ended: bool, comptime Hooks: anytype) void {
    if (!remote_ended and !connection.terminal_write_failed) {
        Hooks.reset(connection, id, .cancel) catch {
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
        };
    }
    Hooks.forgetWindows(connection, id);
}

/// Refund and cancellation after an application callback failure retain one
/// terminal write budget. A fully received frame permits healthy stream-local
/// cleanup, while failed output forbids another frame on the shared transport.
pub fn callbackRejectedBefore(connection: anytype, id: u31, remote_ended: bool, amount: usize, before: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) void {
    if (!connection.terminal_write_failed and amount != 0) {
        if (before) |deadline| {
            Hooks.refund(connection, amount, deadline) catch {
                connection.aggregate_timeout_unusable = true;
                connection.terminal_write_failed = true;
            };
        } else {
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
            var remaining = amount;
            while (remaining != 0) {
                const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
                connection.recv_connection_window.update(increment) catch {
                    connection.aggregate_timeout_unusable = true;
                    connection.terminal_write_failed = true;
                    break;
                };
                remaining -= increment;
            }
        }
    }
    if (!remote_ended and !connection.terminal_write_failed) {
        if (before) |deadline| {
            Hooks.reset(connection, id, .cancel, deadline) catch {
                connection.aggregate_timeout_unusable = true;
                connection.terminal_write_failed = true;
            };
        } else {
            connection.aggregate_timeout_unusable = true;
            connection.terminal_write_failed = true;
        }
    }
    Hooks.forgetWindows(connection, id);
}
