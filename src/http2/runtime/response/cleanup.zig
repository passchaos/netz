/// A stack-based response reader cannot reconstruct discarded headers or body
/// state. Cancel its admitted stream without allocating reset history and
/// prevent later readers or pool leases from consuming ambiguous input.
pub fn failClosed(connection: anytype, id: u31, comptime Hooks: anytype) void {
    connection.aggregate_timeout_unusable = true;
    Hooks.reset(connection, id, .cancel) catch {};
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
