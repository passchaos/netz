//! Release Broker-owned terminal I/O only after its persistence decision.
pub fn run(comptime Context: type, task: anytype, slot: anytype, connection: anytype) void {
    if (!connection.defer_peer_disconnect_shutdown or
        !connection.peer_disconnect_received.load(.acquire)) return;

    task.broker.state_mutex.lockUncancelable(task.broker.io);
    const applied = slot.state.graceful_disconnect;
    task.broker.state_mutex.unlock(task.broker.io);
    if (task.result.* != null and applied) {
        // A normal decision can already have removed its Will and Session
        // handle when encoding or fsync fails. Retry a coherent current image
        // through the existing coordinator before physical shutdown, without
        // replacing the first error or pretending repeated failure committed.
        Context.retryCurrentCommit(task.broker) catch {};
    }
    connection.completePeerDisconnect() catch {};
}
