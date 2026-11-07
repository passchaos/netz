//! Network termination keeps received diagnostics owned without allowing any
//! subsequent MQTT packet to be sent or read from the terminated transport.

pub fn usable(connection: anytype) bool {
    return !connection.transport_unusable.load(.acquire) and
        !connection.peer_disconnect_received.load(.acquire);
}

/// Received packets preceding DISCONNECT can still be delivered from the
/// bounded queue. A local shutdown or ambiguous write failure forbids reuse.
pub fn canReadBuffered(connection: anytype) bool {
    return !connection.transport_unusable.load(.acquire);
}

pub fn receivedDisconnect(connection: anytype) void {
    if (!connection.peer_disconnect_received.swap(true, .acq_rel)) {
        if (!shutdownDeferred(connection)) connection.transport.interrupt() catch {};
    }
}

pub fn shutdownDeferred(connection: anytype) bool {
    return connection.defer_peer_disconnect_shutdown and
        connection.peer_disconnect_received.load(.acquire) and
        !connection.peer_disconnect_shutdown_ready.load(.acquire);
}

pub fn sentDisconnect(connection: anytype) void {
    connection.transport_unusable.store(true, .release);
    connection.transport.interrupt() catch {};
}
