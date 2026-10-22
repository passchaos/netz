//! WebTransport session state and application queues follow QUIC termination.

const control_mod = @import("session_control.zig");
const quic = @import("../../quic/mod.zig");

pub const max_close_reason: usize = 1024;

pub fn terminating(connection: *const quic.one_rtt.Connection) bool {
    return connection.closing() or connection.draining() or connection.closed();
}

pub fn activate(control: *control_mod.Control, h3: anytype, registry: anytype) void {
    control.bindFlow(registry.flow);
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    _ = observe(control, h3, registry);
}

pub fn observe(control: *control_mod.Control, h3: anytype, registry: anytype) bool {
    if (registry.flow_violation) {
        control.flow_violation = true;
        control.capsule_error_pending = !control.capsule_error_reported;
        _ = control.tryRejectInvalidCapsule(&h3.established.connection) catch false;
    }
    if (!control.observeConnection(&h3.established.connection)) return false;
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    h3.connect_datagrams.markTerminal(control.session_id.value, .connection_closed);
    return true;
}

pub fn ensureOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    control.bindFlow(registry.flow);
    if (observe(control, h3, registry)) return error.ConnectionClosed;
    try control.ensureOpen();
}

pub fn ensureDatagramReceiveOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    control.bindFlow(registry.flow);
    // This also supports callers that assemble a preconfigured session value
    // directly rather than promoting it through a CONNECT constructor.
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    if (observe(control, h3, registry)) return error.ConnectionClosed;
    try control.ensureDatagramReceiveOpen();
}
