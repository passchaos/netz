//! WebTransport session state and application queues follow QUIC termination.

const control_mod = @import("session_control.zig");
const flow_credits = @import("flow/credits.zig");
const flow_streams = @import("flow/streams.zig");
const abandoned_receive = @import("association/abandoned.zig");
const quic = @import("../../quic/mod.zig");
const operation_owner = @import("owner.zig");

pub const max_close_reason: usize = 1024;

pub fn terminating(connection: *const quic.one_rtt.Connection) bool {
    return connection.closing() or connection.draining() or connection.closed();
}

pub fn observeGoAway(control: *control_mod.Control, h3: anytype) void {
    if (!terminating(&h3.established.connection)) control.observeGoAway(h3.control.peer_goaway_id);
}

pub fn observeConnectSend(control: *control_mod.Control, h3: anytype) void {
    if (!control.observeConnectSend(&h3.established.connection)) return;
    // Retain already-accepted DATAGRAMs under H3's queue contract, and reject
    // future arrivals for this association without affecting sibling Sessions.
    h3.connect_datagrams.markTerminal(control.session_id.value, .peer_fin);
}

pub fn observeConnectReceive(control: *control_mod.Control, h3: anytype) void {
    const connection = &h3.established.connection;
    if (!control.observeConnectReceive(connection)) return;
    if (connection.recvStreamStats(control.session_id.value).?.reset) |reset| {
        h3.connect_datagrams.markTerminal(control.session_id.value, .{ .peer_reset = reset.application_error_code });
    } else {
        h3.connect_datagrams.markTerminal(control.session_id.value, .peer_fin);
    }
}

pub fn activate(control: *control_mod.Control, h3: anytype, registry: anytype) void {
    control.bindFlow(registry.flow);
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    _ = observe(control, h3, registry);
}

pub fn observe(control: *control_mod.Control, h3: anytype, registry: anytype) bool {
    return observeInternal(control, h3, registry, true);
}

pub fn observeWithoutCredits(control: *control_mod.Control, h3: anytype, registry: anytype) bool {
    return observeInternal(control, h3, registry, false);
}

/// Deferred observation can submit a flow grant or scoped rejection after a
/// method's ordinary timer refresh. Mirror the resulting recovery/pacing work
/// before the shared socket owner next waits for an event.
pub fn observeWithTimer(control: *control_mod.Control, h3: anytype, registry: anytype, dispatcher: ?*quic.endpoint_dispatcher.Dispatcher, handle: ?quic.endpoint_dispatcher.ConnectionHandle) void {
    if (operation_owner.callbackBorrowed(h3)) return;
    _ = observe(control, h3, registry);
    const owner = dispatcher orelse return;
    owner.refreshConnectionTimer(handle orelse return) catch {};
}

fn observeInternal(control: *control_mod.Control, h3: anytype, registry: anytype, replenish: bool) bool {
    // Deferred observers also run when an application facade rejects reentry.
    // The existing callback keeps its borrowed input until it returns.
    if (operation_owner.callbackBorrowed(h3)) return false;
    observeConnectSend(control, h3);
    observeConnectReceive(control, h3);
    // DATAGRAM-only consumers and send-side flow waits still own Session
    // maintenance. Settle terminal receive bytes without consuming the RESET
    // notification, so they can return WT_MAX_DATA before another stream read.
    _ = abandoned_receive.drain(&h3.established.connection, registry, true) catch false;
    flow_streams.observeClosed(&h3.established.connection, registry);
    if (replenish) flow_credits.replenish(control, h3, registry);
    if (registry.flow_violation) {
        control.flow_violation = true;
        control.capsule_error_pending = !control.capsule_error_reported;
        _ = control.tryRejectInvalidCapsule(&h3.established.connection) catch false;
    }
    if (!control.observeConnection(&h3.established.connection)) {
        control.observeGoAway(h3.control.peer_goaway_id);
        return false;
    }
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    h3.connect_datagrams.markTerminal(control.session_id.value, .connection_closed);
    return true;
}

pub fn ensureOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    try operation_owner.buffered(h3);
    control.bindFlow(registry.flow);
    if (observeInternal(control, h3, registry, false)) return error.ConnectionClosed;
    try control.ensureOpen();
}

pub fn ensureCloseOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    try operation_owner.buffered(h3);
    control.bindFlow(registry.flow);
    if (observeInternal(control, h3, registry, false)) return error.ConnectionClosed;
    try control.ensureCloseOpen();
}

pub fn ensureDatagramReceiveOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    try operation_owner.buffered(h3);
    control.bindFlow(registry.flow);
    // This also supports callers that assemble a preconfigured session value
    // directly rather than promoting it through a CONNECT constructor.
    h3.connect_datagrams.discardOnConnectionClose(control.session_id.value);
    if (observeInternal(control, h3, registry, false)) return error.ConnectionClosed;
    try control.ensureDatagramReceiveOpen();
}
