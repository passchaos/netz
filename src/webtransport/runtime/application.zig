//! Buffered CONNECT events precede application stream reservations and sends.
const lifecycle = @import("connection_lifecycle.zig");
const flow_progress = @import("flow/progress.zig");
const control_mod = @import("session_control.zig");

/// One socket-free control pass retains DRAIN/CLOSE notifications. Stream
/// credit cannot bypass a peer CLOSE simply because no flow wait is needed.
pub fn ensureOpen(control: *control_mod.Control, h3: anytype, registry: anytype) control_mod.Error!void {
    try lifecycle.ensureOpen(control, h3, registry);
    try flow_progress.applicationBuffered(control, &h3.established.connection);
    try control.ensureOpen();
}
