//! One-attempt stream cancellation shares its accepted CONNECT lifecycle.
const flow_cancel = @import("../flow/cancel.zig");
const flow_progress = @import("../flow/progress.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const streams = @import("../stream_incremental.zig");

/// Process only buffered CONNECT bytes; the dispatcher owns socket reads and
/// pacing. Control events stay in the Session for its next application poll.
pub fn cancel(target: anytype, stream_id: u62, code: u32, operation: flow_cancel.Operation) @TypeOf(target.resetStream(stream_id, code)) {
    defer lifecycle.observeWithTimer(&target.control, target.h3, &target.streams, target.dispatcher, target.handle);
    try lifecycle.ensureOpen(&target.control, target.h3, &target.streams);
    const connection = &target.h3.established.connection;
    try flow_progress.buffered(&target.control, connection);
    try target.control.ensureOpen();
    const result = switch (operation) {
        .reset => streams.resetOnce(connection, &target.streams, stream_id, code),
        .reliable => |size| streams.resetReliablyOnce(connection, &target.streams, stream_id, code, size),
        .stop => streams.stopOnce(connection, &target.streams, stream_id, code),
    };
    try target.dispatcher.refreshConnectionTimer(target.handle);
    try result;
}
