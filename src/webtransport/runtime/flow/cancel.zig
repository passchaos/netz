//! Stream cancellation waits share the owning CONNECT reader.
const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const streams = @import("../stream_incremental.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const progress_mod = @import("progress.zig");
const wait = @import("../stream/wait.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Operation = union(enum) { reset, reliable: u64, stop };
pub const Error = control_mod.Error;
pub const TimeoutError = progress_mod.Error;

pub fn cancel(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, code: u32, operation: Operation) Error!void {
    return cancelUntil(control, h3, registry, stream_id, code, operation, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

/// Retry only before socket submission. A received terminal event is retained
/// for its Session; failed attempts preserve the cancellation's registry state.
pub fn cancelUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, code: u32, operation: Operation, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    const connection = &h3.established.connection;
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    if (h3.dispatcherBound()) return error.InvalidDispatcherState;
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasField(H3, "callback_reader_active")) {
        if (h3.callback_reader_active) return error.ConcurrentRead;
    }
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = true };
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        try context.progress().maintain(deadline);
        try lifecycle.ensureOpen(control, h3, registry);
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        const result = switch (operation) {
            .reset => streams.resetOnce(connection, registry, stream_id, code),
            .reliable => |size| streams.resetReliablyOnce(connection, registry, stream_id, code, size),
            .stop => streams.stopOnce(connection, registry, stream_id, code),
        };
        result catch |err| switch (err) {
            error.PacingLimited => {
                try wait.pacing(connection, deadline, context.progress());
                continue;
            },
            error.CongestionLimited, error.FlowControlBlocked => {
                // Ordinary cancellation exposes these limits; bounded calls
                // service the owning reader while waiting for transport credit.
                if (deadline == null) return err;
                try wait.receive(connection, deadline, context.progress());
                continue;
            },
            else => return err,
        };
        // STOP is already committed. Reclaim receive bytes without submitting
        // the control frame again if capacity release encounters backpressure.
        if (operation == .stop) _ = try connection.discardStoppedReceived(stream_id);
        return;
    }
}
