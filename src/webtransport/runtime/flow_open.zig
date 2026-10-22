//! Opening credit from ordered session Capsules before allocating a QUIC ID.

const std = @import("std");
const webtransport = @import("../mod.zig");
const control_mod = @import("session_control.zig");
const quic = @import("../../quic/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn prepare(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!u62 {
    return prepareInternal(control, h3, registry, null, direction, deadline);
}

pub fn prepareId(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!void {
    _ = try prepareInternal(control, h3, registry, id, direction, deadline);
}

fn attempt(registry: *webtransport.StreamRegistry, id: ?u62, direction: webtransport.StreamDirection) control_mod.Error!u62 {
    if (id) |value| {
        try registry.prepareLocalId(value, direction);
        return value;
    }
    return registry.prepareLocal(direction);
}

fn progress(control: *control_mod.Control, connection: *quic.one_rtt.Connection) control_mod.Error!void {
    control.progressFlow(connection) catch |err| {
        switch (err) {
            error.InvalidCapsule, error.FlowControlViolation => {
                // Opening may be the first operation to discover a malformed
                // CONNECT. Retain cleanup/reporting state across backpressure,
                // but submit its scoped rejection immediately when possible.
                _ = control.tryRejectInvalidCapsule(connection) catch |rejection_err| switch (rejection_err) {
                    error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => false,
                    else => return rejection_err,
                };
            },
            else => {},
        }
        return err;
    };
}

fn prepareInternal(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: ?u62, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!u62 {
    control.bindFlow(registry.flow);
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
        return attempt(registry, id, direction) catch |err| switch (err) {
            error.FlowControlBlocked => {
                try progress(control, &h3.established.connection);
                try control.ensureOpen();
                if (attempt(registry, id, direction)) |value| return value else |retry_err| {
                    if (retry_err != error.FlowControlBlocked) return retry_err;
                }
                const absolute = deadline orelse return error.FlowControlBlocked;
                if (h3.dispatcherBound()) return error.InvalidDispatcherState;
                const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
                if (comptime @hasDecl(H3, "receiveDetachedRequestProgressWithDeadline")) {
                    try h3.receiveDetachedRequestProgressWithDeadline(control.session_id.value, absolute);
                } else {
                    try h3.receiveDetachedResponseProgressWithDeadline(control.session_id.value, absolute);
                }
                try progress(control, &h3.established.connection);
                try control.ensureOpen();
                continue;
            },
            else => return err,
        };
    }
}
