//! Ordered CONNECT progress shared by flow-blocked opens and writes. The
//! callback context lives only for one synchronous owning-session operation.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Error = control_mod.Error || quic.runtime.ReceiveTimeoutError;

pub fn buffered(control: *control_mod.Control, connection: *quic.one_rtt.Connection) control_mod.Error!void {
    control.progressFlow(connection) catch |err| {
        switch (err) {
            error.InvalidCapsule, error.FlowControlViolation => {
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

pub const Progress = struct {
    context: *anyopaque,
    runFn: *const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void,

    pub fn run(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return self.runFn(self.context, deadline);
    }
};

pub fn Context(comptime H3Pointer: type) type {
    return struct {
        control: *control_mod.Control,
        h3: H3Pointer,
        registry: *webtransport.StreamRegistry,

        pub fn progress(self: *@This()) Progress {
            return .{ .context = self, .runFn = run };
        }

        fn run(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            const connection = &self.h3.established.connection;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
            self.control.bindFlow(self.registry.flow);
            try buffered(self.control, connection);
            try self.control.ensureOpen();
            if (self.registry.flow == null or self.registry.flow.?.sendDataAvailable() != 0) return;
            if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
            const H3 = @typeInfo(H3Pointer).pointer.child;
            if (comptime @hasDecl(H3, "receiveDetachedRequestProgress")) {
                if (deadline) |absolute|
                    try self.h3.receiveDetachedRequestProgressWithDeadline(self.control.session_id.value, absolute)
                else
                    try self.h3.receiveDetachedRequestProgress(self.control.session_id.value);
            } else {
                if (deadline) |absolute|
                    try self.h3.receiveDetachedResponseProgressWithDeadline(self.control.session_id.value, absolute)
                else
                    try self.h3.receiveDetachedResponseProgress(self.control.session_id.value);
            }
            try buffered(self.control, connection);
            try self.control.ensureOpen();
        }
    };
}
