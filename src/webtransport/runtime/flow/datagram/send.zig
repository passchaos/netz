//! DATAGRAM waits service CONNECT capsules while preserving one socket owner.
const std = @import("std");
const control_mod = @import("../../session_control.zig");
const webtransport = @import("../../../mod.zig");
const progress_mod = @import("../progress.zig");
const quic = @import("../../../../quic/mod.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

pub const Error = control_mod.Error || quic.runtime.ReceiveTimeoutError;

fn Context(comptime H3Pointer: type) type {
    return struct {
        base: *progress_mod.Context(H3Pointer),
        pub const ErrorSet = Error;

        pub fn maintain(self: @This(), deadline: ?std.Io.Clock.Timestamp) Error!void {
            return self.base.progress().maintain(deadline);
        }

        pub fn waitForPacing(self: @This(), deadline: std.Io.Clock.Timestamp) Error!void {
            const connection = &self.base.h3.established.connection;
            _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
            const wake_ns = connection.pendingPacingDeadline() orelse return error.PacingLimited;
            const wake: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(@intCast(wake_ns)) };
            const until = deadline_policy.earlier(wake, deadline).?;
            if (until.durationFromNow(connection.endpoint.io).raw.nanoseconds <= 0) return;
            // Wait on this protocol's existing receive pump until either peer
            // control arrives or pacing permits another one-attempt send.
            const H3 = @typeInfo(H3Pointer).pointer.child;
            const result = if (comptime @hasDecl(H3, "receiveDetachedRequestProgressWithDeadline"))
                self.base.h3.receiveDetachedRequestProgressWithDeadline(self.base.control.session_id.value, until)
            else
                self.base.h3.receiveDetachedResponseProgressWithDeadline(self.base.control.session_id.value, until);
            result catch |err| {
                if (err == error.Timeout and std.Io.Clock.Timestamp.compare(until, .lt, deadline)) return;
                return err;
            };
        }
    };
}

pub fn single(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, payload: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
    var base = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = true };
    return h3.sendConnectDatagramWithProgress(id, payload, deadline, Context(@TypeOf(h3)){ .base = &base });
}

pub fn batch(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, payloads: []const []const u8, committed: *usize, deadline: std.Io.Clock.Timestamp) Error!void {
    var base = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = true };
    return h3.sendConnectDatagramsWithProgress(id, payloads, committed, deadline, Context(@TypeOf(h3)){ .base = &base });
}
