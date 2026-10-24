//! Advisory DRAIN with fixed encoded storage and resumable HTTP/3 DATA.
const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const body_fragment = @import("../../../http3/runtime/send/body_fragment.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const flow_progress = @import("../flow/progress.zig");

pub const State = struct {
    bytes: [16]u8 = undefined,
    len: u8 = 0,
    fragment: body_fragment.State = .{},

    pub fn pending(self: State) bool {
        return self.len != 0;
    }

    pub const isPending = pending;

    pub fn clear(self: *State) void {
        self.* = .{};
    }

    pub fn prepare(self: *State, control: *control_mod.Control) control_mod.Error!void {
        if (self.pending()) return;
        const encoded = try control_mod.writeDrainInto(&self.bytes);
        try control.beginLocalDrain();
        self.len = @intCast(encoded.len);
    }

    pub fn advanceOnce(self: *State, h3: *http3.runtime.HandshakeClient, control: *control_mod.Control, reply: *bool) control_mod.Error!control_mod.TerminateProgress {
        if (!self.pending()) return .complete;
        if (control.local_close_failed or control.handledInvalidCapsule()) {
            self.clear();
            return .complete;
        }
        if (control.terminal_reported) {
            if (self.fragment.wire_sent != 0) {
                try h3.tryCancelRequest(control.session_id.value, webtransport.ApplicationErrorCode.session_gone);
                control.recordLocalCloseFailure(0);
                reply.* = false;
                self.clear();
                return .submitted;
            }
            control.local_drain_started = false;
            reply.* = true;
            self.clear();
            return .complete;
        }
        body_fragment.write(&h3.established.connection, &h3.outbound_bodies, control.session_id.value, self.bytes[0..self.len], false, &self.fragment, h3.options) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected, error.StreamStopped, error.StreamStateError, error.UnexpectedStream, error.ConnectionClosed, error.ConnectionUnusable => {
                control.recordLocalCloseFailure(0);
                self.clear();
                return err;
            },
            else => return err,
        };
        if (self.fragment.complete) {
            self.clear();
            try control.recordLocalDrain();
        }
        return .submitted;
    }
};

pub fn Controller(comptime Context: type) type {
    return struct {
        const Session = Context.SessionType;
        const Client = Context.ClientType;
        const Error = Context.ErrorType;
        const TimeoutError = Context.TimeoutErrorType;

        pub fn drain(session: *Session, client: *Client) Error!void {
            return run(session, client, null);
        }

        pub fn drainWithTimeout(session: *Session, client: *Client, timeout: std.Io.Duration) TimeoutError!void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return drainWithDeadline(session, client, .fromNow(client.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
        }

        pub fn drainWithDeadline(session: *Session, client: *Client, deadline: std.Io.Clock.Timestamp) TimeoutError!void {
            _ = try deadline_policy.usableAwake(client.h3.established.connection.endpoint.io, deadline);
            return run(session, client, deadline);
        }

        fn run(session: *Session, client: *Client, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
            try Context.validateOwner(session, client);
            if (client.h3.dispatcherBound()) return error.InvalidDispatcherState;
            if (client.h3.callback_reader_active) return error.ConcurrentRead;
            try Context.ensureConnectionOpen(client);
            defer {
                if (!Context.observeConnection(client)) _ = lifecycle.observe(&session.control, &client.h3, &session.streams);
                if (session.control.connection_terminated or session.control.local_close_failed) session.drain_state.clear();
            }
            if (session.control.local_drain_sent) return;
            try session.drain_state.prepare(&session.control);
            const connection = &client.h3.established.connection;
            while (session.drain_state.pending()) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
                if (Context.observeConnection(client)) return error.ConnectionClosed;
                try flow_progress.buffered(&session.control, connection);
                _ = Context.advanceOnce(&client.h3, &session.control, &session.streams, &session.close_response_pending, &session.close_state, &session.drain_state) catch |err| switch (err) {
                    error.PacingLimited => {
                        if (deadline) |absolute| try connection.waitForPacingAvailabilityWithDeadline(absolute) else try connection.waitForPacingAvailability();
                        continue;
                    },
                    error.CongestionLimited, error.FlowControlBlocked => {
                        if (deadline) |absolute| try client.h3.receiveDetachedResponseProgressWithDeadline(session.session_id.value, absolute) else try client.h3.receiveDetachedResponseProgress(session.session_id.value);
                        continue;
                    },
                    else => return err,
                };
                if (session.control.state.closed) return error.InvalidSessionState;
            }
        }
    };
}
