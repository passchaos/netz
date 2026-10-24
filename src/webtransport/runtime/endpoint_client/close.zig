//! Retained client CLOSE metadata and one-packet DATA/FIN progress.
const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const flow_progress = @import("../flow/progress.zig");
const body_fragment = @import("../../../http3/runtime/send/body_fragment.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const State = struct {
    pending: ?@import("../session_control/pending_close.zig").Pending = null,
    fragment: body_fragment.State = .{},

    pub fn clear(self: *State) void {
        if (self.pending) |*pending| pending.deinit();
        self.* = .{};
    }

    pub fn isPending(self: *const State) bool {
        return self.pending != null;
    }

    pub fn prepare(self: *State, h3: *http3.runtime.HandshakeClient, control: *control_mod.Control, code: u32, reason: []const u8) control_mod.Error!void {
        if (self.pending) |*pending| {
            if (!try pending.matches(code, reason)) return error.InvalidSessionState;
            return;
        }
        var pending = try @import("../session_control/pending_close.zig").Pending.init(h3.allocator, code, reason);
        errdefer pending.deinit();
        try control.beginLocalClose();
        self.pending = pending;
        self.fragment = .{};
    }

    pub fn advanceOnce(self: *State, h3: *http3.runtime.HandshakeClient, control: *control_mod.Control, reply: *bool) control_mod.Error!control_mod.TerminateProgress {
        if (self.pending == null) return .complete;
        if (control.local_close_failed or control.local_close_sent or control.handledInvalidCapsule()) {
            self.clear();
            return .complete;
        }
        if (control.terminal_reported) {
            if (self.fragment.wire_sent != 0) {
                // An incomplete DATA frame cannot be followed by an empty FIN.
                try h3.tryCancelRequest(control.session_id.value, webtransport.ApplicationErrorCode.session_gone);
                control.recordLocalCloseFailure(0);
                reply.* = false;
                self.clear();
                return .submitted;
            }
            control.local_close_started = false;
            reply.* = true;
            self.clear();
            return .complete;
        }
        const pending = &self.pending.?;
        body_fragment.write(&h3.established.connection, &h3.outbound_bodies, control.session_id.value, pending.bytes(), true, &self.fragment, h3.options) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected, error.StreamStopped, error.StreamStateError, error.UnexpectedStream, error.ConnectionClosed, error.ConnectionUnusable => {
                control.recordLocalCloseFailure(pending.code);
                self.clear();
                return err;
            },
            else => return err,
        };
        if (self.fragment.complete) {
            const code = pending.code;
            self.clear();
            try control.recordLocalClose(code);
            reply.* = false;
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

        pub fn close(session: *Session, client: *Client, code: u32, reason: []const u8) Error!void {
            return run(session, client, code, reason, null);
        }

        pub fn closeWithTimeout(session: *Session, client: *Client, code: u32, reason: []const u8, timeout: std.Io.Duration) TimeoutError!void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return closeWithDeadline(session, client, code, reason, .fromNow(client.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
        }

        pub fn closeWithDeadline(session: *Session, client: *Client, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) TimeoutError!void {
            _ = try deadline_policy.usableAwake(client.h3.established.connection.endpoint.io, deadline);
            return run(session, client, code, reason, deadline);
        }

        fn run(session: *Session, client: *Client, code: u32, reason: []const u8, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
            try Context.validateOwner(session, client);
            if (client.h3.dispatcherBound()) return error.InvalidDispatcherState;
            if (client.h3.callback_reader_active) return error.ConcurrentRead;
            try Context.ensureConnectionOpen(client);
            // A partial DRAIN DATA frame must be finished before CLOSE can
            // start its own contribution on the same CONNECT send direction.
            if (session.drain_state.pending()) return error.InvalidSessionState;
            defer {
                if (!Context.observeConnection(client)) _ = lifecycle.observe(&session.control, &client.h3, &session.streams);
                if (session.control.connection_terminated or session.control.local_close_failed) session.close_state.clear();
            }
            if (!session.control.local_close_sent and !session.control.local_close_failed) {
                if (session.control.terminal_reported and session.close_state.pending == null) {
                    session.close_response_pending = true;
                } else try session.close_state.prepare(&client.h3, &session.control, code, reason);
            }
            const connection = &client.h3.established.connection;
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
                if (Context.observeConnection(client)) return error.ConnectionClosed;
                // Preserve peer terminal events while inspecting control data;
                // every resulting rejection precedes an ordinary CLOSE/FIN.
                try flow_progress.buffered(&session.control, connection);
                const result = advance(session, client);
                const progress = result catch |err| switch (err) {
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
                if (progress == .complete) return;
            }
        }

        fn advance(session: *Session, client: *Client) Error!control_mod.TerminateProgress {
            return Context.advanceOnce(&client.h3, &session.control, &session.streams, &session.close_response_pending, &session.close_state, &session.drain_state);
        }
    };
}
