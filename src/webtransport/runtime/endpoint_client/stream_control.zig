//! Cancellation for one Session on a shared, single-owner HTTP/3 client.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const flow_cancel = @import("../flow/cancel.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Session = Context.SessionType;
        const Client = Context.ClientType;
        const Error = Context.ErrorType;
        const TimeoutError = Context.TimeoutErrorType;
        const Operation = flow_cancel.Operation;

        /// Abort after guaranteeing `reliable_size` application bytes. The
        /// association prefix is added internally and never charged as data.
        pub fn resetStreamReliably(session: *Session, client: *Client, stream_id: u62, code: u32, reliable_size: u64) Error!void {
            try prepare(session, client);
            defer observe(session, client);
            try flow_cancel.cancel(&session.control, &client.h3, &session.streams, stream_id, code, .{ .reliable = reliable_size });
        }

        pub fn resetStreamWithTimeout(session: *Session, client: *Client, stream_id: u62, code: u32, timeout: std.Io.Duration) TimeoutError!void {
            return resetStreamWithDeadline(session, client, stream_id, code, try deadline(client, timeout));
        }

        pub fn resetStreamWithDeadline(session: *Session, client: *Client, stream_id: u62, code: u32, absolute: std.Io.Clock.Timestamp) TimeoutError!void {
            return cancel(session, client, stream_id, code, .reset, absolute);
        }

        pub fn resetStreamReliablyWithTimeout(session: *Session, client: *Client, stream_id: u62, code: u32, reliable_size: u64, timeout: std.Io.Duration) TimeoutError!void {
            return resetStreamReliablyWithDeadline(session, client, stream_id, code, reliable_size, try deadline(client, timeout));
        }

        pub fn resetStreamReliablyWithDeadline(session: *Session, client: *Client, stream_id: u62, code: u32, reliable_size: u64, absolute: std.Io.Clock.Timestamp) TimeoutError!void {
            return cancel(session, client, stream_id, code, .{ .reliable = reliable_size }, absolute);
        }

        pub fn stopStreamWithTimeout(session: *Session, client: *Client, stream_id: u62, code: u32, timeout: std.Io.Duration) TimeoutError!void {
            return stopStreamWithDeadline(session, client, stream_id, code, try deadline(client, timeout));
        }

        pub fn stopStreamWithDeadline(session: *Session, client: *Client, stream_id: u62, code: u32, absolute: std.Io.Clock.Timestamp) TimeoutError!void {
            return cancel(session, client, stream_id, code, .stop, absolute);
        }

        fn prepare(session: *Session, client: *Client) Error!void {
            try Context.validateOwner(session, client);
            try Context.ensureConnectionOpen(client);
            try lifecycle.ensureOpen(&session.control, &client.h3, &session.streams);
        }

        fn observe(session: *Session, client: *Client) void {
            // Any owning operation can receive connection termination while
            // waiting for progress. Publish it to every shared Session before
            // returning; scoped Session CLOSE still affects only this owner.
            if (!Context.observeConnection(client)) {
                _ = lifecycle.observe(&session.control, &client.h3, &session.streams);
            }
        }

        fn deadline(client: *Client, timeout: std.Io.Duration) TimeoutError!std.Io.Clock.Timestamp {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return .fromNow(client.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake });
        }

        /// Retry only before socket submission. Route HTTP/3 progress through
        /// its owning reader, preserving unrelated Session events in place.
        fn cancel(session: *Session, client: *Client, stream_id: u62, code: u32, operation: Operation, absolute: std.Io.Clock.Timestamp) TimeoutError!void {
            _ = try deadline_policy.usableAwake(client.h3.established.connection.endpoint.io, absolute);
            try Context.validateOwner(session, client);
            if (client.h3.dispatcherBound()) return error.InvalidDispatcherState;
            if (client.h3.callback_reader_active) return error.ConcurrentRead;
            try prepare(session, client);
            defer observe(session, client);
            return flow_cancel.cancelUntil(&session.control, &client.h3, &session.streams, stream_id, code, operation, absolute);
        }
    };
}
