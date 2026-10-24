//! Peer failures carry their proven scope through one synchronous receive.
//! The capture never outlives that call or changes callback receive semantics.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const http3_error = @import("../../../http3/runtime/error.zig");
const rejection = @import("../connect/rejection.zig");
const lifecycle = @import("../connection_lifecycle.zig");

pub const ConnectRejectionReason = enum {
    invalid_connect,
    webtransport_not_negotiated,
    datagrams_not_negotiated,
    reliable_reset_not_negotiated,
    session_flow_control_required,
    session_limit_exceeded,
    http3_request_error,

    fn fromPending(pending: rejection.Pending) ConnectRejectionReason {
        if (pending.request_failure != null) return .http3_request_error;
        const failure = pending.failure orelse return .session_limit_exceeded;
        return switch (failure) {
            .invalid_connect => .invalid_connect,
            .webtransport_not_negotiated => .webtransport_not_negotiated,
            .datagrams_not_negotiated => .datagrams_not_negotiated,
            .reliable_reset_not_negotiated => .reliable_reset_not_negotiated,
            .session_flow_control_required => .session_flow_control_required,
        };
    }
};

pub const ConnectRejection = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    session_id: webtransport.SessionId,
    reason: ConnectRejectionReason,
    application_error_code: u64,
    /// Present for errors produced by HTTP/3 message parsing before CONNECT
    /// negotiation, such as a missing pseudo-header or truncated request.
    http3_error: ?http3.runtime.Error = null,
};

pub const ConnectionFailure = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    err: runtime.EndpointServerError,
    application_error_code: u64,
};

pub const SessionFailure = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    session_id: webtransport.SessionId,
    err: error{ InvalidCapsule, FlowControlViolation },
    application_error_code: u64,
};

const Notification = union(enum) {
    connect_rejected: ConnectRejection,
    connection_failed: ConnectionFailure,
    session_failed: SessionFailure,
};

pub const Capture = struct {
    err: runtime.EndpointServerError,
    notification: Notification,
};

fn record(server: *runtime.EndpointServer, err: runtime.EndpointServerError, notification: Notification) bool {
    const sink = server.serve_failure_sink orelse return false;
    if (sink.* != null) return false;
    sink.* = .{ .err = err, .notification = notification };
    return true;
}

/// Called only after the CONNECT cancellation reaches the socket. A captured
/// completion interrupts this receive, including otherwise-silent capacity
/// refusals, so no subsequent refusal can overwrite its metadata.
pub fn noteConnect(server: *runtime.EndpointServer, handle: quic.endpoint_dispatcher.ConnectionHandle, pending: rejection.Pending) bool {
    return record(server, error.RequestRejected, .{ .connect_rejected = .{
        .handle = handle,
        .session_id = .init(pending.stream_id),
        .reason = .fromPending(pending),
        .application_error_code = pending.application_error_code,
        .http3_error = if (pending.request_failure) |failure| failure.err else null,
    } });
}

pub fn noteConnection(server: *runtime.EndpointServer, handle: quic.endpoint_dispatcher.ConnectionHandle, err: runtime.EndpointServerError) void {
    if (server.serve_failure_sink == null) return;
    const close = http3_error.protocolClose(err) orelse return;
    const h3 = server.h3.session(handle) orelse return;
    const connection = &h3.established.connection;
    if (!lifecycle.terminating(connection) or connection.peer_close_frame_received) return;
    const actual = connection.close_info orelse return;
    if (!actual.application or actual.error_code != close.code) return;
    _ = record(server, err, .{ .connection_failed = .{ .handle = handle, .err = err, .application_error_code = close.code } });
}

pub fn noteSession(server: *runtime.EndpointServer, session: *runtime.EndpointAcceptedSession, err: runtime.EndpointServerError) void {
    if (server.serve_failure_sink == null) return;
    if (err != error.InvalidCapsule and err != error.FlowControlViolation) return;
    const connection = &session.h3.established.connection;
    if (lifecycle.terminating(connection) or !session.control.state.closed or !session.control.handledInvalidCapsule()) return;
    const stats = connection.sendStreamStats(session.session_id.value) orelse return;
    const reset = stats.reset orelse return;
    const code: u64 = if (err == error.FlowControlViolation) webtransport.ApplicationErrorCode.flow_control_error else http3.ApplicationErrorCode.message_error;
    if (reset.application_error_code != code) return;
    _ = record(server, err, .{ .session_failed = .{
        .handle = session.handle,
        .session_id = session.session_id,
        .err = @errorCast(err),
        .application_error_code = code,
    } });
}

const Receive = *const fn (*runtime.EndpointServer, []const u32, std.Io.Clock.Duration, []u8) runtime.EndpointServerError!?runtime.EndpointServerEvent;
const Poll = union(enum) { event: runtime.EndpointServerEvent, failure: Notification };

fn poll(server: *runtime.EndpointServer, comptime receive: Receive, options: runtime.ServeOptions, buffer: []u8) runtime.EndpointServerError!?Poll {
    if (server.serve_failure_sink != null) return error.ConcurrentRead;
    var capture: ?Capture = null;
    server.serve_failure_sink = &capture;
    defer server.serve_failure_sink = null;
    const event = receive(server, options.supported_versions, options.poll_interval, buffer) catch |err| {
        if (capture) |failure| {
            if (failure.err == err) return .{ .failure = failure.notification };
        }
        return err;
    } orelse return null;
    std.debug.assert(capture == null);
    return .{ .event = event };
}

pub fn run(server: *runtime.EndpointServer, comptime Context: type, context: *Context, comptime handler: *const fn (*Context, *runtime.EndpointServer, runtime.ServeEvent) anyerror!void, options: runtime.ServeOptions, comptime receive: Receive) anyerror!void {
    if (options.supported_versions.len == 0 or options.poll_interval.raw.nanoseconds <= 0 or options.stream_buffer_size == 0) return error.InvalidSessionState;
    const buffer = try server.allocator.alloc(u8, options.stream_buffer_size);
    defer server.allocator.free(buffer);
    while (!options.shutdown.isSet()) {
        const ready = poll(server, receive, options, buffer) catch |err| {
            if (err == error.Canceled and options.shutdown.isSet()) return;
            return err;
        } orelse continue;
        switch (ready) {
            .failure => |failure| switch (failure) {
                .connect_rejected => |value| try handler(context, server, .{ .connect_rejected = value }),
                .connection_failed => |value| try handler(context, server, .{ .connection_failed = value }),
                .session_failed => |value| {
                    const session = server.sessionById(value.handle, value.session_id) orelse return error.InvalidSessionState;
                    // Notification consumes the terminal report, while ordinary
                    // endpoint maintenance still owns associated-stream cleanup.
                    session.control.capsule_error_pending = false;
                    session.control.capsule_error_reported = true;
                    try handler(context, server, .{ .session_failed = value });
                },
            },
            .event => |value| {
                var event = value;
                defer event.deinit(server.allocator);
                switch (event) {
                    .connected => |handle| try handler(context, server, .{ .connected = handle }),
                    .closed => |closed| try handler(context, server, .{ .closed = .{ .handle = closed.handle, .timer = closed.timer } }),
                    .session_request => |handle| {
                        const pending = server.pendingSession(handle) orelse return error.InvalidSessionState;
                        try handler(context, server, .{ .session_request = pending });
                    },
                    .session_event => |*value_event| {
                        const active = server.sessionById(value_event.handle, value_event.session_id) orelse return error.InvalidSessionState;
                        try handler(context, server, .{ .session_event = .{ .session = active, .event = &value_event.event } });
                    },
                    .handshake_failed => |failure| try handler(context, server, .{ .handshake_failed = failure }),
                    .unrouted => {},
                }
            },
        }
    }
}
