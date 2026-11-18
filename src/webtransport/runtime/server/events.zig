const std = @import("std");
const development_stream = @import("../development_stream.zig");
const http3 = @import("../../../http3/mod.zig");
const session_control = @import("../session_control.zig");

const runtime = @import("../../runtime.zig");
const Error = runtime.Error;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionEvent = runtime.SessionEvent;
const protected_control = runtime.protected_control;
const terminalSessionBodySendError = runtime.terminalSessionBodySendError;

const handshake_types = @import("handshake.zig");
const ProtectedServer = handshake_types.ProtectedServer;
const session_types = @import("session.zig");
const AcceptedProtectedSession = session_types.AcceptedProtectedSession;
const AcceptedSession = session_types.AcceptedSession;

pub fn receiveDevelopmentServerEvent(
    session: *AcceptedSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (session.pending_session_event == null) {
        if (try session.control.pollPending()) |event| {
            session.pending_session_event = event;
        } else {
            var buffer: [protected_control.buffer_capacity]u8 = undefined;
            while (session.pending_session_event == null) {
                const read = if (deadline) |absolute|
                    try session.server.receiveSessionDataWithDeadline(
                        session.request.from,
                        session.session_id,
                        &buffer,
                        absolute,
                    )
                else
                    try session.server.receiveSessionData(
                        session.request.from,
                        session.session_id,
                        &buffer,
                    );
                if (read.fin) {
                    session.pending_session_event =
                        (try session.control.finish()) orelse
                        return error.InvalidSessionState;
                } else if (try session.control.consume(
                    buffer[0..read.bytes],
                )) |event| {
                    session.pending_session_event = event;
                }
            }
        }
    }
    const event = session.pending_session_event.?;
    if (deadline) |absolute| {
        try finishDevelopmentServerEventWithDeadline(
            session,
            event,
            absolute,
        );
    } else {
        try finishDevelopmentServerEvent(session, event);
    }
    session.pending_session_event = null;
    return event;
}

fn finishDevelopmentServerEvent(
    session: *AcceptedSession,
    event: SessionEvent,
) Error!void {
    if (event == .closed and
        !session.control.control.local_close_sent and
        !session.control.control.local_close_failed and
        session.pending_close == null)
    {
        // A peer CLOSE capsule or a clean peer FIN only terminates its send
        // half of the CONNECT stream. WebTransport still requires one empty
        // FIN reply on our side so the HTTP/3 stream reaches a symmetric clean
        // close instead of lingering half-open forever.
        session.server.sendSessionData(
            session.request.from,
            session.session_id,
            &.{},
            true,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                session.control.control.recordLocalCloseFailure(0);
            }
            return err;
        };
        session.control.control.local_close_sent = true;
    }
    if (event == .closed or event == .reset) {
        // Terminal control state is definitive session teardown. Release the
        // adapter's associated streams now rather than waiting for deinit; H3
        // retains the peer cursor only if another same-peer session is active.
        session.server.h3.closeDevelopmentSession(
            session.request.from,
            development_stream.match(
                &session.streams,
                session.session_id,
                .server,
            ),
        );
    }
}

fn finishDevelopmentServerEventWithDeadline(
    session: *AcceptedSession,
    event: SessionEvent,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    if (event == .closed and
        !session.control.control.local_close_sent and
        !session.control.control.local_close_failed and
        session.pending_close == null)
    {
        var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
        session.server.sendSessionDataWithDeadline(
            session.request.from,
            session.session_id,
            &.{},
            true,
            &progress,
            deadline,
        ) catch |err| {
            if (progress.send_attempted or terminalSessionBodySendError(err)) {
                session.control.control.recordLocalCloseFailure(0);
            }
            return err;
        };
        std.debug.assert(progress.completed);
        session.control.control.local_close_sent = true;
    }
    if (event == .closed or event == .reset) {
        session.server.h3.closeDevelopmentSession(
            session.request.from,
            development_stream.match(
                &session.streams,
                session.session_id,
                .server,
            ),
        );
    }
}

pub fn receiveProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (session.pending_session_event == null) {
        session.pending_session_event = try @import("../session_control/received_event.zig").receive(&server.h3, &session.control, session.session_id.value, deadline);
    }
    const event = session.pending_session_event.?;
    if (deadline) |absolute| {
        try finishProtectedServerEventWithDeadline(
            server,
            session,
            event,
            absolute,
        );
    } else {
        try finishProtectedServerEvent(server, session, event);
    }
    session.pending_session_event = null;
    return event;
}

fn finishProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    event: SessionEvent,
) Error!void {
    if (event == .closed and
        !session.control.control.local_close_sent)
    {
        // CLOSE (or a clean peer FIN) terminates only the peer's CONNECT
        // direction. Finish our direction as well without synthesizing a
        // second CLOSE capsule.
        try server.sendSessionData(
            session.request.from,
            session.session_id,
            &.{},
            true,
        );
        session.control.control.local_close_sent = true;
    }
}

fn finishProtectedServerEventWithDeadline(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    event: SessionEvent,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    if (event != .closed or
        session.control.control.local_close_sent or
        session.pending_close != null) return;
    var progress: http3.runtime.BodyWriteProgress = .{};
    server.h3.sendResponseBodyPacedWithDeadline(
        session.request.from,
        session.session_id.value,
        &.{},
        true,
        &progress,
        deadline,
    ) catch |err| {
        if (progress.fin_committed) {
            session.control.control.local_close_sent = true;
        }
        return err;
    };
    std.debug.assert(progress.fin_committed);
    session.control.control.local_close_sent = true;
}
