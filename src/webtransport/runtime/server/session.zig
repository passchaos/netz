const std = @import("std");
const net = std.Io.net;
const application = @import("../application.zig");
const connect_headers = @import("../connect/headers.zig");
const connect_negotiation = @import("../connect/negotiation.zig");
const connect_rejection = @import("../connect/rejection.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const development_stream = @import("../development_stream.zig");
const early_streams = @import("../association/early_streams.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const tls_stream = @import("../../../tls/mod.zig").stream;
const session_control = @import("../session_control.zig");
const webtransport = @import("../../mod.zig");

const runtime = @import("../../runtime.zig");
const Error = runtime.Error;
const Limits = runtime.Limits;
const OwnedDevelopmentStream = runtime.OwnedDevelopmentStream;
const PendingSessionClose = runtime.PendingSessionClose;
const PendingSessionDrain = runtime.PendingSessionDrain;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionEvent = runtime.SessionEvent;
const application_protocol = runtime.application_protocol;
const clearPendingSessionClose = runtime.clearPendingSessionClose;
const connectResponseWithHeaders = runtime.connectResponseWithHeaders;
const developmentDirection = runtime.developmentDirection;
const developmentWritableStream = runtime.developmentWritableStream;
const findHeader = runtime.findHeader;
const initHandshakeStreamRegistry = runtime.initHandshakeStreamRegistry;
const protected_control = runtime.protected_control;
const terminalSessionBodySendError = runtime.terminalSessionBodySendError;
const validateAdditionalConnectHeaders = runtime.validateAdditionalConnectHeaders;
const validateConnectOrigin = runtime.validateConnectOrigin;

const events_types = @import("events.zig");
const receiveDevelopmentServerEvent = events_types.receiveDevelopmentServerEvent;
const receiveProtectedServerEvent = events_types.receiveProtectedServerEvent;
const handshake_types = @import("handshake.zig");
const ProtectedServer = handshake_types.ProtectedServer;
const Server = handshake_types.Server;

pub const AcceptedSession = struct {
    server: *Server,
    request: OwnedConnectRequest,
    session_id: webtransport.SessionId,
    selected_application_protocol: ?application_protocol.String = null,
    streams: webtransport.StreamRegistry,
    /// Reuses the protected-session adapter because development HTTP/3 now
    /// yields CONNECT DATA as caller-buffer payload chunks rather than raw
    /// detached QUIC bytes. This keeps timeout-resumable Capsule parsing and
    /// suffix retention identical across the lightweight runtimes.
    control: protected_control.Reader,
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,

    pub fn applicationProtocol(self: AcceptedSession) ?application_protocol.String {
        return self.selected_application_protocol;
    }

    pub fn sessionId(self: AcceptedSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn remoteAddress(self: AcceptedSession) net.IpAddress {
        return self.request.from;
    }

    pub fn sendDatagram(
        self: *AcceptedSession,
        payload: []const u8,
    ) Error!void {
        try self.control.control.ensureOpen();
        return self.server.sendDatagram(
            self.request.from,
            self.session_id,
            payload,
        );
    }

    pub fn sendDatagramWithTimeout(
        self: *AcceptedSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return self.server.sendDatagramWithTimeout(
            self.request.from,
            self.session_id,
            payload,
            timeout,
        );
    }

    pub fn sendDatagramWithDeadline(
        self: *AcceptedSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return self.server.sendDatagramWithDeadline(
            self.request.from,
            self.session_id,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *AcceptedSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        try self.control.control.ensureOpen();
        return self.server.sendDatagrams(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *AcceptedSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return self.server.sendDatagramsWithTimeout(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
            timeout,
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *AcceptedSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return self.server.sendDatagramsWithDeadline(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(self: AcceptedSession) ?usize {
        return self.server.maxDatagramPayloadSize(self.session_id);
    }

    pub fn maxDatagramSize(self: AcceptedSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn openBidirectionalStream(self: *AcceptedSession) Error!u62 {
        return self.openLocalStream(.bidirectional);
    }

    pub fn openUnidirectionalStream(self: *AcceptedSession) Error!u62 {
        return self.openLocalStream(.unidirectional);
    }

    pub fn openLocalStream(
        self: *AcceptedSession,
        direction: webtransport.StreamDirection,
    ) Error!u62 {
        try self.control.control.ensureOpen();
        // Reserve registry allocation first without advancing its cursor. H3
        // then selects and commits the shared peer ID under one mutex.
        try development_stream.preflightLocal(
            &self.streams,
            .server,
            direction,
        );
        const opened = try self.server.h3.reserveDevelopmentStream(
            self.request.from,
            self.session_id.value,
            developmentDirection(direction),
        );
        // External registration preserves the registry's private cursor and
        // accepts the authoritative ID selected by shared HTTP/3 state.
        return (try self.streams.registerLocal(opened, direction)).stream_id;
    }

    pub fn sendStream(
        self: *AcceptedSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            var send_attempted = false;
            self.server.h3.sendDevelopmentStreamParts(
                self.request.from,
                self.session_id.value,
                stream_id,
                try development_stream.prefix(
                    &storage,
                    stream.direction,
                    self.session_id,
                ),
                payload,
                fin,
                &send_attempted,
            ) catch |err| {
                // Deterministic construction failures leave both layers
                // retryable. Once a datagram send begins, suppress the prefix
                // forever because the peer may already have observed it.
                if (send_attempted) {
                    stream.prefix_sent = true;
                    stream.send_reset = .fromHttp3(
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return err;
            };
            stream.prefix_sent = true;
            try self.streams.recordSent(stream_id, payload.len, fin);
            return;
        }
        try self.server.h3.sendDevelopmentStream(
            self.request.from,
            self.session_id.value,
            stream_id,
            payload,
            fin,
        );
        try self.streams.recordSent(stream_id, payload.len, fin);
    }

    pub fn sendStreamWithTimeout(
        self: *AcceptedSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(
            stream_id,
            payload,
            fin,
            progress,
            .fromNow(self.server.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamWithDeadline(
        self: *AcceptedSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            self.server.h3.sendDevelopmentStreamPartsWithDeadline(
                self.request.from,
                self.session_id.value,
                stream_id,
                try development_stream.prefix(
                    &storage,
                    stream.direction,
                    self.session_id,
                ),
                payload,
                fin,
                progress,
                deadline,
            ) catch |err| {
                if (progress.send_attempted or
                    terminalSessionBodySendError(err))
                {
                    stream.prefix_sent = true;
                    stream.send_reset = .fromHttp3(
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return err;
            };
            stream.prefix_sent = true;
            try self.streams.recordSent(stream_id, payload.len, fin);
            return;
        }
        self.server.h3.sendDevelopmentStreamWithDeadline(
            self.request.from,
            self.session_id.value,
            stream_id,
            payload,
            fin,
            progress,
            deadline,
        ) catch |err| {
            if (progress.send_attempted or terminalSessionBodySendError(err)) {
                stream.send_reset = .fromHttp3(
                    webtransport.ApplicationErrorCode.session_gone,
                );
            }
            return err;
        };
        try self.streams.recordSent(stream_id, payload.len, fin);
    }

    /// Send one stream from borrowed payload slices. The slices stay borrowed
    /// until the call completes.
    pub fn sendStreamSlices(
        self: *AcceptedSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        const total = try sliceLength(parts);
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            var send_attempted = false;
            self.server.h3.sendDevelopmentStreamPartsSlices(
                self.request.from,
                self.session_id.value,
                stream_id,
                try development_stream.prefix(
                    &storage,
                    stream.direction,
                    self.session_id,
                ),
                parts,
                fin,
                &send_attempted,
            ) catch |err| {
                if (send_attempted) {
                    stream.prefix_sent = true;
                    stream.send_reset = .fromHttp3(
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return err;
            };
            stream.prefix_sent = true;
            try self.streams.recordSent(stream_id, total, fin);
            return;
        }
        try self.server.h3.sendDevelopmentStreamSlices(
            self.request.from,
            self.session_id.value,
            stream_id,
            parts,
            fin,
        );
        try self.streams.recordSent(stream_id, total, fin);
    }

    pub fn sendStreamSlicesWithTimeout(
        self: *AcceptedSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(
            stream_id,
            parts,
            fin,
            progress,
            .fromNow(self.server.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamSlicesWithDeadline(
        self: *AcceptedSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        const total = try sliceLength(parts);
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            self.server.h3.sendDevelopmentStreamPartsSlicesWithDeadline(
                self.request.from,
                self.session_id.value,
                stream_id,
                try development_stream.prefix(
                    &storage,
                    stream.direction,
                    self.session_id,
                ),
                parts,
                fin,
                progress,
                deadline,
            ) catch |err| {
                if (progress.send_attempted or
                    terminalSessionBodySendError(err))
                {
                    stream.prefix_sent = true;
                    stream.send_reset = .fromHttp3(
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return err;
            };
            stream.prefix_sent = true;
            try self.streams.recordSent(stream_id, total, fin);
            return;
        }
        self.server.h3.sendDevelopmentStreamSlicesWithDeadline(
            self.request.from,
            self.session_id.value,
            stream_id,
            parts,
            fin,
            progress,
            deadline,
        ) catch |err| {
            if (progress.send_attempted or terminalSessionBodySendError(err)) {
                stream.send_reset = .fromHttp3(
                    webtransport.ApplicationErrorCode.session_gone,
                );
            }
            return err;
        };
        try self.streams.recordSent(stream_id, total, fin);
    }

    fn sliceLength(parts: []const []const u8) Error!usize {
        var total: usize = 0;
        for (parts) |part| {
            total = std.math.add(usize, total, part.len) catch
                return error.MessageTooLarge;
        }
        return total;
    }

    pub fn receiveStream(self: *AcceptedSession) Error!OwnedDevelopmentStream {
        const match = development_stream.match(
            &self.streams,
            self.session_id,
            .server,
        );
        const raw = try self.server.h3.receiveDevelopmentStream(
            self.request.from,
            match,
        );
        return development_stream.take(&self.streams, raw);
    }

    pub fn receiveStreamWithTimeout(
        self: *AcceptedSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedDevelopmentStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamWithDeadline(.fromNow(
            self.server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveStreamWithDeadline(
        self: *AcceptedSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDevelopmentStream {
        const match = development_stream.match(
            &self.streams,
            self.session_id,
            .server,
        );
        const raw = try self.server.h3.receiveDevelopmentStreamWithDeadline(
            self.request.from,
            match,
            deadline,
        );
        return development_stream.take(&self.streams, raw);
    }

    pub fn deinit(self: *AcceptedSession, allocator: std.mem.Allocator) void {
        // A development session does not own the shared Server, so destruction
        // must explicitly abort its long-lived CONNECT before releasing only
        // the request metadata. Cancellation mutates H3 state before the UDP
        // send, making best-effort cleanup sufficient even on socket failure.
        self.server.h3.cancelRequest(
            self.request.from,
            self.session_id.value,
            webtransport.ApplicationErrorCode.session_gone,
        ) catch {};
        self.server.h3.closeDevelopmentSession(
            self.request.from,
            development_stream.match(
                &self.streams,
                self.session_id,
                .server,
            ),
        );
        self.request.deinit(allocator);
        self.streams.deinit();
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
        self.* = undefined;
    }

    pub fn drain(self: *AcceptedSession) Error!void {
        if (self.control.control.local_drain_sent) return;
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        self.server.sendSessionData(
            self.request.from,
            self.session_id,
            pending.bytes[pending.committed..pending.len],
            false,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                self.pending_drain = null;
                self.control.control.recordLocalCloseFailure(0);
            }
            return err;
        };
        self.pending_drain = null;
        try self.control.control.recordLocalDrain();
    }

    pub fn drainWithTimeout(
        self: *AcceptedSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(
            self.server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *AcceptedSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        if (self.control.control.local_drain_sent or
            self.control.control.local_close_failed) return;
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
        self.server.sendSessionDataWithDeadline(
            self.request.from,
            self.session_id,
            pending.bytes[pending.committed..pending.len],
            false,
            &progress,
            deadline,
        ) catch |err| {
            if (progress.send_attempted or terminalSessionBodySendError(err)) {
                self.pending_drain = null;
                self.control.control.recordLocalCloseFailure(0);
            }
            return err;
        };
        std.debug.assert(progress.completed);
        self.pending_drain = null;
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        self.server.sendSessionData(
            self.request.from,
            self.session_id,
            pending.remaining(),
            true,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                const failed_code = pending.code;
                clearPendingSessionClose(&self.pending_close);
                self.control.control.recordLocalCloseFailure(failed_code);
            }
            return err;
        };
        const committed_code = pending.code;
        clearPendingSessionClose(&self.pending_close);
        try self.control.control.recordLocalClose(committed_code);
    }

    pub fn closeWithTimeout(
        self: *AcceptedSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(
            self.server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn closeWithDeadline(
        self: *AcceptedSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
        self.server.sendSessionDataWithDeadline(
            self.request.from,
            self.session_id,
            pending.remaining(),
            true,
            &progress,
            deadline,
        ) catch |err| {
            if (progress.send_attempted or terminalSessionBodySendError(err)) {
                const failed_code = pending.code;
                clearPendingSessionClose(&self.pending_close);
                self.control.control.recordLocalCloseFailure(failed_code);
            }
            return err;
        };
        std.debug.assert(progress.completed);
        const committed_code = pending.code;
        clearPendingSessionClose(&self.pending_close);
        try self.control.control.recordLocalClose(committed_code);
    }

    pub fn preparePendingClose(
        self: *AcceptedSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.pending_drain != null) return error.InvalidSessionState;
        if (self.pending_close) |*pending| {
            if (!try pending.matches(code, reason)) {
                return error.InvalidSessionState;
            }
            return;
        }
        var pending = try PendingSessionClose.init(
            self.server.h3.quic_server.endpoint.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.control.beginLocalClose();
        self.pending_close = pending;
    }

    pub fn receiveSessionEvent(self: *AcceptedSession) Error!SessionEvent {
        return receiveDevelopmentServerEvent(self, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            error.InvalidCapsule => {
                try self.server.h3.cancelRequest(
                    self.request.from,
                    self.session_id.value,
                    http3.ApplicationErrorCode.message_error,
                );
                return err;
            },
            else => return err,
        };
    }

    pub fn receiveSessionEventWithTimeout(
        self: *AcceptedSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionEventWithDeadline(.fromNow(
            self.server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveSessionEventWithDeadline(
        self: *AcceptedSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        _ = try deadline_policy.usableAwake(
            self.server.h3.quic_server.endpoint.io,
            deadline,
        );
        return receiveDevelopmentServerEvent(self, deadline) catch |err|
            switch (err) {
                error.InvalidCapsule => {
                    try self.server.h3.cancelRequest(
                        self.request.from,
                        self.session_id.value,
                        http3.ApplicationErrorCode.message_error,
                    );
                    return err;
                },
                else => return err,
            };
    }
};

pub const OwnedConnectRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    request: http3.DecodedRequestHead,

    pub fn deinit(
        self: *OwnedConnectRequest,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const AcceptedProtectedSession = struct {
    request: OwnedProtectedConnectRequest,
    session_id: webtransport.SessionId,
    selected_application_protocol: ?application_protocol.String = null,
    control: protected_control.Reader,
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,

    pub fn applicationProtocol(self: AcceptedProtectedSession) ?application_protocol.String {
        return self.selected_application_protocol;
    }

    pub fn deinit(self: *AcceptedProtectedSession, allocator: std.mem.Allocator) void {
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
        self.request.deinit(allocator);
        self.* = undefined;
    }

    pub fn sendDatagram(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payload: []const u8,
    ) Error!void {
        try self.control.control.ensureOpen();
        return server.sendDatagram(
            self.request.from,
            self.session_id,
            payload,
        );
    }

    pub fn sendDatagramWithTimeout(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return server.sendDatagramWithTimeout(
            self.request.from,
            self.session_id,
            payload,
            timeout,
        );
    }

    pub fn sendDatagramWithDeadline(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            server.h3.quic_server.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return server.sendDatagramWithDeadline(
            self.request.from,
            self.session_id,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        try self.control.control.ensureOpen();
        return server.sendDatagrams(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return server.sendDatagramsWithTimeout(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
            timeout,
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            server.h3.quic_server.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return server.sendDatagramsWithDeadline(
            self.request.from,
            self.session_id,
            payloads,
            committed_count,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(
        self: AcceptedProtectedSession,
        server: *const ProtectedServer,
    ) ?usize {
        return server.maxDatagramPayloadSize(self.session_id);
    }

    pub fn maxDatagramSize(
        self: AcceptedProtectedSession,
        server: *const ProtectedServer,
    ) usize {
        return self.maxDatagramPayloadSize(server) orelse 0;
    }

    pub fn drain(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
    ) Error!void {
        if (self.control.control.local_drain_sent) return;
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        try server.sendSessionData(
            self.request.from,
            self.session_id,
            pending.bytes[pending.committed..pending.len],
            false,
        );
        self.pending_drain = null;
        try self.control.control.recordLocalDrain();
    }

    pub fn drainWithTimeout(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(server, .fromNow(
            server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            server.h3.quic_server.endpoint.io,
            deadline,
        );
        if (self.control.control.local_drain_sent) return;
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        var progress: http3.runtime.BodyWriteProgress = .{};
        server.sendSessionDataWithDeadline(
            self.request.from,
            self.session_id,
            pending.bytes[pending.committed..pending.len],
            false,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            if (pending.committed == pending.len) {
                self.pending_drain = null;
                try self.control.control.recordLocalDrain();
            }
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(pending.committed == pending.len);
        self.pending_drain = null;
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(server, code, reason);
        const pending = &self.pending_close.?;
        server.sendSessionData(
            self.request.from,
            self.session_id,
            pending.remaining(),
            true,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                const failed_code = pending.code;
                clearPendingSessionClose(&self.pending_close);
                self.control.control.recordLocalCloseFailure(failed_code);
            }
            return err;
        };
        const committed_code = pending.code;
        clearPendingSessionClose(&self.pending_close);
        try self.control.control.recordLocalClose(committed_code);
    }

    pub fn closeWithTimeout(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(server, code, reason, .fromNow(
            server.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn closeWithDeadline(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            server.h3.quic_server.endpoint.io,
            deadline,
        );
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(server, code, reason);
        const pending = &self.pending_close.?;
        var progress: http3.runtime.BodyWriteProgress = .{};
        server.sendSessionDataWithDeadline(
            self.request.from,
            self.session_id,
            pending.remaining(),
            true,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            if (progress.fin_committed) {
                const committed_code = pending.code;
                clearPendingSessionClose(&self.pending_close);
                try self.control.control.recordLocalClose(committed_code);
            } else if (terminalSessionBodySendError(err)) {
                const failed_code = pending.code;
                clearPendingSessionClose(&self.pending_close);
                self.control.control.recordLocalCloseFailure(failed_code);
            }
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(
            pending.committed == pending.len and progress.fin_committed,
        );
        const committed_code = pending.code;
        clearPendingSessionClose(&self.pending_close);
        try self.control.control.recordLocalClose(committed_code);
    }

    pub fn preparePendingClose(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.pending_drain != null) return error.InvalidSessionState;
        if (self.pending_close) |*pending| {
            if (!try pending.matches(code, reason)) {
                return error.InvalidSessionState;
            }
            return;
        }
        var pending = try PendingSessionClose.init(
            server.h3.quic_server.endpoint.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.control.beginLocalClose();
        self.pending_close = pending;
    }

    pub fn receiveSessionEvent(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
    ) Error!SessionEvent {
        return receiveProtectedServerEvent(server, self, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            error.InvalidCapsule => {
                try server.h3.cancelRequest(
                    self.request.from,
                    self.session_id.value,
                    http3.ApplicationErrorCode.message_error,
                );
                return err;
            },
            else => return err,
        };
    }

    pub fn receiveSessionEventWithTimeout(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionEventWithDeadline(
            server,
            .fromNow(
                server.h3.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionEventWithDeadline(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        _ = try deadline_policy.usableAwake(
            server.h3.quic_server.endpoint.io,
            deadline,
        );
        return receiveProtectedServerEvent(server, self, deadline) catch |err|
            switch (err) {
                error.InvalidCapsule => {
                    try server.h3.cancelRequest(
                        self.request.from,
                        self.session_id.value,
                        http3.ApplicationErrorCode.message_error,
                    );
                    return err;
                },
                else => return err,
            };
    }
};

pub const OwnedProtectedConnectRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    request: http3.DecodedRequestHead,

    pub fn deinit(
        self: *OwnedProtectedConnectRequest,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedHandshakeConnectRequest = struct {
    stream_id: u62,
    request: http3.DecodedRequestHead,

    pub fn deinit(
        self: *OwnedHandshakeConnectRequest,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

/// A validated WebTransport CONNECT request awaiting application admission.
///
/// This value temporarily owns the HTTP/3 session and decoded request head. It
/// must be consumed by `accept`, `acceptWithHeaders`, or `reject`, or explicitly
/// destroyed with `deinit`. Caller-supplied sessions are restored after
/// rejection or destruction; acceptance transfers them to the WebTransport
/// session.
pub const PendingHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    restore_to: ?*http3.runtime.HandshakeServerSession = null,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp = null,
    rejection_pending: ?connect_rejection.Pending = null,
    early_streams: early_streams.State = .{},

    pub fn offeredApplicationProtocols(self: PendingHandshakeSession) ?application_protocol.Offered {
        return application_protocol.offered(self.request.request.headers);
    }

    /// Authenticated TLS metadata for the connection carrying this pending
    /// CONNECT. Available before acceptance so admission policy can bind to
    /// the client certificate, ALPN and transcript.
    pub fn peerCertificates(
        self: *const PendingHandshakeSession,
    ) ?[]const []const u8 {
        return self.h3.peerCertificates();
    }

    pub fn negotiatedAlpn(self: PendingHandshakeSession) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: PendingHandshakeSession,
    ) quic.tls.cipher_suite.Suite {
        return self.h3.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: PendingHandshakeSession,
    ) quic.tls.secret.Hash {
        return self.h3.negotiatedTranscriptHash();
    }

    /// QUIC mandates TLS 1.3; the optional shape matches the other transports.
    pub fn negotiatedTlsProtocol(
        self: PendingHandshakeSession,
    ) ?tls_stream.Protocol {
        _ = self;
        return .tls13;
    }

    pub fn wasTlsSessionResumed(
        self: PendingHandshakeSession,
    ) ?bool {
        return self.h3.established.resumed;
    }

    pub fn earlyDataStatus(
        self: PendingHandshakeSession,
    ) @TypeOf(self.h3.established.early_data_status) {
        return self.h3.established.early_data_status;
    }

    pub fn deinit(self: *PendingHandshakeSession) void {
        if (self.restore_to != null) {
            self.h3.rejectRequest(self.session_id.value) catch {};
        }
        self.finish();
    }

    fn restoreSession(self: *PendingHandshakeSession) void {
        std.debug.assert(self.restore_to != null);
        self.finish();
    }

    pub fn finish(self: *PendingHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.early_streams.deinit(allocator);
        self.request.deinit(allocator);
        if (self.restore_to) |destination| {
            destination.* = self.h3;
        } else {
            self.h3.deinit();
        }
        self.* = undefined;
    }

    pub fn peerAddress(self: PendingHandshakeSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn authority(self: PendingHandshakeSession) ?[]const u8 {
        return self.request.request.authority;
    }

    pub fn path(self: PendingHandshakeSession) []const u8 {
        return self.request.request.path;
    }

    pub fn origin(self: PendingHandshakeSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "origin");
    }

    pub fn userAgent(self: PendingHandshakeSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "user-agent");
    }

    pub fn headers(
        self: PendingHandshakeSession,
    ) []const http3.Qpack.HeaderField {
        return self.request.request.headers;
    }

    pub fn accept(
        self: *PendingHandshakeSession,
    ) Error!AcceptedHandshakeSession {
        return self.acceptWithHeaders(&.{});
    }

    pub fn acceptWithHeaders(
        self: *PendingHandshakeSession,
        additional_headers: []const http3.Qpack.HeaderField,
    ) Error!AcceptedHandshakeSession {
        if (self.deadline) |absolute| _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, absolute);
        if (self.rejection_pending) |pending| {
            try pending.submitBefore(&self.h3, self.deadline);
            self.rejection_pending = null;
            return pending.failure.?.cause();
        }
        connect_negotiation.validateRequestWithPolicy(&self.h3, self.request.request, self.limits.require_session_flow_control) catch |err| {
            const failure = connect_rejection.Failure.fromError(err) orelse return err;
            const pending = connect_rejection.Pending.forFailure(self.session_id.value, failure);
            self.rejection_pending = pending;
            try pending.submitBefore(&self.h3, self.deadline);
            self.rejection_pending = null;
            return failure.cause();
        };
        try validateConnectOrigin(
            self.request.request,
            self.limits.origin_policy,
        );
        const allocator = self.h3.established.connection.endpoint.allocator;
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponseWithProtocols(
            allocator,
            self.request.request.headers,
            additional_headers,
            self.limits.application_protocols,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        if (self.deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        self.early_streams.limits = self.limits.early_connect_streams;
        if (self.h3.dispatcherBound()) {
            if (!try early_streams.classifyBeforeAdmissionOnce(
                &self.early_streams,
                allocator,
                &self.h3.established.connection,
                early_streams.standaloneOwners(),
            )) return error.PacingLimited;
        } else {
            try early_streams.classifyBeforeAdmission(
                &self.early_streams,
                allocator,
                &self.h3.established.connection,
                early_streams.standaloneOwners(),
                self.deadline,
            );
        }
        var streams = try initHandshakeStreamRegistry(
            allocator,
            self.session_id,
            .server,
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
            self.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        var control = try session_control.Control.init(
            allocator,
            self.session_id,
        );
        if (self.h3.dispatcherBound()) {
            try self.h3.tryAcceptConnectResponse(
                self.session_id.value,
                connectResponseWithHeaders(prepared_headers.fields),
            );
        } else if (self.deadline) |absolute| {
            try self.h3.acceptConnectResponseWithDeadline(
                self.session_id.value,
                connectResponseWithHeaders(prepared_headers.fields),
                absolute,
            );
        } else {
            try self.h3.acceptConnectResponse(
                self.session_id.value,
                connectResponseWithHeaders(prepared_headers.fields),
            );
        }
        connection_lifecycle.activate(&control, &self.h3, &streams);
        const h3 = self.h3;
        const selected = prepared_headers.selected_application_protocol;
        const request = self.request;
        const session_id = self.session_id;
        self.early_streams.deinit(allocator);
        self.* = undefined;
        return .{
            .h3 = h3,
            .request = request,
            .selected_application_protocol = selected,
            .session_id = session_id,
            .streams = streams,
            .control = control,
        };
    }

    /// Reject the request with a final 3xx-5xx response and FIN. A redirect
    /// Location or authentication challenge can be supplied through headers.
    pub fn reject(
        self: *PendingHandshakeSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!RejectedHandshakeSession {
        return self.rejectWithBody(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    /// Reject the CONNECT with ordinary HTTP/3 DATA and final trailers.
    pub fn rejectWithBody(
        self: *PendingHandshakeSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!RejectedHandshakeSession {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try validateAdditionalConnectHeaders(trailers, .response);
        const response: http3.Response = .{
            .status = status,
            .headers = response_headers,
            .body = body,
            .trailers = trailers,
            .request_method = "CONNECT",
            .extended_connect = true,
        };
        try self.h3.connect_datagrams.rejectEarlyAssociation(self.session_id.value);
        if (self.deadline) |absolute| {
            try self.h3.sendResponsePacedWithDeadline(
                self.session_id.value,
                response,
                absolute,
            );
        } else {
            try self.h3.sendResponsePaced(
                self.session_id.value,
                response,
            );
        }
        if (self.deadline) |absolute| {
            try self.h3.finishRejectedRequestWithDeadline(
                self.session_id.value,
                absolute,
            );
        } else {
            try self.h3.finishRejectedRequest(self.session_id.value);
        }
        const allocator = self.h3.established.connection.endpoint.allocator;
        const h3 = self.h3;
        const restore_to = self.restore_to;
        const request = self.request;
        const session_id = self.session_id;
        self.early_streams.deinit(allocator);
        self.* = undefined;
        return .{
            .h3 = h3,
            .restore_to = restore_to,
            .request = request,
            .session_id = session_id,
            .status = status,
        };
    }

    pub fn forbidden(
        self: *PendingHandshakeSession,
    ) Error!RejectedHandshakeSession {
        return self.reject(403, &.{});
    }

    pub fn notFound(
        self: *PendingHandshakeSession,
    ) Error!RejectedHandshakeSession {
        return self.reject(404, &.{});
    }

    pub fn tooManyRequests(
        self: *PendingHandshakeSession,
    ) Error!RejectedHandshakeSession {
        return self.reject(429, &.{});
    }
};

/// Owns a rejected HTTP/3 connection after its final response was submitted.
/// Keeping this value alive preserves QUIC recovery state, allowing event loops
/// to service ACK/PTO progress instead of dropping the response immediately.
pub const RejectedHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    restore_to: ?*http3.runtime.HandshakeServerSession = null,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    status: u16,

    pub fn deinit(self: *RejectedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        if (self.restore_to) |destination| {
            destination.* = self.h3;
        } else {
            self.h3.deinit();
        }
        self.* = undefined;
    }

    /// Process one timer-aware QUIC receive. Applications that keep serving a
    /// rejected connection can call this until their own shutdown policy says
    /// it is safe to release retransmission state.
    pub fn serviceTransport(self: *RejectedHandshakeSession) Error!void {
        try self.h3.established.connection.servicePacketServicingTimers();
    }

    /// Process one timer-aware QUIC receive for at most `timeout`.
    /// A non-positive timeout returns `error.Timeout` without reading UDP.
    pub fn serviceTransportWithTimeout(
        self: *RejectedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.h3.established.connection
            .servicePacketServicingTimersTimeout(.{ .duration = .{
            .raw = timeout,
            .clock = .awake,
        } });
    }

    /// Process one timer-aware QUIC receive until the awake-clock `deadline`.
    pub fn serviceTransportWithDeadline(
        self: *RejectedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.established.connection
            .servicePacketServicingTimersDeadline(deadline);
    }

    /// Drive recovery until the rejected CONNECT response is acknowledged.
    /// Pure receive-credit advertisements do not prolong this application-
    /// delivery boundary.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *RejectedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.h3.waitForRecoveryIdleWithTimeout(timeout);
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *RejectedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.h3.waitForRecoveryIdleWithDeadline(deadline);
    }
};

pub const AcceptedHandshakeSession = @import("../accepted_handshake_session.zig").AcceptedHandshakeSession;
