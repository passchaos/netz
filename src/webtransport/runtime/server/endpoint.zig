const std = @import("std");
const net = std.Io.net;
const application = @import("../application.zig");
const connect_headers = @import("../connect/headers.zig");
const connect_negotiation = @import("../connect/negotiation.zig");
const connect_rejection = @import("../connect/rejection.zig");
const connect_request_head = @import("../connect/request_head.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const early_streams = @import("../association/early_streams.zig");
const endpoint_serve = @import("../endpoint_server/serve.zig");
const flow_datagram = @import("../flow/datagram.zig");
const flow_grant = @import("../flow/grant.zig");
const flow_open = @import("../flow/open.zig");
const flow_streams = @import("../flow/streams.zig");
const handshake_stream = @import("../stream.zig");
const http3 = @import("../../../http3/mod.zig");
const incremental_stream = @import("../stream_incremental.zig");
const quic = @import("../../../quic/mod.zig");
const round_robin = @import("../../../internal/round_robin.zig");
const server_close = @import("../endpoint_server/close.zig");
const server_stream_control = @import("../endpoint_server/stream_control.zig");
const server_terminal = @import("../endpoint_server/terminal.zig");
const session_control = @import("../session_control.zig");
const stream_association = @import("../stream_association.zig");
const stream_batch = @import("../stream/batch.zig");
const webtransport = @import("../../mod.zig");

const runtime = @import("../../runtime.zig");
const EndpointServerError = runtime.EndpointServerError;
const Error = runtime.Error;
const HandshakeFailure = runtime.HandshakeFailure;
const Limits = runtime.Limits;
const OwnedHandshakeDatagram = runtime.OwnedHandshakeDatagram;
const PendingSessionClose = runtime.PendingSessionClose;
const ServeConnectRejection = runtime.ServeConnectRejection;
const ServeConnectionFailure = runtime.ServeConnectionFailure;
const ServeSessionFailure = runtime.ServeSessionFailure;
const SessionEvent = runtime.SessionEvent;
const StableConnectionId = runtime.StableConnectionId;
const StreamRead = runtime.StreamRead;
const StreamWrite = runtime.StreamWrite;
const StreamWriteResult = runtime.StreamWriteResult;
const application_protocol = runtime.application_protocol;
const connectResponseWithHeaders = runtime.connectResponseWithHeaders;
const findHeader = runtime.findHeader;
const initHandshakeStreamRegistry = runtime.initHandshakeStreamRegistry;
const max_connection_close_reason = runtime.max_connection_close_reason;
const ownedHandshakeDatagram = runtime.ownedHandshakeDatagram;
const testing = runtime.testing;
const validateAdditionalConnectHeaders = runtime.validateAdditionalConnectHeaders;
const validateConnectOrigin = runtime.validateConnectOrigin;

const handshake_types = @import("handshake.zig");
const HandshakeServer = handshake_types.HandshakeServer;
const session_types = @import("session.zig");
const OwnedHandshakeConnectRequest = session_types.OwnedHandshakeConnectRequest;

/// An HTTP/3 connection whose first request has been validated as a
/// WebTransport CONNECT but is still awaiting an application admission
/// decision. The `h3` pointer remains owned by `http3.runtime.EndpointServer`;
/// keeping this object separate avoids moving the dispatcher-registered QUIC
/// connection while policy code inspects the request.
pub const EndpointPendingSession = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    h3: *http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    limits: Limits,

    pub fn offeredApplicationProtocols(self: EndpointPendingSession) ?application_protocol.Offered {
        return application_protocol.offered(self.request.request.headers);
    }

    pub fn authority(self: EndpointPendingSession) ?[]const u8 {
        return self.request.request.authority;
    }

    pub fn path(self: EndpointPendingSession) []const u8 {
        return self.request.request.path;
    }

    pub fn origin(self: EndpointPendingSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "origin");
    }

    pub fn userAgent(self: EndpointPendingSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "user-agent");
    }

    pub fn headers(
        self: EndpointPendingSession,
    ) []const http3.Qpack.HeaderField {
        return self.request.request.headers;
    }
};

/// A stable accepted WebTransport session. HTTP/3 owns the heap allocation
/// containing `h3`; this state points into it and therefore cannot invalidate
/// the endpoint dispatcher's `Connection*` route when hash tables grow.
pub const EndpointAcceptedSession = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    h3: *http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    selected_application_protocol: ?application_protocol.String = null,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,
    /// This runtime advertises one WebTransport session per HTTP/3
    /// connection. If rejection is temporarily paced or flow-controlled, keep
    /// the extra request ID here and retry without consuming another head.
    request_rejection_pending: ?u62 = null,
    /// A peer CLOSE was already reported to the application; the endpoint
    /// still owes the CONNECT response FIN and retries it from later turns.
    close_response_pending: bool = false,
    /// The owning QUIC connection closed; the HTTP/3 session may already be
    /// gone, so teardown must not touch `h3` again.
    transport_closed: bool = false,
    pending_close: ?PendingSessionClose = null,
    close_write: http3.runtime.BodyWriteState = .{},

    pub fn applicationProtocol(self: EndpointAcceptedSession) ?application_protocol.String {
        return self.selected_application_protocol;
    }

    pub fn sessionId(self: EndpointAcceptedSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn stableId(self: *const EndpointAcceptedSession) StableConnectionId {
        return self.h3.established.connection.stableId();
    }

    pub fn remoteAddress(self: EndpointAcceptedSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn remoteAddressValidated(self: EndpointAcceptedSession) bool {
        return self.h3.established.connection.peerAddressValidated();
    }

    pub fn rttNanos(self: EndpointAcceptedSession) ?u64 {
        return self.stats().smoothed_rtt_ns;
    }

    /// Derive TLS 1.3 exporter bytes from the authenticated QUIC/TLS session.
    /// This borrows only the caller-provided output buffer; no returned state
    /// outlives `self`.
    pub fn exportKeyingMaterial(
        self: *const EndpointAcceptedSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.h3.exportKeyingMaterial(label, context, out);
    }

    /// Return the retained peer certificate chain borrowed from the promoted
    /// handshake-backed HTTP/3 session. The slices remain valid only until the
    /// endpoint removes this connection and deinitializes the accepted session.
    pub fn peerCertificates(
        self: *const EndpointAcceptedSession,
    ) ?[]const []const u8 {
        return self.h3.peerCertificates();
    }

    /// Return the negotiated ALPN token borrowed from the promoted handshake
    /// session. Callers must not retain the slice after this accepted session
    /// is removed from the endpoint.
    pub fn negotiatedAlpn(self: EndpointAcceptedSession) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: EndpointAcceptedSession,
    ) quic.tls.cipher_suite.Suite {
        return self.h3.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: EndpointAcceptedSession,
    ) quic.tls.secret.Hash {
        return self.h3.negotiatedTranscriptHash();
    }

    pub fn initiateKeyUpdate(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!void {
        try self.h3.initiateKeyUpdate();
        try self.refreshTimer();
    }

    pub fn localKeyUpdateCount(self: EndpointAcceptedSession) u64 {
        return self.h3.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: EndpointAcceptedSession) u64 {
        return self.h3.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: EndpointAcceptedSession) bool {
        return self.h3.keyUpdateAwaitingAck();
    }

    /// Attempt one DATAGRAM send without waiting or reading the shared socket.
    /// Congestion and pacing are returned to the endpoint event loop.
    pub fn sendDatagram(
        self: *EndpointAcceptedSession,
        payload: []const u8,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try flow_datagram.prepareSend(&self.control, self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = self.h3.trySendConnectDatagram(
            self.session_id.value,
            payload,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt one bounded DATAGRAM send without reading the endpoint's shared
    /// UDP socket. If congestion is exhausted, callers must continue driving
    /// `EndpointServer.receive*` and retry before the same deadline; this
    /// preserves the dispatcher's single-owner routing invariant.
    pub fn trySendDatagramWithTimeout(
        self: *EndpointAcceptedSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) EndpointServerError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.trySendDatagramWithDeadline(payload, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn trySendDatagramWithDeadline(
        self: *EndpointAcceptedSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) EndpointServerError!void {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try flow_datagram.prepareSend(&self.control, self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = self.h3.trySendConnectDatagramWithDeadline(
            self.session_id.value,
            payload,
            deadline,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt one ordered DATAGRAM socket batch without reading the shared
    /// endpoint. `committed_count` is the exact socket-visible input prefix.
    pub fn sendDatagrams(
        self: *EndpointAcceptedSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) EndpointServerError!void {
        committed_count.* = 0;
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try flow_datagram.prepareSend(&self.control, self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = self.h3.trySendConnectDatagrams(
            self.session_id.value,
            payloads,
            committed_count,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt one Capsule Protocol DATA send without waiting or reading the
    /// endpoint's shared UDP socket. Backpressure leaves the complete input
    /// retryable and the dispatcher timer is refreshed on every outcome.
    pub fn sendSessionData(
        self: *EndpointAcceptedSession,
        data: []const u8,
        fin: bool,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = self.h3.trySendResponseBody(
            self.session_id.value,
            data,
            fin,
        );
        try self.refreshTimer();
        try result;
    }

    /// Scatter/gather counterpart to `sendSessionData`. All borrowed slices
    /// form one transactional HTTP/3 DATA contribution in one QUIC packet.
    pub fn sendSessionDataSlices(
        self: *EndpointAcceptedSession,
        parts: []const []const u8,
        fin: bool,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = self.h3.trySendResponseBodyParts(
            self.session_id.value,
            parts,
            fin,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt to reserve one bidirectional stream without waiting for peer
    /// credit or pacing; dispatcher progress makes a later retry possible.
    pub fn openBidirectionalStream(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!u62 {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = flow_open.open(&self.control, self.h3, &self.streams, .bidirectional, null, true);
        try self.refreshTimer();
        return result catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    /// Attempt to reserve one unidirectional stream without waiting for peer
    /// credit or pacing; dispatcher progress makes a later retry possible.
    pub fn openUnidirectionalStream(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!u62 {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = flow_open.open(&self.control, self.h3, &self.streams, .unidirectional, null, true);
        try self.refreshTimer();
        return result catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn maxDatagramPayloadSize(
        self: EndpointAcceptedSession,
    ) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return self.h3.maxConnectDatagramPayloadSize(
            self.session_id.value,
        );
    }

    pub fn maxDatagramSize(self: EndpointAcceptedSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: EndpointAcceptedSession) bool {
        connect_negotiation.ensure(&self.h3) catch return false;
        return self.h3.connectDatagramsNegotiated();
    }

    pub fn stats(
        self: EndpointAcceptedSession,
    ) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn closeConnection(
        self: *EndpointAcceptedSession,
        error_code: u62,
        reason: []const u8,
    ) EndpointServerError!void {
        if (reason.len > max_connection_close_reason) {
            return error.InvalidSessionState;
        }
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        const result = self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt one packet-sized write without reading the shared UDP socket.
    /// A zero result means only the association prefix was submitted and the
    /// caller should drive `EndpointServer.receive*` before retrying `payload`.
    pub fn writeStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        payload: []const u8,
    ) EndpointServerError!usize {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = handshake_stream.writeOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
        try self.refreshTimer();
        return try result;
    }

    /// Attempt one packet-sized scatter/gather write without reading the
    /// shared UDP socket. The count excludes any association-prefix bytes.
    pub fn writeStreamSlices(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        parts: []const []const u8,
    ) EndpointServerError!usize {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = handshake_stream.writeSlicesOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
        );
        try self.refreshTimer();
        return try result;
    }

    /// Atomically submit one complete payload and optional FIN in one QUIC
    /// packet. Backpressure or an oversized packet is returned without partial
    /// application progress; use `writeStream` plus `finishStream` for larger
    /// payloads. This method never reads the shared UDP socket.
    pub fn sendStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = handshake_stream.sendOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
        try self.refreshTimer();
        try result;
    }

    /// Atomically submit borrowed payload slices and optional FIN in one QUIC
    /// packet without joining them or reading the shared UDP socket.
    pub fn sendStreamSlices(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = handshake_stream.sendSlicesOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            fin,
        );
        try self.refreshTimer();
        try result;
    }

    pub fn setStreamPriority(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        try self.streams.setPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *EndpointAcceptedSession,
        stream_id: u62,
    ) Error!i32 {
        return self.streams.priority(stream_id);
    }

    /// Make one socket-free batch attempt across the supplied streams.
    /// `counts` and `send_error` identify exactly the socket-visible prefix.
    pub fn writeStreams(
        self: *EndpointAcceptedSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) EndpointServerError!StreamWriteResult {
        if (counts.len < writes.len) return error.BufferTooShort;
        @memset(counts[0..writes.len], 0);
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = stream_batch.writeOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
        try self.refreshTimer();
        return try result;
    }

    /// Attempt to submit FIN without reading or sleeping on the shared socket.
    pub fn finishStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
    ) EndpointServerError!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const result = handshake_stream.finishOnce(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
        );
        try self.refreshTimer();
        try result;
    }

    /// Nonblocking endpoint variant: inspect buffered terminal state, emit any
    /// resulting MAX_STREAMS update, and refresh the dispatcher timer without
    /// performing a UDP receive.
    pub fn releaseCompletedPeerStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
    ) EndpointServerError!bool {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        if (!try flow_streams.shouldReleasePeer(&self.h3.established.connection, &self.streams, stream_id)) return false;
        const result = self.h3.established.connection
            .tryReleaseCompletedPeerStream(stream_id);
        try self.refreshTimer();
        return try result;
    }

    /// Attempt RESET_STREAM once without waiting for pacing or reading the
    /// shared endpoint socket. Buffered CONNECT control is checked first;
    /// pending CLOSE metadata stays available to the application. Retry after
    /// dispatcher transport progress.
    pub fn resetStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        return server_stream_control.cancel(self, stream_id, application_error_code, .reset);
    }

    /// Attempt RESET_STREAM_AT once. `reliable_size` counts WebTransport
    /// application bytes and excludes the stream association prefix.
    pub fn resetStreamReliably(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
    ) EndpointServerError!void {
        return server_stream_control.cancel(self, stream_id, application_error_code, .{ .reliable = reliable_size });
    }

    /// Attempt STOP_SENDING once without waiting for pacing or reading the
    /// shared endpoint socket. Retry after dispatcher transport progress.
    pub fn stopStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        return server_stream_control.cancel(self, stream_id, application_error_code, .stop);
    }

    pub fn drain(self: *EndpointAcceptedSession) EndpointServerError!void {
        if (self.control.local_drain_sent) return;
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        const result = self.h3.trySendResponseBody(
            self.session_id.value,
            capsule,
            false,
        );
        result catch |err| {
            try self.refreshTimer();
            return err;
        };
        try self.control.recordLocalDrain();
        try self.refreshTimer();
    }

    pub fn close(
        self: *EndpointAcceptedSession,
        code: u32,
        reason: []const u8,
    ) EndpointServerError!void {
        if (self.control.local_close_sent or self.control.local_close_failed) {
            server_close.clear(self);
            const result = session_control.terminateStreamsOnce(
                &self.h3.established.connection,
                &self.streams,
            );
            try self.refreshTimer();
            _ = try result;
            return;
        }
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try server_close.prepare(self, code, reason);
        while (self.pending_close != null) _ = try server_terminal.advanceOnce(self);
    }

    fn refreshTimer(self: *EndpointAcceptedSession) EndpointServerError!void {
        try self.dispatcher.refreshConnectionTimer(self.handle);
    }

    pub fn deinit(self: *EndpointAcceptedSession, allocator: std.mem.Allocator) void {
        server_close.clear(self);
        if (!self.transport_closed) {
            self.h3.closeConnectDatagramAssociation(
                self.session_id.value,
            ) catch {};
        }
        self.request.deinit(allocator);
        self.control.deinit();
        self.streams.deinit();
        self.* = undefined;
    }
    /// Submit one WT_MAX_DATA grant. Backpressure leaves the advertised limit
    /// unchanged so an endpoint loop can retry this same operation.
    pub fn grantData(self: *EndpointAcceptedSession, maximum: u64) Error!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        return flow_grant.send(&self.control, self.h3, &self.streams, .{ .max_data = maximum });
    }

    pub fn grantStreams(self: *EndpointAcceptedSession, direction: webtransport.StreamDirection, maximum: u64) Error!void {
        defer connection_lifecycle.observeWithTimer(&self.control, self.h3, &self.streams, self.dispatcher, self.handle);
        try application.ensureOpen(&self.control, self.h3, &self.streams);
        const capsule: webtransport.Capsule = switch (direction) {
            .bidirectional => .{ .max_streams_bidi = maximum },
            .unidirectional => .{ .max_streams_uni = maximum },
        };
        return flow_grant.send(&self.control, self.h3, &self.streams, capsule);
    }
};

pub const EndpointSessionEvent = union(enum) {
    stream: StreamRead,
    datagram: OwnedHandshakeDatagram,
    session: SessionEvent,

    pub fn deinit(self: *EndpointSessionEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .datagram => |*datagram| datagram.deinit(allocator),
            .stream, .session => {},
        }
        self.* = undefined;
    }
};

/// Stable identity of one WebTransport Session within a dispatcher-owned
/// HTTP/3 connection. Session IDs are unique only inside their connection.
pub const EndpointSessionKey = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    session_id: webtransport.SessionId,
};

pub const EndpointServerEvent = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    closed: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        timer: quic.one_rtt.TimerDeadline,
    },
    /// The HTTP/3 handshake supervisor is the producer of this event. Reuse
    /// its finite error payload so applications can exhaustively distinguish
    /// an admission deadline from a protocol/TLS failure.
    handshake_failed: HandshakeFailure,
    session_request: quic.endpoint_dispatcher.ConnectionHandle,
    session_event: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        session_id: webtransport.SessionId,
        event: EndpointSessionEvent,
    },
    unrouted: quic.endpoint_dispatcher.Event,

    pub fn deinit(self: *EndpointServerEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .session_event => |*value| value.event.deinit(allocator),
            .unrouted => |*event| event.deinit(allocator),
            .connected, .closed, .handshake_failed, .session_request => {},
        }
        self.* = undefined;
    }
};

pub const ServeEvent = union(enum) {
    /// Peer failures are notifications. Returning an error from the callback
    /// still stops the endpoint loop.
    handshake_failed: HandshakeFailure,
    connect_rejected: ServeConnectRejection,
    connection_failed: ServeConnectionFailure,
    session_failed: ServeSessionFailure,
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    closed: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        timer: quic.one_rtt.TimerDeadline,
    },
    session_request: *EndpointPendingSession,
    session_event: struct {
        session: *EndpointAcceptedSession,
        /// Borrowed for the duration of the callback.
        event: *EndpointSessionEvent,
    },
};

pub const ServeOptions = struct {
    shutdown: *std.Io.Event,
    supported_versions: []const u32,
    poll_interval: std.Io.Clock.Duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(5),
    },
    /// Maximum bytes returned in one associated-stream callback.
    stream_buffer_size: usize = 16 * 1024,
};

/// Multi-connection, multi-Session WebTransport server with one UDP receive
/// owner.
///
/// HTTP/3 retains stable heap-backed sessions and owns every dispatcher
/// registration. This wrapper stores only protocol state keyed by the same
/// handle, so admission and acceptance never move a registered QUIC
/// connection. Applications inspect a `session_request`, then call `accept` or
/// `reject`; accepted sessions are keyed by connection plus CONNECT stream and
/// subsequently yield isolated stream, DATAGRAM and Capsule events.
pub const EndpointServer = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    /// Stack-owned only during serveUntil's synchronous receive, never during
    /// the application callback or a caller's ordinary receive operation.
    serve_failure_sink: ?*?endpoint_serve.Capture = null,
    h3: http3.runtime.EndpointServer,
    early: std.AutoHashMapUnmanaged(quic.endpoint_dispatcher.ConnectionHandle, early_streams.State) = .empty,
    pending: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        *EndpointPendingSession,
    ) = .empty,
    sessions: std.AutoHashMapUnmanaged(
        EndpointSessionKey,
        *EndpointAcceptedSession,
    ) = .empty,
    /// Session that most recently produced an application event. The next
    /// poll starts after it in the hash table's current iteration order, so a
    /// continuously ready stream or DATAGRAM cannot starve another accepted
    /// session. Handles remain stable across rehashes; if this one is removed,
    /// the poller simply falls back to a complete scan.
    last_session_event_key: ?EndpointSessionKey = null,
    /// Malformed or excess CONNECT whose stream cancellation awaits transport
    /// credit. Other Sessions keep their connection and routing state.
    request_rejection_pending: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        connect_rejection.Pending,
    ) = .empty,
    /// Connections whose most recent Session was rejected and which currently
    /// have no active Session key. They remain eligible for a later CONNECT.
    idle_connections: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        void,
    ) = .empty,

    pub fn init(
        server: *HandshakeServer,
        options: http3.runtime.HandshakeAdmissionOptions,
    ) http3.runtime.HandshakeAdmissionError!EndpointServer {
        return .{
            .allocator = server.h3.allocator,
            .limits = server.limits,
            .h3 = try .init(&server.h3, options),
        };
    }

    pub fn address(self: *const EndpointServer) net.IpAddress {
        return self.h3.server.address();
    }

    pub fn deinit(self: *EndpointServer) void {
        var early = self.early.valueIterator();
        while (early.next()) |state| state.deinit(self.allocator);
        self.early.deinit(self.allocator);
        var pending = self.pending.valueIterator();
        while (pending.next()) |value| {
            value.*.request.deinit(self.allocator);
            self.allocator.destroy(value.*);
        }
        self.pending.deinit(self.allocator);
        var sessions = self.sessions.valueIterator();
        while (sessions.next()) |value| {
            value.*.deinit(self.allocator);
            self.allocator.destroy(value.*);
        }
        self.sessions.deinit(self.allocator);
        self.idle_connections.deinit(self.allocator);
        self.request_rejection_pending.deinit(self.allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn connectionCount(self: *const EndpointServer) usize {
        return self.h3.connectionCount();
    }

    pub fn pendingSessionCount(self: *const EndpointServer) usize {
        return self.pending.count();
    }

    pub fn sessionCount(self: *const EndpointServer) usize {
        return self.sessions.count();
    }

    pub fn rejectedSessionCount(self: *const EndpointServer) usize {
        return self.idle_connections.count();
    }

    pub fn pendingSession(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*EndpointPendingSession {
        return self.pending.get(handle);
    }

    pub fn session(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*EndpointAcceptedSession {
        const key = self.firstSessionKey(handle) orelse return null;
        return self.sessions.get(key);
    }

    pub fn sessionById(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        session_id: webtransport.SessionId,
    ) ?*EndpointAcceptedSession {
        return self.sessions.get(.{
            .handle = handle,
            .session_id = session_id,
        });
    }

    /// Retained accepted Session owners, including closed handles. Concurrent
    /// admission counts only live Sessions.
    pub fn sessionCountForConnection(
        self: *const EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) usize {
        var count: usize = 0;
        var iterator = self.sessions.keyIterator();
        while (iterator.next()) |key| {
            count += @intFromBool(key.handle == handle);
        }
        return count;
    }

    const canAdmitSession = @import("../connect/session_capacity.zig").serverCanAdmit;

    pub fn accept(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) EndpointServerError!*EndpointAcceptedSession {
        return self.acceptWithHeaders(handle, &.{});
    }

    pub fn acceptWithHeaders(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        additional_headers: []const http3.Qpack.HeaderField,
    ) EndpointServerError!*EndpointAcceptedSession {
        const source = self.pending.get(handle) orelse
            return error.InvalidSessionState;
        _ = try self.maintainEarlyConnection(handle, source.h3);
        try validateConnectOrigin(
            source.request.request,
            source.limits.origin_policy,
        );
        if (!try self.canAdmitSession(handle, source.h3)) {
            return error.InvalidSessionState;
        }
        // Reserve every allocation before emitting status 200. Once the peer
        // observes acceptance this state transition must be infallible.
        try self.sessions.ensureUnusedCapacity(self.allocator, 1);
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponseWithProtocols(
            self.allocator,
            source.request.request.headers,
            additional_headers,
            source.limits.application_protocols,
            &header_stack,
        );
        defer prepared_headers.deinit(self.allocator);
        var streams = try initHandshakeStreamRegistry(
            self.allocator,
            source.session_id,
            .server,
            source.h3.options.local_settings,
            source.h3.control.settings.peer,
            source.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        const control = try session_control.Control.init(
            self.allocator,
            source.session_id,
        );
        const accepted = try self.allocator.create(EndpointAcceptedSession);
        errdefer self.allocator.destroy(accepted);
        const response_result = source.h3.tryAcceptConnectResponse(
            source.session_id.value,
            connectResponseWithHeaders(prepared_headers.fields),
        );
        response_result catch |err| {
            try self.h3.dispatcher.refreshConnectionTimer(handle);
            return err;
        };

        const removed_entry = self.pending.fetchRemove(handle) orelse
            unreachable;
        const removed = removed_entry.value;
        const key = EndpointSessionKey{
            .handle = handle,
            .session_id = removed.session_id,
        };
        const slot = self.sessions.getOrPutAssumeCapacity(key);
        std.debug.assert(!slot.found_existing);
        accepted.* = .{
            .handle = handle,
            .dispatcher = self.h3.dispatcher,
            .h3 = removed.h3,
            .request = removed.request,
            .selected_application_protocol = prepared_headers.selected_application_protocol,
            .session_id = removed.session_id,
            .streams = streams,
            .control = control,
        };
        slot.value_ptr.* = accepted;
        _ = self.idle_connections.remove(handle);
        self.allocator.destroy(removed);
        self.h3.dispatcher.refreshConnectionTimer(handle) catch |err| {
            std.debug.panic(
                "WebTransport endpoint lost registered timer after acceptance: {s}",
                .{@errorName(err)},
            );
        };
        return accepted;
    }

    pub fn reject(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) EndpointServerError!void {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        const source = self.pending.get(handle) orelse
            return error.InvalidSessionState;
        const becomes_idle = self.sessionCountForConnection(handle) == 0;
        if (becomes_idle) {
            try self.idle_connections.ensureUnusedCapacity(self.allocator, 1);
        }
        try source.h3.connect_datagrams.rejectEarlyAssociation(source.session_id.value);
        try self.noteEarlyRejection(handle, source.h3, source.session_id.value);
        const response_result = source.h3.trySendResponseLiteral(source.session_id.value, .{
            .status = status,
            .headers = response_headers,
            .request_method = "CONNECT",
            .extended_connect = true,
        });
        response_result catch |err| {
            try self.h3.dispatcher.refreshConnectionTimer(handle);
            return err;
        };
        const removed = self.pending.fetchRemove(handle).?.value;
        removed.request.deinit(self.allocator);
        self.allocator.destroy(removed);
        if (becomes_idle) {
            self.idle_connections.putAssumeCapacity(handle, {});
        }
        self.h3.dispatcher.refreshConnectionTimer(handle) catch |err| {
            std.debug.panic(
                "WebTransport endpoint lost registered timer after rejection: {s}",
                .{@errorName(err)},
            );
        };
    }

    pub fn removeConnection(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) bool {
        if (self.early.fetchRemove(handle)) |removed| {
            var state = removed.value;
            state.deinit(self.allocator);
        }
        while (self.firstSessionKey(handle)) |key| {
            const removed = self.sessions.fetchRemove(key).?.value;
            removed.deinit(self.allocator);
            self.allocator.destroy(removed);
        }
        if (self.pending.fetchRemove(handle)) |removed_value| {
            const removed = removed_value.value;
            removed.request.deinit(self.allocator);
            self.allocator.destroy(removed);
        }
        _ = self.request_rejection_pending.remove(handle);
        _ = self.idle_connections.remove(handle);
        if (self.last_session_event_key) |key| {
            if (key.handle == handle) self.last_session_event_key = null;
        }
        return self.h3.removeConnection(handle);
    }

    /// Terminate and remove one accepted Session while retaining its HTTP/3
    /// connection and siblings. Active Sessions close normally with code zero.
    /// Backpressure or send failure preserves the owner and completed terminal
    /// progress; capacity is released only after cleanup submission succeeds.
    pub fn removeSession(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        session_id: webtransport.SessionId,
    ) EndpointServerError!bool {
        const key = EndpointSessionKey{
            .handle = handle,
            .session_id = session_id,
        };
        const target = self.sessions.get(key) orelse return false;
        const becomes_idle = self.sessionCountForConnection(handle) == 1;
        if (becomes_idle) {
            try self.idle_connections.ensureUnusedCapacity(self.allocator, 1);
        }
        if (self.h3.session(handle)) |h3| try self.noteEarlyRejection(handle, h3, session_id.value);
        try server_terminal.finish(target);
        const removed = self.sessions.fetchRemove(key).?.value;
        removed.deinit(self.allocator);
        self.allocator.destroy(removed);
        if (becomes_idle) self.idle_connections.putAssumeCapacity(handle, {});
        if (self.last_session_event_key) |last| {
            if (std.meta.eql(last, key)) self.last_session_event_key = null;
        }
        return true;
    }

    fn firstSessionKey(
        self: *const EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?EndpointSessionKey {
        var iterator = self.sessions.keyIterator();
        while (iterator.next()) |key| {
            if (key.handle == handle) return key.*;
        }
        return null;
    }

    fn sessionLookup(
        self: *const EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) stream_association.SessionLookup {
        return .{
            .context = self,
            .scope = @intCast(handle),
            .containsFn = endpointContainsSession,
        };
    }

    fn endpointContainsSession(
        context: *const anyopaque,
        scope: u64,
        session_id: u62,
    ) bool {
        const self: *const EndpointServer = @ptrCast(@alignCast(context));
        // The connection's early-stream owner decides quotas and expiry for
        // foreign Session IDs. A live Session must leave those streams alone.
        if (self.early.contains(@intCast(scope))) return true;
        if (self.pending.get(@intCast(scope))) |pending| {
            if (pending.session_id.value == session_id) return true;
        }
        return self.sessions.contains(.{
            .handle = @intCast(scope),
            .session_id = .init(session_id),
        });
    }

    const Early = @import("../association/endpoint.zig").For(@This());
    const maintainEarlyConnection = Early.maintain;
    const maintainEarlyStreams = Early.maintainAll;
    const noteEarlyRejection = Early.reject;
    const earlyDeadline = Early.boundedDeadline;
    const Rejections = @import("../connect/endpoint_rejection.zig").For(@This(), noteEarlyRejection);

    /// Run the endpoint-owned receive loop until `shutdown` is set. The
    /// callback executes synchronously on the sole owner so it may accept or
    /// reject a pending request and use the session send APIs without locks.
    /// Session events borrow the supplied receive buffer only for the callback.
    pub fn serveUntil(
        self: *EndpointServer,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *EndpointServer,
            ServeEvent,
        ) anyerror!void,
        options: ServeOptions,
    ) anyerror!void {
        return endpoint_serve.run(self, Context, context, handler, options, receiveOnceInternal);
    }

    pub fn receive(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
        stream_buffer: []u8,
    ) EndpointServerError!EndpointServerEvent {
        while (true) {
            if (try self.receiveOnce(
                supported_versions,
                poll_interval,
                stream_buffer,
            )) |event| return event;
        }
    }

    /// Wait for one session event under one relative awake-clock budget.
    pub fn receiveWithTimeout(
        self: *EndpointServer,
        supported_versions: []const u32,
        timeout: std.Io.Duration,
        stream_buffer: []u8,
    ) EndpointServerError!EndpointServerEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(
            supported_versions,
            .fromNow(self.h3.server.quic_server.endpoint.io, .{
                .clock = .awake,
                .raw = timeout,
            }),
            stream_buffer,
        );
    }

    /// Perform one bounded endpoint iteration. A null result lets a caller
    /// inspect shutdown or maintenance state without a second UDP reader.
    pub fn receiveOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        if (self.serve_failure_sink != null) return error.ConcurrentRead;
        return self.receiveOnceInternal(supported_versions, poll_interval, stream_buffer);
    }

    fn receiveOnceInternal(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        if (stream_buffer.len == 0) return error.BufferTooShort;
        try self.maintainEarlyStreams();
        if (try self.pollBufferedSessionRequest()) |event| return event;
        if (try self.pollAcceptedSessions(stream_buffer)) |event| return event;

        const poll_deadline = std.Io.Clock.Timestamp.fromNow(self.h3.server.quic_server.endpoint.io, .{ .clock = .awake, .raw = poll_interval.raw });
        const early_deadline = self.earlyDeadline(poll_deadline);
        if (early_deadline.raw.nanoseconds < poll_deadline.raw.nanoseconds and
            early_deadline.raw.nanoseconds <= std.Io.Clock.awake.now(self.h3.server.quic_server.endpoint.io).nanoseconds) return null;
        const interval = if (early_deadline.raw.nanoseconds < poll_deadline.raw.nanoseconds) early_deadline.durationFromNow(self.h3.server.quic_server.endpoint.io) else poll_interval;
        const event_value = (try self.h3.receiveTransportOnce(
            supported_versions,
            interval,
        )) orelse {
            try self.maintainEarlyStreams();
            return null;
        };
        return self.processTransportEvent(event_value, stream_buffer);
    }

    /// Receive one session event under a caller-owned absolute deadline.
    /// Packets for other sessions, handshake completions, and QUIC timers are
    /// processed without renewing that outer budget.
    pub fn receiveWithDeadline(
        self: *EndpointServer,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
        stream_buffer: []u8,
    ) EndpointServerError!EndpointServerEvent {
        if (stream_buffer.len == 0) return error.BufferTooShort;
        const absolute = try deadline_policy.usableAwake(
            self.h3.server.quic_server.endpoint.io,
            deadline,
        );
        if (self.serve_failure_sink != null) return error.ConcurrentRead;
        try self.maintainEarlyStreams();
        if (try self.pollBufferedSessionRequest()) |event| return event;
        if (try self.pollAcceptedSessions(stream_buffer)) |event| return event;
        while (true) {
            const wait_deadline = self.earlyDeadline(absolute);
            const transport_event = self.h3.receiveTransportWithDeadline(
                supported_versions,
                wait_deadline,
            ) catch |err| switch (err) {
                error.Timeout => {
                    if (wait_deadline.raw.nanoseconds >= absolute.raw.nanoseconds) return err;
                    try self.maintainEarlyStreams();
                    continue;
                },
                else => return err,
            };
            if (try self.processTransportEvent(
                transport_event,
                stream_buffer,
            )) |event| return event;
            try self.maintainEarlyStreams();
            if (try self.pollBufferedSessionRequest()) |event| return event;
            if (try self.pollAcceptedSessions(stream_buffer)) |event| {
                return event;
            }
        }
    }

    fn processTransportEvent(
        self: *EndpointServer,
        event_value: http3.runtime.EndpointTransportEvent,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        var event = event_value;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |handle| return .{ .connected = handle },
            .closed => |closed| {
                const handle = closed.handle;
                if (self.early.fetchRemove(handle)) |removed| {
                    var state = removed.value;
                    state.deinit(self.allocator);
                }
                while (self.firstSessionKey(handle)) |key| {
                    const removed = self.sessions.fetchRemove(key).?.value;
                    // The transport is already gone; the HTTP/3 session may
                    // have been released with it.
                    removed.transport_closed = true;
                    removed.deinit(self.allocator);
                    self.allocator.destroy(removed);
                }
                if (self.pending.fetchRemove(handle)) |removed_value| {
                    const removed = removed_value.value;
                    removed.request.deinit(self.allocator);
                    self.allocator.destroy(removed);
                }
                _ = self.request_rejection_pending.remove(handle);
                _ = self.idle_connections.remove(handle);
                if (self.last_session_event_key) |key| {
                    if (key.handle == handle) {
                        self.last_session_event_key = null;
                    }
                }
                return .{ .closed = .{
                    .handle = handle,
                    .timer = closed.timer,
                } };
            },
            .handshake_failed => |failure| return .{
                .handshake_failed = .{
                    .handle = failure.handle,
                    .err = failure.err,
                },
            },
            .packet => |*packet| {
                const handle = packet.connection_handle;
                var result = self.processRoutedPacket(
                    handle,
                    &packet.packet,
                    stream_buffer,
                ) catch |err| {
                    // HTTP/3/WebTransport parsing can queue transport control
                    // or close frames before surfacing an error. The QUIC
                    // dispatcher refreshed before handing out this packet, so
                    // mirror the complete adapter result before returning it.
                    try self.h3.dispatcher.refreshConnectionTimer(handle);
                    endpoint_serve.noteConnection(self, handle, err);
                    return err;
                };
                errdefer if (result) |*owned| owned.deinit(self.allocator);
                try self.h3.dispatcher.refreshConnectionTimer(handle);
                return result;
            },
            .unrouted => {
                const unrouted = event.unrouted;
                event = .{ .connected = 0 };
                return .{ .unrouted = unrouted };
            },
        }
        return null;
    }

    fn processRoutedPacket(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        packet: *const quic.one_rtt.ReceivedPacket,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        const h3 = self.h3.session(handle) orelse
            return error.InvalidSessionState;
        try h3.processRequestPacket(packet);
        _ = try self.maintainEarlyConnection(handle, h3);
        if (try self.pollNewSessionRequest(handle, h3)) |event| return event;
        return self.pollAcceptedSessions(stream_buffer);
    }

    fn pollBufferedSessionRequest(
        self: *EndpointServer,
    ) EndpointServerError!?EndpointServerEvent {
        try Rejections.retryBuffered(self);
        var session_keys = self.sessions.keyIterator();
        while (session_keys.next()) |key| {
            if (self.request_rejection_pending.contains(key.handle)) continue;
            const h3 = self.h3.session(key.handle) orelse
                return error.InvalidSessionState;
            if (try self.pollNewSessionRequest(key.handle, h3)) |event| {
                return event;
            }
        }
        var idle = self.idle_connections.keyIterator();
        while (idle.next()) |handle| {
            if (self.request_rejection_pending.contains(handle.*)) continue;
            const h3 = self.h3.session(handle.*) orelse
                return error.InvalidSessionState;
            if (try self.pollNewSessionRequest(handle.*, h3)) |event| {
                return event;
            }
        }
        return null;
    }

    fn pollNewSessionRequest(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        h3: *http3.runtime.HandshakeServerSession,
    ) EndpointServerError!?EndpointServerEvent {
        if (connection_lifecycle.terminating(&h3.established.connection)) {
            _ = self.request_rejection_pending.remove(handle);
            return null;
        }
        if (self.pending.contains(handle)) return null;
        if (!try Rejections.retryOne(self, handle, h3)) return null;
        try Rejections.reserve(self, handle);
        const result = (try connect_request_head.poll(h3)) orelse return null;
        const request = switch (result) {
            .failure => |failure| {
                Rejections.retain(self, handle, connect_rejection.Pending.forRequestFailure(failure));
                _ = try Rejections.retryOne(self, handle, h3);
                return null;
            },
            .head => |head| head,
        };
        var owned_request = request.request;
        var transferred = false;
        defer if (!transferred) owned_request.deinit(self.allocator);
        connect_negotiation.validateRequestWithPolicy(h3, owned_request.request, self.limits.require_session_flow_control) catch |err| {
            const failure = connect_rejection.Failure.fromError(err) orelse return err;
            const rejection = connect_rejection.Pending.forFailure(request.session_id.value, failure);
            Rejections.retain(self, handle, rejection);
            _ = try Rejections.retryOne(self, handle, h3);
            return null;
        };
        if (!try self.canAdmitSession(handle, h3)) {
            Rejections.retain(self, handle, .{ .stream_id = request.session_id.value, .application_error_code = http3.ApplicationErrorCode.request_rejected });
            _ = try Rejections.retryOne(self, handle, h3);
            return null;
        }
        const pending = try self.allocator.create(EndpointPendingSession);
        errdefer self.allocator.destroy(pending);
        const slot = try self.pending.getOrPut(self.allocator, handle);
        if (slot.found_existing) return error.InvalidSessionState;
        pending.* = .{
            .handle = handle,
            .h3 = h3,
            .request = owned_request,
            .session_id = request.session_id,
            .limits = self.limits,
        };
        transferred = true;
        owned_request = undefined;
        slot.value_ptr.* = pending;
        _ = self.idle_connections.remove(handle);
        return .{ .session_request = handle };
    }

    fn pollAcceptedSessions(
        self: *EndpointServer,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        return self.pollAcceptedSessionsWith(
            stream_buffer,
            self,
            pollEndpointSessionEntry,
        );
    }

    fn pollAcceptedSessionsWith(
        self: *EndpointServer,
        stream_buffer: []u8,
        context: anytype,
        comptime poll: anytype,
    ) EndpointServerError!?EndpointServerEvent {
        return round_robin.poll(
            EndpointSessionKey,
            @TypeOf(self.sessions),
            EndpointServerEvent,
            &self.sessions,
            &self.last_session_event_key,
            .{ .stream_buffer = stream_buffer, .context = context },
            struct {
                fn run(
                    poll_context: anytype,
                    key: EndpointSessionKey,
                    accepted_ptr: **EndpointAcceptedSession,
                ) EndpointServerError!?EndpointServerEvent {
                    const event = (try poll(
                        poll_context.context,
                        key,
                        accepted_ptr.*,
                        poll_context.stream_buffer,
                    )) orelse return null;
                    return .{ .session_event = .{
                        .handle = key.handle,
                        .session_id = key.session_id,
                        .event = event,
                    } };
                }
            }.run,
        );
    }

    fn pollEndpointSessionEntry(
        server: *EndpointServer,
        _: EndpointSessionKey,
        accepted: *EndpointAcceptedSession,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointSessionEvent {
        var event = pollEndpointSession(
            accepted,
            stream_buffer,
            server.sessionLookup(accepted.handle),
        ) catch |err| {
            // A failing protocol poll can still queue transport control or
            // close frames. Preserve its error while ensuring the shared
            // endpoint observes the resulting recovery deadline.
            try accepted.refreshTimer();
            endpoint_serve.noteSession(server, accepted, err);
            endpoint_serve.noteConnection(server, accepted.handle, err);
            return err;
        };
        errdefer if (event) |*owned| {
            owned.deinit(accepted.h3.established.connection.endpoint.allocator);
        };
        // Polling can consume stream bytes, emit receive credit/MAX_STREAMS,
        // or arm a retry after an automatic credit send fails. Mirror the
        // resulting aggregate connection deadline before the endpoint blocks
        // on its shared UDP socket again.
        try accepted.refreshTimer();
        return event;
    }

    pub const testing = struct {
        const ReadyProbe = struct {
            ready: []const quic.endpoint_dispatcher.ConnectionHandle,

            fn poll(
                self: *const ReadyProbe,
                key: EndpointSessionKey,
                _: *EndpointAcceptedSession,
                _: []u8,
            ) Error!?EndpointSessionEvent {
                if (std.mem.indexOfScalar(
                    quic.endpoint_dispatcher.ConnectionHandle,
                    self.ready,
                    key.handle,
                ) == null) return null;
                return .{ .session = .draining };
            }
        };

        /// Apply the production scheduler to synthetic readiness. This keeps
        /// starvation tests deterministic without constructing QUIC traffic
        /// merely to seed already-accepted session queues.
        pub fn pollReadySessionHandle(
            server: *EndpointServer,
            ready: []const quic.endpoint_dispatcher.ConnectionHandle,
        ) EndpointServerError!?quic.endpoint_dispatcher.ConnectionHandle {
            var probe = ReadyProbe{ .ready = ready };
            var scratch: [1]u8 = undefined;
            const event = (try server.pollAcceptedSessionsWith(
                &scratch,
                &probe,
                ReadyProbe.poll,
            )) orelse return null;
            return event.session_event.handle;
        }

        /// Exercise the production accepted-session poll adapter, including
        /// its mandatory dispatcher timer refresh, without constructing the
        /// outer endpoint admission maps in focused transport tests.
        pub fn pollAcceptedSessionEntry(
            accepted: *EndpointAcceptedSession,
            stream_buffer: []u8,
        ) EndpointServerError!?EndpointSessionEvent {
            _ = try rejectAdditionalEndpointRequestsOnce(accepted);
            var event = pollEndpointSession(
                accepted,
                stream_buffer,
                null,
            ) catch |err| {
                try accepted.refreshTimer();
                return err;
            };
            errdefer if (event) |*owned| {
                owned.deinit(
                    accepted.h3.established.connection.endpoint.allocator,
                );
            };
            try accepted.refreshTimer();
            return event;
        }

        pub fn processAcceptedPacket(
            accepted: *EndpointAcceptedSession,
            packet: *const quic.one_rtt.ReceivedPacket,
        ) EndpointServerError!void {
            try accepted.h3.processDetachedRequestPacket(
                accepted.session_id.value,
                packet,
            );
            _ = try rejectAdditionalEndpointRequestsOnce(accepted);
            try accepted.refreshTimer();
        }
    };

    fn pollEndpointSession(
        target: *EndpointAcceptedSession,
        stream_buffer: []u8,
        sessions: ?stream_association.SessionLookup,
    ) Error!?EndpointSessionEvent {
        target.control.bindFlow(target.streams.flow);
        defer _ = connection_lifecycle.observe(&target.control, target.h3, &target.streams);
        if (connection_lifecycle.observe(&target.control, target.h3, &target.streams)) {
            target.close_response_pending = false;
            return null;
        }
        // Accepted sessions remain in the endpoint map until the application
        // removes their connection. Keep polling the CONNECT stream after the
        // terminal event solely to enforce WT_CLOSE_SESSION's no-more-data
        // rule; associated stream/DATAGRAM APIs remain hidden below.
        const control_event = target.control.pollOnce(
            &target.h3.established.connection,
        ) catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => return null,
            error.InvalidCapsule, error.FlowControlViolation => {
                _ = target.control.tryRejectInvalidCapsule(
                    &target.h3.established.connection,
                ) catch |rejection_err| switch (rejection_err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => return null,
                    else => return rejection_err,
                };
                target.close_response_pending = false;
                target.control.capsule_error_reported = true;
                return err;
            },
            else => {
                try http3.runtime.closeConnectionForProtocolError(
                    &target.h3.established.connection,
                    err,
                );
                return err;
            },
        };
        if (control_event) |event| {
            try finishEndpointSessionEvent(target, event);
            return .{ .session = event };
        }
        const close_progress = advanceEndpointCloseOnce(target) catch |err|
            switch (err) {
                error.FlowControlBlocked,
                error.CongestionLimited,
                error.PacingLimited,
                => return null,
                else => |other| return other,
            };
        if (close_progress == .submitted) return null;
        if (target.control.state.closed) return null;
        const stream_event = if (sessions) |known|
            try incremental_stream.pollOnceShared(
                &target.h3.established.connection,
                &target.streams,
                target.session_id,
                stream_buffer,
                known,
            )
        else
            try incremental_stream.pollOnce(
                &target.h3.established.connection,
                &target.streams,
                target.session_id,
                stream_buffer,
            );
        if (stream_event) |event| {
            return .{ .stream = event };
        }
        if (try target.h3.pollConnectDatagram(
            target.session_id.value,
        )) |datagram| {
            return .{ .datagram = ownedHandshakeDatagram(
                datagram,
                target.session_id,
            ) };
        }
        return null;
    }
};

fn rejectAdditionalEndpointRequestsOnce(
    target: *EndpointAcceptedSession,
) Error!bool {
    return rejectAdditionalHandshakeRequestsOnce(
        target.h3,
        &target.streams,
        target.session_id,
        &target.request_rejection_pending,
    );
}

pub fn rejectAdditionalHandshakeRequestsOnce(
    h3: *http3.runtime.HandshakeServerSession,
    streams: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    request_rejection_pending: *?u62,
) Error!bool {
    if (request_rejection_pending.*) |stream_id| {
        h3.tryCancelRequest(
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
        ) catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => return false,
            else => return err,
        };
        request_rejection_pending.* = null;
    }

    var after: ?u62 = null;
    var stream_ids: [16]u62 = undefined;
    while (true) {
        const ids = h3.established.connection
            .receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |stream_id| {
            if (stream_id == session_id.value or
                (stream_id & 0x03) != 0 or
                streams.get(stream_id) != null)
            {
                continue;
            }
            const available = h3.established.connection
                .availableReceivedStream(stream_id) orelse continue;
            const prefix = quic.varint.decodeSlice(available) catch |err|
                switch (err) {
                    error.BufferTooShort => continue,
                    else => return err,
                };
            if (prefix.value == http3.FrameType.webtransport_stream) {
                continue;
            }
            const event_value = (try h3.pollRequestEventForOnce(
                stream_id,
            )) orelse continue;
            var event = event_value;
            defer event.deinit(
                h3.established.connection.endpoint.allocator,
            );
            const request_stream_id = switch (event) {
                .reset => continue,
                .message => |message| message.stream_id,
            };
            request_rejection_pending.* = request_stream_id;
            h3.tryCancelRequest(
                request_stream_id,
                http3.ApplicationErrorCode.request_rejected,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => {
                    return false;
                },
                else => return err,
            };
            request_rejection_pending.* = null;
        }
        if (ids.len == 0 or ids.len < stream_ids.len) return true;
        after = ids[ids.len - 1];
    }
}

fn finishEndpointSessionEvent(
    target: *EndpointAcceptedSession,
    event: SessionEvent,
) Error!void {
    if (event == .closed or event == .reset) {
        if (event == .closed and !target.control.local_close_sent and !target.control.local_close_failed) {
            // Deliver the peer event even when its response FIN is currently
            // paced or flow-control blocked. The next endpoint turn owns the
            // retry and cannot consume another socket receive here.
            target.close_response_pending = true;
        }
        // Keep the detached association registered while this accepted
        // session remains owned by the shared endpoint. Later ACK-only
        // packets still need the detached HTTP/3 visitor, and the registry's
        // terminal state silently drops datagrams after FIN/reset. Session
        // teardown performs the final unregister.
    }
}

const advanceEndpointCloseOnce = server_terminal.advanceOnce;
