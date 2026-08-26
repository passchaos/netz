const std = @import("std");
const webtransport = @import("mod.zig");
const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;
const datagram_stack_capacity: usize = 4096;
const session_control = @import("runtime/session_control.zig");
const protected_control =
    @import("runtime/protected_session_control.zig");
const stream_batch = @import("runtime/stream_batch.zig");

test {
    _ = @import("runtime/endpoint_dispatcher_tests.zig");
    _ = @import("runtime/endpoint_server_tests.zig");
}

pub const Error = webtransport.Error || http3.runtime.Error || error{
    InvalidConnect,
    SessionRejected,
    MissingDatagram,
    InvalidSessionState,
} || protected_control.Error;

pub const EndpointServerError = Error ||
    http3.runtime.HandshakeAdmissionError;

pub const Limits = struct {
    http3: http3.runtime.Limits = .{},
    max_session_streams: usize = 128,
};

// HTTP/3's request/response convenience encoders use a 64-field stack array.
// Leave room for four request pseudo-fields or the response :status field,
// plus the protocol fields inserted by this adapter.
const max_additional_connect_request_headers: usize = 57;
const max_additional_connect_response_headers: usize = 62;
pub const max_connection_close_reason: usize = 1024;

pub const Server = struct {
    h3: http3.runtime.Server,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3) };
    }

    pub fn deinit(self: *Server) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *Server) Error!AcceptedSession {
        var pending = try self.receiveSessionRequest();
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Receive and validate a development-runtime Extended CONNECT before
    /// committing an application admission decision.
    pub fn receiveSessionRequest(self: *Server) Error!PendingSession {
        var request = try self.h3.receiveRequest();
        errdefer request.deinit(self.h3.quic_server.endpoint.allocator);
        try validateConnectRequest(request.request);
        const session_id = webtransport.SessionId.init(request.stream_id);
        if (!session_id.isClientInitiatedBidirectional()) return error.InvalidConnect;
        return .{ .server = self, .request = request, .session_id = session_id };
    }

    pub fn receiveDatagram(self: *Server) Error!OwnedDatagram {
        return receiveDatagramFromEndpoint(&self.h3.quic_server.endpoint);
    }

    pub fn sendDatagram(self: *Server, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try sendDatagramFromEndpoint(&self.h3.quic_server.endpoint, to, session_id, payload);
    }
};

pub const ProtectedServer = struct {
    h3: http3.runtime.ProtectedServer,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        config: http3.runtime.ProtectedConfig,
    ) Error!ProtectedServer {
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3, webTransportProtectedConfig(config)) };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *ProtectedServer) Error!AcceptedProtectedSession {
        var pending = try self.receiveSessionRequest();
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Receive and validate a protected Extended CONNECT before deciding
    /// whether to accept or reject the session.
    pub fn receiveSessionRequest(
        self: *ProtectedServer,
    ) Error!PendingProtectedSession {
        const request = try receiveProtectedConnectRequest(&self.h3);
        var request_head = request.head;
        errdefer request_head.deinit(
            self.h3.quic_server.endpoint.allocator,
        );
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        const session_id = webtransport.SessionId.init(request.stream_id);
        if (!session_id.isClientInitiatedBidirectional()) return error.InvalidConnect;
        return .{
            .server = self,
            .request = .{
                .from = request.from,
                .stream_id = request.stream_id,
                .request = request_head,
            },
            .session_id = session_id,
        };
    }

    pub fn receiveDatagram(self: *ProtectedServer) Error!OwnedProtectedDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_server.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }

    pub fn sendDatagram(self: *ProtectedServer, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        try sendProtectedDatagramFromEndpoint(
            &self.h3.quic_server.endpoint,
            to,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            session_id,
            payload,
        );
    }

    /// Send Capsule Protocol bytes on the long-lived Extended CONNECT stream.
    pub fn sendSessionData(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.h3.sendResponseBody(
            to,
            session_id.value,
            data,
            fin,
        );
    }

    pub fn receiveSessionData(
        self: *ProtectedServer,
        session_id: webtransport.SessionId,
        out: []u8,
    ) Error!ProtectedSessionRead {
        while (true) {
            var event = try self.h3.receiveRequestEvent();
            defer event.deinit(self.h3.quic_server.endpoint.allocator);
            switch (event) {
                .reset => return error.InvalidSessionState,
                .message => |message| {
                    if (message.stream_id != session_id.value) {
                        return error.InvalidSessionState;
                    }
                    switch (message.value) {
                        .data_available => {
                            const count = try self.h3.readRequestData(
                                session_id.value,
                                out,
                            );
                            if (count != 0) {
                                return .{ .bytes = count };
                            }
                        },
                        .finished => return .{ .fin = true },
                        else => return error.InvalidSessionState,
                    }
                },
            }
        }
    }
};

/// A validated development-runtime CONNECT awaiting application admission.
/// The request keeps all received QUIC datagrams alive until this value is
/// accepted, rejected, or explicitly destroyed.
pub const PendingSession = struct {
    server: *Server,
    request: http3.runtime.OwnedRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *PendingSession) void {
        self.request.deinit(
            self.server.h3.quic_server.endpoint.allocator,
        );
        self.* = undefined;
    }

    pub fn peerAddress(self: PendingSession) net.IpAddress {
        return self.request.from;
    }

    pub fn authority(self: PendingSession) ?[]const u8 {
        return self.request.request.authority;
    }

    pub fn path(self: PendingSession) []const u8 {
        return self.request.request.path;
    }

    pub fn origin(self: PendingSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "origin");
    }

    pub fn userAgent(self: PendingSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "user-agent");
    }

    pub fn headers(self: PendingSession) []const http3.Qpack.HeaderField {
        return self.request.request.headers;
    }

    pub fn accept(self: *PendingSession) Error!AcceptedSession {
        return self.acceptWithHeaders(&.{});
    }

    pub fn acceptWithHeaders(
        self: *PendingSession,
        additional_headers: []const http3.Qpack.HeaderField,
    ) Error!AcceptedSession {
        try validateAdditionalConnectHeaders(additional_headers, .response);
        var response_headers: [max_additional_connect_response_headers + 1]http3.Qpack.HeaderField = undefined;
        response_headers[0] = http3.capsule.protocol_header;
        @memcpy(response_headers[1..][0..additional_headers.len], additional_headers);
        try self.server.h3.sendResponse(
            self.request.from,
            self.request.stream_id,
            connectResponseWithHeaders(
                response_headers[0 .. additional_headers.len + 1],
            ),
        );
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{ .request = request, .session_id = session_id };
    }

    pub fn reject(
        self: *PendingSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!RejectedSession {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try self.server.h3.sendResponse(
            self.request.from,
            self.request.stream_id,
            .{ .status = status, .headers = response_headers },
        );
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .request = request,
            .session_id = session_id,
            .status = status,
        };
    }

    pub fn forbidden(self: *PendingSession) Error!RejectedSession {
        return self.reject(403, &.{});
    }

    pub fn notFound(self: *PendingSession) Error!RejectedSession {
        return self.reject(404, &.{});
    }

    pub fn tooManyRequests(self: *PendingSession) Error!RejectedSession {
        return self.reject(429, &.{});
    }
};

pub const RejectedSession = struct {
    request: http3.runtime.OwnedRequest,
    session_id: webtransport.SessionId,
    status: u16,

    pub fn deinit(self: *RejectedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

/// A validated preconfigured-key CONNECT awaiting application admission.
pub const PendingProtectedSession = struct {
    server: *ProtectedServer,
    request: OwnedProtectedConnectRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *PendingProtectedSession) void {
        self.request.deinit(
            self.server.h3.quic_server.endpoint.allocator,
        );
        self.* = undefined;
    }

    pub fn peerAddress(self: PendingProtectedSession) net.IpAddress {
        return self.request.from;
    }

    pub fn authority(self: PendingProtectedSession) ?[]const u8 {
        return self.request.request.authority;
    }

    pub fn path(self: PendingProtectedSession) []const u8 {
        return self.request.request.path;
    }

    pub fn origin(self: PendingProtectedSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "origin");
    }

    pub fn userAgent(self: PendingProtectedSession) ?[]const u8 {
        return findHeader(self.request.request.headers, "user-agent");
    }

    pub fn headers(
        self: PendingProtectedSession,
    ) []const http3.Qpack.HeaderField {
        return self.request.request.headers;
    }

    pub fn accept(
        self: *PendingProtectedSession,
    ) Error!AcceptedProtectedSession {
        return self.acceptWithHeaders(&.{});
    }

    pub fn acceptWithHeaders(
        self: *PendingProtectedSession,
        additional_headers: []const http3.Qpack.HeaderField,
    ) Error!AcceptedProtectedSession {
        try validateAdditionalConnectHeaders(additional_headers, .response);
        var response_headers: [max_additional_connect_response_headers + 1]http3.Qpack.HeaderField = undefined;
        response_headers[0] = http3.capsule.protocol_header;
        @memcpy(response_headers[1..][0..additional_headers.len], additional_headers);
        // Extended CONNECT is the session control stream. Keep both
        // directions open; aggregate sendResponse would terminate it.
        try self.server.h3.startResponse(
            self.request.from,
            self.request.stream_id,
            connectResponseWithHeaders(
                response_headers[0 .. additional_headers.len + 1],
            ),
            null,
        );
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .request = request,
            .session_id = session_id,
            .control = protected_control.Reader.init(
                try session_control.Control.init(session_id),
            ),
        };
    }

    pub fn reject(
        self: *PendingProtectedSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!RejectedProtectedSession {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try self.server.h3.sendResponse(
            self.request.from,
            self.request.stream_id,
            .{ .status = status, .headers = response_headers },
        );
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .request = request,
            .session_id = session_id,
            .status = status,
        };
    }

    pub fn forbidden(
        self: *PendingProtectedSession,
    ) Error!RejectedProtectedSession {
        return self.reject(403, &.{});
    }

    pub fn notFound(
        self: *PendingProtectedSession,
    ) Error!RejectedProtectedSession {
        return self.reject(404, &.{});
    }

    pub fn tooManyRequests(
        self: *PendingProtectedSession,
    ) Error!RejectedProtectedSession {
        return self.reject(429, &.{});
    }
};

pub const RejectedProtectedSession = struct {
    request: OwnedProtectedConnectRequest,
    session_id: webtransport.SessionId,
    status: u16,

    pub fn deinit(
        self: *RejectedProtectedSession,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

/// A preconfigured-key WebTransport server backed by the complete stateful
/// QUIC transport. Unlike `ProtectedServer`, this variant owns recovery,
/// congestion/flow control, stream limits, and RESET/STOP state, so it safely
/// exposes the same associated-stream API as the TLS-handshake runtime.
pub const StatefulProtectedServer = struct {
    endpoint: quic.runtime.Endpoint,
    limits: Limits,
    h3_options: http3.runtime.HandshakeSessionOptions,
    transport: quic.handshake.PreconfiguredConnectionOptions,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        h3_options: http3.runtime.HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!StatefulProtectedServer {
        if (!http3.isHttp3Alpn(transport.alpn_protocol)) {
            return error.InvalidAlpn;
        }
        return .{
            .endpoint = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3.quic,
            ),
            .limits = limits,
            .h3_options = webTransportHandshakeSessionOptions(h3_options),
            .transport = transport,
        };
    }

    pub fn deinit(self: *StatefulProtectedServer) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: StatefulProtectedServer) net.IpAddress {
        return self.endpoint.address();
    }

    /// Receive the first protected packet, bind the stateful QUIC connection
    /// to its source address, and accept the WebTransport request with the
    /// default 200 response. Use `receiveSessionRequest` when admission policy
    /// must inspect request metadata or customize/reject the response.
    pub fn accept(self: *StatefulProtectedServer) Error!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequest();
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn receiveSessionRequest(
        self: *StatefulProtectedServer,
    ) Error!PendingHandshakeSession {
        var first = try self.endpoint.receiveBytes();
        defer first.deinit(self.endpoint.allocator);
        var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
            &self.endpoint,
            first.from,
            self.h3_options,
            self.transport,
        );
        errdefer h3.deinit();
        try h3.established.connection.preloadReceivedDatagram(
            first.from,
            first.bytes,
            first.ecn,
        );
        return receiveStatefulSessionRequest(&h3, self.limits);
    }

    /// Accept one WebTransport session from an already authenticated peer.
    /// The returned value borrows this server's endpoint and must be destroyed
    /// before the server, matching ordinary `HandshakeServer.accept`.
    pub fn acceptFrom(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
    ) Error!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequestFrom(peer);
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn receiveSessionRequestFrom(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
    ) Error!PendingHandshakeSession {
        var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
            &self.endpoint,
            peer,
            self.h3_options,
            self.transport,
        );
        errdefer h3.deinit();
        return receiveStatefulSessionRequest(&h3, self.limits);
    }
};

pub const HandshakeServer = struct {
    h3: http3.runtime.HandshakeServer,
    limits: Limits,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        options: http3.runtime.HandshakeServerOptions,
    ) Error!HandshakeServer {
        return .{
            .h3 = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3,
                webTransportHandshakeServerOptions(options),
            ),
            .limits = limits,
        };
    }

    pub fn deinit(self: *HandshakeServer) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: HandshakeServer) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *HandshakeServer) Error!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequest();
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Start WebTransport admission from an Initial received by the shared
    /// QUIC endpoint dispatcher instead of reading that first datagram again.
    pub fn receiveSessionRequestFromInitial(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!PendingHandshakeSession {
        var session = try self.h3.acceptFromInitial(initial);
        errdefer session.deinit();
        return receiveStatefulSessionRequest(&session, self.limits);
    }

    /// Complete only the QUIC/TLS phase from a routed Initial and datagram
    /// source. After this returns, promote `admission.connection()` into the
    /// endpoint dispatcher and feed it packets until `pollSessionRequest`
    /// yields the Extended CONNECT request. This split prevents either the
    /// handshake worker or WebTransport admission from reading the shared UDP
    /// socket.
    pub fn beginSessionAdmissionFromInitialSource(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!HandshakeAdmission {
        var session = try self.h3.acceptFromInitialSource(source, initial);
        errdefer session.deinit();
        try session.ensureSettingsSent();
        return .{ .h3 = session, .limits = self.limits };
    }

    /// Receive and validate Extended CONNECT without deciding admission. The
    /// caller can inspect authority/path/origin/custom headers, then call one
    /// of `PendingHandshakeSession`'s accept or rejection methods.
    pub fn receiveSessionRequest(
        self: *HandshakeServer,
    ) Error!PendingHandshakeSession {
        var session = try self.h3.accept();
        errdefer session.deinit();
        return receiveStatefulSessionRequest(&session, self.limits);
    }
};

/// In-progress WebTransport admission after QUIC/TLS has completed.
///
/// The caller registers `connection()` with the endpoint dispatcher, feeds
/// routed packets through `processPacket`, and polls for the CONNECT request.
/// Ownership of the HTTP/3 session transfers to the returned pending request.
pub const HandshakeAdmission = struct {
    h3: http3.runtime.HandshakeServerSession,
    limits: Limits,

    pub fn deinit(self: *HandshakeAdmission) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn connection(
        self: *HandshakeAdmission,
    ) *quic.one_rtt.Connection {
        return &self.h3.established.connection;
    }

    pub fn processPacket(
        self: *HandshakeAdmission,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        try self.h3.processRequestPacket(packet);
    }

    pub fn pollSessionRequest(
        self: *HandshakeAdmission,
    ) Error!?PendingHandshakeSession {
        while (try self.h3.pollRequestEvent()) |event_value| {
            var event = event_value;
            const allocator =
                self.h3.established.connection.endpoint.allocator;
            defer event.deinit(allocator);
            switch (event) {
                .reset => return error.InvalidConnect,
                .message => |*message| switch (message.value) {
                    .head => |*head| {
                        if (head.* != .request) return error.InvalidConnect;
                        try validateConnectRequest(head.request);
                        try webtransport.ensureDatagramsNegotiated(
                            self.h3.options.local_settings,
                            self.h3.control.settings.peer,
                        );
                        const session_id = webtransport.SessionId.init(
                            message.stream_id,
                        );
                        if (!session_id.isClientInitiatedBidirectional()) {
                            return error.InvalidConnect;
                        }
                        const request = head.request;
                        message.value = .finished;
                        const h3 = self.h3;
                        const limits = self.limits;
                        self.* = undefined;
                        return .{ .h3 = h3, .limits = limits, .request = .{
                            .stream_id = message.stream_id,
                            .request = request,
                        }, .session_id = session_id };
                    },
                    else => return error.InvalidConnect,
                },
            }
        }
        return null;
    }
};

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
    streams: webtransport.StreamRegistry,
    control: session_control.Control,

    pub fn sessionId(self: EndpointAcceptedSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn remoteAddress(self: EndpointAcceptedSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn sendDatagram(
        self: *EndpointAcceptedSession,
        payload: []const u8,
    ) EndpointServerError!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        try sendHandshakeDatagramFromConnection(
            &self.h3.established.connection,
            self.session_id,
            payload,
        );
        try self.refreshTimer();
    }

    pub fn openBidirectionalStream(
        self: *EndpointAcceptedSession,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return (try self.streams.openLocal(.bidirectional)).stream_id;
    }

    pub fn openUnidirectionalStream(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const stream_id = try self.h3.reserveServerUnidirectionalStreamId();
        const registered = try self.streams.registerLocal(
            stream_id,
            .unidirectional,
        );
        try self.refreshTimer();
        return registered.stream_id;
    }

    pub fn maxDatagramPayloadSize(
        self: EndpointAcceptedSession,
    ) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return webtransport.maxDatagramPayloadSize(
            self.h3.established.connection.maxDatagramPayloadSize(),
            self.session_id,
        );
    }

    pub fn maxDatagramSize(self: EndpointAcceptedSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: EndpointAcceptedSession) bool {
        webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        ) catch return false;
        return true;
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
        try self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
        try self.refreshTimer();
    }

    pub fn writeStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        payload: []const u8,
    ) EndpointServerError!usize {
        try self.control.ensureOpen();
        const written = try handshake_stream.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
        try self.refreshTimer();
        return written;
    }

    pub fn sendStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) EndpointServerError!void {
        try self.control.ensureOpen();
        try sendHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
        try self.refreshTimer();
    }

    pub fn setStreamPriority(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        try self.control.ensureOpen();
        try self.streams.setPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *EndpointAcceptedSession,
        stream_id: u62,
    ) Error!i32 {
        return self.streams.priority(stream_id);
    }

    pub fn writeStreams(
        self: *EndpointAcceptedSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) EndpointServerError!StreamWriteResult {
        try self.control.ensureOpen();
        const result = try stream_batch.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
        try self.refreshTimer();
        return result;
    }

    pub fn finishStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
    ) EndpointServerError!void {
        try self.control.ensureOpen();
        try handshake_stream.finish(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
        );
        try self.refreshTimer();
    }

    pub fn resetStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        try resetHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
        try self.refreshTimer();
    }

    pub fn stopStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        try stopHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
        try self.refreshTimer();
    }

    pub fn drain(self: *EndpointAcceptedSession) EndpointServerError!void {
        if (self.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.h3.sendResponseBodyPaced(
            self.session_id.value,
            capsule,
            false,
        );
        try self.control.recordLocalDrain();
        try self.refreshTimer();
    }

    pub fn close(
        self: *EndpointAcceptedSession,
        code: u32,
        reason: []const u8,
    ) EndpointServerError!void {
        if (self.control.local_close_sent) return;
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        try self.h3.sendResponseBodyPaced(
            self.session_id.value,
            capsule,
            true,
        );
        try self.control.recordLocalClose(code);
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &self.streams,
        );
        try self.refreshTimer();
    }

    fn refreshTimer(self: *EndpointAcceptedSession) EndpointServerError!void {
        try self.dispatcher.refreshConnectionTimer(self.handle);
    }

    fn deinit(self: *EndpointAcceptedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.streams.deinit();
        self.* = undefined;
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

pub const EndpointServerEvent = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    closed: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        timer: quic.one_rtt.TimerDeadline,
    },
    handshake_failed: struct {
        handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
        err: anyerror,
    },
    session_request: quic.endpoint_dispatcher.ConnectionHandle,
    session_event: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
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

/// Multi-connection WebTransport server with one UDP receive owner.
///
/// HTTP/3 retains stable heap-backed sessions and owns every dispatcher
/// registration. This wrapper stores only protocol state keyed by the same
/// handle, so admission and acceptance never move a registered QUIC
/// connection. Applications inspect a `session_request`, then call `accept` or
/// `reject`; accepted sessions subsequently yield stream, DATAGRAM and Capsule
/// events from `receive`.
pub const EndpointServer = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    h3: http3.runtime.EndpointServer,
    pending: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        *EndpointPendingSession,
    ) = .empty,
    sessions: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        *EndpointAcceptedSession,
    ) = .empty,
    rejected: std.AutoHashMapUnmanaged(
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
        self.rejected.deinit(self.allocator);
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
        return self.rejected.count();
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
        return self.sessions.get(handle);
    }

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
        // Reserve every allocation before emitting status 200. Once the peer
        // observes acceptance this state transition must be infallible.
        try self.sessions.ensureUnusedCapacity(self.allocator, 1);
        try validateAdditionalConnectHeaders(additional_headers, .response);
        var response_headers: [max_additional_connect_response_headers + 1]http3.Qpack.HeaderField = undefined;
        response_headers[0] = http3.capsule.protocol_header;
        @memcpy(
            response_headers[1..][0..additional_headers.len],
            additional_headers,
        );
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
        const control = try session_control.Control.init(source.session_id);
        const accepted = try self.allocator.create(EndpointAcceptedSession);
        errdefer self.allocator.destroy(accepted);
        try source.h3.startResponse(
            source.session_id.value,
            connectResponseWithHeaders(
                response_headers[0 .. additional_headers.len + 1],
            ),
            null,
        );
        try source.h3.detachRequestStream(source.session_id.value);

        const removed_entry = self.pending.fetchRemove(handle) orelse
            unreachable;
        const removed = removed_entry.value;
        const slot = self.sessions.getOrPutAssumeCapacity(handle);
        std.debug.assert(!slot.found_existing);
        accepted.* = .{
            .handle = handle,
            .dispatcher = self.h3.dispatcher,
            .h3 = removed.h3,
            .request = removed.request,
            .session_id = removed.session_id,
            .streams = streams,
            .control = control,
        };
        slot.value_ptr.* = accepted;
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
        try self.rejected.ensureUnusedCapacity(self.allocator, 1);
        try source.h3.sendResponse(source.session_id.value, .{
            .status = status,
            .headers = response_headers,
        });
        const removed = self.pending.fetchRemove(handle).?.value;
        removed.request.deinit(self.allocator);
        self.allocator.destroy(removed);
        self.rejected.putAssumeCapacityNoClobber(handle, {});
        try self.h3.dispatcher.refreshConnectionTimer(handle);
    }

    pub fn removeConnection(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) bool {
        if (self.sessions.fetchRemove(handle)) |removed_value| {
            const removed = removed_value.value;
            removed.deinit(self.allocator);
            self.allocator.destroy(removed);
        } else if (self.pending.fetchRemove(handle)) |removed_value| {
            const removed = removed_value.value;
            removed.request.deinit(self.allocator);
            self.allocator.destroy(removed);
        }
        _ = self.rejected.remove(handle);
        return self.h3.removeConnection(handle);
    }

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
        if (options.supported_versions.len == 0 or
            options.poll_interval.raw.nanoseconds <= 0 or
            options.stream_buffer_size == 0)
        {
            return error.InvalidSessionState;
        }
        const stream_buffer = try self.allocator.alloc(
            u8,
            options.stream_buffer_size,
        );
        defer self.allocator.free(stream_buffer);
        while (!options.shutdown.isSet()) {
            const event_value = self.receiveOnce(
                options.supported_versions,
                options.poll_interval,
                stream_buffer,
            ) catch |err| switch (err) {
                error.Canceled => if (options.shutdown.isSet()) return else return err,
                else => |other| return other,
            } orelse continue;
            var event = event_value;
            defer event.deinit(self.allocator);
            switch (event) {
                .connected => |handle| try handler(
                    context,
                    self,
                    .{ .connected = handle },
                ),
                .closed => |closed| try handler(
                    context,
                    self,
                    .{ .closed = .{
                        .handle = closed.handle,
                        .timer = closed.timer,
                    } },
                ),
                .session_request => |handle| {
                    const pending = self.pendingSession(handle) orelse
                        return error.InvalidSessionState;
                    try handler(
                        context,
                        self,
                        .{ .session_request = pending },
                    );
                },
                .session_event => |*value| {
                    const active = self.session(value.handle) orelse
                        return error.InvalidSessionState;
                    try handler(context, self, .{ .session_event = .{
                        .session = active,
                        .event = &value.event,
                    } });
                },
                // Unknown datagrams are already classified and owned. A
                // high-level server has no safe default response other than
                // the Version Negotiation handled below the event boundary.
                .unrouted => {},
                .handshake_failed => |failure| return failure.err,
            }
        }
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

    /// Perform one bounded endpoint iteration. A null result lets a caller
    /// inspect shutdown or maintenance state without a second UDP reader.
    pub fn receiveOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        if (stream_buffer.len == 0) return error.BufferTooShort;
        var sessions = self.sessions.iterator();
        while (sessions.next()) |entry| {
            if (try pollEndpointSession(entry.value_ptr.*, stream_buffer)) |event| {
                return .{ .session_event = .{
                    .handle = entry.key_ptr.*,
                    .event = event,
                } };
            }
        }

        const event_value = (try self.h3.receiveTransportOnce(
            supported_versions,
            poll_interval,
        )) orelse return null;
        var event = event_value;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |handle| return .{ .connected = handle },
            .closed => |closed| {
                const handle = closed.handle;
                if (self.sessions.fetchRemove(handle)) |removed_value| {
                    const removed = removed_value.value;
                    removed.deinit(self.allocator);
                    self.allocator.destroy(removed);
                } else if (self.pending.fetchRemove(handle)) |removed_value| {
                    const removed = removed_value.value;
                    removed.request.deinit(self.allocator);
                    self.allocator.destroy(removed);
                }
                _ = self.rejected.remove(handle);
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
                if (self.sessions.get(handle)) |session_value| {
                    try session_value.h3.processDetachedRequestPacket(
                        session_value.session_id.value,
                        &packet.packet,
                    );
                    return null;
                }
                if (self.pending.get(handle)) |pending_value| {
                    try pending_value.h3.processRequestPacket(
                        &packet.packet,
                    );
                    return null;
                }
                if (self.rejected.contains(handle)) {
                    const h3 = self.h3.session(handle) orelse
                        return error.InvalidSessionState;
                    try h3.processRequestPacket(&packet.packet);
                    while (try h3.pollRequestEvent()) |ignored_value| {
                        var ignored = ignored_value;
                        ignored.deinit(self.allocator);
                    }
                    return null;
                }
                const h3 = self.h3.session(handle) orelse
                    return error.InvalidSessionState;
                try h3.processRequestPacket(&packet.packet);
                const request = (try pollEndpointConnectHead(h3)) orelse
                    return null;
                errdefer {
                    var owned = request.request;
                    owned.deinit(self.allocator);
                }
                const pending = try self.allocator.create(
                    EndpointPendingSession,
                );
                errdefer self.allocator.destroy(pending);
                const slot = try self.pending.getOrPut(
                    self.allocator,
                    handle,
                );
                if (slot.found_existing) return error.InvalidSessionState;
                pending.* = .{
                    .handle = handle,
                    .h3 = h3,
                    .request = request.request,
                    .session_id = request.session_id,
                    .limits = self.limits,
                };
                slot.value_ptr.* = pending;
                return .{ .session_request = handle };
            },
            .unrouted => {
                const unrouted = event.unrouted;
                event = .{ .connected = 0 };
                return .{ .unrouted = unrouted };
            },
        }
    }

    fn pollEndpointSession(
        target: *EndpointAcceptedSession,
        stream_buffer: []u8,
    ) Error!?EndpointSessionEvent {
        if (try target.control.poll(
            &target.h3.established.connection,
        )) |event| {
            try finishEndpointSessionEvent(target, event);
            return .{ .session = event };
        }
        if (try incremental_stream.poll(
            &target.h3.established.connection,
            &target.streams,
            target.session_id,
            stream_buffer,
        )) |event| {
            return .{ .stream = event };
        }
        if (try popHandshakeDatagramFromConnection(
            &target.h3.established.connection,
        )) |datagram| {
            return .{ .datagram = datagram };
        }
        return null;
    }
};

const EndpointConnectHead = struct {
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
};

fn pollEndpointConnectHead(
    h3: *http3.runtime.HandshakeServerSession,
) Error!?EndpointConnectHead {
    while (try h3.pollRequestEvent()) |event_value| {
        var event = event_value;
        defer event.deinit(h3.established.connection.endpoint.allocator);
        switch (event) {
            .reset => return error.InvalidConnect,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidConnect;
                    try validateConnectRequest(head.request);
                    try webtransport.ensureDatagramsNegotiated(
                        h3.options.local_settings,
                        h3.control.settings.peer,
                    );
                    const session_id = webtransport.SessionId.init(
                        message.stream_id,
                    );
                    if (!session_id.isClientInitiatedBidirectional()) {
                        return error.InvalidConnect;
                    }
                    const request = head.request;
                    message.value = .finished;
                    return .{
                        .request = .{
                            .stream_id = message.stream_id,
                            .request = request,
                        },
                        .session_id = session_id,
                    };
                },
                else => return error.InvalidConnect,
            },
        }
    }
    return null;
}

fn finishEndpointSessionEvent(
    target: *EndpointAcceptedSession,
    event: SessionEvent,
) Error!void {
    if (event == .closed or event == .reset) {
        if (event == .closed and !target.control.local_close_sent) {
            try target.h3.sendResponseBodyPaced(
                target.session_id.value,
                &.{},
                true,
            );
            target.control.local_close_sent = true;
        }
        try session_control.terminateStreams(
            &target.h3.established.connection,
            &target.streams,
        );
    }
}

pub const AcceptedSession = struct {
    request: http3.runtime.OwnedRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *AcceptedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const AcceptedProtectedSession = struct {
    request: OwnedProtectedConnectRequest,
    session_id: webtransport.SessionId,
    control: protected_control.Reader,

    pub fn deinit(self: *AcceptedProtectedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }

    pub fn drain(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
    ) Error!void {
        if (self.control.control.local_drain_sent) return;
        try self.control.control.ensureOpen();
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try server.sendSessionData(
            self.request.from,
            self.session_id,
            capsule,
            false,
        );
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent) return;
        try self.control.control.ensureOpen();
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        try server.sendSessionData(
            self.request.from,
            self.session_id,
            capsule,
            true,
        );
        try self.control.control.recordLocalClose(code);
    }

    pub fn receiveSessionEvent(
        self: *AcceptedProtectedSession,
        server: *ProtectedServer,
    ) Error!SessionEvent {
        return receiveProtectedServerEvent(server, self) catch |err| switch (err) {
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
/// This value owns the HTTP/3 session and decoded request head. It must be
/// consumed by `accept`, `acceptWithHeaders`, or `reject`, or explicitly
/// destroyed with `deinit`. This two-phase shape lets authentication, routing,
/// Origin policy, and load shedding run before a success response is sent.
pub const PendingHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    limits: Limits,

    pub fn deinit(self: *PendingHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        self.h3.deinit();
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
        try validateAdditionalConnectHeaders(additional_headers, .response);
        var response_headers: [max_additional_connect_response_headers + 1]http3.Qpack.HeaderField = undefined;
        response_headers[0] = http3.capsule.protocol_header;
        @memcpy(response_headers[1..][0..additional_headers.len], additional_headers);
        const all_headers = response_headers[0 .. additional_headers.len + 1];
        var streams = try initHandshakeStreamRegistry(
            self.h3.established.connection.endpoint.allocator,
            self.session_id,
            .server,
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
            self.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        const control = try session_control.Control.init(self.session_id);
        try self.h3.startResponse(
            self.session_id.value,
            connectResponseWithHeaders(all_headers),
            null,
        );
        try self.h3.detachRequestStream(self.session_id.value);
        const h3 = self.h3;
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .h3 = h3,
            .request = request,
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
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try self.h3.sendResponse(self.session_id.value, .{
            .status = status,
            .headers = response_headers,
        });
        const h3 = self.h3;
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .h3 = h3,
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
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    status: u16,

    pub fn deinit(self: *RejectedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    /// Process one timer-aware QUIC receive. Applications that keep serving a
    /// rejected connection can call this until their own shutdown policy says
    /// it is safe to release retransmission state.
    pub fn serviceTransport(self: *RejectedHandshakeSession) Error!void {
        try self.h3.established.connection.servicePacketServicingTimers();
    }
};

pub const AcceptedHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,

    pub fn deinit(self: *AcceptedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        self.streams.deinit();
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sessionId(
        self: AcceptedHandshakeSession,
    ) webtransport.SessionId {
        return self.session_id;
    }

    /// Return the currently selected QUIC peer path. This can change after an
    /// authenticated NAT rebinding or active migration.
    pub fn remoteAddress(self: AcceptedHandshakeSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn remoteAddressValidated(self: AcceptedHandshakeSession) bool {
        return self.h3.established.connection.peerAddressValidated();
    }

    pub fn rttNanos(self: AcceptedHandshakeSession) ?u64 {
        return self.stats().smoothed_rtt_ns;
    }

    /// Close the entire HTTP/3 connection with an application error. This is
    /// intentionally distinct from `close`, which sends WT_CLOSE_SESSION on
    /// the Extended CONNECT stream and leaves connection scope to HTTP/3.
    pub fn closeConnection(
        self: *AcceptedHandshakeSession,
        error_code: u62,
        reason: []const u8,
    ) Error!void {
        if (reason.len > max_connection_close_reason) {
            return error.InvalidSessionState;
        }
        try self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
    }

    pub fn exportKeyingMaterial(
        self: *const AcceptedHandshakeSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.h3.established.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// Return the authenticated peer certificate chain retained by the QUIC
    /// handshake, or null for PSK/preconfigured sessions without peer identity.
    pub fn peerCertificates(
        self: *const AcceptedHandshakeSession,
    ) ?[]const []const u8 {
        return self.h3.established.peerCertificates();
    }

    pub fn negotiatedAlpn(self: AcceptedHandshakeSession) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: AcceptedHandshakeSession,
    ) quic.tls.cipher_suite.Suite {
        return self.h3.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: AcceptedHandshakeSession,
    ) quic.tls.secret.Hash {
        return self.h3.negotiatedTranscriptHash();
    }

    pub fn initiateKeyUpdate(self: *AcceptedHandshakeSession) Error!void {
        try self.h3.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: AcceptedHandshakeSession) u64 {
        return self.h3.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: AcceptedHandshakeSession) u64 {
        return self.h3.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: AcceptedHandshakeSession) bool {
        return self.h3.keyUpdateAwaitingAck();
    }

    pub fn receiveDatagram(self: *AcceptedHandshakeSession) Error!OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *AcceptedHandshakeSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }

    pub fn sendDatagram(self: *AcceptedHandshakeSession, payload: []const u8) Error!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }

    pub fn maxDatagramPayloadSize(self: AcceptedHandshakeSession) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return webtransport.maxDatagramPayloadSize(
            self.h3.established.connection.maxDatagramPayloadSize(),
            self.session_id,
        );
    }

    /// WebTransport API spelling for the maximum application payload accepted
    /// by `sendDatagram`, after QUIC DATAGRAM and Session ID overhead.
    pub fn maxDatagramSize(self: AcceptedHandshakeSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: AcceptedHandshakeSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
    }

    pub fn stats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn getStats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.stats();
    }

    /// Wait for an authenticated QUIC CONNECTION_CLOSE from the peer.
    ///
    /// This is intentionally distinct from `receiveSessionEvent`, which reads
    /// WebTransport CLOSE capsules and clean FIN from the Extended CONNECT
    /// stream. Some peers terminate the entire HTTP/3 connection directly.
    pub fn receivePeerConnectionClose(
        self: *AcceptedHandshakeSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        return receiveHandshakePeerConnectionClose(
            &self.h3.established.connection,
        );
    }

    pub fn openBidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return (try self.streams.openLocal(.bidirectional)).stream_id;
    }

    pub fn openUnidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        // Server push and WebTransport uni streams share the server-initiated
        // QUIC stream-ID space. Consume the HTTP/3 session's allocator so a
        // later push cannot reuse this ID.
        const stream_id =
            try self.h3.reserveServerUnidirectionalStreamId();
        const stream = try self.streams.registerLocal(
            stream_id,
            .unidirectional,
        );
        return stream.stream_id;
    }

    pub fn sendStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.ensureOpen();
        try sendHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn writeStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        try self.control.ensureOpen();
        return handshake_stream.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
    }

    pub fn setStreamPriority(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        try self.control.ensureOpen();
        try self.streams.setPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!i32 {
        return self.streams.priority(stream_id);
    }

    /// Submit one packet-sized slice per sendable stream in a QUIC packet
    /// batch. Counts commit only the socket-visible prefix.
    pub fn writeStreams(
        self: *AcceptedHandshakeSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) Error!StreamWriteResult {
        try self.control.ensureOpen();
        return stream_batch.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
    }

    pub fn finishStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!void {
        // Completion means the FIN packet was accepted by the socket. QUIC
        // recovery remains responsible for retransmission until peer ACK.
        try self.control.ensureOpen();
        return handshake_stream.finish(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
        );
    }

    pub fn receiveStream(
        self: *AcceptedHandshakeSession,
    ) Error!OwnedHandshakeStream {
        return receiveHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
    }

    /// Read the next stream data/control event without waiting for FIN.
    pub fn readStream(
        self: *AcceptedHandshakeSession,
        out: []u8,
    ) Error!StreamRead {
        return readHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
        );
    }

    /// Apply one packet selected by the endpoint-wide QUIC dispatcher. HTTP/3
    /// control/QPACK and unrelated requests progress while the detached
    /// WebTransport CONNECT stream and associated streams remain available to
    /// the session-specific pollers below.
    pub fn processPacket(
        self: *AcceptedHandshakeSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        try self.h3.processDetachedRequestPacket(
            self.session_id.value,
            packet,
        );
    }

    /// Poll already-buffered associated stream state without reading UDP.
    pub fn pollStream(
        self: *AcceptedHandshakeSession,
        out: []u8,
    ) Error!?StreamRead {
        if (out.len == 0) return error.BufferTooShort;
        return incremental_stream.poll(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
        );
    }

    /// Poll a queued DATAGRAM for this session without reading UDP.
    pub fn pollDatagram(
        self: *AcceptedHandshakeSession,
    ) Error!?OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return popHandshakeDatagramFromConnection(
            &self.h3.established.connection,
        );
    }

    /// Poll the detached CONNECT stream for DRAIN/CLOSE/reset state.
    pub fn pollSessionEvent(
        self: *AcceptedHandshakeSession,
    ) Error!?SessionEvent {
        const event = self.control.poll(
            &self.h3.established.connection,
        ) catch |err| switch (err) {
            error.InvalidCapsule => {
                try self.h3.established.connection.resetStream(
                    self.session_id.value,
                    http3.ApplicationErrorCode.message_error,
                );
                return err;
            },
            else => return err,
        };
        if (event) |value| try self.finishPolledSessionEvent(value);
        return event;
    }

    pub fn resetStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return resetHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
    }

    pub fn stopStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return stopHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
    }

    pub fn drain(self: *AcceptedHandshakeSession) Error!void {
        if (self.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.h3.sendResponseBodyPaced(
            self.session_id.value,
            capsule,
            false,
        );
        try self.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedHandshakeSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.local_close_sent) return;
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        try self.h3.sendResponseBodyPaced(
            self.session_id.value,
            capsule,
            true,
        );
        try self.control.recordLocalClose(code);
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &self.streams,
        );
    }

    pub fn receiveSessionEvent(
        self: *AcceptedHandshakeSession,
    ) Error!SessionEvent {
        const event = while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgress();
        };
        return event;
    }

    fn finishPolledSessionEvent(
        self: *AcceptedHandshakeSession,
        event: SessionEvent,
    ) Error!void {
        if (event == .closed or event == .reset) {
            if (event == .closed and !self.control.local_close_sent) {
                try self.h3.sendResponseBodyPaced(
                    self.session_id.value,
                    &.{},
                    true,
                );
                self.control.local_close_sent = true;
            }
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        }
    }

    fn receiveControlProgress(
        self: *AcceptedHandshakeSession,
    ) Error!void {
        try self.h3.receiveDetachedRequestProgress(
            self.session_id.value,
        );
    }
};

pub const ClientSession = struct {
    h3: http3.runtime.Client,
    session_id: webtransport.SessionId,
    /// Owns the final CONNECT response, including custom admission headers.
    response: http3.runtime.OwnedResponse,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
    ) Error!ClientSession {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    /// Establish the underlying development transport while preserving a
    /// non-success CONNECT response for application inspection.
    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        var header_buf: [max_additional_connect_request_headers + 3]http3.Qpack.HeaderField = undefined;
        const headers = try connectRequestHeadersWithAdditional(
            options.origin,
            options.headers,
            &header_buf,
        );
        var h3_client = try http3.runtime.Client.connect(allocator, io, local_address, server, options.limits.http3);
        errdefer h3_client.deinit();
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers,
        });
        errdefer response.deinit(allocator);
        if (response.response.successful()) {
            try validateOptionalCapsuleProtocol(response.response.headers);
        }
        return .{
            .h3 = h3_client,
            .session_id = .init(0),
            .response = response,
        };
    }

    pub fn deinit(self: *ClientSession) void {
        self.response.deinit(self.h3.quic_client.endpoint.allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: ClientSession) net.IpAddress {
        return self.h3.address();
    }

    pub fn responseHeader(
        self: ClientSession,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.response.headers, name);
    }

    pub fn sendDatagram(self: *ClientSession, payload: []const u8) Error!void {
        try sendDatagramFromEndpoint(&self.h3.quic_client.endpoint, self.h3.quic_client.peer, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *ClientSession) Error!OwnedDatagram {
        return receiveDatagramFromEndpoint(&self.h3.quic_client.endpoint);
    }
};

pub const ConnectAttempt = struct {
    h3: ?http3.runtime.Client,
    session_id: webtransport.SessionId,
    response: http3.runtime.OwnedResponse,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.response.response.successful();
    }

    pub fn status(self: ConnectAttempt) u16 {
        return self.response.response.status;
    }

    pub fn responseHeader(
        self: ConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.response.headers, name);
    }

    pub fn deinit(self: *ConnectAttempt) void {
        const allocator = self.h3.?.quic_client.endpoint.allocator;
        self.response.deinit(allocator);
        if (self.h3) |*h3| h3.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!ClientSession {
        if (!self.accepted()) return error.SessionRejected;
        const session = ClientSession{
            .h3 = self.h3.?,
            .session_id = self.session_id,
            .response = self.response,
        };
        self.* = undefined;
        return session;
    }
};

pub const HandshakeClientSession = struct {
    h3: http3.runtime.HandshakeClient,
    session_id: webtransport.SessionId,
    /// Response metadata from the accepted Extended CONNECT. Header fields are
    /// owned by this session and remain available until `deinit`.
    response: http3.DecodedResponseHead,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
    ) Error!HandshakeClientSession {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    /// Establish authenticated QUIC and preserve a non-success Extended
    /// CONNECT response for application inspection.
    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
    ) Error!HandshakeConnectAttempt {
        try validateAdditionalConnectHeaders(options.headers, .request);
        var h3_client = try http3.runtime.HandshakeClient.connect(allocator, io, local_address, server, options.limits.http3, webTransportHandshakeClientOptions(options.h3));
        errdefer h3_client.deinit();
        return connectStatefulAttempt(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
        );
    }

    /// Connect to a complete HTTPS WebTransport URL. This derives SNI,
    /// authority, and path/query from one parsed value and inherits HTTP/3's
    /// all-address DNS fallback rather than exposing those pieces separately.
    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
    ) Error!HandshakeClientSession {
        var attempt = try connectUriAttempt(
            allocator,
            io,
            local_address,
            uri_text,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
    ) Error!HandshakeConnectAttempt {
        try validateAdditionalConnectHeaders(options.headers, .request);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        var endpoint = try http3.runtime.uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try http3.runtime.uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);

        var h3_options = options.h3;
        if (h3_options.handshake.server_name == null) {
            h3_options.handshake.server_name = endpoint.tls_host;
        }
        var h3_client = try http3.runtime.HandshakeClient.connectUri(
            allocator,
            io,
            local_address,
            uri,
            options.limits.http3,
            webTransportHandshakeClientOptions(h3_options),
        );
        errdefer h3_client.deinit();
        return connectStatefulAttempt(
            &h3_client,
            endpoint.authority,
            path,
            options.origin,
            options.headers,
            options.limits,
        );
    }

    /// Establish WebTransport over externally negotiated 1-RTT keys while
    /// retaining the full stateful QUIC transport used by associated streams.
    pub fn connectPreconfigured(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!HandshakeClientSession {
        var attempt = try connectPreconfiguredAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectPreconfiguredAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!HandshakeConnectAttempt {
        try validateAdditionalConnectHeaders(options.headers, .request);
        const h3_options = webTransportHandshakeSessionOptions(options.h3);
        var h3_client = try http3.runtime.HandshakeClient.initPreconfigured(
            allocator,
            io,
            local_address,
            server,
            options.limits.http3,
            h3_options,
            options.transport,
        );
        errdefer h3_client.deinit();
        return connectStatefulAttempt(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
        );
    }

    pub fn deinit(self: *HandshakeClientSession) void {
        self.response.deinit(self.h3.allocator);
        self.streams.deinit();
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn responseHeader(
        self: HandshakeClientSession,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn sessionId(self: HandshakeClientSession) webtransport.SessionId {
        return self.session_id;
    }

    /// Return the current QUIC peer path rather than the original connect
    /// target, so applications observe validated migration/rebinding changes.
    pub fn remoteAddress(self: HandshakeClientSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn remoteAddressValidated(self: HandshakeClientSession) bool {
        return self.h3.established.connection.peerAddressValidated();
    }

    pub fn rttNanos(self: HandshakeClientSession) ?u64 {
        return self.stats().smoothed_rtt_ns;
    }

    /// Close the entire QUIC connection, not only this WebTransport Session.
    pub fn closeConnection(
        self: *HandshakeClientSession,
        error_code: u62,
        reason: []const u8,
    ) Error!void {
        if (reason.len > max_connection_close_reason) {
            return error.InvalidSessionState;
        }
        try self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
    }

    pub fn exportKeyingMaterial(
        self: *const HandshakeClientSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.h3.established.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    pub fn peerCertificates(
        self: *const HandshakeClientSession,
    ) ?[]const []const u8 {
        return self.h3.established.peerCertificates();
    }

    pub fn negotiatedAlpn(self: HandshakeClientSession) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: HandshakeClientSession,
    ) quic.tls.cipher_suite.Suite {
        return self.h3.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: HandshakeClientSession,
    ) quic.tls.secret.Hash {
        return self.h3.negotiatedTranscriptHash();
    }

    pub fn initiateKeyUpdate(self: *HandshakeClientSession) Error!void {
        try self.h3.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: HandshakeClientSession) u64 {
        return self.h3.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: HandshakeClientSession) u64 {
        return self.h3.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: HandshakeClientSession) bool {
        return self.h3.keyUpdateAwaitingAck();
    }

    pub fn sendDatagram(self: *HandshakeClientSession, payload: []const u8) Error!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *HandshakeClientSession) Error!OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *HandshakeClientSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }

    pub fn maxDatagramPayloadSize(self: HandshakeClientSession) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return webtransport.maxDatagramPayloadSize(
            self.h3.established.connection.maxDatagramPayloadSize(),
            self.session_id,
        );
    }

    /// WebTransport API spelling for the negotiated send-payload limit. Zero
    /// means HTTP Datagrams were not negotiated.
    pub fn maxDatagramSize(self: HandshakeClientSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: HandshakeClientSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
    }

    pub fn stats(self: HandshakeClientSession) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn getStats(self: HandshakeClientSession) quic.one_rtt.ConnectionStats {
        return self.stats();
    }

    /// Wait for an authenticated QUIC CONNECTION_CLOSE from the peer.
    ///
    /// This is intentionally distinct from `receiveSessionEvent`, which reads
    /// WebTransport CLOSE capsules and clean FIN from the Extended CONNECT
    /// stream. Some peers terminate the entire HTTP/3 connection directly.
    pub fn receivePeerConnectionClose(
        self: *HandshakeClientSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        return receiveHandshakePeerConnectionClose(
            &self.h3.established.connection,
        );
    }

    pub fn openBidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        // HTTP requests and WebTransport bidi streams share client-initiated
        // QUIC IDs. Advance the HTTP/3 allocator transactionally.
        const stream_id =
            try self.h3.reserveClientBidirectionalStreamId();
        const stream = try self.streams.registerLocal(
            stream_id,
            .bidirectional,
        );
        return stream.stream_id;
    }

    pub fn openUnidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return (try self.streams.openLocal(.unidirectional)).stream_id;
    }

    pub fn sendStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.ensureOpen();
        try sendHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn writeStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        try self.control.ensureOpen();
        return handshake_stream.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
    }

    pub fn setStreamPriority(
        self: *HandshakeClientSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        try self.control.ensureOpen();
        try self.streams.setPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *HandshakeClientSession,
        stream_id: u62,
    ) Error!i32 {
        return self.streams.priority(stream_id);
    }

    /// Submit one packet-sized slice per sendable stream in a QUIC packet
    /// batch. Counts commit only the socket-visible prefix.
    pub fn writeStreams(
        self: *HandshakeClientSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) Error!StreamWriteResult {
        try self.control.ensureOpen();
        return stream_batch.write(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
    }

    pub fn finishStream(
        self: *HandshakeClientSession,
        stream_id: u62,
    ) Error!void {
        // Completion means the FIN packet was submitted, not yet acknowledged.
        try self.control.ensureOpen();
        return handshake_stream.finish(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
        );
    }

    pub fn receiveStream(
        self: *HandshakeClientSession,
    ) Error!OwnedHandshakeStream {
        return receiveHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
    }

    /// Read the next stream data/control event without waiting for FIN.
    pub fn readStream(
        self: *HandshakeClientSession,
        out: []u8,
    ) Error!StreamRead {
        return readHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
        );
    }

    /// Drive one timer-aware QUIC receive without consuming WebTransport data.
    ///
    /// Event loops waiting on a peer-side terminal condition still need to
    /// process ACK, loss and PTO state after their final local FIN/reset. This
    /// method is cancelable through the caller's `std.Io` future and keeps the
    /// underlying HTTP/3 connection encapsulated.
    pub fn serviceTransport(
        self: *HandshakeClientSession,
    ) Error!void {
        try self.h3.established.connection.servicePacketServicingTimers();
    }

    pub fn resetStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return resetHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
    }

    pub fn stopStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return stopHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
    }

    pub fn drain(self: *HandshakeClientSession) Error!void {
        if (self.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.h3.sendRequestBodyPaced(
            self.session_id.value,
            capsule,
            false,
        );
        try self.control.recordLocalDrain();
    }

    pub fn close(
        self: *HandshakeClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.local_close_sent) return;
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        try self.h3.sendRequestBodyPaced(
            self.session_id.value,
            capsule,
            true,
        );
        try self.control.recordLocalClose(code);
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &self.streams,
        );
    }

    pub fn receiveSessionEvent(
        self: *HandshakeClientSession,
    ) Error!SessionEvent {
        const event = self.control.receive(
            &self.h3.established.connection,
            self,
            HandshakeClientSession.receiveControlProgress,
        ) catch |err| switch (err) {
            error.InvalidCapsule => {
                try self.h3.established.connection.resetStream(
                    self.session_id.value,
                    http3.ApplicationErrorCode.message_error,
                );
                return err;
            },
            else => return err,
        };
        if (event == .closed or event == .reset) {
            if (event == .closed and !self.control.local_close_sent) {
                try self.h3.sendRequestBodyPaced(
                    self.session_id.value,
                    &.{},
                    true,
                );
                self.control.local_close_sent = true;
            }
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        }
        return event;
    }

    fn receiveControlProgress(
        self: *HandshakeClientSession,
    ) Error!void {
        try self.h3.receiveDetachedResponseProgress(
            self.session_id.value,
        );
    }
};

pub const HandshakeConnectAttempt = struct {
    h3: ?http3.runtime.HandshakeClient,
    session_id: webtransport.SessionId,
    response: http3.DecodedResponseHead,
    limits: Limits,

    pub fn accepted(self: HandshakeConnectAttempt) bool {
        return self.response.status >= 200 and self.response.status < 300;
    }

    pub fn status(self: HandshakeConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn responseHeader(
        self: HandshakeConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn deinit(self: *HandshakeConnectAttempt) void {
        const allocator = self.h3.?.allocator;
        self.response.deinit(allocator);
        if (self.h3) |*h3| h3.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(
        self: *HandshakeConnectAttempt,
    ) Error!HandshakeClientSession {
        if (!self.accepted()) return error.SessionRejected;
        var h3 = &self.h3.?;
        try h3.detachResponseStream(self.session_id.value);
        try webtransport.ensureDatagramsNegotiated(
            h3.options.local_settings,
            h3.control.settings.peer,
        );
        var streams = try initHandshakeStreamRegistry(
            h3.allocator,
            self.session_id,
            .client,
            h3.options.local_settings,
            h3.control.settings.peer,
            self.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        const control = try session_control.Control.init(self.session_id);
        const session = HandshakeClientSession{
            .h3 = h3.*,
            .session_id = self.session_id,
            .response = self.response,
            .streams = streams,
            .control = control,
        };
        self.* = undefined;
        return session;
    }
};

pub const ProtectedClientSession = struct {
    h3: http3.runtime.ProtectedClient,
    session_id: webtransport.SessionId,
    /// Owns the final CONNECT response, including custom admission headers.
    response: http3.DecodedResponseHead,
    control: protected_control.Reader,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
    ) Error!ProtectedClientSession {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    /// Establish the preconfigured transport while preserving a non-success
    /// CONNECT response for application inspection.
    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
    ) Error!ProtectedConnectAttempt {
        var header_buf: [max_additional_connect_request_headers + 3]http3.Qpack.HeaderField = undefined;
        const headers = try connectRequestHeadersWithAdditional(
            options.origin,
            options.headers,
            &header_buf,
        );
        var h3_client = try http3.runtime.ProtectedClient.connect(allocator, io, local_address, server, options.limits.http3, webTransportProtectedConfig(options.config));
        errdefer h3_client.deinit();
        const session_stream_id = try h3_client.startRequest(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers,
        }, null);
        var response_head = try receiveProtectedConnectAttemptResponse(
            &h3_client,
            session_stream_id,
        );
        errdefer response_head.deinit(allocator);
        if (response_head.status >= 200 and response_head.status < 300) {
            try validateOptionalCapsuleProtocol(response_head.headers);
            try webtransport.ensureDatagramsNegotiated(h3_client.config.local_settings, h3_client.control.settings.peer);
        }
        return .{
            .h3 = h3_client,
            .session_id = .init(session_stream_id),
            .response = response_head,
        };
    }

    pub fn deinit(self: *ProtectedClientSession) void {
        self.response.deinit(self.h3.quic_client.endpoint.allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn responseHeader(
        self: ProtectedClientSession,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn sendDatagram(self: *ProtectedClientSession, payload: []const u8) Error!void {
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        try sendProtectedDatagramFromEndpoint(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            self.session_id,
            payload,
        );
    }

    pub fn receiveDatagram(self: *ProtectedClientSession) Error!OwnedProtectedDatagram {
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_client.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }

    pub fn datagramsNegotiated(self: ProtectedClientSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
    }

    /// Send Capsule Protocol bytes on this Session's Extended CONNECT stream.
    pub fn sendSessionData(
        self: *ProtectedClientSession,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.control.ensureOpen();
        try self.h3.sendRequestBody(
            self.session_id.value,
            data,
            fin,
        );
    }

    pub fn receiveSessionData(
        self: *ProtectedClientSession,
        out: []u8,
    ) Error!ProtectedSessionRead {
        while (true) {
            var event = (try self.h3.receiveResponseEvent(
                self.session_id.value,
            )) orelse continue;
            defer event.deinit(self.h3.quic_client.endpoint.allocator);
            switch (event) {
                .data_available => {
                    const count = try self.h3.readResponseData(
                        self.session_id.value,
                        out,
                    );
                    if (count != 0) return .{ .bytes = count };
                },
                .finished => return .{ .fin = true },
                else => return error.InvalidSessionState,
            }
        }
    }

    pub fn drain(self: *ProtectedClientSession) Error!void {
        if (self.control.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.sendSessionData(capsule, false);
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *ProtectedClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent) return;
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        try self.sendSessionData(capsule, true);
        try self.control.control.recordLocalClose(code);
    }

    pub fn receiveSessionEvent(
        self: *ProtectedClientSession,
    ) Error!SessionEvent {
        return receiveProtectedClientEvent(self) catch |err| switch (err) {
            error.InvalidCapsule => {
                try self.h3.cancelRequest(
                    self.session_id.value,
                    http3.ApplicationErrorCode.message_error,
                );
                return err;
            },
            else => return err,
        };
    }
};

pub const ProtectedConnectAttempt = struct {
    h3: ?http3.runtime.ProtectedClient,
    session_id: webtransport.SessionId,
    response: http3.DecodedResponseHead,

    pub fn accepted(self: ProtectedConnectAttempt) bool {
        return self.response.status >= 200 and self.response.status < 300;
    }

    pub fn status(self: ProtectedConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn responseHeader(
        self: ProtectedConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn deinit(self: *ProtectedConnectAttempt) void {
        const allocator = self.h3.?.quic_client.endpoint.allocator;
        self.response.deinit(allocator);
        if (self.h3) |*h3| h3.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(
        self: *ProtectedConnectAttempt,
    ) Error!ProtectedClientSession {
        if (!self.accepted()) return error.SessionRejected;
        const control = protected_control.Reader.init(
            try session_control.Control.init(self.session_id),
        );
        const session = ProtectedClientSession{
            .h3 = self.h3.?,
            .session_id = self.session_id,
            .response = self.response,
            .control = control,
        };
        self.* = undefined;
        return session;
    }
};

pub const ProtectedSessionRead = struct {
    bytes: usize = 0,
    fin: bool = false,
};

fn receiveProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
) Error!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeProtectedServerEvent(server, session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
        const read = try server.receiveSessionData(
            session.session_id,
            &buffer,
        );
        if (read.fin) {
            const event = (try session.control.finish()) orelse
                return error.InvalidSessionState;
            return completeProtectedServerEvent(server, session, event);
        }
        if (try session.control.consume(buffer[0..read.bytes])) |event| {
            return completeProtectedServerEvent(server, session, event);
        }
    }
}

fn completeProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    event: SessionEvent,
) Error!SessionEvent {
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
    return event;
}

fn receiveProtectedClientEvent(
    session: *ProtectedClientSession,
) Error!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeProtectedClientEvent(session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
        const read = try session.receiveSessionData(&buffer);
        if (read.fin) {
            const event = (try session.control.finish()) orelse
                return error.InvalidSessionState;
            return completeProtectedClientEvent(session, event);
        }
        if (try session.control.consume(buffer[0..read.bytes])) |event| {
            return completeProtectedClientEvent(session, event);
        }
    }
}

fn completeProtectedClientEvent(
    session: *ProtectedClientSession,
    event: SessionEvent,
) Error!SessionEvent {
    if (event == .closed and
        !session.control.control.local_close_sent)
    {
        // The parser has already closed the public Session state, so bypass
        // sendSessionData's open-state guard for this mandatory FIN reply.
        try session.h3.sendRequestBody(
            session.session_id.value,
            &.{},
            true,
        );
        session.control.control.local_close_sent = true;
    }
    return event;
}

pub const ConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    /// Additional regular CONNECT fields. Reserved WebTransport fields are
    /// constructed by the adapter and cannot be overridden.
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
};

pub const ProtectedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    /// Additional regular CONNECT fields. Reserved WebTransport fields are
    /// constructed by the adapter and cannot be overridden.
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    config: http3.runtime.ProtectedConfig,
};

pub const HandshakeConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    /// Additional regular CONNECT fields, for example Authorization or
    /// User-Agent. Reserved WebTransport fields cannot be overridden.
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
};

pub const HandshakeUriConnectOptions = struct {
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
};

test "WebTransport URI connect rejects non-HTTPS and userinfo before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const options = HandshakeUriConnectOptions{
        .h3 = .{ .handshake = .{
            .original_destination_connection_id = "original",
            .local_connection_id = "local",
        } },
    };
    try std.testing.expectError(
        error.InvalidUri,
        HandshakeClientSession.connectUri(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "http://example.com/wt",
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        HandshakeClientSession.connectUri(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://user@example.com/wt",
            options,
        ),
    );
}

pub const StatefulProtectedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeSessionOptions = .{},
    transport: quic.handshake.PreconfiguredConnectionOptions,
};

pub const StatefulProtectedClientSession = struct {
    session: HandshakeClientSession,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!StatefulProtectedClientSession {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!StatefulProtectedConnectAttempt {
        return .{
            .attempt = try HandshakeClientSession
                .connectPreconfiguredAttempt(
                allocator,
                io,
                local_address,
                server,
                options,
            ),
        };
    }

    pub fn deinit(self: *StatefulProtectedClientSession) void {
        self.session.deinit();
        self.* = undefined;
    }

    pub fn address(
        self: StatefulProtectedClientSession,
    ) net.IpAddress {
        return self.session.h3.address();
    }

    pub fn responseHeader(
        self: StatefulProtectedClientSession,
        name: []const u8,
    ) ?[]const u8 {
        return self.session.responseHeader(name);
    }

    pub fn sessionId(
        self: StatefulProtectedClientSession,
    ) webtransport.SessionId {
        return self.session.sessionId();
    }

    pub fn remoteAddress(
        self: StatefulProtectedClientSession,
    ) net.IpAddress {
        return self.session.remoteAddress();
    }

    pub fn remoteAddressValidated(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.remoteAddressValidated();
    }

    pub fn rttNanos(self: StatefulProtectedClientSession) ?u64 {
        return self.session.rttNanos();
    }

    pub fn closeConnection(
        self: *StatefulProtectedClientSession,
        error_code: u62,
        reason: []const u8,
    ) Error!void {
        return self.session.closeConnection(error_code, reason);
    }

    pub fn exportKeyingMaterial(
        self: *const StatefulProtectedClientSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return self.session.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    pub fn peerCertificates(
        self: *const StatefulProtectedClientSession,
    ) ?[]const []const u8 {
        return self.session.peerCertificates();
    }

    pub fn negotiatedAlpn(
        self: StatefulProtectedClientSession,
    ) []const u8 {
        return self.session.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: StatefulProtectedClientSession,
    ) quic.tls.cipher_suite.Suite {
        return self.session.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: StatefulProtectedClientSession,
    ) quic.tls.secret.Hash {
        return self.session.negotiatedTranscriptHash();
    }

    pub fn initiateKeyUpdate(
        self: *StatefulProtectedClientSession,
    ) Error!void {
        return self.session.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(
        self: StatefulProtectedClientSession,
    ) u64 {
        return self.session.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(
        self: StatefulProtectedClientSession,
    ) u64 {
        return self.session.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.keyUpdateAwaitingAck();
    }

    pub fn openBidirectionalStream(
        self: *StatefulProtectedClientSession,
    ) Error!u62 {
        return self.session.openBidirectionalStream();
    }

    pub fn openUnidirectionalStream(
        self: *StatefulProtectedClientSession,
    ) Error!u62 {
        return self.session.openUnidirectionalStream();
    }

    pub fn sendStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        return self.session.sendStream(stream_id, payload, fin);
    }

    pub fn writeStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        return self.session.writeStream(stream_id, payload);
    }

    pub fn setStreamPriority(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        return self.session.setStreamPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!i32 {
        return self.session.streamPriority(stream_id);
    }

    pub fn writeStreams(
        self: *StatefulProtectedClientSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) Error!StreamWriteResult {
        return self.session.writeStreams(writes, counts);
    }

    pub fn finishStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!void {
        return self.session.finishStream(stream_id);
    }

    pub fn receiveStream(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeStream {
        return self.session.receiveStream();
    }

    pub fn readStream(
        self: *StatefulProtectedClientSession,
        out: []u8,
    ) Error!StreamRead {
        return self.session.readStream(out);
    }

    pub fn serviceTransport(
        self: *StatefulProtectedClientSession,
    ) Error!void {
        return self.session.serviceTransport();
    }

    pub fn resetStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return self.session.resetStream(stream_id, application_error_code);
    }

    pub fn stopStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return self.session.stopStream(stream_id, application_error_code);
    }

    pub fn sendDatagram(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
    ) Error!void {
        return self.session.sendDatagram(payload);
    }

    pub fn receiveDatagram(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeDatagram {
        return self.session.receiveDatagram();
    }

    pub fn receiveManyDatagrams(
        self: *StatefulProtectedClientSession,
        count: usize,
    ) Error!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagrams(count);
    }

    pub fn maxDatagramPayloadSize(
        self: StatefulProtectedClientSession,
    ) ?usize {
        return self.session.maxDatagramPayloadSize();
    }

    pub fn maxDatagramSize(
        self: StatefulProtectedClientSession,
    ) usize {
        return self.session.maxDatagramSize();
    }

    pub fn datagramsNegotiated(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.datagramsNegotiated();
    }

    pub fn drain(self: *StatefulProtectedClientSession) Error!void {
        return self.session.drain();
    }

    pub fn close(
        self: *StatefulProtectedClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        return self.session.close(code, reason);
    }

    pub fn receiveSessionEvent(
        self: *StatefulProtectedClientSession,
    ) Error!SessionEvent {
        return self.session.receiveSessionEvent();
    }

    pub fn receivePeerConnectionClose(
        self: *StatefulProtectedClientSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionClose();
    }

    pub fn stats(
        self: StatefulProtectedClientSession,
    ) quic.one_rtt.ConnectionStats {
        return self.session.stats();
    }

    pub fn getStats(
        self: StatefulProtectedClientSession,
    ) quic.one_rtt.ConnectionStats {
        return self.stats();
    }
};

pub const StatefulProtectedConnectAttempt = struct {
    attempt: HandshakeConnectAttempt,

    pub fn accepted(self: StatefulProtectedConnectAttempt) bool {
        return self.attempt.accepted();
    }

    pub fn status(self: StatefulProtectedConnectAttempt) u16 {
        return self.attempt.status();
    }

    pub fn responseHeader(
        self: StatefulProtectedConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return self.attempt.responseHeader(name);
    }

    pub fn deinit(self: *StatefulProtectedConnectAttempt) void {
        self.attempt.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(
        self: *StatefulProtectedConnectAttempt,
    ) Error!StatefulProtectedClientSession {
        return .{ .session = try self.attempt.requireAccepted() };
    }
};

fn webTransportProtectedConfig(config: http3.runtime.ProtectedConfig) http3.runtime.ProtectedConfig {
    var out = config;
    out.local_settings = webtransport.defaultSettings(out.local_settings);
    return out;
}

fn webTransportHandshakeServerOptions(options: http3.runtime.HandshakeServerOptions) http3.runtime.HandshakeServerOptions {
    var out = options;
    out.session.local_settings = webtransport.defaultSettings(out.session.local_settings);
    return out;
}

fn webTransportHandshakeClientOptions(options: http3.runtime.HandshakeClientOptions) http3.runtime.HandshakeClientOptions {
    var out = options;
    out.session.local_settings = webtransport.defaultSettings(out.session.local_settings);
    return out;
}

fn webTransportHandshakeSessionOptions(
    options: http3.runtime.HandshakeSessionOptions,
) http3.runtime.HandshakeSessionOptions {
    var out = options;
    out.local_settings = webtransport.defaultSettings(out.local_settings);
    return out;
}

fn connectStatefulAttempt(
    h3_client: *http3.runtime.HandshakeClient,
    authority: []const u8,
    path: []const u8,
    origin: []const u8,
    additional_headers: []const http3.Qpack.HeaderField,
    limits: Limits,
) Error!HandshakeConnectAttempt {
    const allocator = h3_client.allocator;
    var header_buf: [max_additional_connect_request_headers + 3]http3.Qpack.HeaderField = undefined;
    const headers = try connectRequestHeadersWithAdditional(
        origin,
        additional_headers,
        &header_buf,
    );
    const session_id = try h3_client.startRequest(.{
        .method = "CONNECT",
        .path = path,
        .scheme = "https",
        .authority = authority,
        .headers = headers,
    }, null);
    var response_head =
        try receiveHandshakeConnectAttemptResponse(h3_client, session_id);
    errdefer response_head.deinit(allocator);
    const webtransport_session_id = webtransport.SessionId.init(session_id);
    const owned_h3 = h3_client.*;
    h3_client.* = undefined;
    return .{
        .h3 = owned_h3,
        .session_id = webtransport_session_id,
        .response = response_head,
        .limits = limits,
    };
}

fn receiveStatefulSessionRequest(
    session: *http3.runtime.HandshakeServerSession,
    limits: Limits,
) Error!PendingHandshakeSession {
    try session.ensureSettingsSent();
    var request = try receiveHandshakeConnectRequest(session);
    errdefer request.head.deinit(
        session.established.connection.endpoint.allocator,
    );
    try webtransport.ensureDatagramsNegotiated(
        session.options.local_settings,
        session.control.settings.peer,
    );
    const session_id = webtransport.SessionId.init(request.stream_id);
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidConnect;
    }
    const owned_h3 = session.*;
    session.* = undefined;
    return .{
        .h3 = owned_h3,
        .request = .{
            .stream_id = request.stream_id,
            .request = request.head,
        },
        .session_id = session_id,
        .limits = limits,
    };
}

fn receiveHandshakeConnectRequest(
    session: *http3.runtime.HandshakeServerSession,
) Error!struct {
    stream_id: u62,
    head: http3.DecodedRequestHead,
} {
    while (true) {
        var event = try session.receiveRequestEvent();
        defer event.deinit(
            session.established.connection.endpoint.allocator,
        );
        switch (event) {
            .reset => return error.InvalidConnect,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidConnect;
                    try validateConnectRequest(head.request);
                    const owned = head.request;
                    message.value = .finished;
                    return .{
                        .stream_id = message.stream_id,
                        .head = owned,
                    };
                },
                else => return error.InvalidConnect,
            },
        }
    }
}

fn receiveProtectedConnectRequest(
    server: *http3.runtime.ProtectedServer,
) Error!struct {
    from: net.IpAddress,
    stream_id: u62,
    head: http3.DecodedRequestHead,
} {
    while (true) {
        var event = try server.receiveRequestEvent();
        defer event.deinit(server.quic_server.endpoint.allocator);
        switch (event) {
            .reset => return error.InvalidConnect,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidConnect;
                    try validateConnectRequest(head.request);
                    const owned = head.request;
                    message.value = .finished;
                    return .{
                        .from = message.from,
                        .stream_id = message.stream_id,
                        .head = owned,
                    };
                },
                else => return error.InvalidConnect,
            },
        }
    }
}

fn receiveHandshakeConnectAttemptResponse(
    client: *http3.runtime.HandshakeClient,
    stream_id: u62,
) Error!http3.DecodedResponseHead {
    while (true) {
        var event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        defer event.deinit(client.allocator);
        switch (event) {
            .head => |*head| {
                if (head.* != .response) return error.InvalidConnect;
                if (head.response.status >= 200 and
                    head.response.status < 300)
                {
                    try validateOptionalCapsuleProtocol(
                        head.response.headers,
                    );
                }
                const owned = head.response;
                event = .finished;
                return owned;
            },
            else => return error.InvalidConnect,
        }
    }
}

fn receiveProtectedConnectAttemptResponse(
    client: *http3.runtime.ProtectedClient,
    stream_id: u62,
) Error!http3.DecodedResponseHead {
    while (true) {
        var event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        defer event.deinit(client.quic_client.endpoint.allocator);
        switch (event) {
            .head => |*head| {
                if (head.* != .response) return error.InvalidConnect;
                const owned = head.response;
                event = .finished;
                return owned;
            },
            else => return error.InvalidConnect,
        }
    }
}

fn validateConnectRequest(request: anytype) Error!void {
    if (!std.mem.eql(u8, request.method, "CONNECT")) return error.InvalidConnect;
    if (!std.mem.eql(u8, request.scheme, "https")) {
        return error.InvalidConnect;
    }
    if (request.authority == null or request.authority.?.len == 0 or
        request.path.len == 0)
    {
        return error.InvalidConnect;
    }
    if (!std.mem.eql(u8, findHeader(request.headers, ":protocol") orelse "", "webtransport")) {
        return error.InvalidConnect;
    }
    try validateOptionalCapsuleProtocol(request.headers);
}

fn connectResponse() http3.Response {
    return connectResponseWithHeaders(&.{http3.capsule.protocol_header});
}

fn connectResponseWithHeaders(
    headers: []const http3.Qpack.HeaderField,
) http3.Response {
    return .{ .status = 200, .headers = headers };
}

fn validateConnectResponse(response: anytype) Error!void {
    if (response.status < 200 or response.status >= 300) {
        return error.SessionRejected;
    }
    try validateOptionalCapsuleProtocol(response.headers);
}

const AdditionalHeaderContext = enum { request, response };

fn validateAdditionalConnectHeaders(
    headers: []const http3.Qpack.HeaderField,
    context: AdditionalHeaderContext,
) Error!void {
    const max_headers = switch (context) {
        .request => max_additional_connect_request_headers,
        .response => max_additional_connect_response_headers,
    };
    if (headers.len > max_headers) return error.InvalidFrame;
    for (headers) |header| {
        try validateAdditionalHeaderSyntax(header);
        // Pseudo-fields are constructed from typed options, and the adapter
        // owns Capsule-Protocol negotiation. Prevent generic metadata from
        // smuggling a duplicate or contradictory reserved field.
        if (std.mem.startsWith(u8, header.name, ":") or
            std.ascii.eqlIgnoreCase(
                header.name,
                http3.capsule.header_name,
            ) or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            (context == .request and
                std.ascii.eqlIgnoreCase(header.name, "origin")))
        {
            return error.InvalidHeader;
        }
    }
}

fn validateAdditionalHeaderSyntax(
    header: http3.Qpack.HeaderField,
) Error!void {
    if (header.name.len == 0) return error.InvalidHeader;
    for (header.name) |byte| {
        if (!std.ascii.isLower(byte) and
            !std.ascii.isDigit(byte) and
            switch (byte) {
                '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => false,
                else => true,
            })
        {
            return error.InvalidHeader;
        }
    }
    for (header.value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) {
            return error.InvalidHeader;
        }
    }
}

fn validateOptionalCapsuleProtocol(
    headers: []const http3.Qpack.HeaderField,
) Error!void {
    // Modern WebTransport peers such as wtransport use DATA capsules as an
    // intrinsic part of the extended CONNECT protocol and omit the older
    // Capsule-Protocol field. Continue advertising it for draft peers, but if
    // a peer explicitly supplies the field it must still be the true item.
    if (findHeader(headers, http3.capsule.header_name) == null) return;
    if (!(http3.capsule.protocolEnabled(headers) catch
        return error.InvalidConnect))
    {
        return error.InvalidConnect;
    }
}

fn connectRequestHeaders(origin: []const u8, out: *[3]http3.Qpack.HeaderField) []const http3.Qpack.HeaderField {
    var count: usize = 0;
    out[count] = .{ .name = ":protocol", .value = "webtransport" };
    count += 1;
    out[count] = http3.capsule.protocol_header;
    count += 1;
    // Keep the historical "/" default from ConnectOptions as "not supplied";
    // real WebTransport clients can pass an Origin value and have it carried in
    // the CONNECT request for server-side policy checks.
    if (origin.len != 0 and !std.mem.eql(u8, origin, "/")) {
        out[count] = .{ .name = "origin", .value = origin };
        count += 1;
    }
    return out[0..count];
}

fn connectRequestHeadersWithAdditional(
    origin: []const u8,
    additional: []const http3.Qpack.HeaderField,
    out: *[max_additional_connect_request_headers + 3]http3.Qpack.HeaderField,
) Error![]const http3.Qpack.HeaderField {
    try validateAdditionalConnectHeaders(additional, .request);
    var count: usize = 0;
    out[count] = .{ .name = ":protocol", .value = "webtransport" };
    count += 1;
    out[count] = http3.capsule.protocol_header;
    count += 1;
    if (origin.len != 0 and !std.mem.eql(u8, origin, "/")) {
        out[count] = .{ .name = "origin", .value = origin };
        count += 1;
    }
    @memcpy(out[count..][0..additional.len], additional);
    return out[0 .. count + additional.len];
}

pub const OwnedDatagram = struct {
    quic_datagram: quic.runtime.OwnedDatagram,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        self.quic_datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedProtectedDatagram = struct {
    packet: quic.one_rtt.ReceivedPacket,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedProtectedDatagram, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedHandshakeDatagram = struct {
    bytes: []u8,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedHandshakeDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?OwnedHandshakeDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedHandshakeDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedHandshakeDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedHandshakeDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

const handshake_stream = @import("runtime/stream.zig");
const incremental_stream = @import("runtime/stream_incremental.zig");
pub const OwnedHandshakeStream = handshake_stream.OwnedHandshakeStream;
pub const StreamRead = incremental_stream.Read;
pub const StreamWrite = stream_batch.Write;
pub const StreamWriteResult = stream_batch.Result;
pub const SessionEvent = session_control.Event;
const initHandshakeStreamRegistry = handshake_stream.initRegistry;
const sendHandshakeSessionStream = handshake_stream.send;
const receiveHandshakeSessionStream = handshake_stream.receive;
const readHandshakeSessionStream = incremental_stream.read;
const resetHandshakeSessionStream = incremental_stream.reset;
const stopHandshakeSessionStream = incremental_stream.stop;

fn sendDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var storage: [datagram_stack_capacity]u8 = undefined;
    if (try encodeDatagramIntoStack(&storage, session_id, payload)) |encoded| {
        const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded, .length_present = true } }};
        try endpoint.sendFrames(to, &frames);
        return;
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try endpoint.sendFrames(to, &frames);
}

fn encodeDatagramIntoStack(
    storage: *[datagram_stack_capacity]u8,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!?[]const u8 {
    if (!session_id.isClientInitiatedBidirectional()) return error.InvalidSessionId;
    const prefix = try quic.varint.encodeInto(storage, session_id.quarterStreamId());
    const total_len = std.math.add(usize, prefix.len, payload.len) catch return error.IntegerOverflow;
    if (total_len > storage.len) return null;
    @memcpy(storage[prefix.len..total_len], payload);
    return storage[0..total_len];
}

fn receiveDatagramFromEndpoint(endpoint: *quic.runtime.Endpoint) Error!OwnedDatagram {
    while (true) {
        var datagram = try endpoint.receive();
        errdefer datagram.deinit(endpoint.allocator);
        for (datagram.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(frame.datagram.data);
                return .{ .quic_datagram = datagram, .datagram = wt };
            }
        }
        datagram.deinit(endpoint.allocator);
    }
}

fn sendHandshakeDatagramFromConnection(
    connection: *quic.one_rtt.Connection,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    const max_payload = webtransport.maxDatagramPayloadSize(
        connection.maxDatagramPayloadSize(),
        session_id,
    ) orelse return error.DatagramsNotNegotiated;
    if (payload.len > max_payload) return error.DatagramTooLarge;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, connection.endpoint.allocator);
    try connection.sendDatagram(encoded.items);
}

fn receiveHandshakeDatagramFromConnection(connection: *quic.one_rtt.Connection) Error!OwnedHandshakeDatagram {
    while (true) {
        if (try popHandshakeDatagramFromConnection(connection)) |datagram| return datagram;
        // DATAGRAM waiters also own the transport progress loop. In
        // particular, a previously sent RESET_STREAM or STOP_SENDING may need
        // PTO retransmission before the peer can emit the DATAGRAM that this
        // call is awaiting. A plain blocking receive would sleep past that
        // recovery deadline and deadlock both endpoints.
        try connection.servicePacketServicingTimers();
    }
}

test "WebTransport DATAGRAM waiter recovers a lost control packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x01 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x02 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x03 };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept();
            defer accepted.deinit();
            var buffer: [32]u8 = undefined;
            const stream_id = try accepted.openUnidirectionalStream();
            try accepted.sendStream(stream_id, "stop", false);
            while (true) {
                const event = try accepted.readStream(&buffer);
                if (event != .stopped) continue;
                try std.testing.expectEqual(stream_id, event.stopped.stream_id);
                try std.testing.expectEqual(
                    @as(?u32, 88),
                    event.stopped.error_info.application_code,
                );
                break;
            }
            try accepted.sendDatagram("cancel observed");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var drop_enabled = false;
    var dropped: usize = 0;
    const DropFirst = struct {
        fn send(context: *anyopaque, _: []const u8) bool {
            const state: *struct { enabled: *bool, count: *usize } =
                @ptrCast(@alignCast(context));
            if (!state.enabled.* or state.count.* != 0) return false;
            state.count.* = 1;
            return true;
        }
    };
    var drop_state = .{ .enabled = &drop_enabled, .count = &dropped };
    var client = try HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-datagram-pto",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
                .send_interceptor = .{
                    .context = &drop_state,
                    .should_drop = DropFirst.send,
                },
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            } },
        },
    );
    defer client.deinit();
    // A server-created unidirectional stream gives the client a receive side
    // on which STOP_SENDING is valid.
    var stopped: ?u62 = null;
    var buffer: [32]u8 = undefined;
    while (stopped == null) {
        const event = try client.readStream(&buffer);
        if (event != .data) return error.UnexpectedStreamEvent;
        try std.testing.expectEqualStrings(
            "stop",
            buffer[0..event.data.bytes],
        );
        stopped = event.data.stream_id;
    }
    drop_enabled = true;
    try client.stopStream(stopped.?, 88);

    var observed = try client.receiveDatagram();
    defer observed.deinit(allocator);
    try std.testing.expectEqualStrings(
        "cancel observed",
        observed.datagram.payload,
    );
    try std.testing.expectEqual(@as(usize, 1), dropped);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn receiveHandshakePeerConnectionClose(
    connection: *quic.one_rtt.Connection,
) Error!quic.one_rtt.PeerCloseInfo {
    while (true) {
        if (connection.peerCloseInfo()) |close| return close;
        connection.servicePacketServicingTimers() catch |err| switch (err) {
            // A previously observed close makes every later receive fail.
            // Re-read its immutable details before propagating a generic
            // terminal error such as idle timeout or a local close.
            error.ConnectionClosed => {
                return connection.peerCloseInfo() orelse return err;
            },
            else => return err,
        };
    }
}

fn popHandshakeDatagramFromConnection(connection: *quic.one_rtt.Connection) Error!?OwnedHandshakeDatagram {
    const allocator = connection.endpoint.allocator;
    const capacity = connection.config.local_max_datagram_frame_size orelse connection.config.max_datagram_size;
    if (capacity == 0) return null;

    var buffer = try allocator.alloc(u8, capacity);
    errdefer allocator.free(buffer);
    const payload = (try connection.popDatagram(buffer)) orelse {
        allocator.free(buffer);
        return null;
    };
    if (payload.len != buffer.len) buffer = try allocator.realloc(buffer, payload.len);
    const wt = try webtransport.Datagram.parse(buffer);
    return .{ .bytes = buffer, .datagram = wt };
}

fn drainQueuedHandshakeDatagrams(connection: *quic.one_rtt.Connection, datagrams: []?OwnedHandshakeDatagram) Error!usize {
    var count: usize = 0;
    while (count < datagrams.len) {
        const datagram = (try popHandshakeDatagramFromConnection(connection)) orelse break;
        datagrams[count] = datagram;
        count += 1;
    }
    return count;
}

fn receiveManyHandshakeDatagrams(connection: *quic.one_rtt.Connection, count: usize) Error!OwnedHandshakeDatagramBatch {
    const datagrams = try connection.endpoint.allocator.alloc(?OwnedHandshakeDatagram, count);
    errdefer connection.endpoint.allocator.free(datagrams);
    @memset(datagrams, null);
    const errors = try connection.endpoint.allocator.alloc(?anyerror, count);
    errdefer connection.endpoint.allocator.free(errors);
    @memset(errors, null);

    const filled = try drainQueuedHandshakeDatagrams(connection, datagrams);
    if (filled == count) return .{ .allocator = connection.endpoint.allocator, .datagrams = datagrams, .errors = errors };

    // A QUIC connection owns packet-number, ACK, flow-control, and DATAGRAM
    // queue state.  Unlike independent endpoint receives, multiple concurrent
    // receivePacket() calls on the same Connection would race those mutable
    // invariants.  Batch reception therefore drains one connection
    // sequentially while still returning the ergonomic batch/error shape used
    // by the higher-level runtime.
    for (datagrams[filled..], errors[filled..]) |*datagram, *err_slot| {
        datagram.* = receiveHandshakeDatagramFromConnection(connection) catch |err| {
            err_slot.* = err;
            break;
        };
        err_slot.* = null;
    }
    return .{ .allocator = connection.endpoint.allocator, .datagrams = datagrams, .errors = errors };
}

fn sendProtectedDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try quic.one_rtt.sendFrames(endpoint, to, keys, .{
        .destination_connection_id = destination_connection_id,
        .packet_number = packet_number.*,
        .frames = &frames,
    });
    packet_number.* += 1;
}

fn receiveProtectedDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    local_connection_id_len: usize,
    expected_packet_number: *u64,
    max_frames: usize,
) Error!OwnedProtectedDatagram {
    while (true) {
        var packet = try quic.one_rtt.receive(endpoint, keys, local_connection_id_len, expected_packet_number.*, max_frames);
        errdefer packet.deinit(endpoint.allocator);
        expected_packet_number.* = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(frame.datagram.data);
                return .{ .packet = packet, .datagram = wt };
            }
        }
        packet.deinit(endpoint.allocator);
    }
}

fn findHeader(headers: []const http3.Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "WebTransport runtime CONNECT headers advertise Capsule-Protocol" {
    var default_buf: [3]http3.Qpack.HeaderField = undefined;
    const default_headers = connectRequestHeaders("/", &default_buf);
    try std.testing.expectEqual(@as(usize, 2), default_headers.len);
    try std.testing.expectEqualStrings("webtransport", findHeader(default_headers, ":protocol").?);
    try std.testing.expect(try http3.capsule.protocolEnabled(default_headers));
    try validateConnectRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = default_headers,
    });

    var origin_buf: [3]http3.Qpack.HeaderField = undefined;
    const origin_headers = connectRequestHeaders("https://example.com", &origin_buf);
    try std.testing.expectEqual(@as(usize, 3), origin_headers.len);
    try std.testing.expectEqualStrings("https://example.com", findHeader(origin_headers, "origin").?);
    try std.testing.expect(try http3.capsule.protocolEnabled(origin_headers));
    try validateConnectRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = origin_headers,
    });

    const missing_capsule = [_]http3.Qpack.HeaderField{
        .{ .name = ":protocol", .value = "webtransport" },
    };
    try validateConnectRequest(.{
        .method = "CONNECT",
        .scheme = "https",
        .path = "/",
        .authority = @as(?[]const u8, "example.com"),
        .headers = &missing_capsule,
    });
    const false_capsule = [_]http3.Qpack.HeaderField{
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = "capsule-protocol", .value = "?0" },
    };
    try std.testing.expectError(
        error.InvalidConnect,
        validateConnectRequest(.{
            .method = "CONNECT",
            .scheme = "https",
            .path = "/",
            .authority = @as(?[]const u8, "example.com"),
            .headers = &false_capsule,
        }),
    );
    try std.testing.expectError(
        error.InvalidConnect,
        validateConnectRequest(.{
            .method = "CONNECT",
            .scheme = "http",
            .path = "/",
            .authority = @as(?[]const u8, "example.com"),
            .headers = default_headers,
        }),
    );

    const response = connectResponse();
    try validateConnectResponse(response);
    try std.testing.expect(try http3.capsule.protocolEnabled(response.headers));
    try validateConnectResponse(.{
        .status = 200,
        .headers = &[_]http3.Qpack.HeaderField{},
    });
    try std.testing.expectError(
        error.SessionRejected,
        validateConnectResponse(.{
            .status = 403,
            .headers = &[_]http3.Qpack.HeaderField{},
        }),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        validateAdditionalConnectHeaders(&.{.{
            .name = ":path",
            .value = "/override",
        }}, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        validateAdditionalConnectHeaders(&.{.{
            .name = "Capsule-Protocol",
            .value = "?0",
        }}, .response),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        validateAdditionalConnectHeaders(&.{.{
            .name = "content-length",
            .value = "0",
        }}, .response),
    );
    const too_many = [_]http3.Qpack.HeaderField{.{
        .name = "x-extra",
        .value = "value",
    }} ** (max_additional_connect_request_headers + 1);
    try std.testing.expectError(
        error.InvalidFrame,
        validateAdditionalConnectHeaders(&too_many, .request),
    );
}

test "WebTransport cleartext accept validates CONNECT session id direction" {
    try std.testing.expect(webtransport.SessionId.init(0).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(1).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(2).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(3).isClientInitiatedBidirectional());
}

test "WebTransport development runtime exposes pending admission metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqual(pending.request.from, pending.peerAddress());
            try std.testing.expectEqualStrings("localhost", pending.authority().?);
            try std.testing.expectEqualStrings("/admission", pending.path());
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.origin().?,
            );
            try std.testing.expectEqualStrings(
                "netz-dev-client",
                pending.userAgent().?,
            );
            var accepted = try pending.acceptWithHeaders(&.{.{
                .name = "x-admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer accepted.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/admission",
            .origin = "https://example.test",
            .headers = &.{.{
                .name = "user-agent",
                .value = "netz-dev-client",
            }},
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-admission").?,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport development runtime sends explicit rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var rejected = try pending.reject(429, &.{.{
                .name = "retry-after",
                .value = "5",
            }});
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u16, 429), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var attempt = try ClientSession.connectAttempt(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/busy",
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 429), attempt.status());
    try std.testing.expectEqualStrings(
        "5",
        attempt.responseHeader("retry-after").?,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport runtime CONNECT and datagrams over HTTP/3 dev runtime" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());

            var datagram = try server_ptr.receiveDatagram();
            defer datagram.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("client-dgram", datagram.datagram.payload);

            try server_ptr.sendDatagram(datagram.quic_datagram.from, accepted.session_id, "server-dgram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
    });
    defer client.deinit();

    try client.sendDatagram("client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("server-dgram", response.datagram.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport protected runtime CONNECT and datagrams over QUIC 1-RTT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .max_stream_frame_data = 5,
    });
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var pending = try server_ptr.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority().?,
            );
            try std.testing.expectEqualStrings(
                "/wt-protected",
                pending.path(),
            );
            var accepted = try pending.acceptWithHeaders(&.{.{
                .name = "x-protected-admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            var control_buffer: [64]u8 = undefined;
            const expected_control = "protected-client-control";
            var control_len: usize = 0;
            while (control_len < expected_control.len) {
                const control = try server_ptr.receiveSessionData(
                    accepted.session_id,
                    control_buffer[control_len..],
                );
                try std.testing.expect(!control.fin);
                control_len += control.bytes;
            }
            try std.testing.expectEqualStrings(
                expected_control,
                control_buffer[0..control_len],
            );
            try accepted.drain(server_ptr);
            var datagram = try server_ptr.receiveDatagram();
            defer datagram.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("protected-client-dgram", datagram.datagram.payload);
            try server_ptr.sendDatagram(datagram.packet.from, accepted.session_id, "protected-server-dgram");
            const close_event = try accepted.receiveSessionEvent(
                server_ptr,
            );
            try std.testing.expect(close_event == .closed);
            try std.testing.expectEqual(
                @as(u32, 91),
                close_event.closed.code,
            );
            try std.testing.expectEqualStrings(
                "protected done",
                close_event.closed.reason,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-protected",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .config = .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_frame_data = 5,
        },
    });
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-protected-admission").?,
    );

    try client.sendSessionData("protected-client-control", false);
    const drain = try client.receiveSessionEvent();
    try std.testing.expect(drain == .draining);
    try client.sendDatagram("protected-client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("protected-server-dgram", response.datagram.payload);
    try client.close(91, "protected done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("protected-late"),
    );
    const peer_fin = try client.receiveSessionEvent();
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expectEqual(@as(u32, 0), peer_fin.closed.code);
    try std.testing.expectEqualStrings("", peer_fin.closed.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport stateful preconfigured runtime exchanges associated streams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    const local_settings = webtransport.defaultSettings(.{});

    var server = try StatefulProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            .max_session_streams = 2,
        },
        .{ .local_settings = local_settings },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *StatefulProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();

            var client_bidi = try session.receiveStream();
            defer client_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                client_bidi.direction,
            );
            try std.testing.expectEqualStrings("client-bidi", client_bidi.payload);
            try session.sendStream(client_bidi.stream_id, "server-bidi", true);

            var client_uni = try session.receiveStream();
            defer client_uni.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.unidirectional,
                client_uni.direction,
            );
            try std.testing.expectEqualStrings("client-uni", client_uni.payload);

            const server_uni = try session.openUnidirectionalStream();
            try session.sendStream(server_uni, "server-uni", true);

            var reset_buffer: [32]u8 = undefined;
            while (true) {
                const event = try session.readStream(&reset_buffer);
                switch (event) {
                    .reset => |reset| {
                        try std.testing.expectEqual(
                            @as(?u32, 91),
                            reset.error_info.application_code,
                        );
                        break;
                    },
                    .data => {},
                    else => return error.UnexpectedStreamEvent,
                }
            }

            const stopped_uni = try session.openUnidirectionalStream();
            try session.sendStream(stopped_uni, "stop-this", false);
            while (true) {
                const event = try session.readStream(&reset_buffer);
                switch (event) {
                    .stopped => |stopped| {
                        try std.testing.expectEqual(stopped_uni, stopped.stream_id);
                        try std.testing.expectEqual(
                            @as(?u32, 92),
                            stopped.error_info.application_code,
                        );
                        break;
                    },
                    .data => {},
                    else => return error.UnexpectedStreamEvent,
                }
            }

            try session.drain();
            const close_event = try session.receiveSessionEvent();
            try std.testing.expect(close_event == .closed);
            try std.testing.expectEqual(
                @as(u32, 93),
                close_event.closed.code,
            );
            try std.testing.expectEqualStrings(
                "stateful done",
                close_event.closed.reason,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try StatefulProtectedClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-stateful-protected",
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
                .max_session_streams = 2,
            },
            .h3 = .{ .local_settings = local_settings },
            .transport = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .local_transport_parameters = quic.practical_transport_parameters,
                .peer_transport_parameters = quic.practical_transport_parameters,
                .one_rtt = .{ .enable_pacing = false },
            },
        },
    );
    defer client.deinit();
    try std.testing.expect(client.datagramsNegotiated());
    try std.testing.expect(client.maxDatagramSize() != 0);
    try std.testing.expectEqual(
        client.address(),
        client.session.h3.address(),
    );
    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, "client-bidi", true);
    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, "client-uni", true);

    var response_bidi = try client.receiveStream();
    defer response_bidi.deinit();
    try std.testing.expectEqual(bidi, response_bidi.stream_id);
    try std.testing.expectEqualStrings("server-bidi", response_bidi.payload);
    var response_uni = try client.receiveStream();
    defer response_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        response_uni.direction,
    );
    try std.testing.expectEqualStrings("server-uni", response_uni.payload);

    const reset_bidi = try client.openBidirectionalStream();
    try std.testing.expectError(
        error.StreamLimitExceeded,
        client.openBidirectionalStream(),
    );
    try client.sendStream(reset_bidi, "before-reset", false);
    try client.resetStream(reset_bidi, 91);
    var stop_buffer: [32]u8 = undefined;
    var stop_sent = false;
    while (!stop_sent) {
        const event = try client.readStream(&stop_buffer);
        switch (event) {
            .data => |data| {
                if (data.direction == .unidirectional and
                    !data.locally_initiated)
                {
                    try client.stopStream(data.stream_id, 92);
                    stop_sent = true;
                }
            },
            else => {},
        }
    }
    const drain_event = try client.receiveSessionEvent();
    try std.testing.expect(drain_event == .draining);
    try client.close(93, "stateful done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.openUnidirectionalStream(),
    );
    const peer_fin = try client.receiveSessionEvent();
    try std.testing.expect(peer_fin == .closed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake runtime CONNECT and datagrams over QUIC handshake" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xea, 0xce, 0x10, 0x01, 0xea, 0xce, 0x10, 0x02 };
    const client_cid = [_]u8{ 0xea, 0xce, 0x10, 0x03 };
    const server_cid = [_]u8{ 0xea, 0xce, 0x10, 0x04 };
    const large_stream_payload = try allocator.alloc(u8, 12 * 1024);
    defer allocator.free(large_stream_payload);
    for (large_stream_payload, 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        large_stream_payload: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());
            const max_datagram_size = accepted.maxDatagramSize();
            try std.testing.expect(max_datagram_size != 0);
            const oversized = try server_ptr.h3.quic_server.endpoint.allocator
                .alloc(u8, max_datagram_size + 1);
            defer server_ptr.h3.quic_server.endpoint.allocator.free(oversized);
            try std.testing.expectError(
                error.DatagramTooLarge,
                accepted.sendDatagram(oversized),
            );

            var client_bidi = try accepted.receiveStream();
            defer client_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                client_bidi.direction,
            );
            try std.testing.expect(!client_bidi.locally_initiated);
            try std.testing.expectEqualStrings(
                "client-bidi",
                client_bidi.payload,
            );
            try accepted.sendStream(
                client_bidi.stream_id,
                "server-bidi",
                true,
            );

            var client_uni = try accepted.receiveStream();
            defer client_uni.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.unidirectional,
                client_uni.direction,
            );
            try std.testing.expectEqualStrings(
                "client-uni",
                client_uni.payload,
            );

            var large_bidi = try accepted.receiveStream();
            defer large_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                large_bidi.direction,
            );
            try std.testing.expectEqualSlices(
                u8,
                shared.large_stream_payload,
                large_bidi.payload,
            );

            const server_uni_id =
                try accepted.openUnidirectionalStream();
            try accepted.sendStream(
                server_uni_id,
                "server-uni",
                true,
            );

            var datagram = try accepted.receiveDatagram();
            defer datagram.deinit(accepted.h3.established.connection.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("handshake-client-dgram", datagram.datagram.payload);
            try accepted.sendDatagram("handshake-server-dgram");
            const stats = accepted.getStats();
            try std.testing.expectEqual(@as(u64, 1), stats.datagrams_received);
            try std.testing.expectEqual(@as(u64, 1), stats.datagrams_sent);
            try std.testing.expect(stats.packets_received > 0);
            try std.testing.expect(stats.packets_sent > 0);
        }
    };

    var shared = Shared{
        .server = &server,
        .large_stream_payload = large_stream_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
        },
    });
    defer client.deinit();
    const max_datagram_size = client.maxDatagramSize();
    try std.testing.expect(max_datagram_size != 0);
    const oversized = try allocator.alloc(u8, max_datagram_size + 1);
    defer allocator.free(oversized);
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagram(oversized),
    );

    const client_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(client_bidi_id, "client-bidi", true);
    const client_uni_id = try client.openUnidirectionalStream();
    try client.sendStream(client_uni_id, "client-uni", true);
    const large_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(large_bidi_id, large_stream_payload, true);

    var server_bidi = try client.receiveStream();
    defer server_bidi.deinit();
    try std.testing.expectEqual(client_bidi_id, server_bidi.stream_id);
    try std.testing.expect(server_bidi.locally_initiated);
    try std.testing.expectEqualStrings("server-bidi", server_bidi.payload);

    var server_uni = try client.receiveStream();
    defer server_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        server_uni.direction,
    );
    try std.testing.expect(!server_uni.locally_initiated);
    try std.testing.expectEqualStrings("server-uni", server_uni.payload);

    try client.sendDatagram("handshake-client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("handshake-server-dgram", response.datagram.payload);
    const stats = client.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.datagrams_received);
    try std.testing.expect(stats.packets_sent > 0);
    try std.testing.expect(stats.packets_received > 0);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives datagrams with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xba, 0xce, 0x20, 0x01, 0xba, 0xce, 0x20, 0x02 };
    const client_cid = [_]u8{ 0xba, 0xce, 0x20, 0x03 };
    const server_cid = [_]u8{ 0xba, 0xce, 0x20, 0x04 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            var batch = try accepted.receiveManyDatagrams(2);
            defer batch.deinit();
            if (batch.firstError()) |err| return err;
            try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

            var saw_one = false;
            var saw_two = false;
            for (batch.datagrams) |maybe_datagram| {
                const datagram = maybe_datagram.?;
                try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-one")) saw_one = true;
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-two")) saw_two = true;
            }
            try std.testing.expect(saw_one);
            try std.testing.expect(saw_two);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake-batch",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
            },
        },
    });
    defer client.deinit();

    try client.sendDatagram("batch-one");
    try client.sendDatagram("batch-two");

    thread.join();
    if (shared.err) |err| return err;
}

test {
    _ = @import("runtime/stream_tests.zig");
    _ = stream_batch;
    _ = @import("runtime/session_control_tests.zig");
    _ = @import("runtime/admission_tests.zig");
    _ = @import("runtime/connection_close_tests.zig");
}
