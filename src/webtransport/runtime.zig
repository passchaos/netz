const std = @import("std");
const webtransport = @import("mod.zig");
const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");
const round_robin = @import("../internal/round_robin.zig");
const deadline_policy = @import("../internal/deadline.zig");

const net = std.Io.net;
const connect_headers = @import("runtime/connect/headers.zig");
const datagram_codec = @import("runtime/datagram/codec.zig");
const datagram_owned = @import("runtime/datagram/owned.zig");
const datagram_send = @import("runtime/datagram/send.zig");
const session_control = @import("runtime/session_control.zig");
const protected_control =
    @import("runtime/protected_session_control.zig");
const stream_batch = @import("runtime/stream/batch.zig");
const development_stream = @import("runtime/development_stream.zig");

test {
    _ = @import("runtime/connect/admission_tests.zig");
    _ = @import("runtime/connect/capacity_tests.zig");
    _ = @import("runtime/endpoint_dispatcher_tests.zig");
    _ = @import("runtime/endpoint_server_tests.zig");
    _ = @import("runtime/development_lifecycle_tests.zig");
    _ = @import("runtime/development_stream_tests.zig");
}

pub const Error = webtransport.Error || http3.runtime.Error ||
    quic.runtime.ReceiveTimeoutError || error{
    InvalidConnect,
    MessageTooLarge,
    SessionRejected,
    MissingDatagram,
    InvalidSessionState,
    InvalidDispatcherState,
} || protected_control.Error;
pub const ReceiveTimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub const EndpointServerError = Error ||
    http3.runtime.HandshakeAdmissionError;
pub const HandshakeFailure = http3.runtime.HandshakeFailure;
pub const OriginPolicy = connect_headers.OriginPolicy;

pub const Limits = struct {
    http3: http3.runtime.Limits = .{},
    max_session_streams: usize = 128,
    /// Browser-origin admission. By default, absent Origin is accepted for
    /// native clients and an explicit Origin must match the CONNECT target.
    origin_policy: OriginPolicy = .same_origin_or_absent,
    /// Maximum response-body bytes retained from a rejected Extended CONNECT
    /// across the development, protected, and authenticated runtimes.
    /// Successful sessions are unaffected.
    max_rejection_body_bytes: usize = 1024 * 1024,
};

pub const max_connection_close_reason: usize = 1024;

pub const Server = struct {
    h3: http3.runtime.Server,
    max_session_streams: usize,
    origin_policy: OriginPolicy,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .h3 = try .bind(allocator, io, bind_address, limits.http3),
            .max_session_streams = limits.max_session_streams,
            .origin_policy = limits.origin_policy,
        };
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

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedSession {
        var pending = try self.receiveSessionRequestWithDeadline(deadline);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Receive and validate a development-runtime Extended CONNECT before
    /// committing an application admission decision.
    pub fn receiveSessionRequest(self: *Server) Error!PendingSession {
        return self.receiveSessionRequestInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveSessionRequestWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveSessionRequestWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingSession {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveSessionRequestInternal(deadline);
    }

    fn receiveSessionRequestInternal(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingSession {
        while (true) {
            var event = if (deadline) |absolute|
                try self.h3.receiveRequestHeadWithDeadline(absolute)
            else
                try self.h3.receiveRequestHead();
            defer event.deinit(self.h3.quic_server.endpoint.allocator);
            switch (event) {
                .reset => unreachable,
                .message => |*message| switch (message.value) {
                    .head => |*head| {
                        // The streaming H3 parser has already admitted this
                        // request. Any WebTransport validation failure must
                        // retire it so malformed CONNECT attempts cannot pin
                        // the server's bounded request capacity.
                        errdefer self.h3.cancelRequest(
                            message.from,
                            message.stream_id,
                            http3.ApplicationErrorCode.request_rejected,
                        ) catch {};
                        if (head.* != .request) return error.InvalidConnect;
                        try validateConnectRequest(head.request);
                        const session_id = webtransport.SessionId.init(
                            message.stream_id,
                        );
                        if (!session_id.isClientInitiatedBidirectional()) {
                            return error.InvalidConnect;
                        }
                        const request = OwnedConnectRequest{
                            .from = message.from,
                            .stream_id = message.stream_id,
                            .request = head.request,
                        };
                        message.value = .finished;
                        return .{
                            .server = self,
                            .request = request,
                            .session_id = session_id,
                        };
                    },
                    else => unreachable,
                },
            }
        }
    }

    pub fn receiveDatagram(self: *Server) Error!OwnedDatagram {
        var datagram = try self.h3.receiveDatagram();
        errdefer datagram.deinit(self.h3.quic_server.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn receiveDatagramWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        var datagram = try self.h3.receiveDatagramWithTimeout(timeout);
        errdefer datagram.deinit(self.h3.quic_server.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn receiveDatagramWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDatagram {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        var datagram = try self.h3.receiveDatagramWithDeadline(deadline);
        errdefer datagram.deinit(self.h3.quic_server.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn sendDatagram(self: *Server, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try sendDatagramFromEndpoint(&self.h3.quic_server.endpoint, to, session_id, payload);
    }

    /// Send Capsule Protocol bytes on the development CONNECT response stream.
    ///
    /// The stream remains open after the successful 2xx response head, so the
    /// response body becomes the long-lived WebTransport control channel.
    pub fn sendSessionData(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.h3.sendResponseBody(to, session_id.value, data, fin);
    }

    pub fn receiveSessionData(
        self: *Server,
        from: net.IpAddress,
        session_id: webtransport.SessionId,
        out: []u8,
    ) Error!SessionDataRead {
        return self.receiveSessionDataInternal(from, session_id, out, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveSessionDataWithTimeout(
        self: *Server,
        from: net.IpAddress,
        session_id: webtransport.SessionId,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionDataRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionDataInternal(
            from,
            session_id,
            out,
            .fromNow(
                self.h3.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionDataWithDeadline(
        self: *Server,
        from: net.IpAddress,
        session_id: webtransport.SessionId,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionDataRead {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveSessionDataInternal(from, session_id, out, deadline);
    }

    fn receiveSessionDataInternal(
        self: *Server,
        from: net.IpAddress,
        session_id: webtransport.SessionId,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionDataRead {
        while (true) {
            var event = if (deadline) |absolute|
                try self.h3.receiveRequestEventForWithDeadline(
                    from,
                    session_id.value,
                    absolute,
                )
            else
                try self.h3.receiveRequestEventFor(
                    from,
                    session_id.value,
                );
            defer event.deinit(self.h3.quic_server.endpoint.allocator);
            switch (event) {
                .reset => return error.InvalidSessionState,
                .message => |message| {
                    std.debug.assert(message.stream_id == session_id.value);
                    switch (message.value) {
                        .data_available => {
                            const count = try self.h3.readRequestData(
                                from,
                                session_id.value,
                                out,
                            );
                            if (count != 0) return .{ .bytes = count };
                        },
                        .finished => return .{ .fin = true },
                        else => return error.InvalidSessionState,
                    }
                },
            }
        }
    }
};

pub const ProtectedServer = struct {
    h3: http3.runtime.ProtectedServer,
    origin_policy: OriginPolicy,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        config: http3.runtime.ProtectedConfig,
    ) Error!ProtectedServer {
        return .{
            .h3 = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3,
                webTransportProtectedConfig(config),
            ),
            .origin_policy = limits.origin_policy,
        };
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

    pub fn acceptWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedProtectedSession {
        var pending = try self.receiveSessionRequestWithDeadline(deadline);
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedProtectedSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive and validate a protected Extended CONNECT before deciding
    /// whether to accept or reject the session.
    pub fn receiveSessionRequest(
        self: *ProtectedServer,
    ) Error!PendingProtectedSession {
        return self.receiveSessionRequestInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveSessionRequestWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingProtectedSession {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveSessionRequestInternal(deadline);
    }

    pub fn receiveSessionRequestWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingProtectedSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn receiveSessionRequestInternal(
        self: *ProtectedServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingProtectedSession {
        const request = if (deadline) |absolute|
            try receiveProtectedConnectRequestBefore(&self.h3, absolute)
        else
            try receiveProtectedConnectRequest(&self.h3);
        var request_head = request.head;
        errdefer request_head.deinit(
            self.h3.quic_server.endpoint.allocator,
        );
        // The protected H3 parser has already admitted this stream. Retire it
        // if WebTransport-specific validation fails so malformed CONNECTs do
        // not pin bounded request state until server teardown.
        errdefer self.h3.rejectRequest(
            request.from,
            request.stream_id,
        ) catch {};
        try validateConnectRequest(request_head);
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

    pub fn receiveDatagramWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedDatagram {
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return receiveProtectedDatagramFromEndpointWithDeadline(
            &self.h3.quic_server.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
            deadline,
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
        return self.receiveSessionDataInternal(session_id, out, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveSessionDataWithTimeout(
        self: *ProtectedServer,
        session_id: webtransport.SessionId,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionDataInternal(
            session_id,
            out,
            .fromNow(
                self.h3.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionDataWithDeadline(
        self: *ProtectedServer,
        session_id: webtransport.SessionId,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveSessionDataInternal(session_id, out, deadline);
    }

    fn receiveSessionDataInternal(
        self: *ProtectedServer,
        session_id: webtransport.SessionId,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        while (true) {
            var event = if (deadline) |absolute|
                try self.h3.receiveRequestEventForWithDeadline(
                    session_id.value,
                    absolute,
                )
            else
                try self.h3.receiveRequestEventFor(session_id.value);
            defer event.deinit(self.h3.quic_server.endpoint.allocator);
            switch (event) {
                .reset => return error.InvalidSessionState,
                .message => |message| {
                    std.debug.assert(message.stream_id == session_id.value);
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
    request: OwnedConnectRequest,
    session_id: webtransport.SessionId,

    pub fn sessionId(self: PendingSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn deinit(self: *PendingSession) void {
        // Dropping an admission decision must also retire the persistent H3
        // request. Merely freeing its decoded head leaves the parser/lifecycle
        // entry active, eventually exhausting the bounded request concurrency.
        self.server.h3.cancelRequest(
            self.request.from,
            self.request.stream_id,
            http3.ApplicationErrorCode.request_rejected,
        ) catch {};
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
        try validateConnectOrigin(
            self.request.request,
            self.server.origin_policy,
        );
        const allocator = self.server.h3.quic_server.endpoint.allocator;
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponse(
            allocator,
            additional_headers,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        // Allocate every fallible per-session resource before the success
        // response becomes observable. A failure therefore leaves the pending
        // request rejectable instead of advertising an unusable session.
        var streams = try initDevelopmentStreamRegistry(
            allocator,
            self.session_id,
            .server,
            self.server.max_session_streams,
        );
        errdefer streams.deinit();
        // Extended CONNECT itself becomes the WebTransport control stream, so
        // the successful response must preserve both directions instead of
        // using the aggregate helper that immediately commits a terminal FIN.
        try self.server.h3.startResponse(
            self.request.from,
            self.request.stream_id,
            connectResponseWithHeaders(prepared_headers.fields),
            null,
        );
        const server = self.server;
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .server = server,
            .request = request,
            .session_id = session_id,
            .streams = streams,
            .control = protected_control.Reader.init(
                try session_control.Control.init(session_id),
            ),
        };
    }

    pub fn reject(
        self: *PendingSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!RejectedSession {
        return self.rejectWithBody(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    pub fn rejectWithBody(
        self: *PendingSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!RejectedSession {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try validateAdditionalConnectHeaders(trailers, .response);
        try self.server.h3.sendResponse(
            self.request.from,
            self.request.stream_id,
            .{
                .status = status,
                .headers = response_headers,
                .body = body,
                .trailers = trailers,
                .request_method = "CONNECT",
                .extended_connect = true,
            },
        );
        // The complete final response is now observable, so cleanup must not
        // turn this into an error that makes a caller's pending defer emit a
        // contradictory cancellation. Missing state is already retired.
        self.server.h3.finishRequest(
            self.request.from,
            self.request.stream_id,
        ) catch {};
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
    request: OwnedConnectRequest,
    session_id: webtransport.SessionId,
    status: u16,

    pub fn sessionId(self: RejectedSession) webtransport.SessionId {
        return self.session_id;
    }

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
        // Dropping an admission decision rejects the persistent CONNECT and
        // releases its protected H3 parser/lifecycle state.
        self.server.h3.rejectRequest(
            self.request.from,
            self.request.stream_id,
        ) catch {};
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
        try validateConnectOrigin(
            self.request.request,
            self.server.origin_policy,
        );
        const allocator = self.server.h3.quic_server.endpoint.allocator;
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponse(
            allocator,
            additional_headers,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        // Extended CONNECT is the session control stream. Keep both
        // directions open; aggregate sendResponse would terminate it.
        try self.server.h3.startResponse(
            self.request.from,
            self.request.stream_id,
            connectResponseWithHeaders(prepared_headers.fields),
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
        return self.rejectWithBody(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    pub fn rejectWithBody(
        self: *PendingProtectedSession,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!RejectedProtectedSession {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateAdditionalConnectHeaders(response_headers, .response);
        try validateAdditionalConnectHeaders(trailers, .response);
        try self.server.h3.sendResponse(
            self.request.from,
            self.request.stream_id,
            .{
                .status = status,
                .headers = response_headers,
                .body = body,
                .trailers = trailers,
                .request_method = "CONNECT",
                .extended_connect = true,
            },
        );
        // Preserve the wire-visible rejection as the terminal decision even
        // when its request bookkeeping was already retired by the writer.
        self.server.h3.finishRequest(self.request.stream_id) catch {};
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

    /// Bound the initial datagram and Extended CONNECT with one absolute
    /// deadline. The preconfigured transport setup itself performs no network
    /// I/O, so the caller's budget is never restarted between those phases.
    pub fn acceptWithDeadline(
        self: *StatefulProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequestWithDeadline(deadline);
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *StatefulProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
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

    pub fn receiveSessionRequestWithDeadline(
        self: *StatefulProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        var first = try self.endpoint.receiveBytesWithDeadline(deadline);
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
        return receiveStatefulSessionRequestWithDeadline(
            &h3,
            self.limits,
            deadline,
        );
    }

    pub fn receiveSessionRequestWithTimeout(
        self: *StatefulProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestWithDeadline(.fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
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

    pub fn acceptFromWithDeadline(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequestFromWithDeadline(
            peer,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptFromWithTimeout(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptFromWithDeadline(
            peer,
            .fromNow(self.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
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

    pub fn receiveSessionRequestFromWithDeadline(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
            &self.endpoint,
            peer,
            self.h3_options,
            self.transport,
        );
        errdefer h3.deinit();
        return receiveStatefulSessionRequestWithDeadline(
            &h3,
            self.limits,
            deadline,
        );
    }

    pub fn receiveSessionRequestFromWithTimeout(
        self: *StatefulProtectedServer,
        peer: net.IpAddress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestFromWithDeadline(
            peer,
            .fromNow(self.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
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

    /// Complete QUIC/TLS and receive the first Extended CONNECT under one
    /// caller-owned awake-clock deadline. The timestamp is preserved between
    /// phases so handshake time cannot be regained by the request receive.
    pub fn acceptWithDeadline(
        self: *HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        var pending = try self.receiveSessionRequestWithDeadline(deadline);
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *HandshakeServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
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

    /// Preserve one caller-owned budget across a dispatcher-provided Initial,
    /// the remaining QUIC/TLS handshake, and the first Extended CONNECT.
    pub fn receiveSessionRequestFromInitialWithDeadline(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        var session = try self.h3.acceptFromInitialWithDeadline(
            initial,
            deadline,
        );
        errdefer session.deinit();
        return receiveStatefulSessionRequestWithDeadline(
            &session,
            self.limits,
            deadline,
        );
    }

    pub fn receiveSessionRequestFromInitialWithTimeout(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestFromInitialWithDeadline(
            initial,
            .fromNow(
                self.h3.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
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

    pub fn beginSessionAdmissionFromInitialSourceWithDeadline(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!HandshakeAdmission {
        var session = try self.h3.acceptFromInitialSourceWithDeadline(
            source,
            initial,
            deadline,
        );
        errdefer session.deinit();
        _ = try deadline_policy.usableAwake(
            session.established.connection.endpoint.io,
            deadline,
        );
        try session.ensureSettingsSent();
        return .{
            .h3 = session,
            .limits = self.limits,
            .deadline = deadline,
        };
    }

    pub fn beginSessionAdmissionFromInitialSourceWithTimeout(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!HandshakeAdmission {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.beginSessionAdmissionFromInitialSourceWithDeadline(
            source,
            initial,
            .fromNow(
                self.h3.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
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

    pub fn receiveSessionRequestWithDeadline(
        self: *HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        var session = try self.h3.acceptWithDeadline(deadline);
        errdefer session.deinit();
        return receiveStatefulSessionRequestWithDeadline(
            &session,
            self.limits,
            deadline,
        );
    }

    pub fn receiveSessionRequestWithTimeout(
        self: *HandshakeServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionRequestWithDeadline(.fromNow(
            self.h3.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptSession(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
    ) Error!AcceptedHandshakeSession {
        var pending = try receiveSessionRequestFromSession(h3, limits);
        return pending.accept() catch |err| {
            pending.restoreSession();
            return err;
        };
    }

    pub fn acceptSessionWithDeadline(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        var pending = try receiveSessionRequestFromSessionWithDeadline(
            h3,
            limits,
            deadline,
        );
        return pending.accept() catch |err| {
            pending.restoreSession();
            return err;
        };
    }

    pub fn acceptSessionWithTimeout(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!AcceptedHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptSessionWithDeadline(
            h3,
            limits,
            .fromNow(h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveSessionRequestFromSession(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
    ) Error!PendingHandshakeSession {
        return receiveStatefulSessionRequestBefore(
            h3,
            limits,
            null,
            h3,
        );
    }

    pub fn receiveSessionRequestFromSessionWithDeadline(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        return receiveStatefulSessionRequestBefore(
            h3,
            limits,
            absolute,
            h3,
        );
    }

    pub fn receiveSessionRequestFromSessionWithTimeout(
        h3: *http3.runtime.HandshakeServerSession,
        limits: Limits,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PendingHandshakeSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveSessionRequestFromSessionWithDeadline(
            h3,
            limits,
            .fromNow(h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
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
    /// Optional caller-owned budget inherited from the routed QUIC handshake.
    /// Packet injection and CONNECT polling both check this same timestamp so
    /// promotion to an endpoint dispatcher cannot silently renew admission.
    deadline: ?std.Io.Clock.Timestamp = null,

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
        try self.ensureWithinDeadline();
        try self.h3.processRequestPacket(packet);
    }

    pub fn pollSessionRequest(
        self: *HandshakeAdmission,
    ) Error!?PendingHandshakeSession {
        try self.ensureWithinDeadline();
        while (try self.h3.pollRequestEventOnce()) |event_value| {
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
                        const deadline = self.deadline;
                        self.* = undefined;
                        return .{ .h3 = h3, .limits = limits, .request = .{
                            .stream_id = message.stream_id,
                            .request = request,
                        }, .session_id = session_id, .deadline = deadline };
                    },
                    else => return error.InvalidConnect,
                },
            }
        }
        return null;
    }

    fn ensureWithinDeadline(self: *HandshakeAdmission) ReceiveTimeoutError!void {
        const deadline = self.deadline orelse return;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
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
    /// This runtime advertises one WebTransport session per HTTP/3
    /// connection. If rejection is temporarily paced or flow-controlled, keep
    /// the extra request ID here and retry without consuming another head.
    request_rejection_pending: ?u62 = null,
    /// A peer CLOSE was already reported to the application; the endpoint
    /// still owes the CONNECT response FIN and retries it from later turns.
    close_response_pending: bool = false,

    pub fn sessionId(self: EndpointAcceptedSession) webtransport.SessionId {
        return self.session_id;
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
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
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
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const result = self.h3.trySendConnectDatagramWithDeadline(
            self.session_id.value,
            payload,
            deadline,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt to reserve one bidirectional stream without waiting for peer
    /// credit or pacing; dispatcher progress makes a later retry possible.
    pub fn openBidirectionalStream(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const stream_id = try self.streams.prepareLocal(.bidirectional);
        const transport_id = self.h3.established.connection
            .tryOpenStream() catch |err| {
            try self.refreshTimer();
            return err;
        };
        std.debug.assert(transport_id == stream_id);
        const committed = (try self.streams.commitPreparedLocal(
            stream_id,
            .bidirectional,
        )).stream_id;
        try self.refreshTimer();
        return committed;
    }

    /// Attempt to reserve one unidirectional stream without waiting for peer
    /// credit or pacing; dispatcher progress makes a later retry possible.
    pub fn openUnidirectionalStream(
        self: *EndpointAcceptedSession,
    ) EndpointServerError!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const stream_id = try self.streams.prepareLocal(.unidirectional);
        const transport_id = self.h3.tryOpenServerUnidirectionalStream() catch |err| {
            try self.refreshTimer();
            return err;
        };
        std.debug.assert(transport_id == stream_id);
        const registered = try self.streams.commitPreparedLocal(
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
        return self.h3.maxConnectDatagramPayloadSize(
            self.session_id.value,
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
        try self.control.ensureOpen();
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
        try self.control.ensureOpen();
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

    /// Make one socket-free batch attempt across the supplied streams.
    /// `counts` and `send_error` identify exactly the socket-visible prefix.
    pub fn writeStreams(
        self: *EndpointAcceptedSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) EndpointServerError!StreamWriteResult {
        try self.control.ensureOpen();
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
        try self.control.ensureOpen();
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
        const stream = self.streams.get(stream_id) orelse
            return error.UnknownStream;
        if (stream.locally_initiated) return error.InvalidStreamState;
        const result = self.h3.established.connection
            .tryReleaseCompletedPeerStream(stream_id);
        try self.refreshTimer();
        return try result;
    }

    /// Attempt RESET_STREAM once without waiting for pacing or reading the
    /// shared endpoint socket. Retry after dispatcher transport progress.
    pub fn resetStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        const result = incremental_stream.resetOnce(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
        try self.refreshTimer();
        try result;
    }

    /// Attempt STOP_SENDING once without waiting for pacing or reading the
    /// shared endpoint socket. Retry after dispatcher transport progress.
    pub fn stopStream(
        self: *EndpointAcceptedSession,
        stream_id: u62,
        application_error_code: u32,
    ) EndpointServerError!void {
        const result = incremental_stream.stopOnce(
            &self.h3.established.connection,
            &self.streams,
            stream_id,
            application_error_code,
        );
        try self.refreshTimer();
        try result;
    }

    pub fn drain(self: *EndpointAcceptedSession) EndpointServerError!void {
        if (self.control.local_drain_sent) return;
        try self.control.ensureOpen();
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
        if (self.control.local_close_sent) {
            const result = session_control.terminateStreamsOnce(
                &self.h3.established.connection,
                &self.streams,
            );
            try self.refreshTimer();
            _ = try result;
            return;
        }
        try self.control.ensureOpen();
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        const result = self.h3.trySendResponseBody(
            self.session_id.value,
            capsule,
            true,
        );
        result catch |err| {
            try self.refreshTimer();
            return err;
        };
        // Local FIN closes only our send direction. Keep the CONNECT
        // association registered until the peer's receive direction reaches
        // FIN/reset so the endpoint can still route its close acknowledgement
        // and any datagram that preceded that terminal signal.
        try self.control.recordLocalClose(code);
        try self.refreshTimer();
    }

    fn refreshTimer(self: *EndpointAcceptedSession) EndpointServerError!void {
        try self.dispatcher.refreshConnectionTimer(self.handle);
    }

    fn deinit(self: *EndpointAcceptedSession, allocator: std.mem.Allocator) void {
        self.h3.closeConnectDatagramAssociation(
            self.session_id.value,
        ) catch {};
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
    /// The HTTP/3 handshake supervisor is the producer of this event. Reuse
    /// its finite error payload so applications can exhaustively distinguish
    /// an admission deadline from a protocol/TLS failure.
    handshake_failed: HandshakeFailure,
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
    /// Handle that most recently produced an application event. The next
    /// poll starts after it in the hash table's current iteration order, so a
    /// continuously ready stream or DATAGRAM cannot starve another accepted
    /// session. Handles remain stable across rehashes; if this one is removed,
    /// the poller simply falls back to a complete scan.
    last_session_event_handle: ?quic.endpoint_dispatcher.ConnectionHandle =
        null,
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
        try validateConnectOrigin(
            source.request.request,
            source.limits.origin_policy,
        );
        // Reserve every allocation before emitting status 200. Once the peer
        // observes acceptance this state transition must be infallible.
        try self.sessions.ensureUnusedCapacity(self.allocator, 1);
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponse(
            self.allocator,
            additional_headers,
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
        const control = try session_control.Control.init(source.session_id);
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
        self.rejected.putAssumeCapacityNoClobber(handle, {});
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
        if (self.last_session_event_handle == handle) {
            self.last_session_event_handle = null;
        }
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
        if (stream_buffer.len == 0) return error.BufferTooShort;
        if (try self.pollAcceptedSessions(stream_buffer)) |event| return event;

        const event_value = (try self.h3.receiveTransportOnce(
            supported_versions,
            poll_interval,
        )) orelse return null;
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
        if (try self.pollAcceptedSessions(stream_buffer)) |event| return event;
        while (true) {
            const transport_event = try self.h3.receiveTransportWithDeadline(
                supported_versions,
                absolute,
            );
            if (try self.processTransportEvent(
                transport_event,
                stream_buffer,
            )) |event| return event;
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
                if (self.last_session_event_handle == handle) {
                    self.last_session_event_handle = null;
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
        if (self.sessions.get(handle)) |session_value| {
            try session_value.h3.processDetachedRequestPacket(
                session_value.session_id.value,
                packet,
            );
            _ = try rejectAdditionalEndpointRequestsOnce(session_value);
            return self.pollAcceptedSessions(stream_buffer);
        }
        if (self.pending.get(handle)) |pending_value| {
            try pending_value.h3.processRequestPacket(packet);
            return null;
        }
        if (self.rejected.contains(handle)) {
            const h3 = self.h3.session(handle) orelse
                return error.InvalidSessionState;
            try h3.processRequestPacket(packet);
            while (try h3.pollRequestEventOnce()) |ignored_value| {
                var ignored = ignored_value;
                ignored.deinit(self.allocator);
            }
            return null;
        }
        const h3 = self.h3.session(handle) orelse
            return error.InvalidSessionState;
        try h3.processRequestPacket(packet);
        const request = (try pollEndpointConnectHead(h3)) orelse
            return null;
        errdefer {
            var owned = request.request;
            owned.deinit(self.allocator);
        }
        const pending = try self.allocator.create(EndpointPendingSession);
        errdefer self.allocator.destroy(pending);
        const slot = try self.pending.getOrPut(self.allocator, handle);
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
    }

    fn pollAcceptedSessions(
        self: *EndpointServer,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointServerEvent {
        return self.pollAcceptedSessionsWith(
            stream_buffer,
            {},
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
            quic.endpoint_dispatcher.ConnectionHandle,
            @TypeOf(self.sessions),
            EndpointServerEvent,
            &self.sessions,
            &self.last_session_event_handle,
            .{ .stream_buffer = stream_buffer, .context = context },
            struct {
                fn run(
                    poll_context: anytype,
                    handle: quic.endpoint_dispatcher.ConnectionHandle,
                    accepted_ptr: **EndpointAcceptedSession,
                ) EndpointServerError!?EndpointServerEvent {
                    const event = (try poll(
                        poll_context.context,
                        handle,
                        accepted_ptr.*,
                        poll_context.stream_buffer,
                    )) orelse return null;
                    return .{ .session_event = .{
                        .handle = handle,
                        .event = event,
                    } };
                }
            }.run,
        );
    }

    fn pollEndpointSessionEntry(
        _: void,
        _: quic.endpoint_dispatcher.ConnectionHandle,
        accepted: *EndpointAcceptedSession,
        stream_buffer: []u8,
    ) EndpointServerError!?EndpointSessionEvent {
        var event = pollEndpointSession(accepted, stream_buffer) catch |err| {
            // A failing protocol poll can still queue transport control or
            // close frames. Preserve its error while ensuring the shared
            // endpoint observes the resulting recovery deadline.
            try accepted.refreshTimer();
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
                handle: quic.endpoint_dispatcher.ConnectionHandle,
                _: *EndpointAcceptedSession,
                _: []u8,
            ) Error!?EndpointSessionEvent {
                if (std.mem.indexOfScalar(
                    quic.endpoint_dispatcher.ConnectionHandle,
                    self.ready,
                    handle,
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
            return pollEndpointSessionEntry(
                {},
                accepted.handle,
                accepted,
                stream_buffer,
            );
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
    ) Error!?EndpointSessionEvent {
        _ = try rejectAdditionalEndpointRequestsOnce(target);
        // Accepted sessions remain in the endpoint map until the application
        // removes their connection. Once the peer terminal event has been
        // delivered, do not poll stream/DATAGRAM APIs whose association is no
        // longer application-visible. The retained HTTP/3 association still
        // lets the dispatcher process late ACKs and reject late datagrams.
        if (!target.control.terminal_reported) {
            const control_event = target.control.pollOnce(
                &target.h3.established.connection,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
            if (control_event) |event| {
                try finishEndpointSessionEvent(target, event);
                return .{ .session = event };
            }
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
        if (target.control.terminal_reported) return null;
        if (try incremental_stream.pollOnce(
            &target.h3.established.connection,
            &target.streams,
            target.session_id,
            stream_buffer,
        )) |event| {
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

fn rejectAdditionalHandshakeRequestsOnce(
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

const EndpointConnectHead = struct {
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
};

fn pollEndpointConnectHead(
    h3: *http3.runtime.HandshakeServerSession,
) Error!?EndpointConnectHead {
    while (try h3.pollRequestEventOnce()) |event_value| {
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

fn advanceEndpointCloseOnce(
    target: *EndpointAcceptedSession,
) Error!session_control.TerminateProgress {
    if (target.close_response_pending) {
        target.h3.trySendResponseBody(
            target.session_id.value,
            &.{},
            true,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {},
            else => |other| return other,
        };
        target.close_response_pending = false;
        target.control.local_close_sent = true;
        return .submitted;
    }
    if (!target.control.local_close_sent and
        !target.control.terminal_reported)
    {
        return .complete;
    }
    return session_control.terminateStreamsOnce(
        &target.h3.established.connection,
        &target.streams,
    );
}

pub const AcceptedSession = struct {
    server: *Server,
    request: OwnedConnectRequest,
    session_id: webtransport.SessionId,
    streams: webtransport.StreamRegistry,
    /// Reuses the protected-session adapter because development HTTP/3 now
    /// yields CONNECT DATA as caller-buffer payload chunks rather than raw
    /// detached QUIC bytes. This keeps timeout-resumable Capsule parsing and
    /// suffix retention identical across the lightweight runtimes.
    control: protected_control.Reader,

    pub fn sessionId(self: AcceptedSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn remoteAddress(self: AcceptedSession) net.IpAddress {
        return self.request.from;
    }

    pub fn openBidirectionalStream(self: *AcceptedSession) Error!u62 {
        return self.openLocalStream(.bidirectional);
    }

    pub fn openUnidirectionalStream(self: *AcceptedSession) Error!u62 {
        return self.openLocalStream(.unidirectional);
    }

    fn openLocalStream(
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
        self.* = undefined;
    }

    pub fn drain(self: *AcceptedSession) Error!void {
        if (self.control.control.local_drain_sent) return;
        try self.control.control.ensureOpen();
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.server.sendSessionData(
            self.request.from,
            self.session_id,
            capsule,
            false,
        );
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedSession,
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
        try self.server.sendSessionData(
            self.request.from,
            self.session_id,
            capsule,
            true,
        );
        try self.control.control.recordLocalClose(code);
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

    fn finish(self: *PendingHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
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
        try validateConnectOrigin(
            self.request.request,
            self.limits.origin_policy,
        );
        const allocator = self.h3.established.connection.endpoint.allocator;
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareResponse(
            allocator,
            additional_headers,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        if (self.deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
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
        const control = try session_control.Control.init(self.session_id);
        try self.h3.prepareConnectDatagramAssociation(
            self.session_id.value,
        );
        errdefer self.h3.cancelPreparedConnectDatagramAssociation(
            self.session_id.value,
        );
        try self.h3.startResponse(
            self.session_id.value,
            connectResponseWithHeaders(prepared_headers.fields),
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
        try self.h3.finishRejectedRequest(self.session_id.value);
        const h3 = self.h3;
        const restore_to = self.restore_to;
        const request = self.request;
        const session_id = self.session_id;
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
};

pub const AcceptedHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,
    request_rejection_pending: ?u62 = null,

    pub fn deinit(self: *AcceptedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.h3.closeConnectDatagramAssociation(
            self.session_id.value,
        ) catch {};
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
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagram(self.session_id.value),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagramWithTimeout(
                self.session_id.value,
                timeout,
            ),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagramWithDeadline(
                self.session_id.value,
                deadline,
            ),
            self.session_id,
        );
    }

    pub fn receiveManyDatagrams(self: *AcceptedHandshakeSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(
            &self.h3,
            self.session_id,
            count,
        );
    }

    /// Receive up to `count` DATAGRAMs within one shared timeout budget. If
    /// the deadline expires after partial progress, the returned batch retains
    /// those DATAGRAMs and records `error.Timeout` in the next error slot.
    pub fn receiveManyDatagramsWithTimeout(
        self: *AcceptedHandshakeSession,
        count: usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveManyDatagramsWithDeadline(
            count,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveManyDatagramsWithDeadline(
        self: *AcceptedHandshakeSession,
        count: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return receiveManyHandshakeDatagramsUntil(
            &self.h3,
            self.session_id,
            count,
            deadline,
        );
    }

    pub fn sendDatagram(self: *AcceptedHandshakeSession, payload: []const u8) Error!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        try self.h3.sendConnectDatagram(self.session_id.value, payload);
    }

    /// Wait for QUIC congestion and pacing capacity while retaining one total
    /// timeout across all HTTP/3 progress needed to free it.
    pub fn sendDatagramWithTimeout(
        self: *AcceptedHandshakeSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(payload, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramWithDeadline(
        self: *AcceptedHandshakeSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        try self.h3.sendConnectDatagramWithDeadline(
            self.session_id.value,
            payload,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(self: AcceptedHandshakeSession) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return self.h3.maxConnectDatagramPayloadSize(self.session_id.value);
    }

    /// WebTransport API spelling for the maximum application payload accepted
    /// by `sendDatagram`, after QUIC DATAGRAM and Session ID overhead.
    pub fn maxDatagramSize(self: AcceptedHandshakeSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: AcceptedHandshakeSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return self.h3.connectDatagramsNegotiated();
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

    /// Return authenticated peer CONNECTION_CLOSE metadata already observed
    /// by this session or by its endpoint dispatcher, without reading UDP.
    pub fn pollPeerConnectionClose(
        self: *const AcceptedHandshakeSession,
    ) ?quic.one_rtt.PeerCloseInfo {
        return self.h3.established.connection.peerCloseInfo();
    }

    pub fn receivePeerConnectionCloseWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        return receiveHandshakePeerConnectionCloseUntil(
            &self.h3.established.connection,
            deadline,
        );
    }

    pub fn receivePeerConnectionCloseWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerConnectionCloseWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        return self.openLocalStream(.bidirectional, null);
    }

    pub fn openBidirectionalStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openBidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.openLocalStream(.bidirectional, deadline);
    }

    pub fn openUnidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        return self.openLocalStream(.unidirectional, null);
    }

    pub fn openUnidirectionalStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openUnidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openUnidirectionalStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.openLocalStream(.unidirectional, deadline);
    }

    fn openLocalStream(
        self: *AcceptedHandshakeSession,
        direction: webtransport.StreamDirection,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const stream_id = try self.streams.prepareLocal(direction);
        const transport_id: u64 = switch (direction) {
            .bidirectional => if (deadline) |absolute|
                try self.h3.established.connection
                    .openStreamWithDeadline(absolute)
            else
                try self.h3.established.connection.openStream(),
            // Server push and WebTransport uni streams share this ID space,
            // so H3 and QUIC must advance as one indivisible reservation.
            .unidirectional => if (deadline) |absolute|
                try self.h3.openServerUnidirectionalStreamWithDeadline(absolute)
            else
                try self.h3.openServerUnidirectionalStream(),
        };
        std.debug.assert(transport_id == stream_id);
        return (try self.streams.commitPreparedLocal(
            stream_id,
            direction,
        )).stream_id;
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

    /// Return cumulative QUIC stream-count credit after a peer-initiated
    /// associated stream has reached a terminal state. Registry accounting is
    /// intentionally retained, so this never replenishes the WT session cap.
    pub fn releaseCompletedPeerStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!bool {
        const stream = self.streams.get(stream_id) orelse
            return error.UnknownStream;
        if (stream.locally_initiated) return error.InvalidStreamState;
        return self.h3.established.connection.releaseCompletedPeerStream(
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

    pub fn receiveStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        return receiveHandshakeSessionStreamWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
            deadline,
        );
    }

    /// Poll a FIN-complete associated stream without reading UDP.
    pub fn pollCompleteStream(
        self: *AcceptedHandshakeSession,
    ) Error!?OwnedHandshakeStream {
        return handshake_stream.poll(
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

    pub fn readStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return incremental_stream.readWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn readStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        return incremental_stream.readWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
            deadline,
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
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
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
        const datagram = try self.h3.pollConnectDatagram(
            self.session_id.value,
        );
        return if (datagram) |owned|
            ownedHandshakeDatagram(owned, self.session_id)
        else
            null;
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
        // Preserve receive-side routing after the local half-close. The
        // terminal event handler retires the association once peer FIN/reset
        // has been consumed.
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

    pub fn receiveSessionEventWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const event = while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgressWithDeadline(deadline);
        };
        return event;
    }

    pub fn receiveSessionEventWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        return while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgressWithDeadline(deadline);
        };
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
            // Retain the terminal association until session teardown so late
            // datagrams are discarded by terminal state instead of becoming
            // unknown-association traffic.
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
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
        );
    }

    fn receiveControlProgressWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.receiveDetachedRequestProgressWithDeadline(
            self.session_id.value,
            deadline,
        );
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
        );
    }
};

pub const ClientSession = struct {
    h3: http3.runtime.Client,
    session_id: webtransport.SessionId,
    /// Owns the final CONNECT response head, including custom admission
    /// headers. The body remains attached to the same stream for long-lived
    /// WebTransport control capsules after the 2xx head has been consumed.
    response: http3.DecodedResponseHead,
    streams: webtransport.StreamRegistry,
    control: protected_control.Reader,

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

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ClientSession {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
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
        return connectDevelopmentAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            null,
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectDevelopmentAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
    }

    fn connectDevelopmentAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ConnectAttempt {
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareRequest(
            allocator,
            options.origin,
            options.headers,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        var h3_client = try http3.runtime.Client.connect(allocator, io, local_address, server, options.limits.http3);
        errdefer h3_client.deinit();
        const session_stream_id = try h3_client.startRequest(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = prepared_headers.fields,
        }, null);
        errdefer h3_client.cancelRequest(
            session_stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ) catch {};
        var response = if (deadline) |absolute|
            try receiveDevelopmentConnectAttemptResponseBefore(
                &h3_client,
                session_stream_id,
                options.limits.max_rejection_body_bytes,
                absolute,
            )
        else
            try receiveDevelopmentConnectAttemptResponse(
                &h3_client,
                session_stream_id,
                options.limits.max_rejection_body_bytes,
            );
        errdefer response.deinit(allocator);
        return .{
            .h3 = h3_client,
            .session_id = .init(session_stream_id),
            .response = response.head,
            .response_body = response.body,
            .response_trailers = response.trailers,
            .stream_complete = response.stream_complete,
            .max_session_streams = options.limits.max_session_streams,
        };
    }

    pub fn deinit(self: *ClientSession) void {
        // Accepted development clients own their H3 transport, but notifying
        // the shared server also lets it retire the CONNECT immediately rather
        // than retaining a dead peer until endpoint shutdown.
        self.h3.cancelRequest(
            self.session_id.value,
            webtransport.ApplicationErrorCode.session_gone,
        ) catch {};
        // This session owns the complete cleartext H3 client, unlike the
        // server's peer-shared runtime. Clear even unclassified partial
        // prefixes before releasing the transport.
        self.h3.clearDevelopmentStreams();
        self.response.deinit(self.h3.quic_client.endpoint.allocator);
        self.streams.deinit();
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
        return findHeader(self.response.headers, name);
    }

    /// The request-stream identifier used as the WebTransport Session ID.
    pub fn sessionId(self: ClientSession) webtransport.SessionId {
        return self.session_id;
    }

    pub fn openBidirectionalStream(self: *ClientSession) Error!u62 {
        return self.openLocalStream(.bidirectional);
    }

    pub fn openUnidirectionalStream(self: *ClientSession) Error!u62 {
        return self.openLocalStream(.unidirectional);
    }

    fn openLocalStream(
        self: *ClientSession,
        direction: webtransport.StreamDirection,
    ) Error!u62 {
        try self.control.control.ensureOpen();
        try development_stream.preflightLocal(
            &self.streams,
            .client,
            direction,
        );
        const opened = try self.h3.reserveDevelopmentStream(
            self.session_id.value,
            developmentDirection(direction),
        );
        return (try self.streams.registerLocal(opened, direction)).stream_id;
    }

    pub fn sendStream(
        self: *ClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            var send_attempted = false;
            self.h3.sendDevelopmentStreamParts(
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
        try self.h3.sendDevelopmentStream(
            self.session_id.value,
            stream_id,
            payload,
            fin,
        );
        try self.streams.recordSent(stream_id, payload.len, fin);
    }

    pub fn receiveStream(self: *ClientSession) Error!OwnedDevelopmentStream {
        const match = development_stream.match(
            &self.streams,
            self.session_id,
            .client,
        );
        const raw = try self.h3.receiveDevelopmentStream(match);
        return development_stream.take(&self.streams, raw);
    }

    pub fn receiveStreamWithTimeout(
        self: *ClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedDevelopmentStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveStreamWithDeadline(
        self: *ClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDevelopmentStream {
        const match = development_stream.match(
            &self.streams,
            self.session_id,
            .client,
        );
        const raw = try self.h3.receiveDevelopmentStreamWithDeadline(
            match,
            deadline,
        );
        return development_stream.take(&self.streams, raw);
    }

    pub fn sendDatagram(self: *ClientSession, payload: []const u8) Error!void {
        try self.control.control.ensureOpen();
        try sendDatagramFromEndpoint(&self.h3.quic_client.endpoint, self.h3.quic_client.peer, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *ClientSession) Error!OwnedDatagram {
        var datagram = try self.h3.receiveDatagram();
        errdefer datagram.deinit(self.h3.quic_client.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn receiveDatagramWithTimeout(
        self: *ClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        var datagram = try self.h3.receiveDatagramWithTimeout(timeout);
        errdefer datagram.deinit(self.h3.quic_client.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn receiveDatagramWithDeadline(
        self: *ClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDatagram {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        var datagram = try self.h3.receiveDatagramWithDeadline(deadline);
        errdefer datagram.deinit(self.h3.quic_client.endpoint.allocator);
        const wt = try parseDatagramFromOwnedQuicDatagram(datagram);
        return .{ .quic_datagram = datagram, .datagram = wt };
    }

    pub fn sendSessionData(
        self: *ClientSession,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.control.ensureOpen();
        try self.h3.sendRequestBody(self.session_id.value, data, fin);
    }

    pub fn receiveSessionData(
        self: *ClientSession,
        out: []u8,
    ) Error!SessionDataRead {
        return self.receiveSessionDataInternal(out, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveSessionDataWithTimeout(
        self: *ClientSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionDataRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionDataInternal(
            out,
            .fromNow(
                self.h3.quic_client.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionDataWithDeadline(
        self: *ClientSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionDataRead {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveSessionDataInternal(out, deadline);
    }

    fn receiveSessionDataInternal(
        self: *ClientSession,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionDataRead {
        while (true) {
            var event = (if (deadline) |absolute|
                try self.h3.receiveResponseEventWithDeadline(
                    self.session_id.value,
                    absolute,
                )
            else
                try self.h3.receiveResponseEvent(self.session_id.value)) orelse
                continue;
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

    pub fn drain(self: *ClientSession) Error!void {
        if (self.control.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        try self.sendSessionData(capsule, false);
        try self.control.control.recordLocalDrain();
    }

    pub fn close(
        self: *ClientSession,
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

    pub fn receiveSessionEvent(self: *ClientSession) Error!SessionEvent {
        return receiveDevelopmentClientEvent(self, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
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

    pub fn receiveSessionEventWithTimeout(
        self: *ClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionEventWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveSessionEventWithDeadline(
        self: *ClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        return receiveDevelopmentClientEvent(self, deadline) catch |err|
            switch (err) {
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

pub const ConnectAttempt = struct {
    h3: ?http3.runtime.Client,
    session_id: webtransport.SessionId,
    response: http3.DecodedResponseHead,
    response_body: []u8 = &.{},
    response_trailers: []http3.Qpack.HeaderField = &.{},
    stream_complete: bool = false,
    max_session_streams: usize,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.response.status >= 200 and self.response.status < 300;
    }

    pub fn status(self: ConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn responseHeader(
        self: ConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn body(self: ConnectAttempt) []const u8 {
        return self.response_body;
    }

    pub fn trailers(self: ConnectAttempt) []const http3.Qpack.HeaderField {
        return self.response_trailers;
    }

    pub fn sessionId(self: ConnectAttempt) webtransport.SessionId {
        return self.session_id;
    }

    pub fn deinit(self: *ConnectAttempt) void {
        const allocator = self.h3.?.quic_client.endpoint.allocator;
        // A rejected streaming CONNECT has already received a complete final
        // response. Release its local state without sending a contradictory
        // reset after that response; accepted attempts transfer the live state
        // to ClientSession through requireAccepted().
        if (!self.accepted() and !self.stream_complete) {
            self.h3.?.finishRequest(self.session_id.value) catch {};
        }
        self.response.deinit(allocator);
        allocator.free(self.response_body);
        http3.Qpack.freeDecodedFields(allocator, self.response_trailers);
        if (self.h3) |*h3| h3.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!ClientSession {
        if (!self.accepted()) return error.SessionRejected;
        std.debug.assert(self.response_body.len == 0);
        std.debug.assert(self.response_trailers.len == 0);
        std.debug.assert(!self.stream_complete);
        var streams = try initDevelopmentStreamRegistry(
            self.h3.?.quic_client.endpoint.allocator,
            self.session_id,
            .client,
            self.max_session_streams,
        );
        errdefer streams.deinit();
        const session = ClientSession{
            .h3 = self.h3.?,
            .session_id = self.session_id,
            .response = self.response,
            .streams = streams,
            .control = protected_control.Reader.init(
                try session_control.Control.init(self.session_id),
            ),
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
    dispatcher: ?*quic.endpoint_dispatcher.Dispatcher = null,
    dispatcher_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null,
    close_response_pending: bool = false,

    /// Open WebTransport on an existing authenticated HTTP/3 connection. The
    /// caller retains `h3` on failure and transfers it on success.
    pub fn connectSession(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
    ) Error!HandshakeClientSession {
        var attempt = try connectSessionAttempt(h3, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectSessionAttempt(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
    ) Error!HandshakeConnectAttempt {
        return connectStatefulAttempt(
            h3,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            null,
            h3,
        );
    }

    pub fn connectSessionWithDeadline(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClientSession {
        var attempt = try connectSessionAttemptWithDeadline(
            h3,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectSessionAttemptWithDeadline(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeConnectAttempt {
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        return connectStatefulAttempt(
            h3,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            absolute,
            h3,
        );
    }

    pub fn connectSessionWithTimeout(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectSessionWithDeadline(
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn connectSessionAttemptWithTimeout(
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectSessionAttemptWithDeadline(
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

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

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClientSession {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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
            null,
            null,
        );
    }

    /// Complete QUIC/TLS and the WebTransport Extended CONNECT under one
    /// caller-owned deadline. HTTP/3's configured connect timeout may shorten
    /// the outer budget but never resets it between these phases.
    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeConnectAttempt {
        try validateAdditionalConnectHeaders(options.headers, .request);
        var h3_client = try http3.runtime.HandshakeClient.connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options.limits.http3,
            webTransportHandshakeClientOptions(options.h3),
            deadline,
        );
        errdefer h3_client.deinit();
        return connectStatefulAttempt(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            deadline,
            null,
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Complete QUIC/TLS through a caller-supplied datagram source, then send
    /// the Extended CONNECT without ever taking ownership of the endpoint.
    /// The returned pending object is intended to be registered with the same
    /// endpoint dispatcher before CONNECT response packets are processed.
    pub fn beginConnectFrom(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
    ) Error!PendingHandshakeConnect {
        try validateAdditionalConnectHeaders(options.headers, .request);
        var h3_client = try http3.runtime.HandshakeClient.connectFrom(
            endpoint,
            source,
            server,
            webTransportHandshakeClientOptions(options.h3),
        );
        errdefer h3_client.deinit();
        const session_id = try startStatefulConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
        );
        return .{
            .h3 = h3_client,
            .session_id = session_id,
            .limits = options.limits,
        };
    }

    /// Bounded form of `beginConnectFrom` for shared-endpoint clients. The
    /// endpoint owner may stop routing or close the handshake inbox when this
    /// returns, so the same absolute deadline must cover both QUIC/TLS and the
    /// initial Extended CONNECT write.
    pub fn beginConnectFromWithDeadline(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingHandshakeConnect {
        try validateAdditionalConnectHeaders(options.headers, .request);
        const absolute = try deadline_policy.capTimeout(
            endpoint.io,
            deadline,
            options.h3.connect_timeout,
        );
        var h3_client = try http3.runtime.HandshakeClient
            .connectFromWithDeadline(
            endpoint,
            source,
            server,
            webTransportHandshakeClientOptions(options.h3),
            absolute,
        );
        errdefer h3_client.deinit();
        _ = try deadline_policy.usableAwake(endpoint.io, absolute);
        const session_id = try startStatefulConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
        );
        return .{
            .h3 = h3_client,
            .session_id = session_id,
            .limits = options.limits,
        };
    }

    pub fn beginConnectFromWithTimeout(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
        timeout: std.Io.Duration,
    ) Error!PendingHandshakeConnect {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return beginConnectFromWithDeadline(
            endpoint,
            source,
            server,
            options,
            .fromNow(
                endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
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

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClientSession {
        var attempt = try connectUriAttemptWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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
            null,
            null,
        );
    }

    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
        deadline: std.Io.Clock.Timestamp,
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
        var h3_client = try http3.runtime.HandshakeClient.connectUriWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            options.limits.http3,
            webTransportHandshakeClientOptions(h3_options),
            deadline,
        );
        errdefer h3_client.deinit();
        return connectStatefulAttempt(
            &h3_client,
            endpoint.authority,
            path,
            options.origin,
            options.headers,
            options.limits,
            deadline,
            null,
        );
    }

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri_text: []const u8,
        options: HandshakeUriConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
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

    pub fn connectPreconfiguredWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClientSession {
        var attempt = try connectPreconfiguredAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectPreconfiguredWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectPreconfiguredWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectPreconfiguredAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!HandshakeConnectAttempt {
        return connectPreconfiguredAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            null,
        );
    }

    pub fn connectPreconfiguredAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectPreconfiguredAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
    }

    pub fn connectPreconfiguredAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectPreconfiguredAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectPreconfiguredAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
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
            deadline,
            null,
        );
    }

    /// Begin WebTransport CONNECT on an authenticated QUIC connection whose
    /// endpoint remains caller-owned. The caller's dispatcher routes packets
    /// to the returned pending object, then calls `pollConnect` until the final
    /// response is available.
    pub fn beginEstablishedConnect(
        endpoint: *quic.runtime.Endpoint,
        server: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: EstablishedConnectOptions,
    ) Error!PendingHandshakeConnect {
        try validateAdditionalConnectHeaders(options.headers, .request);
        var h3_client = try http3.runtime.HandshakeClient.initEstablished(
            endpoint,
            server,
            established,
            webTransportHandshakeSessionOptions(options.h3),
        );
        errdefer h3_client.deinit();
        const session_id = try startStatefulConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
        );
        return .{
            .h3 = h3_client,
            .session_id = session_id,
            .limits = options.limits,
        };
    }

    pub fn deinit(self: *HandshakeClientSession) void {
        if (self.dispatcher) |dispatcher| {
            _ = dispatcher.unregisterConnection(
                self.dispatcher_handle.?,
            ) catch false;
        }
        self.h3.closeConnectDatagramAssociation(
            self.session_id.value,
        ) catch {};
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
        const result = self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
        try self.refreshDispatcherTimer();
        try result;
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
        const result = self.h3.initiateKeyUpdate();
        try self.refreshDispatcherTimer();
        try result;
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
        const result = if (self.dispatcher != null)
            self.h3.trySendConnectDatagram(self.session_id.value, payload)
        else
            self.h3.sendConnectDatagram(self.session_id.value, payload);
        try self.refreshDispatcherTimer();
        try result;
    }

    /// Wait for QUIC congestion and pacing capacity while preserving HTTP/3
    /// control and detached CONNECT routing under one total timeout.
    pub fn sendDatagramWithTimeout(
        self: *HandshakeClientSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(payload, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramWithDeadline(
        self: *HandshakeClientSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const result = if (self.dispatcher != null)
            self.h3.trySendConnectDatagramWithDeadline(
                self.session_id.value,
                payload,
                deadline,
            )
        else
            self.h3.sendConnectDatagramWithDeadline(
                self.session_id.value,
                payload,
                deadline,
            );
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn receiveDatagram(self: *HandshakeClientSession) Error!OwnedHandshakeDatagram {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagram(self.session_id.value),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagramWithTimeout(
                self.session_id.value,
                timeout,
            ),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return ownedHandshakeDatagram(
            try self.h3.receiveConnectDatagramWithDeadline(
                self.session_id.value,
                deadline,
            ),
            self.session_id,
        );
    }

    /// Poll a queued DATAGRAM for this session without reading UDP.
    pub fn pollDatagram(
        self: *HandshakeClientSession,
    ) Error!?OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        if (!try self.prepareDispatcherPoll()) return null;
        const result = self.h3.pollConnectDatagram(
            self.session_id.value,
        );
        try self.refreshDispatcherTimer();
        const datagram = try result;
        return if (datagram) |owned|
            ownedHandshakeDatagram(owned, self.session_id)
        else
            null;
    }

    pub fn receiveManyDatagrams(self: *HandshakeClientSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(
            &self.h3,
            self.session_id,
            count,
        );
    }

    /// Receive up to `count` DATAGRAMs within one shared timeout budget. If
    /// the deadline expires after partial progress, the returned batch retains
    /// those DATAGRAMs and records `error.Timeout` in the next error slot.
    pub fn receiveManyDatagramsWithTimeout(
        self: *HandshakeClientSession,
        count: usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return self.receiveManyDatagramsWithDeadline(
            count,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveManyDatagramsWithDeadline(
        self: *HandshakeClientSession,
        count: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return receiveManyHandshakeDatagramsUntil(
            &self.h3,
            self.session_id,
            count,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(self: HandshakeClientSession) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return self.h3.maxConnectDatagramPayloadSize(self.session_id.value);
    }

    /// WebTransport API spelling for the negotiated send-payload limit. Zero
    /// means HTTP Datagrams were not negotiated.
    pub fn maxDatagramSize(self: HandshakeClientSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: HandshakeClientSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return self.h3.connectDatagramsNegotiated();
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
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return receiveHandshakePeerConnectionClose(
            &self.h3.established.connection,
        );
    }

    pub fn pollPeerConnectionClose(
        self: *const HandshakeClientSession,
    ) ?quic.one_rtt.PeerCloseInfo {
        return self.h3.established.connection.peerCloseInfo();
    }

    pub fn receivePeerConnectionCloseWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return receiveHandshakePeerConnectionCloseUntil(
            &self.h3.established.connection,
            deadline,
        );
    }

    pub fn receivePeerConnectionCloseWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerConnectionCloseWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        if (self.dispatcher != null) {
            return self.openLocalStreamOnce(.bidirectional);
        }
        return self.openLocalStream(.bidirectional, null);
    }

    pub fn openBidirectionalStreamWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openBidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStreamWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher != null) {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                deadline,
            );
            return self.openLocalStreamOnce(.bidirectional);
        }
        return self.openLocalStream(.bidirectional, deadline);
    }

    pub fn openUnidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        if (self.dispatcher != null) {
            return self.openLocalStreamOnce(.unidirectional);
        }
        return self.openLocalStream(.unidirectional, null);
    }

    pub fn openUnidirectionalStreamWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openUnidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openUnidirectionalStreamWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher != null) {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                deadline,
            );
            return self.openLocalStreamOnce(.unidirectional);
        }
        return self.openLocalStream(.unidirectional, deadline);
    }

    fn openLocalStream(
        self: *HandshakeClientSession,
        direction: webtransport.StreamDirection,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        // Registry capacity and the cumulative WT cap are fallible, so reserve
        // them before consuming either the H3 or transport stream-ID cursor.
        const stream_id = try self.streams.prepareLocal(direction);
        const transport_id: u64 = switch (direction) {
            .bidirectional => if (deadline) |absolute|
                try self.h3.openClientBidirectionalStreamWithDeadline(absolute)
            else
                try self.h3.openClientBidirectionalStream(),
            .unidirectional => if (deadline) |absolute|
                try self.h3.established.connection
                    .openUnidirectionalStreamWithDeadline(absolute)
            else
                try self.h3.established.connection
                    .openUnidirectionalStream(),
        };
        std.debug.assert(transport_id == stream_id);
        return (try self.streams.commitPreparedLocal(
            stream_id,
            direction,
        )).stream_id;
    }

    fn openLocalStreamOnce(
        self: *HandshakeClientSession,
        direction: webtransport.StreamDirection,
    ) Error!u62 {
        try self.control.ensureOpen();
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        const stream_id = try self.streams.prepareLocal(direction);
        const transport_id: u64 = switch (direction) {
            .bidirectional => self.h3.established.connection
                .tryOpenStream() catch |err| {
                try self.refreshDispatcherTimer();
                return err;
            },
            .unidirectional => self.h3.established.connection
                .tryOpenUnidirectionalStream() catch |err| {
                try self.refreshDispatcherTimer();
                return err;
            },
        };
        try self.refreshDispatcherTimer();
        std.debug.assert(transport_id == stream_id);
        return (try self.streams.commitPreparedLocal(
            stream_id,
            direction,
        )).stream_id;
    }

    pub fn sendStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.control.ensureOpen();
        if (self.dispatcher != null) {
            const result = handshake_stream.sendOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
                payload,
                fin,
            );
            try self.refreshDispatcherTimer();
            try result;
        } else {
            try sendHandshakeSessionStream(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
                payload,
                fin,
            );
        }
    }

    pub fn writeStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        try self.control.ensureOpen();
        if (self.dispatcher != null) {
            const result = handshake_stream.writeOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
                payload,
            );
            try self.refreshDispatcherTimer();
            return try result;
        }
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
        if (self.dispatcher != null) {
            const result = stream_batch.writeOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                writes,
                counts,
            );
            try self.refreshDispatcherTimer();
            return try result;
        }
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
        if (self.dispatcher != null) {
            const result = handshake_stream.finishOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
            );
            try self.refreshDispatcherTimer();
            try result;
            return;
        }
        return handshake_stream.finish(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
        );
    }

    /// Return cumulative QUIC MAX_STREAMS credit for one terminal peer
    /// associated stream without removing its lifetime registry entry.
    pub fn releaseCompletedPeerStream(
        self: *HandshakeClientSession,
        stream_id: u62,
    ) Error!bool {
        const stream = self.streams.get(stream_id) orelse
            return error.UnknownStream;
        if (stream.locally_initiated) return error.InvalidStreamState;
        const result = if (self.dispatcher != null)
            self.h3.established.connection.tryReleaseCompletedPeerStream(
                stream_id,
            )
        else
            self.h3.established.connection.releaseCompletedPeerStream(
                stream_id,
            );
        try self.refreshDispatcherTimer();
        return try result;
    }

    pub fn receiveStream(
        self: *HandshakeClientSession,
    ) Error!OwnedHandshakeStream {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return receiveHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
    }

    pub fn receiveStreamWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return self.receiveStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveStreamWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return receiveHandshakeSessionStreamWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
            deadline,
        );
    }

    pub fn pollCompleteStream(
        self: *HandshakeClientSession,
    ) Error!?OwnedHandshakeStream {
        if (!try self.prepareDispatcherPoll()) return null;
        const result = if (self.dispatcher != null)
            handshake_stream.pollOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                self.h3.options.max_stream_buffer,
            )
        else
            handshake_stream.poll(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                self.h3.options.max_stream_buffer,
            );
        try self.refreshDispatcherTimer();
        return try result;
    }

    /// Apply one packet selected by the endpoint-wide QUIC dispatcher. HTTP/3
    /// control/QPACK and unrelated responses progress while the detached
    /// WebTransport CONNECT stream and associated streams remain available to
    /// the session-specific pollers below.
    pub fn processPacket(
        self: *HandshakeClientSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        const result = self.h3.processDetachedResponsePacket(
            self.session_id.value,
            packet,
        );
        try self.refreshDispatcherTimer();
        try result;
        if (self.dispatcher != null and
            (self.control.local_close_sent or self.control.terminal_reported))
        {
            const cleanup = self.advanceTerminalCleanupOnce();
            try self.refreshDispatcherTimer();
            _ = cleanup catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return,
                else => return err,
            };
        }
    }

    /// Poll already-buffered associated stream state without reading UDP.
    pub fn pollStream(
        self: *HandshakeClientSession,
        out: []u8,
    ) Error!?StreamRead {
        if (out.len == 0) return error.BufferTooShort;
        if (!try self.prepareDispatcherPoll()) return null;
        const result = if (self.dispatcher != null)
            incremental_stream.pollOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                out,
            )
        else
            incremental_stream.poll(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                out,
            );
        try self.refreshDispatcherTimer();
        return try result;
    }

    /// Read the next stream data/control event without waiting for FIN.
    pub fn readStream(
        self: *HandshakeClientSession,
        out: []u8,
    ) Error!StreamRead {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return readHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
        );
    }

    pub fn readStreamWithTimeout(
        self: *HandshakeClientSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return incremental_stream.readWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn readStreamWithDeadline(
        self: *HandshakeClientSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return incremental_stream.readWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
            deadline,
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
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.h3.established.connection.servicePacketServicingTimers();
    }

    pub fn resetStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        const result = if (self.dispatcher != null)
            incremental_stream.resetOnce(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            )
        else
            resetHandshakeSessionStream(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            );
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn stopStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        const result = if (self.dispatcher != null)
            incremental_stream.stopOnce(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            )
        else
            stopHandshakeSessionStream(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            );
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn drain(self: *HandshakeClientSession) Error!void {
        if (self.control.local_drain_sent) return;
        var encoded: [16]u8 = undefined;
        const capsule = try session_control.writeDrainInto(&encoded);
        const result = if (self.dispatcher != null)
            self.h3.trySendRequestBody(
                self.session_id.value,
                capsule,
                false,
            )
        else
            self.h3.sendRequestBodyPaced(
                self.session_id.value,
                capsule,
                false,
            );
        try self.refreshDispatcherTimer();
        try result;
        try self.control.recordLocalDrain();
    }

    pub fn close(
        self: *HandshakeClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.local_close_sent) {
            if (self.dispatcher != null) {
                const cleanup = self.advanceTerminalCleanupOnce();
                try self.refreshDispatcherTimer();
                _ = cleanup catch |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => return,
                    else => return err,
                };
            }
            return;
        }
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        const result = if (self.dispatcher != null)
            self.h3.trySendRequestBody(
                self.session_id.value,
                capsule,
                true,
            )
        else
            self.h3.sendRequestBodyPaced(
                self.session_id.value,
                capsule,
                true,
            );
        try self.refreshDispatcherTimer();
        try result;
        // A local FIN does not close the peer-to-client direction. Retain the
        // association so receiveSessionEvent can process the peer's terminal
        // capsule/FIN; finishPolledSessionEvent performs final retirement.
        try self.control.recordLocalClose(code);
        if (self.dispatcher == null) {
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        } else {
            const cleanup = self.advanceTerminalCleanupOnce();
            try self.refreshDispatcherTimer();
            _ = cleanup catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return,
                else => return err,
            };
        }
    }

    pub fn receiveSessionEvent(
        self: *HandshakeClientSession,
    ) Error!SessionEvent {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgress();
        };
    }

    /// Poll the detached CONNECT stream for DRAIN/CLOSE/reset state without
    /// reading UDP. Terminal events perform the same FIN and associated-stream
    /// cleanup as the blocking receive helpers.
    pub fn pollSessionEvent(
        self: *HandshakeClientSession,
    ) Error!?SessionEvent {
        if (self.dispatcher == null) {
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

        if (!try self.prepareDispatcherPoll()) return null;
        const result = self.pollSessionEventOnce();
        try self.refreshDispatcherTimer();
        return try result;
    }

    pub fn receiveSessionEventWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgressWithDeadline(deadline);
        };
    }

    pub fn receiveSessionEventWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgressWithDeadline(deadline);
        };
    }

    fn finishPolledSessionEvent(
        self: *HandshakeClientSession,
        event: SessionEvent,
    ) Error!void {
        if (event == .closed or event == .reset) {
            if (event == .closed and !self.control.local_close_sent) {
                try self.h3.sendRequestBodyPaced(
                    self.session_id.value,
                    &.{},
                    true,
                );
                self.control.local_close_sent = true;
            }
            // Keep the terminal association until deinit so late packets are
            // classified and dropped without reviving application state.
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        }
    }

    fn pollSessionEventOnce(
        self: *HandshakeClientSession,
    ) Error!?SessionEvent {
        if (!self.control.terminal_reported) {
            const event = self.control.pollOnce(
                &self.h3.established.connection,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                error.InvalidCapsule => {
                    self.h3.established.connection.tryResetStream(
                        self.session_id.value,
                        http3.ApplicationErrorCode.message_error,
                    ) catch |reset_err| switch (reset_err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        => return null,
                        else => return reset_err,
                    };
                    return err;
                },
                else => return err,
            };
            if (event) |value| {
                if (value == .closed and !self.control.local_close_sent) {
                    self.close_response_pending = true;
                }
                return value;
            }
        }

        _ = self.advanceTerminalCleanupOnce() catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => return null,
            else => return err,
        };
        return null;
    }

    fn advanceTerminalCleanupOnce(
        self: *HandshakeClientSession,
    ) Error!session_control.TerminateProgress {
        if (self.close_response_pending) {
            self.h3.trySendRequestBody(
                self.session_id.value,
                &.{},
                true,
            ) catch |err| switch (err) {
                error.RequestCancelled, error.RequestRejected => {},
                else => return err,
            };
            self.close_response_pending = false;
            self.control.local_close_sent = true;
            return .submitted;
        }
        if (!self.control.local_close_sent and
            !self.control.terminal_reported)
        {
            return .complete;
        }
        return session_control.terminateStreamsOnce(
            &self.h3.established.connection,
            &self.streams,
        );
    }

    fn refreshDispatcherTimer(self: *HandshakeClientSession) Error!void {
        const dispatcher = self.dispatcher orelse return;
        dispatcher.refreshConnectionTimer(
            self.dispatcher_handle orelse return error.InvalidDispatcherState,
        ) catch return error.InvalidDispatcherState;
    }

    fn prepareDispatcherPoll(self: *HandshakeClientSession) Error!bool {
        if (self.dispatcher == null) return true;
        self.h3.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {
                try self.refreshDispatcherTimer();
                return false;
            },
            else => {
                try self.refreshDispatcherTimer();
                return err;
            },
        };
        return true;
    }

    fn receiveControlProgress(
        self: *HandshakeClientSession,
    ) Error!void {
        try self.h3.receiveDetachedResponseProgress(
            self.session_id.value,
        );
    }

    fn receiveControlProgressWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.receiveDetachedResponseProgressWithDeadline(
            self.session_id.value,
            deadline,
        );
    }
};

/// A dispatcher-driven WebTransport CONNECT whose final response has not yet
/// arrived. Promotion APIs can update a dispatcher atomically so its route
/// never points at moved-from QUIC connection storage.
pub const PendingHandshakeConnect = struct {
    h3: ?http3.runtime.HandshakeClient,
    session_id: webtransport.SessionId,
    limits: Limits,
    pending_datagram_registered: bool = false,
    rejection: ?HandshakeConnectResponse = null,
    rejection_body: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *PendingHandshakeConnect) void {
        if (self.h3) |*h3| {
            if (self.rejection) |*rejection| {
                rejection.deinit(h3.allocator);
            }
            self.rejection_body.deinit(h3.allocator);
            if (self.pending_datagram_registered) {
                h3.cancelPendingConnectDatagramAssociation(
                    self.session_id.value,
                );
            }
            h3.deinit();
        }
        self.* = undefined;
    }

    pub fn connection(
        self: *PendingHandshakeConnect,
    ) *quic.one_rtt.Connection {
        return &self.h3.?.established.connection;
    }

    pub fn sessionId(self: PendingHandshakeConnect) webtransport.SessionId {
        return self.session_id;
    }

    pub fn processPacket(
        self: *PendingHandshakeConnect,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.rejection != null) {
            return self.h3.?.processResponsePacket(packet);
        }
        var registered_now = false;
        if (!self.pending_datagram_registered) {
            try self.h3.?.registerPendingConnectDatagramAssociation(
                self.session_id.value,
            );
            self.pending_datagram_registered = true;
            registered_now = true;
        }
        self.h3.?.processPendingExtendedConnectPacket(
            self.session_id.value,
            packet,
        ) catch |err| {
            if (registered_now) {
                self.h3.?.cancelPendingConnectDatagramAssociation(
                    self.session_id.value,
                );
                self.pending_datagram_registered = false;
            }
            return err;
        };
    }

    /// Poll the already-buffered CONNECT response without reading UDP.
    pub fn pollConnect(
        self: *PendingHandshakeConnect,
    ) Error!?HandshakeConnectAttempt {
        // The response stream can arrive before the peer control stream under
        // QUIC packet reordering. Do not consume it until SETTINGS is ready,
        // because `requireAccepted` must validate negotiated WebTransport and
        // DATAGRAM capabilities against that same connection state.
        var response = (try self.pollConnectResponse(false)) orelse return null;
        errdefer response.deinit(self.h3.?.allocator);
        const h3 = self.h3.?;
        self.h3 = null;
        // NRVO is not guaranteed for aggregate returns. Register the final
        // destination in `requireAcceptedForDispatcher`, after this by-value
        // attempt has reached caller storage.
        return .{
            .h3 = h3,
            .session_id = self.session_id,
            .response = response.head,
            .response_body = response.body,
            .response_trailers = response.trailers,
            .stream_complete = response.stream_complete,
            .limits = self.limits,
        };
    }

    /// Poll a dispatcher-driven CONNECT and unregister its current address
    /// before moving the connection into a by-value attempt. The caller must
    /// complete promotion with `requireAcceptedForDispatcher`, which publishes
    /// the exact caller-selected destination address.
    pub fn pollConnectForDispatcher(
        self: *PendingHandshakeConnect,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!?HandshakeConnectAttempt {
        if (!self.h3.?.dispatcherBound()) try self.h3.?.bindDispatcher();
        const maybe_response = self.pollConnectResponse(true) catch |err| {
            _ = dispatcher.unregisterConnection(handle) catch
                return error.InvalidDispatcherState;
            return err;
        };
        var ready_response = maybe_response orelse {
            // A once-only feedback or credit attempt may have armed pacing.
            // Publish that deadline before the shared endpoint waits again.
            dispatcher.refreshConnectionTimer(handle) catch
                return error.InvalidDispatcherState;
            return null;
        };
        errdefer ready_response.deinit(self.h3.?.allocator);
        // Moving a by-value attempt would briefly make the route point at a
        // return-value temporary. Unregister first; the accepted promotion
        // below registers the connection again at its final stable address.
        _ = dispatcher.unregisterConnection(handle) catch
            return error.InvalidDispatcherState;
        errdefer dispatcher.registerConnection(
            handle,
            self.connection(),
        ) catch {};
        const h3 = self.h3.?;
        self.h3 = null;
        return .{
            .h3 = h3,
            .session_id = self.session_id,
            .response = ready_response.head,
            .response_body = ready_response.body,
            .response_trailers = ready_response.trailers,
            .stream_complete = ready_response.stream_complete,
            .limits = self.limits,
        };
    }

    fn pollConnectResponse(
        self: *PendingHandshakeConnect,
        single_attempt: bool,
    ) Error!?HandshakeConnectResponse {
        const h3 = &self.h3.?;
        if (self.rejection == null) {
            if (!h3.control.settings.received) return null;
            var head = (if (single_attempt)
                try pollHandshakeConnectAttemptResponseOnce(
                    h3,
                    self.session_id.value,
                )
            else
                try pollHandshakeConnectAttemptResponse(
                    h3,
                    self.session_id.value,
                )) orelse return null;
            if (head.status >= 200 and head.status < 300) {
                return .{ .head = head };
            }
            if ((head.content_length orelse 0) >
                self.limits.max_rejection_body_bytes)
            {
                head.deinit(h3.allocator);
                return error.MessageTooLarge;
            }
            self.rejection = .{ .head = head };
            if (head.content_length) |expected| {
                try self.rejection_body.ensureTotalCapacityPrecise(
                    h3.allocator,
                    expected,
                );
            }
            h3.cancelPendingConnectDatagramAssociation(
                self.session_id.value,
            );
            self.pending_datagram_registered = false;
        }

        while (if (single_attempt)
            try h3.pollResponseEventOnce(self.session_id.value)
        else
            try h3.pollResponseEvent(self.session_id.value)) |event_value|
        {
            var event = event_value;
            defer event.deinit(h3.allocator);
            switch (event) {
                .data_available => {
                    const remaining = self.limits.max_rejection_body_bytes -|
                        self.rejection_body.items.len;
                    var scratch: [16 * 1024]u8 = undefined;
                    const read = if (single_attempt)
                        (try h3.readResponseDataOnce(
                            self.session_id.value,
                            scratch[0..@min(scratch.len, remaining +| 1)],
                        )) orelse return null
                    else
                        try h3.readResponseData(
                            self.session_id.value,
                            scratch[0..@min(scratch.len, remaining +| 1)],
                        );
                    if (read > remaining) return error.MessageTooLarge;
                    try self.rejection_body.appendSlice(
                        h3.allocator,
                        scratch[0..read],
                    );
                },
                .trailers => |value| {
                    if (self.rejection.?.trailers.len != 0) {
                        return error.InvalidConnect;
                    }
                    self.rejection.?.trailers = value.fields;
                    event = .finished;
                },
                .finished => {
                    const body = try finalizeRejectionBody(
                        &self.rejection_body,
                        h3.allocator,
                        self.rejection.?.head.content_length,
                    );
                    var completed = self.rejection.?;
                    self.rejection = null;
                    completed.body = body;
                    completed.stream_complete = true;
                    return completed;
                },
                .push_promise => continue,
                .head => return error.InvalidConnect,
            }
        }
        return null;
    }
};

pub const HandshakeConnectAttempt = struct {
    h3: ?http3.runtime.HandshakeClient,
    restore_to: ?*http3.runtime.HandshakeClient = null,
    session_id: webtransport.SessionId,
    response: http3.DecodedResponseHead,
    response_body: []u8 = &.{},
    response_trailers: []http3.Qpack.HeaderField = &.{},
    stream_complete: bool = false,
    limits: Limits,
    dispatcher_registered: bool = false,
    dispatcher: ?*quic.endpoint_dispatcher.Dispatcher = null,
    dispatcher_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null,

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

    pub fn body(self: HandshakeConnectAttempt) []const u8 {
        return self.response_body;
    }

    pub fn trailers(
        self: HandshakeConnectAttempt,
    ) []const http3.Qpack.HeaderField {
        return self.response_trailers;
    }

    pub fn deinit(self: *HandshakeConnectAttempt) void {
        const allocator = self.h3.?.allocator;
        self.response.deinit(allocator);
        allocator.free(self.response_body);
        http3.Qpack.freeDecodedFields(allocator, self.response_trailers);
        if (self.h3) |*h3| {
            if (self.dispatcher_registered) {
                _ = self.dispatcher.?.unregisterConnection(
                    self.dispatcher_handle.?,
                ) catch false;
            }
            if (self.restore_to) |destination| {
                if (!self.stream_complete) {
                    h3.abandonExtendedConnect(self.session_id.value);
                }
                destination.* = h3.*;
            } else {
                h3.deinit();
            }
        }
        self.* = undefined;
    }

    pub fn requireAccepted(
        self: *HandshakeConnectAttempt,
    ) Error!HandshakeClientSession {
        if (!self.accepted()) return error.SessionRejected;
        if (self.dispatcher_registered or self.h3.?.dispatcherBound()) {
            return error.InvalidDispatcherState;
        }
        return self.requireAcceptedInternal(false);
    }

    fn requireAcceptedInternal(
        self: *HandshakeConnectAttempt,
        single_attempt: bool,
    ) Error!HandshakeClientSession {
        if (!self.accepted()) return error.SessionRejected;
        std.debug.assert(self.response_body.len == 0);
        std.debug.assert(self.response_trailers.len == 0);
        std.debug.assert(!self.stream_complete);
        var h3 = &self.h3.?;
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
        if (single_attempt)
            try h3.detachResponseStreamOnce(self.session_id.value)
        else
            try h3.detachResponseStream(self.session_id.value);
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

    /// Complete promotion directly into caller-selected stable storage, then
    /// publish that exact connection address to the dispatcher.
    pub fn requireAcceptedForDispatcher(
        self: *HandshakeConnectAttempt,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        out: *HandshakeClientSession,
    ) Error!void {
        if (self.dispatcher_registered) {
            const removed = self.dispatcher.?.unregisterConnection(
                self.dispatcher_handle.?,
            ) catch
                return error.InvalidDispatcherState;
            if (!removed) return error.InvalidDispatcherState;
            self.dispatcher_registered = false;
            self.dispatcher = null;
            self.dispatcher_handle = null;
        }
        out.* = self.requireAcceptedInternal(true) catch |err| {
            if (self.h3) |*h3| {
                dispatcher.registerConnection(
                    handle,
                    &h3.established.connection,
                ) catch return error.InvalidDispatcherState;
                self.dispatcher_registered = true;
                self.dispatcher = dispatcher;
                self.dispatcher_handle = handle;
                dispatcher.refreshConnectionTimer(handle) catch
                    return error.InvalidDispatcherState;
            }
            return err;
        };
        var out_owned = true;
        errdefer if (out_owned) out.deinit();
        out.dispatcher = dispatcher;
        out.dispatcher_handle = handle;
        dispatcher.registerConnection(
            handle,
            &out.h3.established.connection,
        ) catch return error.InvalidDispatcherState;
        out_owned = false;
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

    /// Establish the complete preconfigured HTTP/3 Extended CONNECT within
    /// one caller-owned deadline, including peer SETTINGS and the response
    /// head needed to validate WebTransport capability negotiation.
    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ProtectedClientSession {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ProtectedClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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
        return connectProtectedAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            null,
        );
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ProtectedConnectAttempt {
        try validateAdditionalConnectHeaders(options.headers, .request);
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectProtectedAttemptBefore(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ProtectedConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectProtectedAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ProtectedConnectAttempt {
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareRequest(
            allocator,
            options.origin,
            options.headers,
            &header_stack,
        );
        defer prepared_headers.deinit(allocator);
        var h3_client = try http3.runtime.ProtectedClient.connect(allocator, io, local_address, server, options.limits.http3, webTransportProtectedConfig(options.config));
        errdefer h3_client.deinit();
        const session_stream_id = try h3_client.startRequest(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = prepared_headers.fields,
        }, null);
        errdefer h3_client.cancelRequest(
            session_stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ) catch {};
        // A response stream is allowed to race ahead of the server control
        // stream. The H3 client retains it while SETTINGS is awaited, and the
        // same absolute timestamp bounds both protocol phases.
        _ = if (deadline) |absolute|
            try h3_client.receivePeerSettingsWithDeadline(absolute)
        else
            try h3_client.receivePeerSettings();
        var response = if (deadline) |absolute|
            try receiveProtectedConnectAttemptResponseBefore(
                &h3_client,
                session_stream_id,
                options.limits.max_rejection_body_bytes,
                absolute,
            )
        else
            try receiveProtectedConnectAttemptResponse(
                &h3_client,
                session_stream_id,
                options.limits.max_rejection_body_bytes,
            );
        errdefer response.deinit(allocator);
        if (response.head.status >= 200 and response.head.status < 300) {
            try webtransport.ensureDatagramsNegotiated(h3_client.config.local_settings, h3_client.control.settings.peer);
        }
        return .{
            .h3 = h3_client,
            .session_id = .init(session_stream_id),
            .response = response.head,
            .response_body = response.body,
            .response_trailers = response.trailers,
            .stream_complete = response.stream_complete,
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

    pub fn receiveDatagramWithTimeout(
        self: *ProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramWithDeadline(
        self: *ProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedDatagram {
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return receiveProtectedDatagramFromEndpointWithDeadline(
            &self.h3.quic_client.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
            deadline,
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
        return self.receiveSessionDataInternal(out, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveSessionDataWithTimeout(
        self: *ProtectedClientSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionDataInternal(
            out,
            .fromNow(
                self.h3.quic_client.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionDataWithDeadline(
        self: *ProtectedClientSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveSessionDataInternal(out, deadline);
    }

    fn receiveSessionDataInternal(
        self: *ProtectedClientSession,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ProtectedSessionRead {
        while (true) {
            var event = (if (deadline) |absolute|
                try self.h3.receiveResponseEventWithDeadline(
                    self.session_id.value,
                    absolute,
                )
            else
                try self.h3.receiveResponseEvent(self.session_id.value)) orelse
                continue;
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
        return receiveProtectedClientEvent(self, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
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

    pub fn receiveSessionEventWithTimeout(
        self: *ProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveSessionEventWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveSessionEventWithDeadline(
        self: *ProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        return receiveProtectedClientEvent(self, deadline) catch |err|
            switch (err) {
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
    response_body: []u8 = &.{},
    response_trailers: []http3.Qpack.HeaderField = &.{},
    stream_complete: bool = false,

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

    pub fn body(self: ProtectedConnectAttempt) []const u8 {
        return self.response_body;
    }

    pub fn trailers(
        self: ProtectedConnectAttempt,
    ) []const http3.Qpack.HeaderField {
        return self.response_trailers;
    }

    pub fn deinit(self: *ProtectedConnectAttempt) void {
        const allocator = self.h3.?.quic_client.endpoint.allocator;
        self.response.deinit(allocator);
        allocator.free(self.response_body);
        http3.Qpack.freeDecodedFields(allocator, self.response_trailers);
        if (self.h3) |*h3| h3.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(
        self: *ProtectedConnectAttempt,
    ) Error!ProtectedClientSession {
        if (!self.accepted()) return error.SessionRejected;
        std.debug.assert(self.response_body.len == 0);
        std.debug.assert(self.response_trailers.len == 0);
        std.debug.assert(!self.stream_complete);
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

pub const SessionDataRead = struct {
    bytes: usize = 0,
    fin: bool = false,
};

pub const ProtectedSessionRead = SessionDataRead;

fn receiveDevelopmentServerEvent(
    session: *AcceptedSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeDevelopmentServerEvent(session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
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
            const event = (try session.control.finish()) orelse
                return error.InvalidSessionState;
            return completeDevelopmentServerEvent(session, event);
        }
        if (try session.control.consume(buffer[0..read.bytes])) |event| {
            return completeDevelopmentServerEvent(session, event);
        }
    }
}

fn completeDevelopmentServerEvent(
    session: *AcceptedSession,
    event: SessionEvent,
) Error!SessionEvent {
    if (event == .closed and !session.control.control.local_close_sent) {
        // A peer CLOSE capsule or a clean peer FIN only terminates its send
        // half of the CONNECT stream. WebTransport still requires one empty
        // FIN reply on our side so the HTTP/3 stream reaches a symmetric clean
        // close instead of lingering half-open forever.
        try session.server.sendSessionData(
            session.request.from,
            session.session_id,
            &.{},
            true,
        );
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
    return event;
}

fn receiveProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeProtectedServerEvent(server, session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
        const read = if (deadline) |absolute|
            try server.receiveSessionDataWithDeadline(
                session.session_id,
                &buffer,
                absolute,
            )
        else
            try server.receiveSessionData(session.session_id, &buffer);
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
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeProtectedClientEvent(session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
        const read = if (deadline) |absolute|
            try session.receiveSessionDataWithDeadline(&buffer, absolute)
        else
            try session.receiveSessionData(&buffer);
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

fn receiveDevelopmentClientEvent(
    session: *ClientSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (try session.control.pollPending()) |event| {
        return completeDevelopmentClientEvent(session, event);
    }
    var buffer: [protected_control.buffer_capacity]u8 = undefined;
    while (true) {
        const read = if (deadline) |absolute|
            try session.receiveSessionDataWithDeadline(&buffer, absolute)
        else
            try session.receiveSessionData(&buffer);
        if (read.fin) {
            const event = (try session.control.finish()) orelse
                return error.InvalidSessionState;
            return completeDevelopmentClientEvent(session, event);
        }
        if (try session.control.consume(buffer[0..read.bytes])) |event| {
            return completeDevelopmentClientEvent(session, event);
        }
    }
}

fn completeDevelopmentClientEvent(
    session: *ClientSession,
    event: SessionEvent,
) Error!SessionEvent {
    if (event == .closed and !session.control.control.local_close_sent) {
        // The control parser already transitioned the public session state to
        // closed. Send the mandatory empty FIN directly through HTTP/3 so the
        // reply does not trip the public open-state guard.
        try session.h3.sendRequestBody(session.session_id.value, &.{}, true);
        session.control.control.local_close_sent = true;
    }
    if (event == .closed or event == .reset) {
        session.h3.closeDevelopmentSession(development_stream.match(
            &session.streams,
            session.session_id,
            .client,
        ));
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

pub const EstablishedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeSessionOptions = .{},
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

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!StatefulProtectedClientSession {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!StatefulProtectedClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!StatefulProtectedConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        try validateAdditionalConnectHeaders(options.headers, .request);
        return .{ .attempt = try HandshakeClientSession
            .connectPreconfiguredAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        ) };
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!StatefulProtectedConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
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

    pub fn openBidirectionalStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        return self.session.openBidirectionalStreamWithTimeout(timeout);
    }

    pub fn openBidirectionalStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.session.openBidirectionalStreamWithDeadline(deadline);
    }

    pub fn openUnidirectionalStream(
        self: *StatefulProtectedClientSession,
    ) Error!u62 {
        return self.session.openUnidirectionalStream();
    }

    pub fn openUnidirectionalStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        return self.session.openUnidirectionalStreamWithTimeout(timeout);
    }

    pub fn openUnidirectionalStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.session.openUnidirectionalStreamWithDeadline(deadline);
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

    pub fn releaseCompletedPeerStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!bool {
        return self.session.releaseCompletedPeerStream(stream_id);
    }

    pub fn receiveStream(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeStream {
        return self.session.receiveStream();
    }

    pub fn receiveStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        return self.session.receiveStreamWithTimeout(timeout);
    }

    pub fn receiveStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        return self.session.receiveStreamWithDeadline(deadline);
    }

    pub fn pollCompleteStream(
        self: *StatefulProtectedClientSession,
    ) Error!?OwnedHandshakeStream {
        return self.session.pollCompleteStream();
    }

    pub fn processPacket(
        self: *StatefulProtectedClientSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        return self.session.processPacket(packet);
    }

    pub fn pollStream(
        self: *StatefulProtectedClientSession,
        out: []u8,
    ) Error!?StreamRead {
        return self.session.pollStream(out);
    }

    pub fn readStream(
        self: *StatefulProtectedClientSession,
        out: []u8,
    ) Error!StreamRead {
        return self.session.readStream(out);
    }

    pub fn readStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamWithTimeout(out, timeout);
    }

    pub fn readStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamWithDeadline(out, deadline);
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

    pub fn sendDatagramWithTimeout(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramWithTimeout(payload, timeout);
    }

    pub fn sendDatagramWithDeadline(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramWithDeadline(payload, deadline);
    }

    pub fn receiveDatagram(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeDatagram {
        return self.session.receiveDatagram();
    }

    pub fn receiveDatagramWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        return self.session.receiveDatagramWithTimeout(timeout);
    }

    pub fn receiveDatagramWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        return self.session.receiveDatagramWithDeadline(deadline);
    }

    pub fn pollDatagram(
        self: *StatefulProtectedClientSession,
    ) Error!?OwnedHandshakeDatagram {
        return self.session.pollDatagram();
    }

    pub fn receiveManyDatagrams(
        self: *StatefulProtectedClientSession,
        count: usize,
    ) Error!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagrams(count);
    }

    pub fn receiveManyDatagramsWithTimeout(
        self: *StatefulProtectedClientSession,
        count: usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagramsWithTimeout(count, timeout);
    }

    pub fn receiveManyDatagramsWithDeadline(
        self: *StatefulProtectedClientSession,
        count: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagramsWithDeadline(count, deadline);
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

    pub fn pollSessionEvent(
        self: *StatefulProtectedClientSession,
    ) Error!?SessionEvent {
        return self.session.pollSessionEvent();
    }

    pub fn receiveSessionEventWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        return self.session.receiveSessionEventWithTimeout(timeout);
    }

    pub fn receiveSessionEventWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        return self.session.receiveSessionEventWithDeadline(deadline);
    }

    pub fn receivePeerConnectionClose(
        self: *StatefulProtectedClientSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionClose();
    }

    pub fn pollPeerConnectionClose(
        self: *const StatefulProtectedClientSession,
    ) ?quic.one_rtt.PeerCloseInfo {
        return self.session.pollPeerConnectionClose();
    }

    pub fn receivePeerConnectionCloseWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionCloseWithDeadline(deadline);
    }

    pub fn receivePeerConnectionCloseWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionCloseWithTimeout(timeout);
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

    pub fn body(self: StatefulProtectedConnectAttempt) []const u8 {
        return self.attempt.body();
    }

    pub fn trailers(
        self: StatefulProtectedConnectAttempt,
    ) []const http3.Qpack.HeaderField {
        return self.attempt.trailers();
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
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeClient,
) Error!HandshakeConnectAttempt {
    const session_id = try startStatefulConnect(
        h3_client,
        authority,
        path,
        origin,
        additional_headers,
    );
    errdefer if (restore_to != null) {
        h3_client.abandonExtendedConnect(session_id.value);
    };
    // A response stream can race ahead of the server control stream. Retain
    // it in HTTP/3 state while completing SETTINGS, instead of exposing a
    // successful CONNECT that cannot yet be validated as WebTransport.
    _ = if (deadline) |absolute|
        try h3_client.receivePeerSettingsWithDeadline(absolute)
    else
        try h3_client.receivePeerSettings();
    const allocator = h3_client.allocator;
    var response = if (deadline) |absolute|
        try receiveHandshakeConnectAttemptResponseBefore(
            h3_client,
            session_id.value,
            limits.max_rejection_body_bytes,
            absolute,
        )
    else
        try receiveHandshakeConnectAttemptResponse(
            h3_client,
            session_id.value,
            limits.max_rejection_body_bytes,
        );
    errdefer response.deinit(allocator);
    const owned_h3 = h3_client.*;
    h3_client.* = undefined;
    return .{
        .h3 = owned_h3,
        .restore_to = restore_to,
        .session_id = session_id,
        .response = response.head,
        .response_body = response.body,
        .response_trailers = response.trailers,
        .stream_complete = response.stream_complete,
        .limits = limits,
    };
}

fn startStatefulConnect(
    h3_client: *http3.runtime.HandshakeClient,
    authority: []const u8,
    path: []const u8,
    origin: []const u8,
    additional_headers: []const http3.Qpack.HeaderField,
) Error!webtransport.SessionId {
    const allocator = h3_client.allocator;
    var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
        undefined;
    var prepared_headers = try connect_headers.prepareRequest(
        allocator,
        origin,
        additional_headers,
        &header_stack,
    );
    defer prepared_headers.deinit(allocator);
    const stream_id = try h3_client.startRequest(.{
        .method = "CONNECT",
        .path = path,
        .scheme = "https",
        .authority = authority,
        .headers = prepared_headers.fields,
    }, null);
    return webtransport.SessionId.init(stream_id);
}

const HandshakeConnectRequest = struct {
    stream_id: u62,
    head: http3.DecodedRequestHead,
};

fn receiveStatefulSessionRequest(
    session: *http3.runtime.HandshakeServerSession,
    limits: Limits,
) Error!PendingHandshakeSession {
    return receiveStatefulSessionRequestBefore(session, limits, null, null);
}

fn receiveStatefulSessionRequestWithDeadline(
    session: *http3.runtime.HandshakeServerSession,
    limits: Limits,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!PendingHandshakeSession {
    return receiveStatefulSessionRequestBefore(
        session,
        limits,
        deadline,
        null,
    );
}

fn receiveStatefulSessionRequestBefore(
    session: *http3.runtime.HandshakeServerSession,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeServerSession,
) ReceiveTimeoutError!PendingHandshakeSession {
    try session.ensureSettingsSent();
    var request = if (deadline) |absolute|
        try receiveHandshakeConnectRequestWithDeadline(session, absolute)
    else
        try receiveHandshakeConnectRequest(session);
    errdefer request.head.deinit(
        session.established.connection.endpoint.allocator,
    );
    try validateConnectRequest(request.head);
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
        .restore_to = restore_to,
        .request = .{
            .stream_id = request.stream_id,
            .request = request.head,
        },
        .session_id = session_id,
        .limits = limits,
        .deadline = deadline,
    };
}

fn receiveHandshakeConnectRequest(
    session: *http3.runtime.HandshakeServerSession,
) Error!HandshakeConnectRequest {
    return receiveHandshakeConnectRequestBefore(session, null);
}

fn receiveHandshakeConnectRequestWithDeadline(
    session: *http3.runtime.HandshakeServerSession,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!HandshakeConnectRequest {
    return receiveHandshakeConnectRequestBefore(session, deadline);
}

fn receiveHandshakeConnectRequestBefore(
    session: *http3.runtime.HandshakeServerSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!HandshakeConnectRequest {
    while (true) {
        var event = if (deadline) |absolute|
            try session.receiveRequestEventWithDeadline(absolute)
        else
            try session.receiveRequestEvent();
        defer event.deinit(
            session.established.connection.endpoint.allocator,
        );
        switch (event) {
            .reset => return error.InvalidConnect,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidConnect;
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

const ProtectedConnectRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    head: http3.DecodedRequestHead,
};

fn receiveProtectedConnectRequest(
    server: *http3.runtime.ProtectedServer,
) Error!ProtectedConnectRequest {
    while (true) {
        var event = try server.receiveRequestEvent();
        defer event.deinit(server.quic_server.endpoint.allocator);
        switch (event) {
            .reset => return error.InvalidConnect,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidConnect;
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

fn receiveProtectedConnectRequestBefore(
    server: *http3.runtime.ProtectedServer,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!ProtectedConnectRequest {
    while (true) {
        var event = try server.receiveRequestEventWithDeadline(deadline);
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

const HandshakeConnectResponse = struct {
    head: http3.DecodedResponseHead,
    body: []u8 = &.{},
    trailers: []http3.Qpack.HeaderField = &.{},
    stream_complete: bool = false,

    fn deinit(
        self: *HandshakeConnectResponse,
        allocator: std.mem.Allocator,
    ) void {
        self.head.deinit(allocator);
        allocator.free(self.body);
        http3.Qpack.freeDecodedFields(allocator, self.trailers);
        self.* = undefined;
    }
};

fn receiveHandshakeConnectAttemptResponse(
    client: *http3.runtime.HandshakeClient,
    stream_id: u62,
    max_body_bytes: usize,
) Error!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveHandshakeConnectAttemptResponseBefore(
    client: *http3.runtime.HandshakeClient,
    stream_id: u62,
    max_body_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        deadline,
    );
}

fn receiveConnectAttemptResponseUntil(
    client: anytype,
    stream_id: u62,
    max_body_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!HandshakeConnectResponse {
    const allocator = if (comptime @TypeOf(client) ==
        *http3.runtime.HandshakeClient)
        client.allocator
    else
        client.quic_client.endpoint.allocator;
    while (true) {
        var event = (if (deadline) |absolute|
            try client.receiveResponseEventWithDeadline(stream_id, absolute)
        else
            try client.receiveResponseEvent(stream_id)) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |*head| {
                if (head.* != .response) return error.InvalidConnect;
                if (head.response.status < 200) continue;
                if (head.response.status >= 200 and
                    head.response.status < 300)
                {
                    try validateOptionalCapsuleProtocol(head.response.headers);
                }
                const owned = head.response;
                event = .finished;
                if (owned.status >= 200 and owned.status < 300) {
                    return .{ .head = owned };
                }
                var result = HandshakeConnectResponse{ .head = owned };
                errdefer result.deinit(allocator);
                const rejection = try receiveRejectionEntityUntil(
                    client,
                    allocator,
                    stream_id,
                    owned.content_length,
                    max_body_bytes,
                    deadline,
                );
                result.body = rejection.body;
                result.trailers = rejection.trailers;
                result.stream_complete = true;
                return result;
            },
            else => return error.InvalidConnect,
        }
    }
}

const HandshakeRejectionEntity = struct {
    body: []u8,
    trailers: []http3.Qpack.HeaderField,
};

fn finalizeRejectionBody(
    body: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_length: ?usize,
) std.mem.Allocator.Error![]u8 {
    if (content_length != null) return body.toOwnedSliceAssert();
    return body.toOwnedSlice(allocator);
}

fn receiveRejectionEntityUntil(
    client: anytype,
    allocator: std.mem.Allocator,
    stream_id: u62,
    content_length: ?usize,
    max_body_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!HandshakeRejectionEntity {
    if ((content_length orelse 0) > max_body_bytes) {
        return error.MessageTooLarge;
    }
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    if (content_length) |expected| {
        // The stream reader enforces the declared final length. Reserve it
        // exactly once so split rejection DATA does not grow geometrically.
        try body.ensureTotalCapacityPrecise(allocator, expected);
    }
    var trailers: []http3.Qpack.HeaderField = &.{};
    errdefer http3.Qpack.freeDecodedFields(allocator, trailers);
    var scratch: [16 * 1024]u8 = undefined;
    while (true) {
        var event = (if (deadline) |absolute|
            try client.receiveResponseEventWithDeadline(stream_id, absolute)
        else
            try client.receiveResponseEvent(stream_id)) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .data_available => {
                const remaining = max_body_bytes -| body.items.len;
                const read = try client.readResponseData(
                    stream_id,
                    scratch[0..@min(scratch.len, remaining +| 1)],
                );
                if (read > remaining) return error.MessageTooLarge;
                try body.appendSlice(allocator, scratch[0..read]);
            },
            .trailers => |value| {
                if (trailers.len != 0) return error.InvalidConnect;
                trailers = value.fields;
                event = .finished;
            },
            .finished => break,
            .push_promise => continue,
            .head => return error.InvalidConnect,
        }
    }
    return .{
        .body = try finalizeRejectionBody(
            &body,
            allocator,
            content_length,
        ),
        .trailers = trailers,
    };
}

test "WebTransport declared rejection body retains one exact allocation" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(tracking.allocator());

    try body.ensureTotalCapacityPrecise(tracking.allocator(), 9);
    try body.appendSlice(tracking.allocator(), "try");
    try body.appendSlice(tracking.allocator(), " later");
    const owned = try finalizeRejectionBody(
        &body,
        tracking.allocator(),
        9,
    );
    defer tracking.allocator().free(owned);
    try std.testing.expectEqualStrings("try later", owned);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
}

fn pollHandshakeConnectAttemptResponse(
    client: *http3.runtime.HandshakeClient,
    stream_id: u62,
) Error!?http3.DecodedResponseHead {
    var head = (try client.pollDetachedResponseHead(stream_id)) orelse
        return null;
    errdefer head.deinit(client.allocator);
    if (head.status >= 200 and head.status < 300) {
        try validateOptionalCapsuleProtocol(head.headers);
    }
    return head;
}

fn pollHandshakeConnectAttemptResponseOnce(
    client: *http3.runtime.HandshakeClient,
    stream_id: u62,
) Error!?http3.DecodedResponseHead {
    var head = (try client.pollDetachedResponseHeadOnce(stream_id)) orelse
        return null;
    errdefer head.deinit(client.allocator);
    if (head.status >= 200 and head.status < 300) {
        try validateOptionalCapsuleProtocol(head.headers);
    }
    return head;
}

fn receiveProtectedConnectAttemptResponse(
    client: *http3.runtime.ProtectedClient,
    stream_id: u62,
    max_body_bytes: usize,
) Error!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveDevelopmentConnectAttemptResponse(
    client: *http3.runtime.Client,
    stream_id: u62,
    max_body_bytes: usize,
) Error!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveDevelopmentConnectAttemptResponseBefore(
    client: *http3.runtime.Client,
    stream_id: u62,
    max_body_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        deadline,
    );
}

fn receiveProtectedConnectAttemptResponseBefore(
    client: *http3.runtime.ProtectedClient,
    stream_id: u62,
    max_body_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) Error!HandshakeConnectResponse {
    return receiveConnectAttemptResponseUntil(
        client,
        stream_id,
        max_body_bytes,
        deadline,
    );
}

const validateConnectRequest = connect_headers.validateRequest;
const validateConnectOrigin = connect_headers.validateOrigin;
const connectResponseWithHeaders = connect_headers.response;
const validateConnectResponse = connect_headers.validateResponse;
const AdditionalHeaderContext = connect_headers.Context;
const validateAdditionalConnectHeaders = connect_headers.validate;
const validateOptionalCapsuleProtocol =
    connect_headers.validateOptionalCapsule;

pub const OwnedDatagram = datagram_owned.Datagram;
pub const OwnedProtectedDatagram = datagram_owned.Protected;
pub const OwnedHandshakeDatagram = datagram_owned.Handshake;
pub const OwnedHandshakeDatagramBatch = datagram_owned.HandshakeBatch;
const parseDatagramFromOwnedQuicDatagram = datagram_owned.parseQuic;

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
const receiveHandshakeSessionStreamWithDeadline =
    handshake_stream.receiveWithDeadline;
const readHandshakeSessionStream = incremental_stream.read;
const resetHandshakeSessionStream = incremental_stream.reset;
const stopHandshakeSessionStream = incremental_stream.stop;
const initDevelopmentStreamRegistry = development_stream.initRegistry;
pub const OwnedDevelopmentStream = development_stream.Owned;

fn developmentDirection(
    direction: webtransport.StreamDirection,
) http3.runtime.DevelopmentStreamDirection {
    return switch (direction) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
}

fn developmentWritableStream(
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
) Error!*webtransport.StreamState {
    const stream = registry.get(stream_id) orelse return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated) return error.InvalidStreamState;
    if (stream.send_reset != null or stream.stopped != null or
        stream.local_fin) return error.InvalidStreamState;
    return stream;
}

const sendDatagramFromEndpoint = datagram_send.development;

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

fn receiveHandshakePeerConnectionCloseUntil(
    connection: *quic.one_rtt.Connection,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
    while (true) {
        if (connection.peerCloseInfo()) |close| return close;
        connection.servicePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => {
                    return connection.peerCloseInfo() orelse return err;
                },
                else => return err,
            };
    }
}

/// Transfer an HTTP/3 association payload into the established WebTransport
/// owning shape. The registry has already stripped and validated the Quarter
/// Stream ID, so the same allocation can be retained without re-encoding or
/// copying it merely to reconstruct the WebTransport view.
const ownedHandshakeDatagram = datagram_owned.fromConnect;

/// Wire-only test peer helper. Stateful WebTransport APIs must send through
/// HTTP/3's association registry; this deliberately unregistered connection
/// exists only to generate peer traffic for the bounded-batch regression.
fn sendHandshakeDatagramForTest(
    connection: *quic.one_rtt.Connection,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    try (webtransport.Datagram{
        .session_id = session_id,
        .payload = payload,
    }).write(&encoded, connection.endpoint.allocator);
    try connection.sendDatagram(encoded.items);
}

fn drainQueuedHandshakeDatagrams(
    h3: anytype,
    session_id: webtransport.SessionId,
    datagrams: []?OwnedHandshakeDatagram,
) Error!usize {
    var count: usize = 0;
    while (count < datagrams.len) {
        const datagram = (try h3.pollConnectDatagram(
            session_id.value,
        )) orelse break;
        datagrams[count] = ownedHandshakeDatagram(datagram, session_id);
        count += 1;
    }
    return count;
}

fn receiveManyHandshakeDatagrams(
    h3: anytype,
    session_id: webtransport.SessionId,
    count: usize,
) Error!OwnedHandshakeDatagramBatch {
    return receiveManyHandshakeDatagramsUntil(
        h3,
        session_id,
        count,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveManyHandshakeDatagramsUntil(
    h3: anytype,
    session_id: webtransport.SessionId,
    count: usize,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
    const allocator = h3.established.connection.endpoint.allocator;
    const datagrams = try allocator.alloc(?OwnedHandshakeDatagram, count);
    errdefer {
        for (datagrams) |*datagram| {
            if (datagram.*) |*owned| {
                owned.deinit(allocator);
            }
        }
        allocator.free(datagrams);
    }
    @memset(datagrams, null);
    const errors = try allocator.alloc(?anyerror, count);
    errdefer allocator.free(errors);
    @memset(errors, null);

    const filled = try drainQueuedHandshakeDatagrams(
        h3,
        session_id,
        datagrams,
    );
    if (filled == count) return .{
        .allocator = allocator,
        .datagrams = datagrams,
        .errors = errors,
    };

    // A QUIC connection owns packet-number, ACK, flow-control, and DATAGRAM
    // queue state.  Unlike independent endpoint receives, multiple concurrent
    // receivePacket() calls on the same Connection would race those mutable
    // invariants.  Batch reception therefore drains one connection
    // sequentially while still returning the ergonomic batch/error shape used
    // by the higher-level runtime. A bounded batch uses one absolute deadline
    // for every slot so unrelated packets and earlier DATAGRAMs cannot renew
    // the caller's budget. Partial results remain owned by the returned batch.
    for (datagrams[filled..], errors[filled..]) |*datagram, *err_slot| {
        const owned = (if (deadline) |absolute|
            h3.receiveConnectDatagramWithDeadline(
                session_id.value,
                absolute,
            )
        else
            h3.receiveConnectDatagram(session_id.value)) catch |err| {
            err_slot.* = err;
            break;
        };
        datagram.* = ownedHandshakeDatagram(owned, session_id);
        err_slot.* = null;
    }
    return .{
        .allocator = allocator,
        .datagrams = datagrams,
        .errors = errors,
    };
}

const sendProtectedDatagramFromEndpoint = datagram_send.protected;

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

fn receiveProtectedDatagramFromEndpointWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    local_connection_id_len: usize,
    expected_packet_number: *u64,
    max_frames: usize,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!OwnedProtectedDatagram {
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    while (true) {
        var datagram = try endpoint.receiveBytesTimeout(.{
            .deadline = deadline,
        });
        defer datagram.deinit(endpoint.allocator);
        var packet = try quic.one_rtt.openReceivedBytes(
            endpoint,
            datagram.from,
            datagram.bytes,
            keys,
            local_connection_id_len,
            expected_packet_number.*,
            max_frames,
        );
        errdefer packet.deinit(endpoint.allocator);
        expected_packet_number.* = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(
                    frame.datagram.data,
                );
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
        .{
            .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            .origin_policy = .{
                .exact = &.{"https://example.test"},
            },
        },
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
            var rejected = try pending.rejectWithBody(
                429,
                &.{.{
                    .name = "retry-after",
                    .value = "5",
                }},
                "slow down",
                &.{.{ .name = "x-final", .value = "true" }},
            );
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
                .max_rejection_body_bytes = 9,
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
    try std.testing.expectEqualStrings(
        "9",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("slow down", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-final",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport development rejected CONNECT enforces body limit" {
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
            var rejected = try pending.rejectWithBody(
                413,
                &.{},
                "12345",
                &.{},
            );
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.MessageTooLarge,
        ClientSession.connectAttempt(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = "/too-large",
                .limits = .{
                    .http3 = .{
                        .quic = .{ .max_datagram_size = 4096 },
                    },
                    .max_rejection_body_bytes = 4,
                },
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected runtime sends explicit rejection entity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x20, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x20, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_frames_per_packet = 1,
            .max_stream_frame_data = 3,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
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
            var rejected = try pending.rejectWithBody(
                503,
                &.{.{ .name = "retry-after", .value = "7" }},
                "try later",
                &.{.{ .name = "x-final", .value = "protected" }},
            );
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u16, 503), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try ProtectedClientSession.connectAttempt(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/protected-busy",
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
                .max_rejection_body_bytes = 9,
            },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_frames_per_packet = 1,
                .max_stream_frame_data = 3,
            },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 503), attempt.status());
    try std.testing.expectEqualStrings(
        "7",
        attempt.responseHeader("retry-after").?,
    );
    try std.testing.expectEqualStrings(
        "9",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("try later", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-final",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "protected",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected pending deinit retires request capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x21, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x21, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    const limits: Limits = .{ .http3 = .{
        .quic = .{ .max_datagram_size = 4096 },
        .max_concurrent_request_streams = 1,
    } };
    const server_config: http3.runtime.ProtectedConfig = .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    };
    const client_config: http3.runtime.ProtectedConfig = .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = webtransport.defaultSettings(.{}),
    };

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        server_config,
    );
    defer server.deinit();
    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |_| {
                var pending = try self.server.receiveSessionRequest();
                pending.deinit();
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits.http3,
        client_config,
    );
    defer client.deinit();
    for (0..2) |index| {
        const stream_id = try client.startRequest(.{
            .method = "CONNECT",
            .path = if (index == 0) "/drop-one" else "/drop-two",
            .scheme = "https",
            .authority = "localhost",
            .headers = &.{
                .{ .name = ":protocol", .value = "webtransport" },
                http3.capsule.protocol_header,
            },
        }, null);
        try std.testing.expectError(
            error.RequestRejected,
            client.receiveResponseEvent(stream_id),
        );
    }

    thread.join();
    joined = true;
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

    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
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
        io: std.Io,
        initial_timeout_done: std.Io.Event = .unset,
        sibling_stream_id: u62 = 4,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
                shared.initial_timeout_done.set(shared.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.receiveSessionRequestWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectError(
                error.Timeout,
                server_ptr.receiveSessionRequestWithTimeout(
                    .fromMilliseconds(10),
                ),
            );
            shared.initial_timeout_done.set(shared.io);
            var pending = try server_ptr.receiveSessionRequestWithDeadline(
                .fromNow(shared.io, .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                }),
            );
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
            // The ordinary request was ready first. The targeted session read
            // above must leave its events buffered for this explicit sibling
            // consumer rather than returning InvalidSessionState.
            var sibling_head = try server_ptr.h3
                .receiveRequestEventForWithTimeout(
                shared.sibling_stream_id,
                .fromSeconds(1),
            );
            defer sibling_head.deinit(allocator);
            try std.testing.expect(sibling_head == .message);
            try std.testing.expect(sibling_head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/protected-sibling",
                sibling_head.message.value.head.request.path,
            );
            var sibling_finished = try server_ptr.h3
                .receiveRequestEventForWithTimeout(
                shared.sibling_stream_id,
                .fromSeconds(1),
            );
            defer sibling_finished.deinit(allocator);
            try std.testing.expect(sibling_finished == .message);
            try std.testing.expect(
                sibling_finished.message.value == .finished,
            );
            try server_ptr.h3.sendResponse(
                accepted.request.from,
                shared.sibling_stream_id,
                .{ .status = 204 },
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

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try shared.initial_timeout_done.wait(io);

    const connect_options: ProtectedConnectOptions = .{
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
    };
    try std.testing.expectError(
        error.Timeout,
        ProtectedClientSession.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        ProtectedClientSession.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .zero,
        ),
    );
    var client = try ProtectedClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        connect_options,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-protected-admission").?,
    );

    const sibling_stream_id = try client.h3.sendRequest(.{
        .method = "GET",
        .path = "/protected-sibling",
        .authority = "localhost",
    });
    try std.testing.expectEqual(shared.sibling_stream_id, sibling_stream_id);
    try client.sendSessionData("protected-client-control", false);
    var sibling_response = try client.h3.receiveResponseWithTimeout(
        sibling_stream_id,
        .fromSeconds(1),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 204),
        sibling_response.response.status,
    );
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

test "WebTransport protected control receive deadlines preserve parser state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x10, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x10, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_frame_data = 5,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        io: std.Io,
        client_timeout_done: std.Io.Event = .unset,
        close_prefix_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var pending = try shared.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var accepted = try pending.accept();
            pending_owned = false;
            defer accepted.deinit(
                shared.server.h3.quic_server.endpoint.allocator,
            );

            try std.testing.expectError(
                error.Timeout,
                accepted.receiveSessionEventWithTimeout(
                    shared.server,
                    .fromMilliseconds(5),
                ),
            );
            try shared.client_timeout_done.wait(shared.io);
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                "server-after-timeout",
                false,
            );

            var close_storage: [64]u8 = undefined;
            const close = try session_control.writeCloseInto(
                &close_storage,
                71,
                "server done",
            );
            try std.Io.sleep(
                shared.io,
                .fromMilliseconds(5),
                .awake,
            );
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                close[0..3],
                false,
            );
            shared.close_prefix_sent.set(shared.io);
            try std.Io.sleep(shared.io, .fromMilliseconds(25), .awake);
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                close[3..],
                true,
            );
            try accepted.control.control.recordLocalClose(71);
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try ProtectedClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-protected-deadline",
            .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.receiveDatagramWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
    var control_bytes: [64]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionDataWithTimeout(
            &control_bytes,
            .fromMilliseconds(5),
        ),
    );
    shared.client_timeout_done.set(io);
    const read = try client.receiveSessionDataWithDeadline(
        &control_bytes,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqualStrings(
        "server-after-timeout",
        control_bytes[0..read.bytes],
    );
    try shared.close_prefix_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionEventWithTimeout(.fromMilliseconds(5)),
    );
    const closed = try client.receiveSessionEventWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 71), closed.closed.code);
    try std.testing.expectEqualStrings("server done", closed.closed.reason);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected control deadlines reject invalid budgets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    const config: http3.runtime.ProtectedConfig = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline",
        .peer_connection_id = "wt-deadline-peer",
    };

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        config,
    );
    defer server.deinit();
    var server_session = AcceptedProtectedSession{
        .request = undefined,
        .session_id = .init(0),
        .control = protected_control.Reader.init(
            try session_control.Control.init(.init(0)),
        ),
    };
    try std.testing.expectError(
        error.Timeout,
        server_session.receiveSessionEventWithTimeout(&server, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        server_session.receiveSessionEventWithDeadline(
            &server,
            .{ .raw = .zero, .clock = .real },
        ),
    );

    var client_h3 = try http3.runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        config,
    );
    var client_session = ProtectedClientSession{
        .h3 = client_h3,
        .session_id = .init(0),
        .response = undefined,
        .control = protected_control.Reader.init(
            try session_control.Control.init(.init(0)),
        ),
    };
    client_h3 = undefined;
    defer client_session.h3.deinit();
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client_session.receiveSessionDataWithTimeout(&buffer, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client_session.receiveSessionEventWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
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
        io: std.Io,
        initial_timeout_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.initial_timeout_done.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            try std.testing.expectError(
                error.Timeout,
                self.server.receiveSessionRequestWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectError(
                error.Timeout,
                self.server.receiveSessionRequestWithTimeout(
                    .fromMilliseconds(10),
                ),
            );
            self.initial_timeout_done.set(self.io);
            var session = try self.server.acceptWithDeadline(.fromNow(
                self.io,
                .{ .raw = .fromSeconds(1), .clock = .awake },
            ));
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
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try shared.initial_timeout_done.wait(io);

    const connect_options: StatefulProtectedConnectOptions = .{
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
    };
    try std.testing.expectError(
        error.Timeout,
        StatefulProtectedClientSession.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        StatefulProtectedClientSession.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .zero,
        ),
    );
    var client = try StatefulProtectedClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        connect_options,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer client.deinit();
    try std.testing.expect(client.datagramsNegotiated());
    try std.testing.expect(client.maxDatagramSize() != 0);
    try std.testing.expectEqual(
        client.address(),
        client.session.h3.address(),
    );
    const before_invalid_open = client.stats().outgoing_streams_created;
    const before_invalid_registry = client.session.streams.registered().len;
    try std.testing.expectError(
        error.Timeout,
        client.openBidirectionalStreamWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.openUnidirectionalStreamWithTimeout(.zero),
    );
    try std.testing.expectEqual(
        before_invalid_open,
        client.stats().outgoing_streams_created,
    );
    try std.testing.expectEqual(
        before_invalid_registry,
        client.session.streams.registered().len,
    );

    // Practical transport parameters provide immediate credit. Exercise both
    // bounded directions and verify the QUIC reservation counter advances.
    const bidi = try client.openBidirectionalStreamWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        before_invalid_open + 1,
        client.stats().outgoing_streams_created,
    );
    try client.sendStream(bidi, "client-bidi", true);
    const uni = try client.openUnidirectionalStreamWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    try std.testing.expectEqual(
        before_invalid_open + 2,
        client.stats().outgoing_streams_created,
    );
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
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("after-close"),
    );
    try std.testing.expect(client.session.h3.hasConnectDatagramAssociation(
        client.session.session_id.value,
    ));
    const peer_fin = try client.receiveSessionEvent();
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expect(client.session.h3.hasConnectDatagramAssociation(
        client.session.session_id.value,
    ));
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        client.receiveDatagram(),
    );

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

test "WebTransport bounded DATAGRAM send waits for congestion ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x62, 0x64, 0x67, 0x01, 0x62, 0x64, 0x67, 0x02 };
    const client_cid = [_]u8{ 0x62, 0x64, 0x67, 0x03 };
    const server_cid = [_]u8{ 0x62, 0x64, 0x67, 0x04 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x63} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        release_receive: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept();
            defer accepted.deinit();
            const before = accepted.stats();
            try std.testing.expectError(
                error.Timeout,
                accepted.sendDatagramWithTimeout("not-sent", .zero),
            );
            try std.testing.expectEqual(
                before.datagrams_sent,
                accepted.stats().datagrams_sent,
            );
            try self.release_receive.wait(self.server.h3.quic_server.endpoint.io);
            var first = try accepted.receiveDatagram();
            defer first.deinit(
                accepted.h3.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "fill-window",
                first.datagram.payload,
            );
            var second = try accepted.receiveDatagram();
            defer second.deinit(
                accepted.h3.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "after-ack",
                second.datagram.payload,
            );
            try accepted.sendDatagramWithTimeout(
                "server-bounded",
                .fromSeconds(5),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-bounded-datagram",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x65} ** 32,
                .x25519_secret_key = [_]u8{0x66} ** 32,
            } },
        },
    );
    defer client.deinit();

    try client.sendDatagram("fill-window");
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(
        &client.h3.established.connection,
    );
    const before = client.stats();
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramWithTimeout("not-sent", .zero),
    );
    try std.testing.expectEqual(
        before.datagrams_sent,
        client.stats().datagrams_sent,
    );

    shared.release_receive.set(io);
    try client.sendDatagramWithTimeout(
        "after-ack",
        .fromSeconds(5),
    );
    try std.testing.expectEqual(
        before.datagrams_sent + 1,
        client.stats().datagrams_sent,
    );
    var response = try client.receiveDatagramWithTimeout(.fromSeconds(5));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "server-bounded",
        response.datagram.payload,
    );

    thread.join();
    joined = true;
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

test "WebTransport bounded DATAGRAM batch retains partial progress" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    const client_cid = "wt-batch-client";
    const server_cid = "wt-batch-server";
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var session = AcceptedHandshakeSession{
        .h3 = h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(.init(0)),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
        session.streams.deinit();
        session.h3.deinit();
    }
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer peer.deinit();

    try sendHandshakeDatagramForTest(&peer, .init(0), "first");
    var batch = try session.receiveManyDatagramsWithTimeout(
        2,
        .fromMilliseconds(20),
    );
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), batch.receivedCount());
    try std.testing.expectEqual(error.Timeout, batch.firstError().?);
    try std.testing.expectEqualStrings(
        "first",
        batch.datagrams[0].?.datagram.payload,
    );
    try std.testing.expect(batch.datagrams[1] == null);

    try sendHandshakeDatagramForTest(&peer, .init(0), "second");
    var resumed = try session.receiveManyDatagramsWithDeadline(
        1,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer resumed.deinit();
    try std.testing.expectEqual(@as(usize, 1), resumed.receivedCount());
    try std.testing.expect(resumed.firstError() == null);
    try std.testing.expectEqualStrings(
        "second",
        resumed.datagrams[0].?.datagram.payload,
    );
}

test {
    _ = @import("runtime/datagram/tests/codec.zig");
    _ = @import("runtime/datagram/tests/send.zig");
    _ = @import("runtime/stream_tests.zig");
    _ = @import("runtime/stream/tests/batch.zig");
    _ = @import("runtime/stream/pagination_tests.zig");
    _ = @import("runtime/development_control_tests.zig");
    _ = stream_batch;
    _ = @import("runtime/session_control_tests.zig");
    _ = @import("runtime/connection_close_tests.zig");
}
