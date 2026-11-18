const std = @import("std");
const net = std.Io.net;
const application = @import("../application.zig");
const connect_configuration = @import("../connect/options.zig");
const connect_headers = @import("../connect/headers.zig");
const connect_negotiation = @import("../connect/negotiation.zig");
const connect_rejection = @import("../connect/rejection.zig");
const datagram_send = @import("../datagram/send.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const session_control = @import("../session_control.zig");
const webtransport = @import("../../mod.zig");

const runtime = @import("../../runtime.zig");
const Error = runtime.Error;
const Limits = runtime.Limits;
const OriginPolicy = runtime.OriginPolicy;
const OwnedDatagram = runtime.OwnedDatagram;
const OwnedProtectedDatagram = runtime.OwnedProtectedDatagram;
const ProtectedSessionRead = runtime.ProtectedSessionRead;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionDataRead = runtime.SessionDataRead;
const application_protocol = runtime.application_protocol;
const connectResponseWithHeaders = runtime.connectResponseWithHeaders;
const findHeader = runtime.findHeader;
const initDevelopmentStreamRegistry = runtime.initDevelopmentStreamRegistry;
const parseDatagramFromOwnedQuicDatagram = runtime.parseDatagramFromOwnedQuicDatagram;
const protected_control = runtime.protected_control;
const receiveProtectedConnectRequest = runtime.receiveProtectedConnectRequest;
const receiveProtectedConnectRequestBefore = runtime.receiveProtectedConnectRequestBefore;
const receiveProtectedDatagramFromEndpoint = runtime.receiveProtectedDatagramFromEndpoint;
const receiveProtectedDatagramFromEndpointWithDeadline = runtime.receiveProtectedDatagramFromEndpointWithDeadline;
const receiveStatefulSessionRequest = runtime.receiveStatefulSessionRequest;
const receiveStatefulSessionRequestBefore = runtime.receiveStatefulSessionRequestBefore;
const receiveStatefulSessionRequestWithDeadline = runtime.receiveStatefulSessionRequestWithDeadline;
const sendDatagramFromEndpoint = runtime.sendDatagramFromEndpoint;
const sendDatagramFromEndpointWithDeadline = runtime.sendDatagramFromEndpointWithDeadline;
const sendProtectedDatagramFromEndpoint = runtime.sendProtectedDatagramFromEndpoint;
const sendProtectedDatagramFromEndpointWithDeadline = runtime.sendProtectedDatagramFromEndpointWithDeadline;
const validateAdditionalConnectHeaders = runtime.validateAdditionalConnectHeaders;
const validateConnectOrigin = runtime.validateConnectOrigin;
const validateConnectRequest = runtime.validateConnectRequest;

const endpoint_types = @import("endpoint.zig");
const EndpointServer = endpoint_types.EndpointServer;
const session_types = @import("session.zig");
const AcceptedHandshakeSession = session_types.AcceptedHandshakeSession;
const AcceptedProtectedSession = session_types.AcceptedProtectedSession;
const AcceptedSession = session_types.AcceptedSession;
const OwnedConnectRequest = session_types.OwnedConnectRequest;
const OwnedProtectedConnectRequest = session_types.OwnedProtectedConnectRequest;
const PendingHandshakeSession = session_types.PendingHandshakeSession;

pub const Server = struct {
    h3: http3.runtime.Server,
    max_session_streams: usize,
    origin_policy: OriginPolicy,
    application_protocols: application_protocol.Policy = .{},
    datagram_batch_scratch: datagram_send.DevelopmentBatchScratch = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        if (limits.require_session_flow_control) return error.SessionFlowControlRequired;
        if (limits.initial_flow_limits != null) return error.WebTransportNotNegotiated;
        try application_protocol.validateValues(limits.application_protocols.values);
        return .{
            .h3 = try .bind(allocator, io, bind_address, limits.http3),
            .max_session_streams = limits.max_session_streams,
            .origin_policy = limits.origin_policy,
            .application_protocols = limits.application_protocols,
        };
    }

    pub fn deinit(self: *Server) void {
        self.datagram_batch_scratch.deinit(
            self.h3.quic_server.endpoint.allocator,
        );
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

    pub fn sendDatagramWithTimeout(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(
            to,
            session_id,
            payload,
            .fromNow(self.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return sendDatagramFromEndpointWithDeadline(
            &self.h3.quic_server.endpoint,
            to,
            session_id,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        return datagram_send.developmentBatch(
            &self.h3.quic_server.endpoint,
            to,
            session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(
            to,
            session_id,
            payloads,
            committed_count,
            .fromNow(self.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return datagram_send.developmentBatchWithDeadline(
            &self.h3.quic_server.endpoint,
            to,
            session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(
        self: *const Server,
        session_id: webtransport.SessionId,
    ) ?usize {
        return datagram_send.developmentPayloadLimit(
            self.h3.quic_server.endpoint.limits.max_datagram_size,
            session_id,
        );
    }

    pub fn maxDatagramSize(
        self: *const Server,
        session_id: webtransport.SessionId,
    ) usize {
        return self.maxDatagramPayloadSize(session_id) orelse 0;
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

    pub fn sendSessionDataWithTimeout(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.h3.sendResponseBodyWithTimeout(
            to,
            session_id.value,
            data,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.h3.sendResponseBodyWithDeadline(
            to,
            session_id.value,
            data,
            fin,
            progress,
            deadline,
        );
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
    application_protocols: application_protocol.Policy = .{},
    datagram_batch_scratch: datagram_send.ProtectedBatchScratch = .{},

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        config: http3.runtime.ProtectedConfig,
    ) Error!ProtectedServer {
        try application_protocol.validateValues(limits.application_protocols.values);
        return .{
            .h3 = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3,
                try connect_configuration.protected(config, limits),
            ),
            .origin_policy = limits.origin_policy,
            .application_protocols = limits.application_protocols,
        };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.datagram_batch_scratch.deinit(
            self.h3.quic_server.endpoint.allocator,
        );
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

    pub fn sendDatagramWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(
            to,
            session_id,
            payload,
            .fromNow(self.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        try sendProtectedDatagramFromEndpointWithDeadline(
            &self.h3.quic_server.endpoint,
            to,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            session_id,
            payload,
            deadline,
        );
    }

    /// Submit one ordered batch of independently protected DATAGRAMs. The
    /// batch is capped by QUIC's socket-batch bound; `committed_count` reports
    /// only the socket-visible input prefix.
    pub fn sendDatagrams(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return datagram_send.protectedBatch(
            &self.h3.quic_server.endpoint,
            to,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(
            to,
            session_id,
            payloads,
            committed_count,
            .fromNow(self.h3.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return datagram_send.protectedBatchWithDeadline(
            &self.h3.quic_server.endpoint,
            to,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(
        self: *const ProtectedServer,
        session_id: webtransport.SessionId,
    ) ?usize {
        webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        ) catch return null;
        return datagram_send.protectedPayloadLimit(
            self.h3.quic_server.endpoint.limits.max_datagram_size,
            self.h3.config.peer_connection_id.len,
            self.h3.next_packet_number,
            session_id,
        );
    }

    pub fn maxDatagramSize(
        self: *const ProtectedServer,
        session_id: webtransport.SessionId,
    ) usize {
        return self.maxDatagramPayloadSize(session_id) orelse 0;
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

    pub fn sendSessionDataWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.h3.sendResponseBodyPacedWithTimeout(
            to,
            session_id.value,
            data,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.h3.sendResponseBodyPacedWithDeadline(
            to,
            session_id.value,
            data,
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendSessionDataSlices(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        return self.h3.sendResponseBodyPartsPaced(
            to,
            session_id.value,
            parts,
            fin,
        );
    }

    /// Send borrowed Capsule Protocol slices without joining them. On error,
    /// `progress.committed_bytes` is the exact socket-visible prefix across
    /// the concatenation of `parts`, so callers can retry only its suffix.
    pub fn sendSessionDataSlicesWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.h3.sendResponseBodyPartsPacedWithTimeout(
            to,
            session_id.value,
            parts,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataSlicesWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        session_id: webtransport.SessionId,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.quic_server.endpoint.io,
            deadline,
        );
        return self.h3.sendResponseBodyPartsPacedWithDeadline(
            to,
            session_id.value,
            parts,
            fin,
            progress,
            deadline,
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

    pub fn offeredApplicationProtocols(self: PendingSession) ?application_protocol.Offered {
        return application_protocol.offered(self.request.request.headers);
    }

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
        var prepared_headers = try connect_headers.prepareResponseWithProtocols(
            allocator,
            self.request.request.headers,
            additional_headers,
            self.server.application_protocols,
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
        const selected = prepared_headers.selected_application_protocol;
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .server = server,
            .request = request,
            .selected_application_protocol = selected,
            .session_id = session_id,
            .streams = streams,
            .control = protected_control.Reader.init(
                try session_control.Control.init(allocator, session_id),
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

    pub fn offeredApplicationProtocols(self: PendingProtectedSession) ?application_protocol.Offered {
        return application_protocol.offered(self.request.request.headers);
    }

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
        var prepared_headers = try connect_headers.prepareResponseWithProtocols(
            allocator,
            self.request.request.headers,
            additional_headers,
            self.server.application_protocols,
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
        const selected = prepared_headers.selected_application_protocol;
        const request = self.request;
        const session_id = self.session_id;
        self.* = undefined;
        return .{
            .request = request,
            .selected_application_protocol = selected,
            .session_id = session_id,
            .control = protected_control.Reader.init(
                try session_control.Control.init(allocator, session_id),
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
        try application_protocol.validateValues(limits.application_protocols.values);
        if (!http3.isHttp3Alpn(transport.alpn_protocol)) {
            return error.InvalidAlpn;
        }
        var resolved_h3 = try connect_configuration.session(h3_options, limits);
        resolved_h3.early_connect_datagrams = limits.early_connect_datagrams;
        return .{
            .endpoint = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3.quic,
            ),
            .limits = limits,
            .h3_options = resolved_h3,
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
        try application_protocol.validateValues(limits.application_protocols.values);
        if (limits.max_sessions_per_connection != 1) {
            return error.InvalidSessionState;
        }
        return bindWithSessionCapacity(
            allocator,
            io,
            bind_address,
            limits,
            options,
            1,
        );
    }

    /// Bind an HTTP/3 server for `EndpointServer`, which retains each
    /// connection and can independently route the configured Session count.
    pub fn bindForEndpoint(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        options: http3.runtime.HandshakeServerOptions,
    ) Error!HandshakeServer {
        const capacity = std.math.cast(
            u64,
            limits.max_sessions_per_connection,
        ) orelse return error.IntegerOverflow;
        if (capacity == 0 or capacity > quic.varint.max_value) {
            return error.InvalidSessionState;
        }
        return bindWithSessionCapacity(
            allocator,
            io,
            bind_address,
            limits,
            options,
            capacity,
        );
    }

    fn bindWithSessionCapacity(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        options: http3.runtime.HandshakeServerOptions,
        capacity: u64,
    ) Error!HandshakeServer {
        try application_protocol.validateValues(limits.application_protocols.values);
        try @import("../connect/session_capacity.zig").validateServerLimits(limits);
        return .{
            .h3 = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3,
                try connect_configuration.server(options, capacity, limits),
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
        try session.bindDispatcher();
        return .{
            .h3 = session,
            .limits = self.limits,
        };
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
        try session.bindDispatcher();
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
    rejection_pending: ?connect_rejection.Pending = null,

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
        if (self.rejection_pending) |pending| {
            pending.submit(&self.h3) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
                else => return err,
            };
            self.rejection_pending = null;
            return pending.failure.?.cause();
        }
        if (!self.h3.control.settings.received) return null;
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
                        connect_negotiation.validateRequestWithPolicy(&self.h3, head.request, self.limits.require_session_flow_control) catch |err| {
                            const failure = connect_rejection.Failure.fromError(err) orelse return err;
                            const pending = connect_rejection.Pending.forFailure(message.stream_id, failure);
                            self.rejection_pending = pending;
                            pending.submit(&self.h3) catch |submission_error| switch (submission_error) {
                                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
                                else => return submission_error,
                            };
                            self.rejection_pending = null;
                            return failure.cause();
                        };
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
                        return .{
                            .h3 = h3,
                            .limits = limits,
                            .request = .{
                                .stream_id = message.stream_id,
                                .request = request,
                            },
                            .session_id = session_id,
                            .deadline = deadline,
                        };
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
