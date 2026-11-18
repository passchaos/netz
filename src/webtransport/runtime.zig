const std = @import("std");
const builtin = @import("builtin");
const webtransport = @import("mod.zig");
const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");
const round_robin = @import("../internal/round_robin.zig");
pub const deadline_policy = @import("../internal/deadline.zig");

const net = std.Io.net;
const connect_headers = @import("runtime/connect/headers.zig");
const connect_request_head = @import("runtime/connect/request_head.zig");
pub const connect_negotiation = @import("runtime/connect/negotiation.zig");
const connect_rejection = @import("runtime/connect/rejection.zig");
pub const connect_configuration = @import("runtime/connect/options.zig");
const endpoint_serve = @import("runtime/endpoint_server/serve.zig");
pub const application_protocol = webtransport.application_protocol;
const protocol_negotiation = @import("runtime/connect/application_protocol.zig");
const pending_connect_request = @import("runtime/connect/pending_request.zig");
const pending_connect_preface = @import("runtime/connect/preface.zig");
const datagram_codec = @import("runtime/datagram/codec.zig");
const datagram_owned = @import("runtime/datagram/owned.zig");
const datagram_send = @import("runtime/datagram/send.zig");
pub const endpoint_client = @import("runtime/endpoint_client.zig");
pub const session_control = @import("runtime/session_control.zig");
pub const capsule_rejection = @import("runtime/session_control/rejection.zig");
pub const connection_lifecycle = @import("runtime/connection_lifecycle.zig");
pub const flow_grant = @import("runtime/flow/grant.zig");
pub const flow_open = @import("runtime/flow/open.zig");
pub const flow_write = @import("runtime/flow/write.zig");
pub const flow_cancel = @import("runtime/flow/cancel.zig");
pub const flow_read = @import("runtime/flow/read.zig");
pub const flow_datagram = @import("runtime/flow/datagram.zig");
pub const flow_streams = @import("runtime/flow/streams.zig");
pub const protected_control =
    @import("runtime/protected_session_control.zig");
pub const stream_batch = @import("runtime/stream/batch.zig");
const stream_association = @import("runtime/stream_association.zig");
pub const early_streams = @import("runtime/association/early_streams.zig");
const server_terminal = @import("runtime/endpoint_server/terminal.zig");
const server_close = @import("runtime/endpoint_server/close.zig");
const server_stream_control = @import("runtime/endpoint_server/stream_control.zig");
pub const application = @import("runtime/application.zig");
const development_stream = @import("runtime/development_stream.zig");

pub const EndpointClient = endpoint_client.Client;
pub const EndpointClientError = endpoint_client.Error;
pub const EndpointClientTimeoutError = endpoint_client.TimeoutError;
pub const EndpointClientSession = endpoint_client.Session;
pub const EndpointClientOptions = endpoint_client.Options;
pub const AddressResolver = http3.runtime.AddressResolver;
pub const EndpointClientSessionOptions = endpoint_client.SessionOptions;
pub const EndpointClientOpenResult = endpoint_client.OpenResult;
pub const EndpointClientEvent = endpoint_client.Event;
pub const EndpointClientAnyEvent = endpoint_client.AnyEvent;
pub const EndpointClientRejection = endpoint_client.Rejection;
pub const StableConnectionId = quic.one_rtt.StableConnectionId;

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
pub const ConnectRejectionReason = endpoint_serve.ConnectRejectionReason;
pub const ServeConnectRejection = endpoint_serve.ConnectRejection;
pub const ServeConnectionFailure = endpoint_serve.ConnectionFailure;
pub const ServeSessionFailure = endpoint_serve.SessionFailure;
pub const OriginPolicy = connect_headers.OriginPolicy;
pub const EarlyDatagramLimits = http3.runtime.EarlyConnectDatagramLimits;
pub const EarlyStreamLimits = early_streams.Limits;

pub const Limits = struct {
    http3: http3.runtime.Limits = .{},
    /// Exact initial quotas advertised by stateful QUIC constructors. Null
    /// uses existing defaults; negotiated zero quotas require a Capsule grant.
    /// Adoption of an existing transport requires matching its SETTINGS.
    initial_flow_limits: ?webtransport.flow_control.Limits = null,
    /// Reject Session establishment unless both peers declare flow-control intent.
    require_session_flow_control: bool = false,
    max_session_streams: usize = 128,
    /// Concurrent Sessions admitted on one HTTP/3 connection by
    /// `EndpointServer`. Standalone owning Session adapters remain limited to
    /// one and reject larger values during construction.
    max_sessions_per_connection: usize = 1,
    /// Total Session owners retained by EndpointServer on one connection,
    /// including closed Sessions whose metadata the application still owns.
    /// Null uses max(16, max_sessions_per_connection); an explicit bound must
    /// be non-zero. Remove closed owners to reclaim this local memory quota.
    max_retained_sessions_per_connection: ?usize = null,
    /// Browser-origin admission. By default, absent Origin is accepted for
    /// native clients and an explicit Origin must match the CONNECT target.
    origin_policy: OriginPolicy = .same_origin_or_absent,
    /// Maximum response-body bytes retained from a rejected Extended CONNECT
    /// across the development, protected, and authenticated runtimes.
    /// Successful sessions are unaffected.
    max_rejection_body_bytes: usize = 1024 * 1024,
    /// Client offers or server-supported protocols, in preference order.
    application_protocols: application_protocol.Policy = .{},
    /// Connection-wide DATAGRAM retention before CONNECT acceptance. These
    /// bounds are separate from each accepted association's receive queue.
    early_connect_datagrams: EarlyDatagramLimits = .{ .max_datagrams = 64, .max_bytes = 64 * 1024 },
    /// `EndpointServer` retention for streams whose Session is not yet accepted.
    early_connect_streams: EarlyStreamLimits = .{},
};

pub const max_connection_close_reason: usize = connection_lifecycle.max_close_reason;

pub const PendingSessionClose = @import("runtime/session_control/pending_close.zig").Pending;

pub fn clearPendingSessionClose(slot: *?PendingSessionClose) void {
    if (slot.*) |*pending| pending.deinit();
    slot.* = null;
}

pub const PendingSessionDrain = struct {
    bytes: [16]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,

    pub fn init() Error!PendingSessionDrain {
        var pending: PendingSessionDrain = .{};
        const encoded = try session_control.writeDrainInto(&pending.bytes);
        pending.len = encoded.len;
        return pending;
    }
};

pub fn terminalSessionBodySendError(err: anyerror) bool {
    return switch (err) {
        error.RequestCancelled,
        error.RequestRejected,
        error.StreamStopped,
        error.StreamStateError,
        error.UnexpectedStream,
        error.ConnectionClosed,
        error.ConnectionUnusable,
        => true,
        else => false,
    };
}

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
        try @import("runtime/connect/session_capacity.zig").validateServerLimits(limits);
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

    const canAdmitSession = @import("runtime/connect/session_capacity.zig").serverCanAdmit;

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

    const Early = @import("runtime/association/endpoint.zig").For(@This());
    const maintainEarlyConnection = Early.maintain;
    const maintainEarlyStreams = Early.maintainAll;
    const noteEarlyRejection = Early.reject;
    const earlyDeadline = Early.boundedDeadline;
    const Rejections = @import("runtime/connect/endpoint_rejection.zig").For(@This(), noteEarlyRejection);

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

pub const AcceptedHandshakeSession = @import("runtime/accepted_handshake_session.zig").AcceptedHandshakeSession;

pub const ClientSession = struct {
    h3: http3.runtime.Client,
    session_id: webtransport.SessionId,
    /// Owns the final CONNECT response head, including custom admission
    /// headers. The body remains attached to the same stream for long-lived
    /// WebTransport control capsules after the 2xx head has been consumed.
    response: http3.DecodedResponseHead,
    streams: webtransport.StreamRegistry,
    control: protected_control.Reader,
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,
    datagram_batch_scratch: datagram_send.DevelopmentBatchScratch = .{},

    pub fn applicationProtocol(self: ClientSession) ?application_protocol.String {
        return application_protocol.selected(self.response.headers);
    }

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
        if (options.limits.require_session_flow_control) return error.SessionFlowControlRequired;
        if (options.limits.initial_flow_limits != null) return error.WebTransportNotNegotiated;
        try connect_headers.validate(options.headers, .request);
        var offer = try application_protocol.Request.init(allocator, options.limits.application_protocols, options.headers);
        defer offer.deinit(allocator);
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareRequestWithOffer(
            allocator,
            options.origin,
            options.headers,
            &header_stack,
            .legacy,
            &offer,
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
        var protocol_failure = false;
        errdefer if (!protocol_failure) h3_client.cancelRequest(session_stream_id, http3.ApplicationErrorCode.request_cancelled) catch {};
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
        if (response.head.status >= 200 and response.head.status < 300) {
            _ = offer.validateResponse(response.head.headers) catch |err| {
                protocol_failure = true;
                try h3_client.cancelRequest(session_stream_id, webtransport.ApplicationErrorCode.alpn_error);
                return err;
            };
        }
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
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
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
        self.datagram_batch_scratch.deinit(
            self.h3.quic_client.endpoint.allocator,
        );
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

    pub fn openLocalStream(
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

    pub fn sendStreamWithTimeout(
        self: *ClientSession,
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
            .fromNow(self.h3.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamWithDeadline(
        self: *ClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        const stream = try developmentWritableStream(&self.streams, stream_id);
        if (!stream.prefix_sent) {
            var storage: [16]u8 = undefined;
            self.h3.sendDevelopmentStreamPartsWithDeadline(
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
        self.h3.sendDevelopmentStreamWithDeadline(
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

    pub fn sendDatagramWithTimeout(
        self: *ClientSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(payload, .fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramWithDeadline(
        self: *ClientSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return sendDatagramFromEndpointWithDeadline(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.session_id,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *ClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        try self.control.control.ensureOpen();
        return datagram_send.developmentBatch(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *ClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(
            payloads,
            committed_count,
            .fromNow(self.h3.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *ClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return datagram_send.developmentBatchWithDeadline(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(self: ClientSession) ?usize {
        return datagram_send.developmentPayloadLimit(
            self.h3.quic_client.endpoint.limits.max_datagram_size,
            self.session_id,
        );
    }

    pub fn maxDatagramSize(self: ClientSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
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

    pub fn sendSessionDataWithTimeout(
        self: *ClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyWithTimeout(
            self.session_id.value,
            data,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *ClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyWithDeadline(
            self.session_id.value,
            data,
            fin,
            progress,
            deadline,
        );
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
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        self.h3.sendRequestBody(
            self.session_id.value,
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
        self: *ClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *ClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
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
        self.h3.sendRequestBodyWithDeadline(
            self.session_id.value,
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
        self: *ClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        self.h3.sendRequestBody(
            self.session_id.value,
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
        self: *ClientSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn closeWithDeadline(
        self: *ClientSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
        self.h3.sendRequestBodyWithDeadline(
            self.session_id.value,
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
        self: *ClientSession,
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
            self.h3.quic_client.endpoint.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.control.beginLocalClose();
        self.pending_close = pending;
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
                try session_control.Control.init(
                    self.h3.?.quic_client.endpoint.allocator,
                    self.session_id,
                ),
            ),
        };
        self.* = undefined;
        return session;
    }
};

pub const HandshakeClientSession = @import("runtime/handshake_client_session.zig").HandshakeClientSession;

fn retainedClientLimits(limits: Limits) Limits {
    var retained = limits;
    retained.application_protocols.values = &.{};
    return retained;
}

pub fn beginPendingConnect(h3: *http3.runtime.HandshakeClient, authority: []const u8, path: []const u8, origin: []const u8, additional: []const http3.Qpack.HeaderField, limits: Limits, deadline: ?std.Io.Clock.Timestamp) Error!PendingHandshakeConnect {
    try @import("settings/flow.zig").validateExisting(h3.options.local_settings, limits.initial_flow_limits);
    try @import("settings/flow.zig").validateRequired(h3.options.local_settings, limits.require_session_flow_control);
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
    try connect_headers.validate(additional, .request);
    try connect_negotiation.ensureCanStart(h3);
    var offer = try application_protocol.Request.init(h3.allocator, limits.application_protocols, additional);
    errdefer offer.deinit(h3.allocator);
    var queued = try pending_connect_request.Request.initWithOffer(h3.allocator, authority, path, origin, additional, &offer);
    errdefer queued.deinit(h3.allocator);
    var preface: pending_connect_preface.State = .{};
    errdefer preface.deinit(h3.allocator);
    _ = preface.poll(h3) catch |err| switch (err) {
        error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked, error.StreamLimitExceeded => false,
        else => return err,
    };
    return .{ .h3 = h3.*, .session_id = .init(h3.next_stream_id), .limits = retainedClientLimits(limits), .queued_connect = queued, .connect_deadline = deadline, .preface = preface, .protocol_offer = offer };
}

/// A dispatcher-driven WebTransport CONNECT whose final response has not yet
/// arrived. Promotion APIs can update a dispatcher atomically so its route
/// never points at moved-from QUIC connection storage.
pub const PendingHandshakeConnect = struct {
    h3: ?http3.runtime.HandshakeClient,
    session_id: webtransport.SessionId,
    limits: Limits,
    queued_connect: ?pending_connect_request.Request = null,
    protocol_offer: application_protocol.Request = .{},
    protocol_rejection: ?protocol_negotiation.Rejection = null,
    preface: pending_connect_preface.State = .{},
    connect_deadline: ?std.Io.Clock.Timestamp = null,
    pending_datagram_registered: bool = false,
    rejection: ?HandshakeConnectResponse = null,
    rejection_body: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *PendingHandshakeConnect) void {
        if (self.h3) |*h3| {
            if (self.queued_connect) |*queued| queued.deinit(h3.allocator);
            self.protocol_offer.deinit(h3.allocator);
            self.preface.deinit(h3.allocator);
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
        if (self.queued_connect != null) return self.h3.?.processResponsePacket(packet);
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
        self.protocol_offer.deinit(self.h3.?.allocator);
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
            .deadline = self.connect_deadline,
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
            if (self.protocol_rejection != null and err != error.ApplicationProtocolNegotiationFailed) {
                dispatcher.refreshConnectionTimer(handle) catch return error.InvalidDispatcherState;
                return err;
            }
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
        self.protocol_offer.deinit(self.h3.?.allocator);
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
            .deadline = self.connect_deadline,
        };
    }

    fn pollConnectResponse(
        self: *PendingHandshakeConnect,
        single_attempt: bool,
    ) Error!?HandshakeConnectResponse {
        const h3 = &self.h3.?;
        if (self.protocol_rejection) |*rejection| {
            if (!try rejection.poll(h3)) return null;
            return error.ApplicationProtocolNegotiationFailed;
        }
        if (self.queued_connect) |*queued| {
            if (self.connect_deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
            const preface_ready = self.preface.poll(h3) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked, error.StreamLimitExceeded => return null,
                else => return err,
            };
            if (!preface_ready or !h3.control.settings.received) return null;
            const version = try connect_negotiation.clientVersionWithPolicy(h3, self.limits.require_session_flow_control);
            const complete = queued.submit(h3, version, self.session_id.value) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked, error.StreamLimitExceeded => return null,
                else => return err,
            };
            if (!complete) return null;
            queued.deinit(h3.allocator);
            self.preface.deinit(h3.allocator);
            self.queued_connect = null;
        }
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
                _ = self.protocol_offer.validateResponse(head.headers) catch {
                    head.deinit(h3.allocator);
                    self.protocol_rejection = .{ .stream_id = self.session_id.value };
                    if (!try self.protocol_rejection.?.poll(h3)) return null;
                    return error.ApplicationProtocolNegotiationFailed;
                };
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
    deadline: ?std.Io.Clock.Timestamp = null,
    early_streams: early_streams.State = .{},
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
        self.early_streams.deinit(allocator);
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
        _ = try connect_negotiation.clientVersionWithPolicy(h3, self.limits.require_session_flow_control);
        self.early_streams.limits = self.limits.early_connect_streams;
        if (single_attempt) {
            if (!try early_streams.classifyBeforeAdmissionOnce(
                &self.early_streams,
                h3.allocator,
                &h3.established.connection,
                early_streams.standaloneOwners(),
            )) return error.PacingLimited;
        } else {
            try early_streams.classifyBeforeAdmission(
                &self.early_streams,
                h3.allocator,
                &h3.established.connection,
                early_streams.standaloneOwners(),
                self.deadline,
            );
        }
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
        var control = try session_control.Control.init(
            h3.allocator,
            self.session_id,
        );
        if (single_attempt)
            try h3.detachResponseStreamOnce(self.session_id.value)
        else
            try h3.detachResponseStream(self.session_id.value);
        connection_lifecycle.activate(&control, h3, &streams);
        const session = HandshakeClientSession{
            .h3 = h3.*,
            .session_id = self.session_id,
            .response = self.response,
            .streams = streams,
            .control = control,
        };
        self.early_streams.deinit(h3.allocator);
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
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,
    datagram_batch_scratch: datagram_send.ProtectedBatchScratch = .{},

    pub fn applicationProtocol(self: ProtectedClientSession) ?application_protocol.String {
        return application_protocol.selected(self.response.headers);
    }

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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
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
        try connect_headers.validate(options.headers, .request);
        var offer = try application_protocol.Request.init(allocator, options.limits.application_protocols, options.headers);
        defer offer.deinit(allocator);
        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_headers = try connect_headers.prepareRequestWithOffer(
            allocator,
            options.origin,
            options.headers,
            &header_stack,
            .legacy,
            &offer,
        );
        defer prepared_headers.deinit(allocator);
        var h3_client = try http3.runtime.ProtectedClient.connect(allocator, io, local_address, server, options.limits.http3, try connect_configuration.protected(options.config, options.limits));
        errdefer h3_client.deinit();
        const session_stream_id = try h3_client.startRequest(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = prepared_headers.fields,
        }, null);
        var protocol_failure = false;
        errdefer if (!protocol_failure) h3_client.cancelRequest(session_stream_id, http3.ApplicationErrorCode.request_cancelled) catch {};
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
            _ = offer.validateResponse(response.head.headers) catch |err| {
                protocol_failure = true;
                try h3_client.cancelRequest(session_stream_id, webtransport.ApplicationErrorCode.alpn_error);
                return err;
            };
        }
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
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
        self.datagram_batch_scratch.deinit(
            self.h3.quic_client.endpoint.allocator,
        );
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

    pub fn sendDatagramWithTimeout(
        self: *ProtectedClientSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(payload, .fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramWithDeadline(
        self: *ProtectedClientSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        try sendProtectedDatagramFromEndpointWithDeadline(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            self.session_id,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *ProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return datagram_send.protectedBatch(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            self.session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *ProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(
            payloads,
            committed_count,
            .fromNow(self.h3.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *ProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.config.local_settings,
            self.h3.control.settings.peer,
        );
        return datagram_send.protectedBatchWithDeadline(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            self.session_id,
            payloads,
            committed_count,
            &self.datagram_batch_scratch,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(
        self: ProtectedClientSession,
    ) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return datagram_send.protectedPayloadLimit(
            self.h3.quic_client.endpoint.limits.max_datagram_size,
            self.h3.config.peer_connection_id.len,
            self.h3.next_packet_number,
            self.session_id,
        );
    }

    pub fn maxDatagramSize(self: ProtectedClientSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
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

    pub fn sendSessionDataWithTimeout(
        self: *ProtectedClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyPacedWithTimeout(
            self.session_id.value,
            data,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *ProtectedClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyPacedWithDeadline(
            self.session_id.value,
            data,
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendSessionDataSlices(
        self: *ProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyPartsPaced(
            self.session_id.value,
            parts,
            fin,
        );
    }

    /// Send borrowed Capsule Protocol slices without joining them. On error,
    /// `progress.committed_bytes` is the exact socket-visible prefix across
    /// the concatenation of `parts`, so callers can retry only its suffix.
    pub fn sendSessionDataSlicesWithTimeout(
        self: *ProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyPartsPacedWithTimeout(
            self.session_id.value,
            parts,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataSlicesWithDeadline(
        self: *ProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        try self.control.control.ensureOpen();
        return self.h3.sendRequestBodyPartsPacedWithDeadline(
            self.session_id.value,
            parts,
            fin,
            progress,
            deadline,
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
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        try self.h3.sendRequestBody(
            self.session_id.value,
            pending.bytes[pending.committed..pending.len],
            false,
        );
        self.pending_drain = null;
        try self.control.control.recordLocalDrain();
    }

    pub fn drainWithTimeout(
        self: *ProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *ProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
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
        self.h3.sendRequestBodyPacedWithDeadline(
            self.session_id.value,
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
        self: *ProtectedClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        self.h3.sendRequestBody(
            self.session_id.value,
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
        self: *ProtectedClientSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(
            self.h3.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn closeWithDeadline(
        self: *ProtectedClientSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.quic_client.endpoint.io,
            deadline,
        );
        if (self.control.control.local_close_sent or
            self.control.control.local_close_failed) return;
        try self.preparePendingClose(code, reason);
        const pending = &self.pending_close.?;
        var progress: http3.runtime.BodyWriteProgress = .{};
        self.h3.sendRequestBodyPacedWithDeadline(
            self.session_id.value,
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
        self: *ProtectedClientSession,
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
            self.h3.quic_client.endpoint.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.control.beginLocalClose();
        self.pending_close = pending;
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
            try session_control.Control.init(
                self.h3.?.quic_client.endpoint.allocator,
                self.session_id,
            ),
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

fn receiveProtectedServerEvent(
    server: *ProtectedServer,
    session: *AcceptedProtectedSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (session.pending_session_event == null) {
        session.pending_session_event = try @import("runtime/session_control/received_event.zig").receive(&server.h3, &session.control, session.session_id.value, deadline);
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

fn receiveProtectedClientEvent(
    session: *ProtectedClientSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (session.pending_session_event == null) {
        session.pending_session_event = try @import("runtime/session_control/received_event.zig").receive(&session.h3, &session.control, session.session_id.value, deadline);
    }
    const event = session.pending_session_event.?;
    if (deadline) |absolute| {
        try finishProtectedClientEventWithDeadline(
            session,
            event,
            absolute,
        );
    } else {
        try finishProtectedClientEvent(session, event);
    }
    session.pending_session_event = null;
    return event;
}

fn finishProtectedClientEvent(
    session: *ProtectedClientSession,
    event: SessionEvent,
) Error!void {
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
}

fn finishProtectedClientEventWithDeadline(
    session: *ProtectedClientSession,
    event: SessionEvent,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    if (event != .closed or
        session.control.control.local_close_sent or
        session.pending_close != null) return;
    var progress: http3.runtime.BodyWriteProgress = .{};
    session.h3.sendRequestBodyPacedWithDeadline(
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

fn receiveDevelopmentClientEvent(
    session: *ClientSession,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!SessionEvent {
    if (session.pending_session_event == null) {
        if (try session.control.pollPending()) |event| {
            session.pending_session_event = event;
        } else {
            var buffer: [protected_control.buffer_capacity]u8 = undefined;
            while (session.pending_session_event == null) {
                const read = if (deadline) |absolute|
                    try session.receiveSessionDataWithDeadline(
                        &buffer,
                        absolute,
                    )
                else
                    try session.receiveSessionData(&buffer);
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
        try finishDevelopmentClientEventWithDeadline(
            session,
            event,
            absolute,
        );
    } else {
        try finishDevelopmentClientEvent(session, event);
    }
    session.pending_session_event = null;
    return event;
}

fn finishDevelopmentClientEvent(
    session: *ClientSession,
    event: SessionEvent,
) Error!void {
    if (event == .closed and
        !session.control.control.local_close_sent and
        !session.control.control.local_close_failed and
        session.pending_close == null)
    {
        // The control parser already transitioned the public session state to
        // closed. Send the mandatory empty FIN directly through HTTP/3 so the
        // reply does not trip the public open-state guard.
        session.h3.sendRequestBody(
            session.session_id.value,
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
        session.h3.closeDevelopmentSession(development_stream.match(
            &session.streams,
            session.session_id,
            .client,
        ));
    }
}

fn finishDevelopmentClientEventWithDeadline(
    session: *ClientSession,
    event: SessionEvent,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    if (event == .closed and
        !session.control.control.local_close_sent and
        !session.control.control.local_close_failed and
        session.pending_close == null)
    {
        var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
        session.h3.sendRequestBodyWithDeadline(
            session.session_id.value,
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
        session.h3.closeDevelopmentSession(development_stream.match(
            &session.streams,
            session.session_id,
            .client,
        ));
    }
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
    /// HTTP/3 transport policy, including the optional WebTransport URI
    /// resolver. Literal IP hosts bypass it; returned addresses do not replace
    /// URI authority or TLS identity.
    h3: http3.runtime.HandshakeClientOptions,
    /// Route QUIC through SOCKS5 UDP ASSOCIATE without locally resolving the
    /// URI host. TLS and `:authority` remain bound to the WebTransport URL.
    socks5_proxy: ?http3.socks5_runtime.Proxy = null,
};

pub const EstablishedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeSessionOptions = .{},
};

pub const StatefulProtectedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    limits: Limits = .{},
    h3: http3.runtime.HandshakeSessionOptions = .{},
    transport: quic.handshake.PreconfiguredConnectionOptions,
};

pub const StatefulProtectedClientSession = @import("runtime/stateful_protected_client_session.zig").StatefulProtectedClientSession;

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

pub fn connectStatefulAttempt(
    h3_client: *http3.runtime.HandshakeClient,
    authority: []const u8,
    path: []const u8,
    origin: []const u8,
    additional_headers: []const http3.Qpack.HeaderField,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeClient,
) Error!HandshakeConnectAttempt {
    try @import("settings/flow.zig").validateExisting(h3_client.options.local_settings, limits.initial_flow_limits);
    try @import("settings/flow.zig").validateRequired(h3_client.options.local_settings, limits.require_session_flow_control);
    try connect_headers.validate(additional_headers, .request);
    const allocator = h3_client.allocator;
    var offer = try application_protocol.Request.init(allocator, limits.application_protocols, additional_headers);
    defer offer.deinit(allocator);
    const session_id = try startStatefulConnect(
        h3_client,
        authority,
        path,
        origin,
        additional_headers,
        limits.require_session_flow_control,
        deadline,
        &offer,
    );
    var protocol_failure = false;
    errdefer if (restore_to != null) {
        if (protocol_failure) h3_client.tryCancelRequest(session_id.value, webtransport.ApplicationErrorCode.alpn_error) catch {} else h3_client.abandonExtendedConnect(session_id.value);
    };
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
    if (response.head.status >= 200 and response.head.status < 300) {
        protocol_negotiation.validateResponse(h3_client, session_id.value, &offer, response.head, deadline) catch |err| {
            protocol_failure = true;
            return err;
        };
        // A successful Extended CONNECT keeps its response stream open while
        // ownership moves from HTTP/3 to WebTransport. Flush the response
        // HEAD's delayed ACK before that boundary so a short-lived server can
        // retire its response recovery state even if the application does not
        // immediately drive another receive. Dispatcher promotion uses its
        // non-blocking poll path instead of this synchronous helper.
        if (deadline) |absolute|
            _ = try h3_client.established.connection
                .flushPendingAckWithDeadline(absolute)
        else
            _ = try h3_client.established.connection.flushPendingAck();
    }
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
        .limits = retainedClientLimits(limits),
        .deadline = deadline,
    };
}

fn startStatefulConnect(
    h3_client: *http3.runtime.HandshakeClient,
    authority: []const u8,
    path: []const u8,
    origin: []const u8,
    additional_headers: []const http3.Qpack.HeaderField,
    required_flow_control: bool,
    deadline: ?std.Io.Clock.Timestamp,
    offer: *const application_protocol.Request,
) Error!webtransport.SessionId {
    try connect_headers.validate(additional_headers, .request);
    const version = try connect_negotiation.prepareClient(h3_client, deadline);
    try connect_negotiation.requireFlowControl(h3_client.options.local_settings, h3_client.control.settings.peer, required_flow_control);
    const allocator = h3_client.allocator;
    var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
        undefined;
    var prepared_headers = try connect_headers.prepareRequestWithOffer(
        allocator,
        origin,
        additional_headers,
        &header_stack,
        version,
        offer,
    );
    defer prepared_headers.deinit(allocator);
    const request = http3.Request{
        .method = "CONNECT",
        .path = path,
        .scheme = "https",
        .authority = authority,
        .headers = prepared_headers.fields,
    };
    const stream_id = if (deadline) |absolute| try h3_client.startRequestWithDeadline(request, null, absolute) else try h3_client.startRequest(request, null);
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
    // Local policy is decided by PendingHandshakeSession.accept, where a
    // failed cancellation can retain both the request and transport owner.
    try connect_rejection.validate(session, request.stream_id, request.head, deadline);
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
    try connect_negotiation.waitServerSettings(session, deadline);
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

pub fn finalizeRejectionBody(
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
pub const validateAdditionalConnectHeaders = connect_headers.validate;
const validateOptionalCapsuleProtocol =
    connect_headers.validateOptionalCapsule;

pub const OwnedDatagram = datagram_owned.Datagram;
pub const OwnedProtectedDatagram = datagram_owned.Protected;
pub const OwnedHandshakeDatagram = datagram_owned.Handshake;
pub const OwnedHandshakeDatagramBatch = datagram_owned.HandshakeBatch;
const parseDatagramFromOwnedQuicDatagram = datagram_owned.parseQuic;

pub const handshake_stream = @import("runtime/stream.zig");
pub const incremental_stream = @import("runtime/stream_incremental.zig");
pub const OwnedHandshakeStream = handshake_stream.OwnedHandshakeStream;
pub const StreamRead = incremental_stream.Read;
pub const StreamWrite = stream_batch.Write;
pub const StreamWriteResult = stream_batch.Result;
/// Narrow white-box hooks for deterministic CPU regression benchmarks.
pub const testing = struct {
    pub const stream_batch = @import("runtime/stream/batch.zig").testing;

    pub const PendingCloseProgress = struct {
        committed: usize,
        total: usize,
    };

    pub fn pendingCloseProgress(
        session: anytype,
    ) ?PendingCloseProgress {
        const pending = session.pending_close orelse return null;
        return .{
            .committed = pending.committed,
            .total = pending.len,
        };
    }

    pub fn pendingDrainProgress(
        session: anytype,
    ) ?PendingCloseProgress {
        const pending = session.pending_drain orelse return null;
        return .{
            .committed = pending.committed,
            .total = pending.len,
        };
    }

    pub fn localCloseSent(session: anytype) bool {
        return session.control.local_close_sent;
    }

    pub fn localCloseFailed(session: anytype) bool {
        return session.control.local_close_failed;
    }

    pub fn hasPendingSessionEvent(session: anytype) bool {
        return session.pending_session_event != null;
    }

    pub fn classifyTerminalSessionBodySendError(err: anyerror) bool {
        return terminalSessionBodySendError(err);
    }
};

pub fn testBodyPartsSuffix(
    parts: []const []const u8,
    committed: usize,
    storage: [][]const u8,
) []const []const u8 {
    std.debug.assert(storage.len >= parts.len);
    var skip = committed;
    var count: usize = 0;
    for (parts) |part| {
        if (skip >= part.len) {
            skip -= part.len;
            continue;
        }
        storage[count] = part[skip..];
        count += 1;
        skip = 0;
    }
    std.debug.assert(skip == 0);
    return storage[0..count];
}

pub const SessionEvent = session_control.Event;
const initHandshakeStreamRegistry = handshake_stream.initRegistry;
const sendHandshakeSessionStream = handshake_stream.send;
const receiveHandshakeSessionStream = handshake_stream.receive;
const receiveHandshakeSessionStreamWithDeadline =
    handshake_stream.receiveWithDeadline;
const readHandshakeSessionStream = incremental_stream.read;
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
const sendDatagramFromEndpointWithDeadline =
    datagram_send.developmentWithDeadline;

pub fn receiveHandshakePeerConnectionClose(
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

pub fn receiveHandshakePeerConnectionCloseUntil(
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
pub const ownedHandshakeDatagram = datagram_owned.fromConnect;

/// Wire-only test peer helper. Stateful WebTransport APIs must send through
/// HTTP/3's association registry; this deliberately unregistered connection
/// exists only to generate peer traffic for the bounded-batch regression.
pub fn sendHandshakeDatagramForTest(
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

pub fn receiveManyHandshakeDatagrams(
    control: *session_control.Control,
    h3: anytype,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    count: usize,
) Error!OwnedHandshakeDatagramBatch {
    return receiveManyHandshakeDatagramsUntil(
        control,
        h3,
        registry,
        session_id,
        count,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn receiveManyHandshakeDatagramsUntil(
    control: *session_control.Control,
    h3: anytype,
    registry: *webtransport.StreamRegistry,
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
        const owned = flow_datagram.receiveUntil(control, h3, registry, session_id.value, deadline) catch |err| {
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
const sendProtectedDatagramFromEndpointWithDeadline =
    datagram_send.protectedWithDeadline;

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

pub fn findHeader(headers: []const http3.Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

pub fn preferPeerError(shared: anytype, fallback: anyerror) anyerror {
    if (shared.failed.load(.acquire)) return shared.err.?;
    return fallback;
}

test {
    _ = @import("runtime/tests.zig");
}
