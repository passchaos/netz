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

// Server-side handshake, session, and endpoint types live in runtime/server.zig.
const server_types = @import("runtime/server.zig");

pub const Server = server_types.Server;
pub const ProtectedServer = server_types.ProtectedServer;
pub const PendingSession = server_types.PendingSession;
pub const RejectedSession = server_types.RejectedSession;
pub const PendingProtectedSession = server_types.PendingProtectedSession;
pub const RejectedProtectedSession = server_types.RejectedProtectedSession;
pub const StatefulProtectedServer = server_types.StatefulProtectedServer;
pub const HandshakeServer = server_types.HandshakeServer;
pub const HandshakeAdmission = server_types.HandshakeAdmission;
pub const EndpointPendingSession = server_types.EndpointPendingSession;
pub const EndpointAcceptedSession = server_types.EndpointAcceptedSession;
pub const EndpointSessionEvent = server_types.EndpointSessionEvent;
pub const EndpointSessionKey = server_types.EndpointSessionKey;
pub const EndpointServerEvent = server_types.EndpointServerEvent;
pub const ServeEvent = server_types.ServeEvent;
pub const ServeOptions = server_types.ServeOptions;
pub const EndpointServer = server_types.EndpointServer;
pub const rejectAdditionalHandshakeRequestsOnce = server_types.rejectAdditionalHandshakeRequestsOnce;
pub const AcceptedSession = server_types.AcceptedSession;
pub const OwnedConnectRequest = server_types.OwnedConnectRequest;
pub const AcceptedProtectedSession = server_types.AcceptedProtectedSession;
pub const OwnedProtectedConnectRequest = server_types.OwnedProtectedConnectRequest;
pub const OwnedHandshakeConnectRequest = server_types.OwnedHandshakeConnectRequest;
pub const PendingHandshakeSession = server_types.PendingHandshakeSession;
pub const RejectedHandshakeSession = server_types.RejectedHandshakeSession;
pub const AcceptedHandshakeSession = server_types.AcceptedHandshakeSession;

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
        if (options.limits.initial_flow_limits != null) return error.UnsupportedWebTransportOption;
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

pub fn receiveStatefulSessionRequest(
    session: *http3.runtime.HandshakeServerSession,
    limits: Limits,
) Error!PendingHandshakeSession {
    return receiveStatefulSessionRequestBefore(session, limits, null, null);
}

pub fn receiveStatefulSessionRequestWithDeadline(
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

pub fn receiveStatefulSessionRequestBefore(
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

pub fn receiveProtectedConnectRequest(
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

pub fn receiveProtectedConnectRequestBefore(
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

pub const validateConnectRequest = connect_headers.validateRequest;
pub const validateConnectOrigin = connect_headers.validateOrigin;
pub const connectResponseWithHeaders = connect_headers.response;
const validateConnectResponse = connect_headers.validateResponse;
const AdditionalHeaderContext = connect_headers.Context;
pub const validateAdditionalConnectHeaders = connect_headers.validate;
const validateOptionalCapsuleProtocol =
    connect_headers.validateOptionalCapsule;

pub const OwnedDatagram = datagram_owned.Datagram;
pub const OwnedProtectedDatagram = datagram_owned.Protected;
pub const OwnedHandshakeDatagram = datagram_owned.Handshake;
pub const OwnedHandshakeDatagramBatch = datagram_owned.HandshakeBatch;
pub const parseDatagramFromOwnedQuicDatagram = datagram_owned.parseQuic;

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
pub const initHandshakeStreamRegistry = handshake_stream.initRegistry;
const sendHandshakeSessionStream = handshake_stream.send;
const receiveHandshakeSessionStream = handshake_stream.receive;
const receiveHandshakeSessionStreamWithDeadline =
    handshake_stream.receiveWithDeadline;
const readHandshakeSessionStream = incremental_stream.read;
pub const initDevelopmentStreamRegistry = development_stream.initRegistry;
pub const OwnedDevelopmentStream = development_stream.Owned;

pub fn developmentDirection(
    direction: webtransport.StreamDirection,
) http3.runtime.DevelopmentStreamDirection {
    return switch (direction) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
}

pub fn developmentWritableStream(
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

pub const sendDatagramFromEndpoint = datagram_send.development;
pub const sendDatagramFromEndpointWithDeadline =
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

pub const sendProtectedDatagramFromEndpoint = datagram_send.protected;
pub const sendProtectedDatagramFromEndpointWithDeadline =
    datagram_send.protectedWithDeadline;

pub fn receiveProtectedDatagramFromEndpoint(
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

pub fn receiveProtectedDatagramFromEndpointWithDeadline(
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
