//! WebTransport handshake client session over HTTP/3.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const ConnectOptions = runtime.ConnectOptions;
const Error = runtime.Error;
const EstablishedConnectOptions = runtime.EstablishedConnectOptions;
const HandshakeConnectAttempt = runtime.HandshakeConnectAttempt;
const HandshakeConnectOptions = runtime.HandshakeConnectOptions;
const HandshakeUriConnectOptions = runtime.HandshakeUriConnectOptions;
const OwnedHandshakeDatagram = runtime.OwnedHandshakeDatagram;
const OwnedHandshakeDatagramBatch = runtime.OwnedHandshakeDatagramBatch;
const OwnedHandshakeStream = runtime.OwnedHandshakeStream;
const PendingHandshakeConnect = runtime.PendingHandshakeConnect;
const PendingSessionClose = runtime.PendingSessionClose;
const PendingSessionDrain = runtime.PendingSessionDrain;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionEvent = runtime.SessionEvent;
const StableConnectionId = runtime.StableConnectionId;
const StatefulProtectedConnectOptions = runtime.StatefulProtectedConnectOptions;
const StreamRead = runtime.StreamRead;
const StreamWrite = runtime.StreamWrite;
const StreamWriteResult = runtime.StreamWriteResult;
const application = runtime.application;
const application_protocol = runtime.application_protocol;
const beginPendingConnect = runtime.beginPendingConnect;
const capsule_rejection = runtime.capsule_rejection;
const clearPendingSessionClose = runtime.clearPendingSessionClose;
const connectStatefulAttempt = runtime.connectStatefulAttempt;
const connect_configuration = runtime.connect_configuration;
const connect_negotiation = runtime.connect_negotiation;
const connection_lifecycle = runtime.connection_lifecycle;
const deadline_policy = runtime.deadline_policy;
const findHeader = runtime.findHeader;
const flow_cancel = runtime.flow_cancel;
const flow_datagram = runtime.flow_datagram;
const flow_grant = runtime.flow_grant;
const flow_open = runtime.flow_open;
const flow_read = runtime.flow_read;
const flow_streams = runtime.flow_streams;
const flow_write = runtime.flow_write;
const handshake_stream = runtime.handshake_stream;
const incremental_stream = runtime.incremental_stream;
const max_connection_close_reason = runtime.max_connection_close_reason;
const ownedHandshakeDatagram = runtime.ownedHandshakeDatagram;
const receiveHandshakePeerConnectionClose = runtime.receiveHandshakePeerConnectionClose;
const receiveHandshakePeerConnectionCloseUntil = runtime.receiveHandshakePeerConnectionCloseUntil;
const receiveManyHandshakeDatagrams = runtime.receiveManyHandshakeDatagrams;
const receiveManyHandshakeDatagramsUntil = runtime.receiveManyHandshakeDatagramsUntil;
const session_control = runtime.session_control;
const stream_batch = runtime.stream_batch;
const terminalSessionBodySendError = runtime.terminalSessionBodySendError;
const validateAdditionalConnectHeaders = runtime.validateAdditionalConnectHeaders;

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
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,

    pub fn ensureApplicationSendOpen(
        self: *HandshakeClientSession,
    ) Error!void {
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try application.ensureOpen(&self.control, &self.h3, &self.streams);
    }

    /// Open WebTransport on an existing authenticated HTTP/3 connection. The
    /// caller retains `h3` on failure and transfers it on success.
    pub fn applicationProtocol(self: HandshakeClientSession) ?application_protocol.String {
        return application_protocol.selected(self.response.headers);
    }

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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        var h3_client = try http3.runtime.HandshakeClient.connect(allocator, io, local_address, server, options.limits.http3, try connect_configuration.client(options.h3, options.limits));
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        var h3_client = try http3.runtime.HandshakeClient.connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options.limits.http3,
            try connect_configuration.client(options.h3, options.limits),
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        var h3_client = try http3.runtime.HandshakeClient.connectFrom(
            endpoint,
            source,
            server,
            try connect_configuration.client(options.h3, options.limits),
        );
        errdefer h3_client.deinit();
        return beginPendingConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            null,
        );
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
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
            try connect_configuration.client(options.h3, options.limits),
            absolute,
        );
        errdefer h3_client.deinit();
        _ = try deadline_policy.usableAwake(endpoint.io, absolute);
        return beginPendingConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            absolute,
        );
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        var endpoint = try http3.runtime.uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try http3.runtime.uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);

        var h3_options = options.h3;
        if (h3_options.handshake.server_name == null) {
            h3_options.handshake.server_name = endpoint.tls_host;
        }
        const effective_h3 = try connect_configuration.client(h3_options, options.limits);
        var h3_client = if (options.socks5_proxy) |proxy|
            try http3.socks5_runtime.connectHost(
                allocator,
                io,
                local_address,
                proxy,
                endpoint.tls_host,
                endpoint.port,
                options.limits.http3,
                effective_h3,
            )
        else
            try http3.runtime.HandshakeClient.connectUri(
                allocator,
                io,
                local_address,
                uri,
                options.limits.http3,
                effective_h3,
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        var endpoint = try http3.runtime.uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try http3.runtime.uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);

        var h3_options = options.h3;
        if (h3_options.handshake.server_name == null) {
            h3_options.handshake.server_name = endpoint.tls_host;
        }
        const effective_h3 = try connect_configuration.client(h3_options, options.limits);
        var h3_client = if (options.socks5_proxy) |proxy|
            try http3.socks5_runtime.connectHostWithDeadline(
                allocator,
                io,
                local_address,
                proxy,
                endpoint.tls_host,
                endpoint.port,
                options.limits.http3,
                effective_h3,
                deadline,
            )
        else
            try http3.runtime.HandshakeClient.connectUriWithDeadline(
                allocator,
                io,
                local_address,
                uri,
                options.limits.http3,
                effective_h3,
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        const h3_options = try connect_configuration.session(options.h3, options.limits);
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
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        var h3_client = try http3.runtime.HandshakeClient.initEstablished(
            endpoint,
            server,
            established,
            try connect_configuration.session(options.h3, options.limits),
        );
        errdefer h3_client.deinit();
        return beginPendingConnect(
            &h3_client,
            options.authority,
            options.path,
            options.origin,
            options.headers,
            options.limits,
            null,
        );
    }

    pub fn deinit(self: *HandshakeClientSession) void {
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
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

    pub fn stableId(self: *const HandshakeClientSession) StableConnectionId {
        return self.h3.established.connection.stableId();
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
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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

    /// QUIC mandates TLS 1.3; the optional shape matches the other transports.
    pub fn negotiatedTlsProtocol(
        self: HandshakeClientSession,
    ) ?tls_stream.Protocol {
        _ = self;
        return .tls13;
    }

    pub fn wasTlsSessionResumed(self: HandshakeClientSession) ?bool {
        return self.h3.established.resumed;
    }

    /// Whether the peer accepted, rejected or did not receive a 0-RTT offer
    /// on the underlying QUIC connection.
    pub fn earlyDataStatus(
        self: HandshakeClientSession,
    ) @TypeOf(self.h3.established.early_data_status) {
        return self.h3.established.early_data_status;
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
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = if (self.dispatcher != null)
            self.h3.trySendConnectDatagram(self.session_id.value, payload)
        else
            flow_datagram.sendDatagram(&self.control, &self.h3, &self.streams, self.session_id.value, payload);
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
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = if (self.dispatcher != null)
            self.h3.trySendConnectDatagramWithDeadline(
                self.session_id.value,
                payload,
                deadline,
            )
        else
            flow_datagram.sendWithDeadline(
                &self.control,
                &self.h3,
                &self.streams,
                self.session_id.value,
                payload,
                deadline,
            );
        try self.refreshDispatcherTimer();
        try result;
    }

    /// Submit at most one ordered DATAGRAM socket batch. This form remains
    /// nonblocking when the session belongs to a shared endpoint dispatcher.
    pub fn sendDatagrams(
        self: *HandshakeClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const result = if (self.dispatcher != null)
            self.h3.trySendConnectDatagrams(
                self.session_id.value,
                payloads,
                committed_count,
            )
        else
            flow_datagram.sendDatagrams(
                &self.control,
                &self.h3,
                &self.streams,
                self.session_id.value,
                payloads,
                committed_count,
            );
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn sendDatagramsWithTimeout(
        self: *HandshakeClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(payloads, committed_count, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramsWithDeadline(
        self: *HandshakeClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.sendManyWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            payloads,
            committed_count,
            deadline,
        );
    }

    /// Send Capsule Protocol bytes on this Session's Extended CONNECT stream.
    pub fn sendSessionData(
        self: *HandshakeClientSession,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = if (self.dispatcher != null)
            self.h3.trySendRequestBody(
                self.session_id.value,
                data,
                fin,
            )
        else
            self.h3.sendRequestBodyPaced(
                self.session_id.value,
                data,
                fin,
            );
        try self.refreshDispatcherTimer();
        return result;
    }

    pub fn sendSessionDataWithTimeout(
        self: *HandshakeClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.sendSessionDataSlicesWithTimeout(
            &.{data},
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *HandshakeClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendSessionDataSlicesWithDeadline(
            &.{data},
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendSessionDataSlices(
        self: *HandshakeClientSession,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = if (self.dispatcher != null)
            self.h3.trySendRequestBodyParts(
                self.session_id.value,
                parts,
                fin,
            )
        else
            self.h3.sendRequestBodyPartsPaced(
                self.session_id.value,
                parts,
                fin,
            );
        try self.refreshDispatcherTimer();
        return result;
    }

    /// Send borrowed Capsule Protocol slices on this Extended CONNECT stream
    /// under one timeout. Dispatcher-bound sessions use their nonblocking
    /// event-loop send path and therefore reject this blocking API.
    pub fn sendSessionDataSlicesWithTimeout(
        self: *HandshakeClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return self.h3.sendRequestBodyPartsPacedWithTimeout(
            self.session_id.value,
            parts,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataSlicesWithDeadline(
        self: *HandshakeClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return self.h3.sendRequestBodyPartsPacedWithDeadline(
            self.session_id.value,
            parts,
            fin,
            progress,
            deadline,
        );
    }

    pub fn receiveDatagram(self: *HandshakeClientSession) Error!OwnedHandshakeDatagram {
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return ownedHandshakeDatagram(
            try flow_datagram.receive(&self.control, &self.h3, &self.streams, self.session_id.value),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return ownedHandshakeDatagram(
            try flow_datagram.receiveWithTimeout(
                &self.control,
                &self.h3,
                &self.streams,
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
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return ownedHandshakeDatagram(
            try flow_datagram.receiveWithDeadline(
                &self.control,
                &self.h3,
                &self.streams,
                self.session_id.value,
                deadline,
            ),
            self.session_id,
        );
    }

    /// Receive one application DATAGRAM directly into caller storage. The
    /// returned slice aliases `output`; queued payloads remain retryable when
    /// the supplied buffer is too short.
    pub fn receiveDatagramInto(
        self: *HandshakeClientSession,
        output: []u8,
    ) Error![]u8 {
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveInto(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            output,
        );
    }

    pub fn receiveDatagramIntoWithTimeout(
        self: *HandshakeClientSession,
        output: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError![]u8 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveIntoWithTimeout(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            output,
            timeout,
        );
    }

    pub fn receiveDatagramIntoWithDeadline(
        self: *HandshakeClientSession,
        output: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError![]u8 {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveIntoWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            output,
            deadline,
        );
    }

    /// Fill an arrival-ordered caller-owned DATAGRAM batch. On failure,
    /// `received_count` identifies the exact completed output prefix.
    pub fn receiveDatagramsInto(
        self: *HandshakeClientSession,
        outputs: [][]u8,
        received_count: *usize,
    ) Error!void {
        received_count.* = 0;
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveManyInto(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            outputs,
            received_count,
        );
    }

    pub fn receiveDatagramsIntoWithTimeout(
        self: *HandshakeClientSession,
        outputs: [][]u8,
        received_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveManyIntoWithTimeout(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            outputs,
            received_count,
            timeout,
        );
    }

    pub fn receiveDatagramsIntoWithDeadline(
        self: *HandshakeClientSession,
        outputs: [][]u8,
        received_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveManyIntoWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            outputs,
            received_count,
            deadline,
        );
    }

    /// Poll a queued DATAGRAM for this session without reading UDP.
    pub fn pollDatagram(
        self: *HandshakeClientSession,
    ) Error!?OwnedHandshakeDatagram {
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try connect_negotiation.ensure(&self.h3);
        if (!try self.prepareDispatcherPoll()) return null;
        const result = flow_datagram.poll(
            &self.control,
            &self.h3,
            &self.streams,
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
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return receiveManyHandshakeDatagrams(
            &self.control,
            &self.h3,
            &self.streams,
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
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connect_negotiation.ensure(&self.h3);
        return receiveManyHandshakeDatagramsUntil(
            &self.control,
            &self.h3,
            &self.streams,
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
        connect_negotiation.ensure(&self.h3) catch return false;
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
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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

    pub fn openLocalStream(
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
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try connect_negotiation.ensure(&self.h3);
        // Registry capacity and the cumulative WT cap are fallible, so reserve
        // them before consuming either the H3 or transport stream-ID cursor.
        return flow_open.open(&self.control, &self.h3, &self.streams, direction, deadline, false);
    }

    fn openLocalStreamOnce(
        self: *HandshakeClientSession,
        direction: webtransport.StreamDirection,
    ) Error!u62 {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try connect_negotiation.ensure(&self.h3);
        return flow_open.open(&self.control, &self.h3, &self.streams, direction, null, true) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn sendStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
            try flow_write.send(
                &self.control,
                &self.h3,
                &self.streams,
                self.session_id,
                stream_id,
                payload,
                fin,
            );
        }
    }

    pub fn sendStreamWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(
            stream_id,
            payload,
            fin,
            committed,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.sendWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
            committed,
            deadline,
        );
    }

    pub fn sendStreamSlices(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) {
            const result = handshake_stream.sendSlicesOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
                parts,
                fin,
            );
            try self.refreshDispatcherTimer();
            return result;
        }
        return flow_write.sendSlices(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            fin,
        );
    }

    pub fn sendStreamSlicesWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(
            stream_id,
            parts,
            fin,
            committed,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamSlicesWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.sendSlicesWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            fin,
            committed,
            deadline,
        );
    }

    pub fn writeStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        return flow_write.write(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
    }

    pub fn writeStreamWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamWithDeadline(
            stream_id,
            payload,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.writeWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            deadline,
        );
    }

    pub fn writeStreamSlices(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
    ) Error!usize {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) {
            const result = handshake_stream.writeSlicesOnce(
                &self.h3.established.connection,
                &self.streams,
                self.session_id,
                stream_id,
                parts,
            );
            try self.refreshDispatcherTimer();
            return result;
        }
        return flow_write.writeSlices(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
        );
    }

    pub fn writeStreamSlicesWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamSlicesWithDeadline(
            stream_id,
            parts,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamSlicesWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        parts: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.writeSlicesWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            deadline,
        );
    }

    pub fn setStreamPriority(
        self: *HandshakeClientSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        return flow_write.writeStreams(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
    }

    pub fn writeStreamsWithTimeout(
        self: *HandshakeClientSession,
        writes: []const StreamWrite,
        counts: []usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamWriteResult {
        if (counts.len < writes.len) return error.BufferTooShort;
        @memset(counts[0..writes.len], 0);
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamsWithDeadline(
            writes,
            counts,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamsWithDeadline(
        self: *HandshakeClientSession,
        writes: []const StreamWrite,
        counts: []usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamWriteResult {
        if (counts.len < writes.len) return error.BufferTooShort;
        @memset(counts[0..writes.len], 0);
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.writeStreamsWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            writes,
            counts,
            deadline,
        );
    }

    pub fn finishStream(
        self: *HandshakeClientSession,
        stream_id: u62,
    ) Error!void {
        // Completion means the FIN packet was submitted, not yet acknowledged.
        try self.ensureApplicationSendOpen();
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        return flow_write.finish(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
        );
    }

    pub fn finishStreamWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishStreamWithDeadline(
            stream_id,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn finishStreamWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_write.finishWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            deadline,
        );
    }

    /// Return cumulative QUIC MAX_STREAMS credit for one terminal peer
    /// associated stream without removing its lifetime registry entry.
    pub fn releaseCompletedPeerStream(
        self: *HandshakeClientSession,
        stream_id: u62,
    ) Error!bool {
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (!try flow_streams.shouldReleasePeer(&self.h3.established.connection, &self.streams, stream_id)) return false;
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
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.receive(
            &self.control,
            &self.h3,
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
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.receiveWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
            deadline,
        );
    }

    pub fn pollCompleteStream(
        self: *HandshakeClientSession,
    ) Error!?OwnedHandshakeStream {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = self.h3.processDetachedResponsePacket(
            self.session_id.value,
            packet,
        );
        try self.refreshDispatcherTimer();
        try result;
        if (self.dispatcher != null and
            (self.control.local_close_sent or
                self.control.local_close_failed or
                self.control.terminal_reported))
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
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.read(
            &self.control,
            &self.h3,
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
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.readWithDeadline(
            &self.control,
            &self.h3,
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
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.readWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            out,
            deadline,
        );
    }

    /// Read only `stream_id`, leaving ready sibling streams untouched.
    pub fn readStreamId(
        self: *HandshakeClientSession,
        stream_id: u62,
        out: []u8,
    ) Error!StreamRead {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.readId(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            out,
        );
    }

    pub fn readStreamIdWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return self.readStreamIdWithDeadline(
            stream_id,
            out,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn readStreamIdWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return flow_read.readIdWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            out,
            deadline,
        );
    }

    /// Flush a delayed transport ACK before a one-shot session is torn down.
    pub fn flushPendingAck(self: *HandshakeClientSession) Error!bool {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return self.h3.established.connection.flushPendingAck();
    }

    /// Drive QUIC ACK/loss/PTO processing until every reliable application or
    /// control frame submitted by this session has been acknowledged. Use
    /// this before destroying a short-lived session after its final CLOSE/FIN.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForRecoveryIdleWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try self.h3.waitForRecoveryIdleWithDeadline(deadline);
        _ = try self.h3.established.connection
            .flushPendingAckWithDeadline(deadline);
    }

    pub fn waitForStreamRecoveryIdleWithTimeout(self: *HandshakeClientSession, stream_id: u62, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (self.h3.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForStreamRecoveryIdleWithDeadline(stream_id, .fromNow(self.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn waitForStreamRecoveryIdleWithDeadline(self: *HandshakeClientSession, stream_id: u62, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (self.h3.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
        return @import("stream/recovery.zig").wait(ReceiveTimeoutError, &self.control, &self.h3, &self.streams, stream_id, deadline);
    }

    /// Drive one timer-aware QUIC receive without consuming WebTransport data.
    ///
    /// Event loops waiting on a peer-side terminal condition still need to
    /// process ACK, loss and PTO state after their final local FIN/reset. The
    /// timeout/deadline variants let long-lived workers stop cooperatively
    /// without canceling an in-flight socket receive.
    pub fn serviceTransport(
        self: *HandshakeClientSession,
    ) Error!void {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try self.h3.established.connection.servicePacketServicingTimers();
    }

    /// Process one timer-aware QUIC receive for at most `timeout`.
    /// A non-positive timeout returns `error.Timeout` without reading UDP.
    pub fn serviceTransportWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try self.h3.established.connection
            .servicePacketServicingTimersTimeout(.{ .duration = .{
            .raw = timeout,
            .clock = .awake,
        } });
    }

    /// Process one timer-aware QUIC receive until the awake-clock `deadline`.
    pub fn serviceTransportWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        try self.h3.established.connection
            .servicePacketServicingTimersDeadline(deadline);
    }

    pub fn resetStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = if (self.dispatcher != null)
            incremental_stream.resetOnce(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            )
        else
            flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .reset);
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn resetStreamWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn resetStreamWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .reset, deadline);
    }

    /// Reset after reliably delivering `reliable_size` WebTransport
    /// application bytes; the stream association prefix is accounted for
    /// internally.
    pub fn resetStreamReliably(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
    ) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = if (self.dispatcher != null)
            incremental_stream.resetReliablyOnce(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
                reliable_size,
            )
        else
            flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .{ .reliable = reliable_size });
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn resetStreamReliablyWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamReliablyWithDeadline(
            stream_id,
            application_error_code,
            reliable_size,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn resetStreamReliablyWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .{ .reliable = reliable_size }, deadline);
    }

    pub fn stopStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const result = if (self.dispatcher != null)
            incremental_stream.stopOnce(
                &self.h3.established.connection,
                &self.streams,
                stream_id,
                application_error_code,
            )
        else
            flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .stop);
        try self.refreshDispatcherTimer();
        try result;
    }

    pub fn stopStreamWithTimeout(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopStreamWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn stopStreamWithDeadline(
        self: *HandshakeClientSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .stop, deadline);
    }

    pub fn drain(self: *HandshakeClientSession) Error!void {
        if (self.control.local_drain_sent) return;
        if (self.dispatcher != null) {
            try self.ensureApplicationSendOpen();
            defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
            var encoded: [16]u8 = undefined;
            const capsule = try session_control.writeDrainInto(&encoded);
            const result = self.h3.trySendRequestBody(
                self.session_id.value,
                capsule,
                false,
            );
            try self.refreshDispatcherTimer();
            try result;
            try self.control.recordLocalDrain();
            return;
        }
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        try self.h3.sendRequestBodyPaced(
            self.session_id.value,
            pending.bytes[pending.committed..pending.len],
            false,
        );
        self.pending_drain = null;
        try self.control.recordLocalDrain();
    }

    pub fn drainWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (self.control.local_drain_sent) return;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.beginLocalDrain();
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
                try self.control.recordLocalDrain();
            }
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(pending.committed == pending.len);
        self.pending_drain = null;
        try self.control.recordLocalDrain();
    }

    pub fn close(
        self: *HandshakeClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        if (self.control.local_close_sent or
            self.control.local_close_failed)
        {
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
                return;
            }
            return session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        }
        if (self.pending_drain != null) return error.InvalidSessionState;
        if (self.pending_close != null) return error.InvalidSessionState;
        if (self.dispatcher != null) {
            var encoded: [4 + session_control.max_close_reason + 16]u8 =
                undefined;
            const capsule = try session_control.writeCloseInto(
                &encoded,
                code,
                reason,
            );
            const result = self.h3.trySendRequestBody(
                self.session_id.value,
                capsule,
                true,
            );
            try self.refreshDispatcherTimer();
            try result;
            try self.control.recordLocalClose(code);
            const cleanup = self.advanceTerminalCleanupOnce();
            try self.refreshDispatcherTimer();
            _ = cleanup catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return,
                else => return err,
            };
            return;
        }
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        self.h3.sendRequestBodyPaced(
            self.session_id.value,
            capsule,
            true,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                self.control.recordLocalCloseFailure(code);
            }
            return err;
        };
        // A local FIN does not close the peer-to-client direction. Retain the
        // association so receiveSessionEvent can process the peer's terminal
        // capsule/FIN; finishPolledSessionEvent performs final retirement.
        try self.control.recordLocalClose(code);
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &self.streams,
        );
    }

    pub fn closeWithTimeout(
        self: *HandshakeClientSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send the CLOSE_WEBTRANSPORT_SESSION capsule, CONNECT FIN, and all
    /// associated SESSION_GONE terminal frames under one absolute deadline.
    /// Dispatcher-bound sessions retain their event-loop one-shot close path.
    pub fn closeWithDeadline(
        self: *HandshakeClientSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        if (self.control.local_close_failed) {
            return session_control.terminateStreamsWithDeadline(
                &self.h3.established.connection,
                &self.streams,
                deadline,
            );
        }
        if (!self.control.local_close_sent) {
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
                    try self.control.recordLocalClose(committed_code);
                } else if (terminalSessionBodySendError(err)) {
                    const failed_code = pending.code;
                    clearPendingSessionClose(&self.pending_close);
                    self.control.recordLocalCloseFailure(failed_code);
                }
                return err;
            };
            pending.committed += progress.committed_bytes;
            std.debug.assert(
                pending.committed == pending.len and progress.fin_committed,
            );
            const committed_code = pending.code;
            clearPendingSessionClose(&self.pending_close);
            try self.control.recordLocalClose(committed_code);
        }
        try session_control.terminateStreamsWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            deadline,
        );
    }

    pub fn preparePendingClose(
        self: *HandshakeClientSession,
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
            self.h3.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.beginLocalClose();
        self.pending_close = pending;
    }

    pub fn receiveSessionEvent(
        self: *HandshakeClientSession,
    ) Error!SessionEvent {
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
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
        self.control.bindFlow(self.streams.flow);
        connection_lifecycle.observeGoAway(&self.control, &self.h3);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher == null) {
            if (capsule_rejection.pending(&self.control)) {
                try capsule_rejection.finish(&self.control, &self.h3.established.connection, &self.streams);
                return capsule_rejection.errorFor(&self.control);
            }
            if (self.pending_session_event == null) {
                self.pending_session_event = self.control.poll(
                    &self.h3.established.connection,
                ) catch |err| switch (err) {
                    error.InvalidCapsule, error.FlowControlViolation => {
                        try capsule_rejection.finish(
                            &self.control,
                            &self.h3.established.connection,
                            &self.streams,
                        );
                        return err;
                    },
                    else => {
                        try http3.runtime.closeConnectionForProtocolError(
                            &self.h3.established.connection,
                            err,
                        );
                        return err;
                    },
                };
            }
            const event = self.pending_session_event orelse return null;
            try self.finishPolledSessionEvent(event);
            self.pending_session_event = null;
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
        return self.receiveSessionEventWithDeadline(deadline);
    }

    pub fn receiveSessionEventWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (self.dispatcher != null) return error.InvalidDispatcherState;
        return while (true) {
            if (try self.pollSessionEventWithCleanupDeadline(deadline)) |ready| {
                break ready;
            }
            try self.receiveControlProgressWithDeadline(deadline);
        };
    }

    pub fn pollSessionEventWithCleanupDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?SessionEvent {
        self.control.bindFlow(self.streams.flow);
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        connection_lifecycle.observeGoAway(&self.control, &self.h3);
        if (capsule_rejection.pending(&self.control)) {
            try capsule_rejection.finishWithDeadline(&self.control, &self.h3.established.connection, &self.streams, deadline);
            return capsule_rejection.errorFor(&self.control);
        }
        if (self.pending_session_event == null) {
            self.pending_session_event = self.control.pollWithDeadline(
                &self.h3.established.connection,
                deadline,
            ) catch |err| switch (err) {
                error.InvalidCapsule, error.FlowControlViolation => {
                    try capsule_rejection.finishWithDeadline(
                        &self.control,
                        &self.h3.established.connection,
                        &self.streams,
                        deadline,
                    );
                    return err;
                },
                else => {
                    try http3.runtime.closeConnectionForProtocolError(
                        &self.h3.established.connection,
                        err,
                    );
                    return err;
                },
            };
        }
        const event = self.pending_session_event orelse return null;
        try self.finishPolledSessionEventWithDeadline(event, deadline);
        self.pending_session_event = null;
        return event;
    }

    pub fn finishPolledSessionEvent(
        self: *HandshakeClientSession,
        event: SessionEvent,
    ) Error!void {
        if (connection_lifecycle.observe(&self.control, &self.h3, &self.streams)) return;
        if (event == .closed or event == .reset) {
            _ = try self.control.rejectPostTerminalData(
                &self.h3.established.connection,
            );
            if (event == .closed and
                !self.control.local_close_sent and
                !self.control.local_close_failed)
            {
                // Preserve a partially sent local CLOSE until its explicit
                // continuation; an empty FIN here would truncate its capsule.
                if (self.pending_close == null) {
                    self.h3.sendRequestBodyPaced(
                        self.session_id.value,
                        &.{},
                        true,
                    ) catch |err| {
                        const stream_stats = self.h3.established.connection
                            .sendStreamStats(self.session_id.value);
                        if (stream_stats != null and
                            stream_stats.?.final_size != null)
                        {
                            self.control.local_close_sent = true;
                        }
                        return err;
                    };
                    self.control.local_close_sent = true;
                }
            }
            // Keep the terminal association until deinit so late packets are
            // classified and dropped without reviving application state.
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
            // A caller commonly stops receiving immediately after this
            // terminal event. Flush its cumulative ACK before returning so
            // the peer can retire reliable CLOSE/FIN recovery state.
            _ = self.h3.established.connection.tryFlushPendingAck() catch {};
        }
    }

    pub fn finishPolledSessionEventWithTimeout(
        self: *HandshakeClientSession,
        event: SessionEvent,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishPolledSessionEventWithDeadline(
            event,
            .fromNow(
                self.h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn finishPolledSessionEventWithDeadline(
        self: *HandshakeClientSession,
        event: SessionEvent,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (connection_lifecycle.observe(&self.control, &self.h3, &self.streams)) return;
        if (event != .closed and event != .reset) return;
        _ = try self.control.rejectPostTerminalDataWithDeadline(
            &self.h3.established.connection,
            deadline,
        );
        if (event == .closed and !self.control.local_close_sent and
            !self.control.local_close_failed and
            self.pending_close == null)
        {
            var progress: http3.runtime.BodyWriteProgress = .{};
            self.h3.sendRequestBodyPacedWithDeadline(
                self.session_id.value,
                &.{},
                true,
                &progress,
                deadline,
            ) catch |err| {
                if (progress.fin_committed) {
                    self.control.local_close_sent = true;
                }
                return err;
            };
            std.debug.assert(progress.fin_committed);
            self.control.local_close_sent = true;
        }
        try session_control.terminateStreamsWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            deadline,
        );
        _ = self.h3.established.connection.tryFlushPendingAck() catch {};
    }

    fn pollSessionEventOnce(
        self: *HandshakeClientSession,
    ) Error!?SessionEvent {
        self.control.bindFlow(self.streams.flow);
        connection_lifecycle.observeGoAway(&self.control, &self.h3);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        if (capsule_rejection.pending(&self.control)) {
            const ready = capsule_rejection.finishOnce(&self.control, &self.h3.established.connection, &self.streams) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
                else => return err,
            };
            if (!ready) return null;
            return capsule_rejection.errorFor(&self.control);
        }
        const event = self.control.pollOnce(
            &self.h3.established.connection,
        ) catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => return null,
            error.InvalidCapsule, error.FlowControlViolation => {
                const ready = capsule_rejection.finishOnce(&self.control, &self.h3.established.connection, &self.streams) catch |rejection_err| switch (rejection_err) {
                    error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
                    else => return rejection_err,
                };
                self.close_response_pending = false;
                if (!ready) return null;
                return err;
            },
            else => {
                try http3.runtime.closeConnectionForProtocolError(
                    &self.h3.established.connection,
                    err,
                );
                return err;
            },
        };
        if (event) |value| {
            if (value == .closed and !self.control.local_close_sent and !self.control.local_close_failed) {
                self.close_response_pending = true;
            }
            return value;
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
        if (self.control.local_close_sent or self.control.local_close_failed) self.close_response_pending = false;
        if (try self.control.tryRejectPostTerminalData(
            &self.h3.established.connection,
        )) {
            self.close_response_pending = false;
            return .submitted;
        }
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
            !self.control.local_close_failed and
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

    pub fn receiveControlProgress(
        self: *HandshakeClientSession,
    ) Error!void {
        try self.h3.receiveDetachedResponseProgress(
            self.session_id.value,
        );
    }

    pub fn receiveControlProgressWithTimeout(
        self: *HandshakeClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveControlProgressWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveControlProgressWithDeadline(
        self: *HandshakeClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.receiveDetachedResponseProgressWithDeadline(
            self.session_id.value,
            deadline,
        );
    }
    /// Submit one WT_MAX_DATA grant. Backpressure leaves the advertised limit
    /// unchanged so an endpoint loop can retry this same operation.
    pub fn grantData(self: *HandshakeClientSession, maximum: u64) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        return flow_grant.send(&self.control, &self.h3, &self.streams, .{ .max_data = maximum });
    }

    pub fn grantStreams(self: *HandshakeClientSession, direction: webtransport.StreamDirection, maximum: u64) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer connection_lifecycle.observeWithTimer(&self.control, &self.h3, &self.streams, self.dispatcher, self.dispatcher_handle);
        const capsule: webtransport.Capsule = switch (direction) {
            .bidirectional => .{ .max_streams_bidi = maximum },
            .unidirectional => .{ .max_streams_uni = maximum },
        };
        return flow_grant.send(&self.control, &self.h3, &self.streams, capsule);
    }
};
