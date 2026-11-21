//! HTTP/3 client handshake session over QUIC.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const BatchHandshakeCancellationObserver = runtime.BatchHandshakeCancellationObserver;
const BatchOwnedHandshakeResponseObserver = runtime.BatchOwnedHandshakeResponseObserver;
const BodyBatchProgress = runtime.BodyBatchProgress;
const BodyChunk = runtime.BodyChunk;
const BodyWriteProgress = runtime.BodyWriteProgress;
const Client = runtime.Client;
const ClientPushAggregateState = runtime.ClientPushAggregateState;
const ClientRequestLifecycle = runtime.ClientRequestLifecycle;
const ConnectIpClientSession = runtime.ConnectIpClientSession;
const ConnectUdpClientSession = runtime.ConnectUdpClientSession;
const ConnectionPacketCursor = runtime.ConnectionPacketCursor;
const ConnectionResponseReceiveContext = runtime.ConnectionResponseReceiveContext;
const CriticalStreamSendScratch = runtime.CriticalStreamSendScratch;
const EarlyDataRequestResult = runtime.EarlyDataRequestResult;
const EarlyHandshakeClient = runtime.EarlyHandshakeClient;
const EarlyRequestDisposition = runtime.EarlyRequestDisposition;
const Error = runtime.Error;
const GoAwayRetryDisposition = runtime.GoAwayRetryDisposition;
const HandshakeClientOptions = runtime.HandshakeClientOptions;
const HandshakeServerSession = runtime.HandshakeServerSession;
const HandshakeSessionOptions = runtime.HandshakeSessionOptions;
const HappyEyeballsOptions = runtime.HappyEyeballsOptions;
const InformationalCallbackGuard = runtime.InformationalCallbackGuard;
const InformationalObserver = runtime.InformationalObserver;
const Limits = runtime.Limits;
const MultiplexedInformationalContext = runtime.MultiplexedInformationalContext;
const MultiplexedInformationalObserver = runtime.MultiplexedInformationalObserver;
const NoConnectProgress = runtime.NoConnectProgress;
const OutboundBodySet = runtime.OutboundBodySet;
const OwnedConnectDatagram = runtime.OwnedConnectDatagram;
const OwnedHandshakeResponse = runtime.OwnedHandshakeResponse;
const OwnedHandshakeResponseEvent = runtime.OwnedHandshakeResponseEvent;
const PreparedEarlyRequest = runtime.PreparedEarlyRequest;
const PreparedEarlyRequestOptions = runtime.PreparedEarlyRequestOptions;
const PushEventResult = runtime.PushEventResult;
const PushFailure = runtime.PushFailure;
const PushInformationalCallbackGuard = runtime.PushInformationalCallbackGuard;
const PushInformationalObserver = runtime.PushInformationalObserver;
const PushStreamSet = runtime.PushStreamSet;
const PushedResponse = runtime.PushedResponse;
const QpackDecodeState = runtime.QpackDecodeState;
const QpackEncodeState = runtime.QpackEncodeState;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const RedirectOptions = runtime.RedirectOptions;
const RedirectTimeoutError = runtime.RedirectTimeoutError;
const RedirectedHandshakeResponse = runtime.RedirectedHandshakeResponse;
const ResponseEventResult = runtime.ResponseEventResult;
const ResponseFailure = runtime.ResponseFailure;
const ResponseStreamSet = runtime.ResponseStreamSet;
const StreamMessageSendScratch = runtime.StreamMessageSendScratch;
const StreamingEvent = runtime.StreamingEvent;
const StreamingPushEvent = runtime.StreamingPushEvent;
const StreamingResponseEvent = runtime.StreamingResponseEvent;
const StreamingResponseSet = runtime.StreamingResponseSet;
const UriRequestOptions = runtime.UriRequestOptions;
const addressAttemptDeadline = runtime.addressAttemptDeadline;
const address_resolver = runtime.address_resolver;
const applyResponseReaderSemantics = runtime.applyResponseReaderSemantics;
const cancelConnectionRequest = runtime.cancelConnectionRequest;
const cancelHandshakeRequestWithDeadline = runtime.cancelHandshakeRequestWithDeadline;
const cappedConnectDeadline = runtime.cappedConnectDeadline;
const client_control_stream_id = runtime.client_control_stream_id;
const client_qpack_decoder_stream_id = runtime.client_qpack_decoder_stream_id;
const client_qpack_encoder_stream_id = runtime.client_qpack_encoder_stream_id;
const closeConnectionForHttp3Error = runtime.closeConnectionForHttp3Error;
const complete_request = runtime.complete_request;
const concurrent = runtime.concurrent;
const connectDatagramTerminalError = runtime.connectDatagramTerminalError;
const connectDeadline = runtime.connectDeadline;
const connect_datagram = runtime.connect_datagram;
const connect_datagram_progress = runtime.connect_datagram_progress;
const connect_datagram_send = runtime.connect_datagram_send;
const deadline_policy = runtime.deadline_policy;
const default_paced_request_body_chunk_bytes = runtime.default_paced_request_body_chunk_bytes;
const ensureConnectDatagramSendSideOpen = runtime.ensureConnectDatagramSendSideOpen;
const ensureConnectDatagramsNegotiated = runtime.ensureConnectDatagramsNegotiated;
const first_client_extension_uni_stream_id = runtime.first_client_extension_uni_stream_id;
const handshakeRecoveryBefore = runtime.handshakeRecoveryBefore;
const happy_eyeballs = runtime.happy_eyeballs;
const messageStreamErrorCode = runtime.messageStreamErrorCode;
const messageUsesDynamicQpack = runtime.messageUsesDynamicQpack;
const message_data = runtime.message_data;
const observeConnectDatagramTerminal = runtime.observeConnectDatagramTerminal;
const paced_body = runtime.paced_body;
const packetView = runtime.packetView;
const pollConnectDatagramRegistry = runtime.pollConnectDatagramRegistry;
const pollConnectDatagramRegistryInto = runtime.pollConnectDatagramRegistryInto;
const push_aggregate = runtime.push_aggregate;
const push_failure = runtime.push_failure;
const push_read_failure = runtime.push_read_failure;
const receiveConnectDatagramFromSession = runtime.receiveConnectDatagramFromSession;
const receiveConnectDatagramIntoFromSession = runtime.receiveConnectDatagramIntoFromSession;
const receiveConnectDatagramsIntoFromSession = runtime.receiveConnectDatagramsIntoFromSession;
const receiveConnectionResponsePacket = runtime.receiveConnectionResponsePacket;
const receiveConnectionResponsePacketUntil = runtime.receiveConnectionResponsePacketUntil;
const receiveConnectionResponseStreamBytesUntil = runtime.receiveConnectionResponseStreamBytesUntil;
const receivedInputComplete = runtime.receivedInputComplete;
const redirectH3Headers = runtime.redirectH3Headers;
const redirectH3Location = runtime.redirectH3Location;
const registerResponsePushPromises = runtime.registerResponsePushPromises;
const releaseStreamingReaderCapacity = runtime.releaseStreamingReaderCapacity;
const releaseStreamingReaderCapacityOnce = runtime.releaseStreamingReaderCapacityOnce;
const requestHasProtocol = runtime.requestHasProtocol;
const resolveEndpointWithResolverBefore = runtime.resolveEndpointWithResolverBefore;
const resolveHostPortWithResolverBefore = runtime.resolveHostPortWithResolverBefore;
const resolvePacedBodyChunkBytes = runtime.resolvePacedBodyChunkBytes;
const responseFieldSectionCount = runtime.responseFieldSectionCount;
const responseHeadErrorAtFin = runtime.responseHeadErrorAtFin;
const responseResetError = runtime.responseResetError;
const response_failure = runtime.response_failure;
const runtime_error = runtime.runtime_error;
const sendConnectionBodyBatchPaced = runtime.sendConnectionBodyBatchPaced;
const sendConnectionBodyBatchPacedProgress = runtime.sendConnectionBodyBatchPacedProgress;
const sendConnectionBodyBatchPacedWithDeadline = runtime.sendConnectionBodyBatchPacedWithDeadline;
const sendConnectionBodyChunk = runtime.sendConnectionBodyChunk;
const sendConnectionControlFrame = runtime.sendConnectionControlFrame;
const sendConnectionControlFrameWithDeadline = runtime.sendConnectionControlFrameWithDeadline;
const sendConnectionPriorityUpdate = runtime.sendConnectionPriorityUpdate;
const sendConnectionPriorityUpdateRaw = runtime.sendConnectionPriorityUpdateRaw;
const sendConnectionPriorityUpdateRawWithDeadline = runtime.sendConnectionPriorityUpdateRawWithDeadline;
const sendConnectionPushControl = runtime.sendConnectionPushControl;
const sendConnectionPushControlWithDeadline = runtime.sendConnectionPushControlWithDeadline;
const sendConnectionQpackFeedback = runtime.sendConnectionQpackFeedback;
const sendConnectionQpackFeedbackWithDeadline = runtime.sendConnectionQpackFeedbackWithDeadline;
const sendConnectionSettings = runtime.sendConnectionSettings;
const sendConnectionSettingsWithDeadline = runtime.sendConnectionSettingsWithDeadline;
const sendConnectionStreamingHead = runtime.sendConnectionStreamingHead;
const sendConnectionStreamingHeadProgress = runtime.sendConnectionStreamingHeadProgress;
const sendConnectionStreamingHeadWithDeadline = runtime.sendConnectionStreamingHeadWithDeadline;
const sendConnectionTrailers = runtime.sendConnectionTrailers;
const sendConnectionTrailersWithDeadline = runtime.sendConnectionTrailersWithDeadline;
const stream_lifecycle = runtime.stream_lifecycle;
const streamingResponseSectionAcknowledgments = runtime.streamingResponseSectionAcknowledgments;
const ticket_receiver = runtime.ticket_receiver;
const trySendConnectionBodyChunk = runtime.trySendConnectionBodyChunk;
const trySendConnectionBodyParts = runtime.trySendConnectionBodyParts;
const trySendConnectionControlFrame = runtime.trySendConnectionControlFrame;
const trySendConnectionPriorityUpdateRaw = runtime.trySendConnectionPriorityUpdateRaw;
const trySendConnectionPushControl = runtime.trySendConnectionPushControl;
const trySendConnectionQpackFeedback = runtime.trySendConnectionQpackFeedback;
const trySendConnectionRequestLiteral = runtime.trySendConnectionRequestLiteral;
const trySendConnectionSettings = runtime.trySendConnectionSettings;
const trySendConnectionStreamingRequestHeadLiteral = runtime.trySendConnectionStreamingRequestHeadLiteral;
const trySendConnectionTrailersLiteral = runtime.trySendConnectionTrailersLiteral;
const uriEndpoint = runtime.uriEndpoint;
const uriRequestTargetAlloc = runtime.uriRequestTargetAlloc;
const uri_redirect = runtime.uri_redirect;
const validateClientGoAwayPushId = runtime.validateClientGoAwayPushId;
const validateHandshakeSessionOptions = runtime.validateHandshakeSessionOptions;
const visitConnectionResponsePacket = runtime.visitConnectionResponsePacket;

pub const HandshakeClient = struct {
    const ConnectDatagramProgress = connect_datagram_progress.Pump(.{
        .Error = ReceiveTimeoutError,
        .check_callback = true,
        .io = connectionIo,
        .receive = receiveDetachedResponsePacketInto,
        .receiveAttached = receiveAttachedConnectDatagramPacket,
        .feedback = flushResponsePacketFeedbackOnce,
    });
    const ConnectDatagramSend = connect_datagram_send.Controller(.{
        .Error = ReceiveTimeoutError,
        .check_callback = true,
        .validate = validateConnectDatagramSend,
        .io = connectionIo,
        .receive = receiveDetachedResponsePacketInto,
        .feedback = flushResponsePacketFeedbackOnce,
    });
    endpoint: *quic.runtime.Endpoint,
    owns_endpoint: bool,
    /// Set while an endpoint dispatcher is the sole UDP receive owner.
    /// Socket-reading convenience methods fail closed in this mode; callers
    /// inject routed packets and use the `*Once` polling surface instead.
    dispatcher_bound: bool = false,
    /// Aggregate informational callbacks borrow decoded field storage and
    /// must not recursively advance this connection's receive state.
    callback_reader_active: bool = false,
    /// A best-effort dispatcher-side cleanup can retire HTTP/3 bookkeeping
    /// without successfully emitting every QUIC terminal frame. Such a
    /// connection must be discarded rather than returned to an idle pool.
    reuse_safe: bool = true,
    peer: net.IpAddress,
    allocator: std.mem.Allocator,
    established: quic.handshake.EstablishedConnection,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    response_streams: ResponseStreamSet,
    streaming_responses: StreamingResponseSet,
    pending_response_failures: response_failure.Pending = .{},
    pending_push_failures: push_failure.Pending = .{},
    push_streams: PushStreamSet,
    push_aggregate: ClientPushAggregateState = .{},
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ClientRequestLifecycle,
    connect_datagrams: connect_datagram.Registry,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
    ticket_receiver: ticket_receiver.Receiver,
    next_stream_id: u62 = 0,

    /// Reserve one client-initiated bidirectional stream ID.
    ///
    /// Request streams and WebTransport bidirectional streams share this QUIC
    /// ID space. Protocol adapters must reserve through this method rather than
    /// maintaining an independent counter.
    pub fn reserveClientBidirectionalStreamId(
        self: *HandshakeClient,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        self.next_stream_id = std.math.add(
            u62,
            stream_id,
            4,
        ) catch return error.StreamCreationError;
        self.request_lifecycle.markAllocated(stream_id);
        return stream_id;
    }

    /// Reserve a client-initiated bidirectional ID in both HTTP/3's request
    /// namespace and QUIC. This cohesive operation prevents WebTransport from
    /// advancing either cursor while leaving the other behind.
    pub fn openClientBidirectionalStream(
        self: *HandshakeClient,
    ) Error!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const expected = self.next_stream_id;
        _ = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection
            .nextLocalBidirectionalStreamId() != expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection.openStream();
        const stream_id = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(stream_id == expected and stream_id == transport_id);
        return stream_id;
    }

    /// Reserve one bidirectional stream without waiting for STREAMS_BLOCKED
    /// pacing. This is the dispatcher-safe counterpart to
    /// `openClientBidirectionalStream`.
    pub fn tryOpenClientBidirectionalStream(
        self: *HandshakeClient,
    ) Error!u62 {
        const expected = self.next_stream_id;
        const next_stream_id = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection.nextLocalBidirectionalStreamId() !=
            expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection.tryOpenStream();
        self.next_stream_id = next_stream_id;
        self.request_lifecycle.markAllocated(expected);
        std.debug.assert(expected == transport_id);
        return expected;
    }

    pub fn tryOpenClientBidirectionalStreamWithResetPrefix(self: *HandshakeClient, prefix: []const u8) Error!u62 {
        const expected = self.next_stream_id;
        const advanced = std.math.add(u62, expected, 4) catch return error.StreamCreationError;
        if (self.established.connection.nextLocalBidirectionalStreamId() != expected) return error.StreamCreationError;
        const actual = try self.established.connection.tryOpenStreamWithResetPrefix(.bidirectional, prefix);
        self.next_stream_id = advanced;
        self.request_lifecycle.markAllocated(expected);
        std.debug.assert(actual == expected);
        return expected;
    }

    pub fn openClientBidirectionalStreamWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openClientBidirectionalStreamWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openClientBidirectionalStreamWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const expected = self.next_stream_id;
        _ = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection
            .nextLocalBidirectionalStreamId() != expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection
            .openStreamWithDeadline(deadline);
        const stream_id = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(stream_id == expected and stream_id == transport_id);
        return stream_id;
    }

    fn requestStreamSendRetryable(
        self: *const HandshakeClient,
        stream_id: u62,
        next_stream_id: u62,
    ) bool {
        if (self.established.connection.closed() or
            self.established.connection.closing() or
            self.established.connection.draining() or
            self.established.connection.nextLocalBidirectionalStreamId() !=
                next_stream_id)
        {
            return false;
        }
        const stats = self.established.connection.sendStreamStats(stream_id) orelse
            return true;
        return stats.highest_sent_offset == 0 and
            stats.final_size == null and
            stats.stopped == null and
            stats.reset == null;
    }

    fn retireReservedRequestStreamId(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        if (self.next_stream_id != stream_id) return;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch return;
        if (self.established.connection.nextLocalBidirectionalStreamId() ==
            next_stream_id)
        {
            self.next_stream_id = next_stream_id;
        }
    }

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, options: HandshakeClientOptions) Error!HandshakeClient {
        return connectBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            try connectDeadline(io, options.connect_timeout),
            null,
        );
    }

    /// Establish a connection with one complete typed HTTP/3 request in the
    /// QUIC 0-RTT flight. The returned disposition is explicit so applications
    /// decide whether a rejected request is safe to replay under 1-RTT.
    pub fn connectWithEarlyRequest(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    ) Error!EarlyHandshakeClient {
        return connectWithEarlyRequestBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            early_request,
            cache,
            lease,
            try connectDeadline(io, options.connect_timeout),
        );
    }

    pub fn connectWithEarlyRequestWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        return connectWithEarlyRequestBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            early_request,
            cache,
            lease,
            try cappedConnectDeadline(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectWithEarlyRequestWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        timeout: std.Io.Duration,
    ) Error!EarlyHandshakeClient {
        if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
        return connectWithEarlyRequestWithDeadline(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            early_request,
            cache,
            lease,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectWithEarlyRequestBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        if (options.handshake.early_data != null) {
            return error.InvalidEarlyDataLease;
        }
        if (options.session.max_concurrent_request_streams == 0) {
            return error.ExcessiveLoad;
        }
        if (!std.meta.eql(
            early_request.local_settings,
            options.session.local_settings,
        )) {
            return error.InvalidSetting;
        }
        try early_request.validateTransportLimits(limits, options, lease);
        var early_options = options;
        early_options.handshake.early_data = early_request.offer(cache, lease);
        var client = try connectBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            early_options,
            deadline,
            early_request,
        );
        errdefer client.deinit();
        const disposition = try client.adoptEarlyRequest(
            early_request,
        );
        if (options.handshake.resumption_server_id) |server_id| {
            if (options.handshake.resumption_now_ms) |now_ms| {
                try client.configureSessionTicketCache(
                    cache,
                    server_id,
                    now_ms,
                );
            }
        }
        return .{ .client = client, .disposition = disposition };
    }

    /// Send one complete request in 0-RTT when possible and return its final
    /// result. RFC 8470 retries a TLS-rejected early request or a 425
    /// response exactly once after the handshake, never in early data.
    pub fn requestWithEarlyData(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        request_options: http3.Request,
        early_options: PreparedEarlyRequestOptions,
        remembered_peer_settings: http3.Settings,
        limits: Limits,
        options: HandshakeClientOptions,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    ) Error!EarlyDataRequestResult {
        return requestWithEarlyDataBefore(
            allocator,
            io,
            local_address,
            server,
            request_options,
            early_options,
            remembered_peer_settings,
            limits,
            options,
            cache,
            lease,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn requestWithEarlyDataWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        request_options: http3.Request,
        early_options: PreparedEarlyRequestOptions,
        remembered_peer_settings: http3.Settings,
        limits: Limits,
        options: HandshakeClientOptions,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!EarlyDataRequestResult {
        return requestWithEarlyDataBefore(
            allocator,
            io,
            local_address,
            server,
            request_options,
            early_options,
            remembered_peer_settings,
            limits,
            options,
            cache,
            lease,
            deadline,
        );
    }

    pub fn requestWithEarlyDataWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        request_options: http3.Request,
        early_options: PreparedEarlyRequestOptions,
        remembered_peer_settings: http3.Settings,
        limits: Limits,
        options: HandshakeClientOptions,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!EarlyDataRequestResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestWithEarlyDataWithDeadline(
            allocator,
            io,
            local_address,
            server,
            request_options,
            early_options,
            remembered_peer_settings,
            limits,
            options,
            cache,
            lease,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestWithEarlyDataBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        request_options: http3.Request,
        early_options: PreparedEarlyRequestOptions,
        remembered_peer_settings: http3.Settings,
        limits: Limits,
        options: HandshakeClientOptions,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!EarlyDataRequestResult {
        const operation_deadline = if (deadline) |absolute|
            try deadline_policy.usableAwake(io, absolute)
        else
            null;
        var early_request = try PreparedEarlyRequest.initWithOptions(
            allocator,
            request_options,
            options.session.local_settings,
            remembered_peer_settings,
            early_options,
        );
        defer early_request.deinit();
        const handshake_deadline = if (operation_deadline) |absolute|
            try cappedConnectDeadline(
                io,
                absolute,
                options.connect_timeout,
            )
        else
            try connectDeadline(io, options.connect_timeout);
        const connected = try connectWithEarlyRequestBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            &early_request,
            cache,
            lease,
            handshake_deadline,
        );
        var client = connected.client;
        defer client.deinit();

        if (connected.disposition == .accepted) {
            var response = if (operation_deadline) |absolute|
                try client.receiveResponseWithDeadline(
                    early_request.stream_id,
                    absolute,
                )
            else
                try client.receiveResponse(early_request.stream_id);
            if (response.response.status != 425) {
                return .{
                    .response = response,
                    .disposition = .accepted,
                    .retry_reason = .none,
                };
            }
            response.deinit(allocator);
        }

        const response = if (operation_deadline) |absolute|
            try client.requestWithDeadline(request_options, absolute)
        else
            try client.request(request_options);
        return .{
            .response = response,
            .disposition = connected.disposition,
            .retry_reason = if (connected.disposition == .accepted)
                .too_early
            else
                .early_data_rejected,
        };
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            try cappedConnectDeadline(
                io,
                deadline,
                options.connect_timeout,
            ),
            null,
        );
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        accepted_early_request: ?*const PreparedEarlyRequest,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options.session);
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(endpoint);
        endpoint.* = try quic.runtime.Endpoint.bind(allocator, io, local_address, limits.quic);
        errdefer endpoint.deinit();

        var established = if (deadline) |absolute|
            try quic.handshake.connectWithDeadline(
                endpoint,
                server,
                options.handshake,
                absolute,
            )
        else
            try quic.handshake.connect(endpoint, server, options.handshake);
        errdefer established.deinit();
        var client = try initOwnedEstablished(
            allocator,
            endpoint,
            server,
            established,
            options.session,
            accepted_early_request,
        );
        errdefer client.deinit();
        if (options.handshake.auto_resumption) |automatic| {
            try client.configureSessionTicketCache(
                automatic.cache,
                automatic.server_id,
                automatic.now_ms,
            );
        }
        return client;
    }

    /// Complete QUIC/TLS on a caller-owned endpoint while consuming only the
    /// supplied datagram source. This is the handshake counterpart to
    /// `initEstablished`: an endpoint-wide receive owner can route the
    /// client's long-header packets into a bounded inbox, then register the
    /// returned 1-RTT connection without transferring endpoint ownership.
    pub fn connectFrom(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        return connectFromBefore(
            endpoint,
            source,
            server,
            options,
            try connectDeadline(endpoint.io, options.connect_timeout),
        );
    }

    pub fn connectFromWithDeadline(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectFromBefore(
            endpoint,
            source,
            server,
            options,
            try cappedConnectDeadline(
                endpoint.io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectFromWithTimeout(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
        return connectFromWithDeadline(
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

    /// Move a preconfigured endpoint into a new authenticated HTTP/3 client.
    /// This is the owning composition point for transports such as SOCKS5 UDP
    /// ASSOCIATE that must construct the socket before QUIC/TLS starts.
    /// `endpoint_value` becomes invalid only after ownership transfers.
    pub fn connectAdoptingEndpoint(
        allocator: std.mem.Allocator,
        endpoint_value: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        return connectAdoptingEndpointBefore(
            allocator,
            endpoint_value,
            server,
            options,
            try connectDeadline(endpoint_value.io, options.connect_timeout),
        );
    }

    pub fn connectAdoptingEndpointWithDeadline(
        allocator: std.mem.Allocator,
        endpoint_value: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectAdoptingEndpointBefore(
            allocator,
            endpoint_value,
            server,
            options,
            try cappedConnectDeadline(
                endpoint_value.io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectAdoptingEndpointWithTimeout(
        allocator: std.mem.Allocator,
        endpoint_value: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAdoptingEndpointWithDeadline(
            allocator,
            endpoint_value,
            server,
            options,
            .fromNow(endpoint_value.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn connectAdoptingEndpointBefore(
        allocator: std.mem.Allocator,
        endpoint_value: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        endpoint.* = endpoint_value.*;
        endpoint_value.* = undefined;
        return connectOwningEndpointBefore(
            endpoint,
            server,
            options,
            deadline,
        );
    }

    /// Take ownership of an allocator-created endpoint pointer immediately.
    /// On failure this function closes and destroys it; on success ownership
    /// moves into the returned client.
    pub fn connectOwningEndpoint(
        endpoint: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        return connectOwningEndpointBefore(
            endpoint,
            server,
            options,
            try connectDeadline(endpoint.io, options.connect_timeout),
        );
    }

    pub fn connectOwningEndpointWithDeadline(
        endpoint: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectOwningEndpointBefore(
            endpoint,
            server,
            options,
            try cappedConnectDeadline(
                endpoint.io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectOwningEndpointWithTimeout(
        endpoint: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectOwningEndpointWithDeadline(
            endpoint,
            server,
            options,
            .fromNow(endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn connectOwningEndpointBefore(
        endpoint: *quic.runtime.Endpoint,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        const allocator = endpoint.allocator;
        errdefer {
            endpoint.deinit();
            allocator.destroy(endpoint);
        }
        try validateHandshakeSessionOptions(options.session);
        var connect_options = options;
        connect_options.connect_timeout = null;
        var established = if (deadline) |absolute|
            try quic.handshake.connectWithDeadline(
                endpoint,
                server,
                connect_options.handshake,
                absolute,
            )
        else
            try quic.handshake.connect(
                endpoint,
                server,
                connect_options.handshake,
            );
        errdefer established.deinit();
        var client = try initOwnedEstablished(
            allocator,
            endpoint,
            server,
            established,
            connect_options.session,
            null,
        );
        errdefer client.deinit();
        if (connect_options.handshake.auto_resumption) |automatic| {
            try client.configureSessionTicketCache(
                automatic.cache,
                automatic.server_id,
                automatic.now_ms,
            );
        }
        return client;
    }

    /// Complete a typed 0-RTT handshake on a caller-owned endpoint while
    /// consuming only the supplied CID-routed datagram source.
    pub fn connectFromWithEarlyRequest(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    ) Error!EarlyHandshakeClient {
        return connectFromWithEarlyRequestBefore(
            endpoint,
            source,
            server,
            options,
            early_request,
            cache,
            lease,
            try connectDeadline(endpoint.io, options.connect_timeout),
        );
    }

    pub fn connectFromWithEarlyRequestWithDeadline(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        return connectFromWithEarlyRequestBefore(
            endpoint,
            source,
            server,
            options,
            early_request,
            cache,
            lease,
            try cappedConnectDeadline(
                endpoint.io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectFromWithEarlyRequestWithTimeout(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        timeout: std.Io.Duration,
    ) Error!EarlyHandshakeClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectFromWithEarlyRequestWithDeadline(
            endpoint,
            source,
            server,
            options,
            early_request,
            cache,
            lease,
            .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectFromWithEarlyRequestBefore(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        if (options.handshake.early_data != null) {
            return error.InvalidEarlyDataLease;
        }
        if (options.session.max_concurrent_request_streams == 0) {
            return error.ExcessiveLoad;
        }
        if (!std.meta.eql(
            early_request.local_settings,
            options.session.local_settings,
        )) {
            return error.InvalidSetting;
        }
        try early_request.validateTransportLimits(
            .{ .quic = endpoint.limits },
            options,
            lease,
        );
        var early_options = options;
        early_options.handshake.early_data = early_request.offer(cache, lease);
        var client = try connectFromBeforeInternal(
            endpoint,
            source,
            server,
            early_options,
            deadline,
            early_request,
        );
        errdefer client.deinit();
        const disposition = try client.adoptEarlyRequest(early_request);
        if (options.handshake.resumption_server_id) |server_id| {
            if (options.handshake.resumption_now_ms) |now_ms| {
                try client.configureSessionTicketCache(
                    cache,
                    server_id,
                    now_ms,
                );
            }
        }
        return .{ .client = client, .disposition = disposition };
    }

    fn connectFromBefore(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectFromBeforeInternal(
            endpoint,
            source,
            server,
            options,
            deadline,
            null,
        );
    }

    fn connectFromBeforeInternal(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        accepted_early_request: ?*const PreparedEarlyRequest,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options.session);
        var established = if (deadline) |absolute|
            try quic.handshake.connectFromWithDeadline(
                endpoint,
                source,
                server,
                options.handshake,
                absolute,
            )
        else
            try quic.handshake.connectFrom(
                endpoint,
                source,
                server,
                options.handshake,
            );
        errdefer established.deinit();
        var client = try initEstablishedWithEndpointOwnership(
            endpoint.allocator,
            endpoint,
            false,
            server,
            established,
            options.session,
            accepted_early_request,
        );
        errdefer client.deinit();
        if (options.handshake.auto_resumption) |automatic| {
            try client.configureSessionTicketCache(
                automatic.cache,
                automatic.server_id,
                automatic.now_ms,
            );
        }
        return client;
    }

    /// Build an HTTP/3 client around an established connection on a
    /// caller-owned endpoint. This is the client-side composition point for
    /// endpoint-wide dispatchers that multiplex several connections over one
    /// UDP socket. Ownership of `established` transfers on success; `endpoint`
    /// remains caller-owned and must outlive this client.
    pub fn initEstablished(
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options);
        if (established.connection.endpoint != endpoint) {
            return error.InvalidTransportParameter;
        }
        return initEstablishedWithEndpointOwnership(
            endpoint.allocator,
            endpoint,
            false,
            peer,
            established,
            options,
            null,
        );
    }

    /// Build the HTTP/3 client state around a successfully initialized QUIC
    /// connection. Ownership of both `endpoint` and `established` transfers
    /// only on success. Keeping this common path prevents the TLS and external
    /// key-negotiation entry points from drifting in lifecycle behavior.
    fn initOwnedEstablished(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
        accepted_early_request: ?*const PreparedEarlyRequest,
    ) Error!HandshakeClient {
        return initEstablishedWithEndpointOwnership(
            allocator,
            endpoint,
            true,
            peer,
            established,
            options,
            accepted_early_request,
        );
    }

    fn initEstablishedWithEndpointOwnership(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        owns_endpoint: bool,
        peer: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
        accepted_early_request: ?*const PreparedEarlyRequest,
    ) Error!HandshakeClient {
        const resolved_options = resolvePacedBodyChunkBytes(
            options,
            default_paced_request_body_chunk_bytes,
        );
        try validateHandshakeSessionOptions(resolved_options);
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            resolved_options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        const transport_next_stream_id = std.math.cast(
            u62,
            established.connection.nextLocalBidirectionalStreamId(),
        ) orelse return error.StreamCreationError;
        const typed_early_data = established.early_data_status == .accepted and
            established.early_data_sent_packet_count != 0 and
            accepted_early_request != null;
        const expected_bidi_stream_id: u62 = if (typed_early_data) 4 else 0;
        if (transport_next_stream_id != expected_bidi_stream_id) {
            return error.UnexpectedEarlyData;
        }
        const transport_next_uni_stream_id =
            established.connection.nextLocalUnidirectionalStreamId();
        const expected_uni_stream_id: u64 = if (typed_early_data)
            first_client_extension_uni_stream_id
        else
            client_control_stream_id;
        if (transport_next_uni_stream_id != expected_uni_stream_id) {
            // Accepted typed early data reserves exactly the three mandatory
            // HTTP/3 critical streams. Other preexisting unidirectional state
            // cannot be reconstructed safely by this fresh session.
            return error.StreamCreationError;
        }
        var client = HandshakeClient{
            .endpoint = endpoint,
            .owns_endpoint = owns_endpoint,
            .peer = peer,
            .allocator = allocator,
            .established = established,
            .options = resolved_options,
            .control = try .init(.{
                .max_priority_updates = resolved_options.max_priority_updates,
                .max_priority_update_payload_size = resolved_options.max_priority_update_payload_size,
            }),
            .qpack_decode = .init(
                allocator,
                max_capacity,
                resolved_options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                resolved_options.max_stream_buffer,
            ),
            .response_streams = .init(
                allocator,
                resolved_options.max_stream_buffer,
                resolved_options.max_concurrent_request_streams,
            ),
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                resolved_options.max_concurrent_request_streams,
                resolved_options.max_stream_buffer,
                resolved_options.max_informational_responses,
                resolved_options.local_settings,
                .response,
            ),
            .push_streams = .initWithInformationalLimit(
                allocator,
                resolved_options.max_concurrent_request_streams,
                resolved_options.max_stream_buffer,
                resolved_options.max_informational_responses,
                resolved_options.local_settings,
            ),
            .receive_packets = .{
                .max_datagrams = resolved_options.max_receive_batch_datagrams,
            },
            .request_lifecycle = .init(
                allocator,
                resolved_options.max_concurrent_request_streams,
            ),
            .connect_datagrams = .initWithEarly(allocator, .{
                .max_associations = resolved_options.max_concurrent_request_streams,
                .max_queued_per_association = resolved_options.max_queued_connect_datagrams,
                .max_queued_bytes_per_association = resolved_options.max_queued_connect_datagram_bytes,
            }, established.connection.endpoint.io, resolved_options.early_connect_datagrams),
            .outbound_bodies = .init(
                allocator,
                resolved_options.max_concurrent_request_streams,
            ),
            .ticket_receiver = .init(
                allocator,
                resolved_options.max_post_handshake_crypto_bytes,
            ),
            .next_stream_id = transport_next_stream_id,
        };
        if (transport_next_stream_id != 0) {
            client.request_lifecycle.markAllocated(
                transport_next_stream_id - 4,
            );
        }
        client.streaming_responses.setMaxBodyBytes(resolved_options.max_body_bytes);
        client.push_streams.setMaxBodyBytes(resolved_options.max_body_bytes);
        return client;
    }

    pub fn initPreconfigured(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        peer: net.IpAddress,
        limits: Limits,
        options: HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options);
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(endpoint);
        endpoint.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            local_address,
            limits.quic,
        );
        errdefer endpoint.deinit();
        var established = try quic.handshake.establishPreconfigured(
            endpoint,
            peer,
            .client,
            transport,
        );
        errdefer established.deinit();
        return initOwnedEstablished(
            allocator,
            endpoint,
            peer,
            established,
            options,
            null,
        );
    }

    const ResolvedEarlyConnect = struct {
        request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    };

    const ResolvedConnectResult = struct {
        client: HandshakeClient,
        disposition: ?EarlyRequestDisposition = null,
    };

    /// Try every reachable DNS result under the configured ordered or
    /// RFC 8305-style staggered policy. Protocol/authentication failures remain
    /// fatal across the origin, while path failures can advance another route.
    fn connectAnyResolvedAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        const connected = try connectAnyResolvedAddressInternal(
            allocator,
            io,
            local_address,
            servers,
            limits,
            options,
            deadline,
            null,
        );
        std.debug.assert(connected.disposition == null);
        return connected.client;
    }

    fn connectAnyResolvedAddressWithEarlyRequest(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        const connected = try connectAnyResolvedAddressInternal(
            allocator,
            io,
            local_address,
            servers,
            limits,
            options,
            deadline,
            .{ .request = early_request, .cache = cache, .lease = lease },
        );
        return .{
            .client = connected.client,
            .disposition = connected.disposition orelse unreachable,
        };
    }

    fn connectAnyResolvedAddressInternal(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        early: ?ResolvedEarlyConnect,
    ) Error!ResolvedConnectResult {
        if (servers.len == 0) return error.NoAddressReturned;
        try validateResolvedAddressPolicy(local_address, options);
        return switch (options.address_connect_policy) {
            .ordered => connectResolvedAddressesOrdered(
                allocator,
                io,
                local_address,
                servers,
                limits,
                options,
                deadline,
                early,
            ),
            .happy_eyeballs => |policy| connectResolvedAddressesRacing(
                allocator,
                io,
                local_address,
                servers,
                limits,
                options,
                deadline,
                early,
                policy,
            ),
        };
    }

    fn connectResolvedAddressesOrdered(
        allocator: std.mem.Allocator,
        io: std.Io,
        primary_local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        early: ?ResolvedEarlyConnect,
    ) Error!ResolvedConnectResult {
        var attempted = false;
        var attempt_index: usize = 0;
        var early_path_failed = false;
        var last_err: ?Error = null;
        for (servers) |server| {
            const local_address = localAddressForResolvedPeer(
                primary_local_address,
                options.alternate_local_address,
                server,
            ) orelse continue;
            attempted = true;
            const attempt_early = if (!early_path_failed) early else null;
            return connectResolvedAddressAttempt(
                allocator,
                io,
                local_address,
                server,
                limits,
                options,
                deadline,
                attempt_early,
                early != null and attempt_early == null,
                attempt_index != 0,
            ) catch |err| {
                last_err = err;
                if (!shouldTryNextResolvedAddress(err)) return err;
                if (attempt_early != null) early_path_failed = true;
                attempt_index += 1;
                continue;
            };
        }
        if (!attempted) return error.AddressFamilyUnsupported;
        return last_err orelse error.NoAddressReturned;
    }

    fn connectResolvedAddressesRacing(
        allocator: std.mem.Allocator,
        io: std.Io,
        primary_local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        early: ?ResolvedEarlyConnect,
        policy: HappyEyeballsOptions,
    ) Error!ResolvedConnectResult {
        try happy_eyeballs.validate(policy);
        const stack_address_capacity: usize = 8;
        var eligible_count: usize = 0;
        for (servers) |server| {
            if (localAddressForResolvedPeer(
                primary_local_address,
                options.alternate_local_address,
                server,
            ) != null) eligible_count += 1;
        }
        if (eligible_count == 0) return error.AddressFamilyUnsupported;

        var eligible_stack: [stack_address_capacity]net.IpAddress = undefined;
        const eligible_heap = if (eligible_count > eligible_stack.len)
            try allocator.alloc(net.IpAddress, eligible_count)
        else
            null;
        defer if (eligible_heap) |storage| allocator.free(storage);
        const eligible = eligible_heap orelse eligible_stack[0..eligible_count];
        var eligible_index: usize = 0;
        for (servers) |server| {
            if (localAddressForResolvedPeer(
                primary_local_address,
                options.alternate_local_address,
                server,
            ) == null) continue;
            eligible[eligible_index] = server;
            eligible_index += 1;
        }

        const RaceContext = struct {
            allocator: std.mem.Allocator,
            primary_local_address: net.IpAddress,
            limits: Limits,
            options: HandshakeClientOptions,
            deadline: ?std.Io.Clock.Timestamp,
            early: ?ResolvedEarlyConnect,

            fn connect(
                self: @This(),
                io_value: std.Io,
                server: net.IpAddress,
                index: usize,
            ) Error!ResolvedConnectResult {
                return connectResolvedAddressAttempt(
                    self.allocator,
                    io_value,
                    localAddressForResolvedPeer(
                        self.primary_local_address,
                        self.options.alternate_local_address,
                        server,
                    ).?,
                    server,
                    self.limits,
                    self.options,
                    self.deadline,
                    if (index == 0) self.early else null,
                    self.early != null and index != 0,
                    index != 0,
                );
            }

            fn deinitConnected(
                _: @This(),
                connected: *ResolvedConnectResult,
            ) void {
                connected.client.deinit();
            }
        };
        return happy_eyeballs.race(
            Error,
            ResolvedConnectResult,
            allocator,
            io,
            eligible,
            policy,
            null,
            null,
            RaceContext{
                .allocator = allocator,
                .primary_local_address = primary_local_address,
                .limits = limits,
                .options = options,
                .deadline = deadline,
                .early = early,
            },
            RaceContext.connect,
            RaceContext.deinitConnected,
            shouldTryNextResolvedAddress,
        );
    }

    fn connectResolvedAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
        early: ?ResolvedEarlyConnect,
        fallback_from_early: bool,
        fresh_identity: bool,
    ) Error!ResolvedConnectResult {
        var attempt_options = options;
        var original_dcid: [8]u8 = undefined;
        var local_cid: [8]u8 = undefined;
        if (fresh_identity) {
            try std.Io.randomSecure(io, &original_dcid);
            try std.Io.randomSecure(io, &local_cid);
            attempt_options.handshake.original_destination_connection_id =
                &original_dcid;
            attempt_options.handshake.local_connection_id = &local_cid;
            attempt_options.handshake.retry_source_connection_id = &.{};
            attempt_options.handshake.address_validation_token = &.{};
            attempt_options.handshake.resumption_session = null;
            attempt_options.handshake.resumption_server_id = null;
            attempt_options.handshake.auto_resumption = null;
            attempt_options.handshake.random = null;
            attempt_options.handshake.x25519_secret_key = null;
            attempt_options.handshake.p256_secret_key = null;
            attempt_options.handshake.p384_secret_key = null;
            attempt_options.handshake.x25519_mlkem768_secret_key = null;
            attempt_options.handshake.x25519_mlkem768_seed = null;
            attempt_options.handshake.nist_hybrid_key_material = .{};
            attempt_options.handshake.early_data = null;
        }
        const attempt_deadline = try addressAttemptDeadline(
            io,
            deadline,
            options.address_attempt_timeout,
        );
        if (attempt_deadline) |absolute| {
            attempt_options.handshake.handshake_recovery =
                try handshakeRecoveryBefore(
                    io,
                    absolute,
                    options.handshake.handshake_recovery,
                );
        }
        if (early) |early_context| {
            const connected = try connectWithEarlyRequestBefore(
                allocator,
                io,
                local_address,
                server,
                limits,
                attempt_options,
                early_context.request,
                early_context.cache,
                early_context.lease,
                attempt_deadline,
            );
            return .{
                .client = connected.client,
                .disposition = connected.disposition,
            };
        }
        return .{
            .client = try connect(
                allocator,
                io,
                local_address,
                server,
                limits,
                attempt_options,
            ),
            .disposition = if (fallback_from_early) .rejected else null,
        };
    }

    fn validateResolvedAddressPolicy(
        primary_local_address: net.IpAddress,
        options: HandshakeClientOptions,
    ) Error!void {
        switch (options.address_connect_policy) {
            .ordered => {},
            .happy_eyeballs => |policy| try happy_eyeballs.validate(policy),
        }
        if (options.alternate_local_address) |alternate| {
            if (sameIpAddressFamily(primary_local_address, alternate)) {
                return error.InvalidAddressConnectPolicy;
            }
        }
    }

    fn localAddressForResolvedPeer(
        primary: net.IpAddress,
        alternate: ?net.IpAddress,
        peer: net.IpAddress,
    ) ?net.IpAddress {
        if (sameIpAddressFamily(primary, peer)) return primary;
        if (alternate) |candidate| {
            if (sameIpAddressFamily(candidate, peer)) return candidate;
        }
        return null;
    }

    fn sameIpAddressFamily(a: net.IpAddress, b: net.IpAddress) bool {
        return switch (a) {
            .ip4 => switch (b) {
                .ip4 => true,
                .ip6 => false,
            },
            .ip6 => switch (b) {
                .ip4 => false,
                .ip6 => true,
            },
        };
    }

    fn shouldTryNextResolvedAddress(err: Error) bool {
        return switch (err) {
            error.HandshakeTimeout,
            error.HandshakeSendFailed,
            error.HandshakeReceiveFailed,
            error.AddressFamilyUnsupported,
            error.ConnectionRefused,
            error.ConnectionResetByPeer,
            error.HostUnreachable,
            error.NetworkDown,
            error.NetworkUnreachable,
            error.PortUnreachable,
            => true,
            else => false,
        };
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        return connectUriBefore(
            allocator,
            io,
            local_address,
            uri,
            limits,
            options,
            try connectDeadline(io, options.connect_timeout),
        );
    }

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectUriBefore(
            allocator,
            io,
            local_address,
            uri,
            limits,
            options,
            try cappedConnectDeadline(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        limits: Limits,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
        return connectUriWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            limits,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        var endpoint = try uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const servers = try resolveEndpointWithResolverBefore(
            endpoint,
            allocator,
            io,
            options.address_resolver,
            deadline,
        );
        defer allocator.free(servers);
        var connect_options = options;
        // `connect` applies its own direct-address budget. The URI path has
        // already converted that duration into the shared absolute deadline.
        connect_options.connect_timeout = null;
        if (connect_options.handshake.server_name == null) {
            connect_options.handshake.server_name = endpoint.tls_host;
        }
        return try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
            deadline,
        );
    }

    pub fn requestUriFollowingRedirects(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
    ) RedirectTimeoutError!OwnedHandshakeResponse {
        var result = try requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            null,
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailed(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
    ) RedirectTimeoutError!RedirectedHandshakeResponse {
        return requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            null,
        );
    }

    pub fn requestUriFollowingRedirectsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) RedirectTimeoutError!OwnedHandshakeResponse {
        var result = try requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailedWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) RedirectTimeoutError!RedirectedHandshakeResponse {
        return requestUriFollowingRedirectsDetailedBefore(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn requestUriFollowingRedirectsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) RedirectTimeoutError!OwnedHandshakeResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriFollowingRedirectsWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsDetailedWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) RedirectTimeoutError!RedirectedHandshakeResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriFollowingRedirectsDetailedWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            redirect_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestUriFollowingRedirectsDetailedBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        initial_uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        redirect_options: RedirectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) RedirectTimeoutError!RedirectedHandshakeResponse {
        var chain = uri_redirect.Chain.init(
            allocator,
            redirect_options.policy,
        );
        defer chain.deinit();
        var current_uri = try std.fmt.allocPrint(
            allocator,
            "{f}",
            .{initial_uri.fmt(.all)},
        );
        defer allocator.free(current_uri);
        try chain.recordInitial(current_uri);
        var hop_request = request_options;
        var hop_options = options;
        const original_cid = try allocator.alloc(
            u8,
            options.handshake.original_destination_connection_id.len,
        );
        defer allocator.free(original_cid);
        const local_cid = try allocator.alloc(
            u8,
            options.handshake.local_connection_id.len,
        );
        defer allocator.free(local_cid);
        var owned_headers: ?[]http3.Qpack.HeaderField = null;
        defer if (owned_headers) |headers| allocator.free(headers);

        while (true) {
            const parsed_uri = std.Uri.parse(current_uri) catch
                return error.InvalidUri;
            var response = if (deadline) |absolute|
                try requestUriWithDeadline(
                    allocator,
                    io,
                    local_address,
                    parsed_uri,
                    hop_request,
                    limits,
                    hop_options,
                    absolute,
                )
            else
                try requestUri(
                    allocator,
                    io,
                    local_address,
                    parsed_uri,
                    hop_request,
                    limits,
                    hop_options,
                );
            errdefer response.deinit(allocator);
            if (!uri_redirect.isRedirectStatus(response.response.status)) {
                return .{
                    .allocator = allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            const location = try redirectH3Location(response.response.headers);
            if (location == null) {
                return .{
                    .allocator = allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            var next = try chain.follow(
                current_uri,
                location.?,
                response.response.status,
            );
            var next_owned = true;
            defer if (next_owned) next.deinit();
            const next_uri = std.Uri.parse(next.uri) catch
                return error.InvalidUri;
            if (!std.ascii.eqlIgnoreCase(next_uri.scheme, "https")) {
                return error.InsecureRedirect;
            }

            const action = uri_redirect.methodActionBytes(
                redirect_options.policy,
                response.response.status,
                hop_request.method,
            );
            const remove_credentials = next.cross_origin and
                !redirect_options.policy.forward_cross_origin_credentials;
            if (next.cross_origin) {
                try uri_redirect.enforceClientIdentityPolicy(
                    redirect_options.policy,
                    true,
                    hop_options.handshake.client_identity != null,
                );
            }
            hop_request.headers = try redirectH3Headers(
                allocator,
                hop_request.headers,
                remove_credentials,
                action == .rewrite_get,
                &owned_headers,
            );
            if (action == .rewrite_get) {
                hop_request.method = "GET";
                hop_request.body = &.{};
                hop_request.trailers = &.{};
            } else if (remove_credentials) {
                hop_request.trailers = &.{};
            }

            try std.Io.randomSecure(io, original_cid);
            try std.Io.randomSecure(io, local_cid);
            hop_options.handshake.original_destination_connection_id = original_cid;
            hop_options.handshake.local_connection_id = local_cid;
            hop_options.handshake.retry_source_connection_id = &.{};
            hop_options.handshake.server_name = null;
            hop_options.handshake.address_validation_token = &.{};
            hop_options.handshake.resumption_session = null;
            hop_options.handshake.resumption_server_id = null;
            hop_options.handshake.auto_resumption = null;
            hop_options.handshake.random = null;
            hop_options.handshake.x25519_secret_key = null;
            hop_options.handshake.p256_secret_key = null;
            hop_options.handshake.p384_secret_key = null;
            hop_options.handshake.x25519_mlkem768_secret_key = null;
            hop_options.handshake.x25519_mlkem768_seed = null;
            hop_options.handshake.nist_hybrid_key_material = .{};
            hop_options.handshake.early_data = null;

            response.deinit(allocator);
            allocator.free(current_uri);
            current_uri = next.uri;
            next_owned = false;
        }
    }

    pub fn requestUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        const deadline = try connectDeadline(io, options.connect_timeout);
        var endpoint = try uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);
        const servers = try resolveEndpointWithResolverBefore(
            endpoint,
            allocator,
            io,
            options.address_resolver,
            deadline,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.connect_timeout = null;
        if (connect_options.handshake.server_name == null) {
            connect_options.handshake.server_name = endpoint.tls_host;
        }
        var client = try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
            deadline,
        );
        defer client.deinit();

        return try client.request(.{
            .method = request_options.method,
            .path = path,
            .scheme = "https",
            .authority = endpoint.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        });
    }

    /// Perform a complete one-shot HTTP/3 request under one caller-owned
    /// deadline spanning resolution, all QUIC/TLS address attempts, request
    /// transmission, and response aggregation.
    pub fn requestUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        const absolute = try cappedConnectDeadline(
            io,
            deadline,
            options.connect_timeout,
        );
        var endpoint = try uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);
        const servers = try resolveEndpointWithResolverBefore(
            endpoint,
            allocator,
            io,
            options.address_resolver,
            absolute,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.connect_timeout = null;
        if (connect_options.handshake.server_name == null) {
            connect_options.handshake.server_name = endpoint.tls_host;
        }
        var client = try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
            absolute,
        );
        defer client.deinit();

        return client.requestWithDeadline(.{
            .method = request_options.method,
            .path = path,
            .scheme = "https",
            .authority = endpoint.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        }, absolute);
    }

    pub fn requestUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            request_options,
            limits,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriAltSvc(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        if (!http3.isHttp3Alpn(target.alpn) or
            target.connect_host.len == 0 or target.port == 0)
        {
            return error.InvalidHeader;
        }
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        if (!std.ascii.eqlIgnoreCase(
            target.origin_host,
            origin.tls_host,
        )) return error.InvalidHeader;
        const path = try uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);
        var client = try connectUriAltSvc(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
        );
        defer client.deinit();

        return try client.request(.{
            .method = request_options.method,
            .path = path,
            .scheme = "https",
            .authority = origin.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        });
    }

    /// Establish HTTP/3 to an alternative service while authenticating and
    /// addressing requests as the original URI origin. The alternative host
    /// is only a transport route; SNI, certificate policy, and later
    /// `:authority` remain bound to `uri`.
    pub fn connectUriAltSvc(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        return connectUriAltSvcBefore(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            try connectDeadline(io, options.connect_timeout),
        );
    }

    pub fn connectUriAltSvcWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        return connectUriAltSvcBefore(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            try cappedConnectDeadline(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectUriAltSvcWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        timeout: std.Io.Duration,
    ) Error!HandshakeClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAltSvcWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriAltSvcWithEarlyRequest(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    ) Error!EarlyHandshakeClient {
        return connectUriAltSvcWithEarlyRequestBefore(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            early_request,
            cache,
            lease,
            try connectDeadline(io, options.connect_timeout),
        );
    }

    pub fn connectUriAltSvcWithEarlyRequestWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        return connectUriAltSvcWithEarlyRequestBefore(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            early_request,
            cache,
            lease,
            try cappedConnectDeadline(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    pub fn connectUriAltSvcWithEarlyRequestWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        timeout: std.Io.Duration,
    ) Error!EarlyHandshakeClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAltSvcWithEarlyRequestWithDeadline(
            allocator,
            io,
            local_address,
            uri,
            target,
            limits,
            options,
            early_request,
            cache,
            lease,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriAltSvcWithEarlyRequestBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        early_request: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!EarlyHandshakeClient {
        if (!http3.isHttp3Alpn(target.alpn)) return error.InvalidHeader;
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        if (!std.ascii.eqlIgnoreCase(
            target.origin_host,
            origin.tls_host,
        )) return error.InvalidHeader;
        const servers = try resolveHostPortWithResolverBefore(
            allocator,
            io,
            target.connect_host,
            target.port,
            options.address_resolver,
            deadline,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.connect_timeout = null;
        connect_options.handshake.server_name = origin.tls_host;
        connect_options.handshake.alpn_protocols = &.{target.alpn};
        return connectAnyResolvedAddressWithEarlyRequest(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
            early_request,
            cache,
            lease,
            deadline,
        );
    }

    fn connectUriAltSvcBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        if (!http3.isHttp3Alpn(target.alpn)) return error.InvalidHeader;
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        if (!std.ascii.eqlIgnoreCase(
            target.origin_host,
            origin.tls_host,
        )) return error.InvalidHeader;
        const servers = try resolveHostPortWithResolverBefore(
            allocator,
            io,
            target.connect_host,
            target.port,
            options.address_resolver,
            deadline,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.connect_timeout = null;
        connect_options.handshake.server_name = origin.tls_host;
        connect_options.handshake.alpn_protocols = &.{target.alpn};
        return connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
            deadline,
        );
    }

    /// Resolve the first HTTP/3 Alt-Svc advertisement from any header list
    /// whose items expose `.name` and `.value`, then issue an origin-preserving
    /// HTTP/3 request to the advertised alternative service.
    pub fn requestUriAltSvcHeader(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        headers: anytype,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        const target = (try http3.firstHttp3AltSvcTarget(
            origin.tls_host,
            headers,
            origin.port,
        )) orelse return error.InvalidHeader;
        return try requestUriAltSvc(
            allocator,
            io,
            local_address,
            uri,
            target,
            request_options,
            limits,
            options,
        );
    }

    pub fn deinit(self: *HandshakeClient) void {
        self.pending_response_failures.deinit(self.allocator);
        self.pending_push_failures.deinit(self.allocator);
        self.critical_stream_send_scratch.deinit(self.allocator);
        self.stream_send_scratch.deinit(self.allocator);
        self.ticket_receiver.deinit();
        self.outbound_bodies.deinit();
        self.receive_packets.deinit();
        self.connect_datagrams.deinit();
        self.push_aggregate.deinit(self.allocator);
        self.push_streams.deinit();
        self.streaming_responses.deinit();
        self.request_lifecycle.deinit();
        self.response_streams.deinit();
        self.control.deinit(self.allocator);
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.established.deinit();
        if (self.owns_endpoint) {
            self.endpoint.deinit();
            self.allocator.destroy(self.endpoint);
        }
        self.* = undefined;
    }

    pub fn address(self: HandshakeClient) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn configureSessionTicketCache(
        self: *HandshakeClient,
        cache: *quic.resumption.Cache,
        server_id: []const u8,
        now_ms: u64,
    ) std.mem.Allocator.Error!void {
        try self.ticket_receiver.configure(cache, server_id, now_ms);
    }

    pub fn sessionTicketStats(
        self: *const HandshakeClient,
    ) ticket_receiver.Stats {
        return self.ticket_receiver.stats();
    }

    pub fn bindDispatcher(self: *HandshakeClient) Error!void {
        if (self.owns_endpoint or self.dispatcher_bound) {
            return error.InvalidDispatcherState;
        }
        self.dispatcher_bound = true;
    }

    pub fn dispatcherBound(self: *const HandshakeClient) bool {
        return self.dispatcher_bound;
    }

    pub fn negotiatedAlpn(self: HandshakeClient) []const u8 {
        return self.established.alpn;
    }

    pub fn negotiatedCipherSuite(
        self: HandshakeClient,
    ) quic.tls.cipher_suite.Suite {
        return self.established.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: HandshakeClient,
    ) quic.tls.secret.Hash {
        return self.established.negotiatedTranscriptHash();
    }

    pub fn peerCertificates(
        self: *const HandshakeClient,
    ) ?[]const []const u8 {
        return self.established.peerCertificates();
    }

    pub fn exportKeyingMaterial(
        self: *const HandshakeClient,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.established.exportKeyingMaterial(label, context, out);
    }

    pub fn initiateKeyUpdate(self: *HandshakeClient) Error!void {
        try self.established.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: HandshakeClient) u64 {
        return self.established.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: HandshakeClient) u64 {
        return self.established.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: HandshakeClient) bool {
        return self.established.keyUpdateAwaitingAck();
    }

    pub fn earlyDataStatus(
        self: HandshakeClient,
    ) quic.zero_rtt.handshake.Status {
        return self.established.early_data_status;
    }

    fn adoptAcceptedEarlyCriticalStreams(
        self: *HandshakeClient,
        early_request: *const PreparedEarlyRequest,
    ) Error!void {
        const expected = [_]struct {
            stream_id: u62,
            bytes: []const u8,
        }{
            .{
                .stream_id = client_control_stream_id,
                .bytes = early_request.control_bytes,
            },
            .{
                .stream_id = client_qpack_encoder_stream_id,
                .bytes = early_request.encoder_prefix,
            },
            .{
                .stream_id = client_qpack_decoder_stream_id,
                .bytes = early_request.decoder_prefix,
            },
        };
        for (expected) |stream| {
            const stats = self.established.connection
                .sendStreamStats(stream.stream_id) orelse
                return error.UnexpectedStream;
            if (stats.highest_sent_offset != stream.bytes.len or
                stats.final_size != null or stats.reset != null or
                stats.stopped != null)
            {
                return error.UnexpectedStream;
            }
        }
        self.control.settings.markSent(self.options.local_settings);
        self.control.early_data_peer_settings =
            early_request.remembered_peer_settings;
        self.control_send.next_offset = early_request.control_bytes.len;
        self.qpack_encoder_send.next_offset = early_request.encoder_prefix.len;
        self.qpack_encoder_prefix_sent = true;
        self.qpack_decoder_send.next_offset = early_request.decoder_prefix.len;
        self.qpack_decoder_prefix_sent = true;
    }

    /// Adopt one complete literal/static-QPACK request sent through the raw
    /// QUIC 0-RTT offer. The transport has already imported accepted STREAM
    /// bytes; this restores the HTTP method/CONNECT semantics needed to route
    /// its eventual response. Rejected early data must instead be replayed as
    /// a normal 1-RTT request.
    pub fn adoptEarlyRequest(
        self: *HandshakeClient,
        early_request: *const PreparedEarlyRequest,
    ) Error!EarlyRequestDisposition {
        if (self.established.early_data_status == .rejected) {
            return .rejected;
        }
        if (self.established.early_data_status != .accepted) {
            return error.UnexpectedEarlyData;
        }
        if (self.established.early_data_sent_packet_count == 0) {
            return .rejected;
        }
        if (!std.meta.eql(
            early_request.local_settings,
            self.options.local_settings,
        )) {
            return error.InvalidSetting;
        }
        const stream_id = early_request.stream_id;
        if (stream_id >= self.next_stream_id or
            self.request_lifecycle.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        const stats = self.established.connection.sendStreamStats(stream_id) orelse
            return error.UnexpectedStream;
        if (stats.highest_sent_offset != early_request.request_bytes.len or
            stats.final_size != stats.highest_sent_offset or
            stats.reset != null or stats.stopped != null)
        {
            return error.UnexpectedStream;
        }
        try self.adoptAcceptedEarlyCriticalStreams(early_request);
        try self.request_lifecycle.open(
            stream_id,
            early_request.method,
            early_request.extended_connect,
        );
        return .accepted;
    }

    pub fn peerGoAwayId(self: HandshakeClient) ?u64 {
        return self.control.peer_goaway_id;
    }

    /// Return whether this connection can move into an exclusive idle pool.
    /// HTTP/3 compression/control state is intentionally retained, but no
    /// application request, response, push, reset, or outbound body may leak
    /// into the next lease. A GOAWAY or QUIC close state is never reusable.
    pub fn isReusable(self: *const HandshakeClient) bool {
        return self.control.peer_goaway_id == null and
            self.reuse_safe and
            !self.established.connection.closed() and
            !self.established.connection.closing() and
            !self.established.connection.draining() and
            self.request_lifecycle.isEmpty() and
            self.outbound_bodies.isEmpty() and
            self.qpack_decode.pendingDecoderInstructions().len == 0 and
            self.response_streams.isEmpty() and
            self.streaming_responses.retainedCount() == 0 and
            self.push_streams.isIdle() and
            !self.push_aggregate.active();
    }

    pub fn goAwayRetryDisposition(
        self: HandshakeClient,
        stream_id: u62,
    ) GoAwayRetryDisposition {
        return stream_lifecycle.goAwayRetryDisposition(
            self.control.peer_goaway_id,
            stream_id,
        );
    }

    pub fn request(self: *HandshakeClient, request_options: http3.Request) Error!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponse(stream_id);
    }

    /// Send a complete request and wait for its response under one absolute
    /// application deadline. Transport PTO/ACK timers may wake earlier but do
    /// not renew this caller-owned budget.
    pub fn requestWithDeadline(
        self: *HandshakeClient,
        request_options: http3.Request,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        const stream_id = try self.sendRequestUntil(
            request_options,
            deadline,
        );
        return self.receiveResponseWithDeadline(stream_id, deadline);
    }

    pub fn requestWithTimeout(
        self: *HandshakeClient,
        request_options: http3.Request,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(
            request_options,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Execute independent requests concurrently on this HTTP/3 connection.
    ///
    /// Requests are opened in input order, but responses are reported as soon
    /// as their streams complete. Each member owns its absolute deadline: an
    /// expired member is canceled with H3_REQUEST_CANCELLED without consuming
    /// a sibling response or renewing any other budget. Successful response
    /// ownership transfers to `observer`.
    ///
    /// The observer runs on the sole connection owner and must not re-enter
    /// this client. No other request may already be active when the batch
    /// begins; this invariant lets every reset/response map to exactly one
    /// input index.
    pub fn requestBatchWithPerStreamDeadlines(
        self: *HandshakeClient,
        requests: []const http3.Request,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedHandshakeResponseObserver,
    ) ReceiveTimeoutError!void {
        return self.requestBatchWithPerStreamDeadlinesInternal(
            requests,
            deadlines,
            observer,
            null,
        );
    }

    /// Cancellation-aware counterpart used by multi-producer drivers. The
    /// event interrupts the sole response wait; racing response completion is
    /// consumed first so cancellation cannot drop a peer packet.
    pub fn requestBatchWithPerStreamDeadlinesAndCancellation(
        self: *HandshakeClient,
        requests: []const http3.Request,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedHandshakeResponseObserver,
        cancellation: BatchHandshakeCancellationObserver,
    ) ReceiveTimeoutError!void {
        return self.requestBatchWithPerStreamDeadlinesInternal(
            requests,
            deadlines,
            observer,
            cancellation,
        );
    }

    fn requestBatchWithPerStreamDeadlinesInternal(
        self: *HandshakeClient,
        requests: []const http3.Request,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedHandshakeResponseObserver,
        cancellation: ?BatchHandshakeCancellationObserver,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active or
            !self.request_lifecycle.isEmpty())
        {
            return error.ConcurrentRead;
        }
        if (requests.len != deadlines.len) return error.InvalidSetting;
        if (requests.len == 0) return;
        if (requests.len > self.options.max_concurrent_request_streams) {
            return error.ExcessiveLoad;
        }

        const Slot = struct {
            stream_id: ?u62 = null,
            active: bool = false,
        };
        var stack_slots: [16]Slot = undefined;
        const slots = if (requests.len <= stack_slots.len)
            stack_slots[0..requests.len]
        else
            try self.allocator.alloc(Slot, requests.len);
        defer if (requests.len > stack_slots.len) self.allocator.free(slots);
        for (slots) |*slot| slot.* = .{};

        var fail_unfinished: ?anyerror = null;
        defer if (fail_unfinished) |err| {
            for (slots, 0..) |*slot, index| {
                if (!slot.active) continue;
                if (slot.stream_id) |stream_id| {
                    self.cancelRequest(
                        stream_id,
                        http3.ApplicationErrorCode.request_cancelled,
                    ) catch {};
                }
                slot.active = false;
                observer.on_result(
                    observer.context,
                    index,
                    .{ .err = err },
                );
            }
        };

        var active_count: usize = 0;
        for (requests, deadlines, slots, 0..) |request_value, deadline, *slot, index| {
            if (cancellation) |cancel| {
                if (cancel.take_canceled(cancel.context, index)) {
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = error.Canceled },
                    );
                    continue;
                }
            }
            if (deadline) |absolute| {
                _ = deadline_policy.usableAwake(
                    self.connectionIo(),
                    absolute,
                ) catch |err| {
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = err },
                    );
                    continue;
                };
            }
            const expected_stream_id = self.next_stream_id;
            const stream_id = self.sendRequestUntil(
                request_value,
                deadline,
            ) catch |err| {
                if (self.request_lifecycle.contains(expected_stream_id)) {
                    self.cancelRequest(
                        expected_stream_id,
                        http3.ApplicationErrorCode.request_cancelled,
                    ) catch |cancel_err| {
                        fail_unfinished = cancel_err;
                        return cancel_err;
                    };
                }
                if (self.established.connection.closed() or
                    self.established.connection.closing() or
                    self.established.connection.draining())
                {
                    fail_unfinished = err;
                    return err;
                }
                observer.on_result(
                    observer.context,
                    index,
                    .{ .err = err },
                );
                continue;
            };
            slot.* = .{ .stream_id = stream_id, .active = true };
            active_count += 1;
        }
        if (cancellation) |cancel| cancel.acknowledge(cancel.context);

        while (active_count != 0) {
            var earliest: ?std.Io.Clock.Timestamp = null;
            for (slots, deadlines, 0..) |*slot, deadline, index| {
                if (!slot.active) continue;
                if (cancellation) |cancel| {
                    if (cancel.take_canceled(cancel.context, index)) {
                        self.cancelRequest(
                            slot.stream_id.?,
                            http3.ApplicationErrorCode.request_cancelled,
                        ) catch |err| {
                            fail_unfinished = err;
                            return err;
                        };
                        slot.active = false;
                        active_count -= 1;
                        observer.on_result(
                            observer.context,
                            index,
                            .{ .err = error.Canceled },
                        );
                        continue;
                    }
                }
                if (deadline) |absolute| {
                    if (absolute.durationFromNow(
                        self.connectionIo(),
                    ).raw.nanoseconds <= 0) {
                        self.cancelRequest(
                            slot.stream_id.?,
                            http3.ApplicationErrorCode.request_cancelled,
                        ) catch |err| {
                            fail_unfinished = err;
                            return err;
                        };
                        slot.active = false;
                        active_count -= 1;
                        observer.on_result(
                            observer.context,
                            index,
                            .{ .err = error.Timeout },
                        );
                        continue;
                    }
                    earliest = deadline_policy.earlier(
                        earliest,
                        absolute,
                    );
                }
            }
            if (cancellation) |cancel| cancel.acknowledge(cancel.context);
            if (active_count == 0) break;

            const maybe_event = self.receiveNextBatchResponse(
                earliest,
                cancellation,
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => {
                    fail_unfinished = err;
                    return err;
                },
            };
            if (maybe_event == null) continue;
            var event = maybe_event.?;
            var event_owned = true;
            defer if (event_owned) event.deinit(self.allocator);
            const stream_id = switch (event) {
                .response => |response| response.stream_id,
                .reset => |reset| reset.stream_id,
            };
            var request_index: ?usize = null;
            for (slots, 0..) |slot, index| {
                if (slot.active and slot.stream_id == stream_id) {
                    request_index = index;
                    break;
                }
            }
            const index = request_index orelse {
                fail_unfinished = error.UnexpectedStream;
                return error.UnexpectedStream;
            };
            slots[index].active = false;
            active_count -= 1;
            switch (event) {
                .response => |response| {
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .response = response.value },
                    );
                    event_owned = false;
                },
                .reset => |reset| observer.on_result(
                    observer.context,
                    index,
                    .{ .err = responseResetError(
                        reset.application_error_code,
                    ) },
                ),
            }
        }
    }

    fn receiveNextBatchResponse(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
        cancellation: ?BatchHandshakeCancellationObserver,
    ) ReceiveTimeoutError!?OwnedHandshakeResponseEvent {
        const cancel = cancellation orelse return if (deadline) |absolute|
            try self.receiveNextResponseWithDeadline(absolute)
        else
            try self.receiveNextResponse();

        return self.receiveNextResponseBeforeOrWake(
            deadline,
            cancel.event,
        );
    }

    /// Wait for the next aggregate response or for a driver-control event.
    ///
    /// A response which races the wake is consumed first, so admitting a new
    /// request or canceling a sibling cannot drop an already-received packet.
    /// `null` means only `wake` completed. The caller remains the sole owner
    /// of every send, receive, timeout, and cancellation on this connection.
    pub fn receiveNextResponseBeforeOrWake(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
        wake: *std.Io.Event,
    ) ReceiveTimeoutError!?OwnedHandshakeResponseEvent {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connectionIo(),
                absolute,
            );
        }

        const Wake = union(enum) {
            response: ReceiveTimeoutError!OwnedHandshakeResponseEvent,
            control: std.Io.Cancelable!void,
        };
        const Task = struct {
            fn receive(
                client: *HandshakeClient,
                absolute: ?std.Io.Clock.Timestamp,
            ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
                return if (absolute) |bounded|
                    client.receiveNextResponseWithDeadline(bounded)
                else
                    client.receiveNextResponse();
            }

            fn wait(
                event: *std.Io.Event,
                io: std.Io,
            ) std.Io.Cancelable!void {
                return event.wait(io);
            }
        };
        var storage: [2]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(self.connectionIo(), &storage);
        defer while (select.cancel()) |late| switch (late) {
            .response => |result| if (result) |response| {
                var dropped = response;
                dropped.deinit(self.allocator);
            } else |_| {},
            .control => {},
        };
        try select.concurrent(
            .response,
            Task.receive,
            .{ self, deadline },
        );
        try select.concurrent(
            .control,
            Task.wait,
            .{ wake, self.connectionIo() },
        );

        var response: ?OwnedHandshakeResponseEvent = null;
        var response_err: ?anyerror = null;
        var woke = false;
        const first = select.await() catch |err| return err;
        switch (first) {
            .response => |result| if (result) |value| {
                response = value;
            } else |err| {
                response_err = err;
            },
            .control => |result| {
                try result;
                woke = true;
            },
        }
        while (select.cancel()) |late| switch (late) {
            .response => |result| if (result) |value| {
                if (response == null) {
                    response = value;
                } else {
                    var dropped = value;
                    dropped.deinit(self.allocator);
                }
            } else |err| {
                if (err != error.Canceled) response_err = err;
            },
            .control => |result| result catch |err| {
                if (err != error.Canceled) return err;
            },
        };
        if (response) |value| return value;
        if (response_err) |err| return @errorCast(err);
        std.debug.assert(woke);
        return null;
    }

    /// Streaming counterpart to `receiveNextResponseBeforeOrWake`: return one
    /// buffered response event, or null when `wake` fires first. The caller
    /// must keep consuming the stream through the streaming APIs.
    pub fn receiveResponseEventBeforeOrWake(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        wake: *std.Io.Event,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connectionIo(),
                absolute,
            );
        }

        const Wake = union(enum) {
            event: ReceiveTimeoutError!?StreamingEvent,
            control: std.Io.Cancelable!void,
        };
        const Task = struct {
            fn receive(
                client: *HandshakeClient,
                id: u62,
                absolute: ?std.Io.Clock.Timestamp,
            ) ReceiveTimeoutError!?StreamingEvent {
                return client.receiveResponseEventInternal(id, absolute);
            }

            fn wait(
                event: *std.Io.Event,
                io: std.Io,
            ) std.Io.Cancelable!void {
                return event.wait(io);
            }
        };
        var storage: [2]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(self.connectionIo(), &storage);
        defer while (select.cancel()) |late| switch (late) {
            .event => |result| if (result) |maybe| {
                if (maybe) |event| {
                    var dropped = event;
                    dropped.deinit(self.allocator);
                }
            } else |_| {},
            .control => {},
        };
        try select.concurrent(
            .event,
            Task.receive,
            .{ self, stream_id, deadline },
        );
        try select.concurrent(
            .control,
            Task.wait,
            .{ wake, self.connectionIo() },
        );

        var response: ?StreamingEvent = null;
        var response_err: ?anyerror = null;
        const first = select.await() catch |err| return err;
        switch (first) {
            .event => |result| if (result) |value| {
                response = value;
            } else |err| {
                response_err = err;
            },
            .control => |result| {
                try result;
            },
        }
        while (select.cancel()) |late| switch (late) {
            .event => |result| if (result) |maybe| {
                if (maybe) |value| {
                    if (response == null) {
                        response = value;
                    } else {
                        var dropped = value;
                        dropped.deinit(self.allocator);
                    }
                }
            } else |err| {
                if (err != error.Canceled) response_err = err;
            },
            .control => |result| result catch |err| {
                if (err != error.Canceled) return err;
            },
        };
        if (response) |value| return value;
        if (response_err) |err| return @errorCast(err);
        return null;
    }

    /// Send a request and observe ordered 1xx heads before the final response.
    pub fn requestWithInformational(
        self: *HandshakeClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponseWithInformational(stream_id, informational);
    }

    pub fn requestWithInformationalAndTimeout(
        self: *HandshakeClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn requestWithInformationalAndDeadline(
        self: *HandshakeClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        const stream_id = try self.sendRequestUntil(
            request_options,
            deadline,
        );
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            informational,
            deadline,
        );
    }

    pub fn sendRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
    ) Error!u62 {
        return self.sendRequestUntil(request_options, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendRequestWithTimeout(
        self: *HandshakeClient,
        request_options: http3.Request,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestWithDeadline(request_options, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send one complete request under an absolute deadline without waiting
    /// for its response. A sole connection driver can use this to admit new
    /// streams while older requests are still awaiting responses.
    pub fn sendRequestWithDeadline(
        self: *HandshakeClient,
        request_options: http3.Request,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendRequestUntil(request_options, deadline);
    }

    fn sendRequestUntil(
        self: *HandshakeClient,
        request_options: http3.Request,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return complete_request.send(self, request_options, deadline, .{
            .open = openCompleteRequestStream,
            .receive = receivePacedRequestBody,
            .retryable = requestStreamSendRetryable,
        });
    }

    fn openCompleteRequestStream(self: *HandshakeClient, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!u62 {
        return if (deadline) |absolute|
            self.openClientBidirectionalStreamWithDeadline(absolute)
        else
            self.openClientBidirectionalStream();
    }

    /// Submit one complete request without waiting for pacing or reading UDP.
    /// This static-QPACK path is intended for dispatcher-owned connections;
    /// the encoded request must fit in one transport packet.
    pub fn trySendRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        const lifecycle_exists = self.request_lifecycle.contains(stream_id);
        const transport_next = self.established.connection
            .nextLocalBidirectionalStreamId();
        const retrying_reserved_stream =
            transport_next == next_stream_id and lifecycle_exists;
        if (transport_next != stream_id and !retrying_reserved_stream) {
            return error.StreamCreationError;
        }
        if (retrying_reserved_stream and
            !self.requestStreamSendRetryable(stream_id, next_stream_id))
        {
            return error.UnexpectedStream;
        }
        const extended_connect = requestHasProtocol(request_options.headers);
        if (!lifecycle_exists) {
            try self.request_lifecycle.open(
                stream_id,
                request_options.method,
                extended_connect,
            );
        } else if (!self.request_lifecycle.matchesRequest(
            stream_id,
            request_options.method,
            extended_connect,
        )) {
            return error.UnexpectedStream;
        }
        errdefer if (!lifecycle_exists) {
            // A zero-byte transport stream may have been materialized by a
            // flow-control preflight. Keep its request semantics so the exact
            // same stream ID can be retried without colliding namespaces.
            const keep_for_retry = if (self.established.connection
                .sendStreamStats(stream_id)) |stats|
                stats.highest_sent_offset == 0 and stats.final_size == null
            else
                false;
            if (!keep_for_retry) {
                _ = self.request_lifecycle.finish(stream_id) catch false;
            }
        };
        try self.ensureSettingsSentOnce();
        try trySendConnectionRequestLiteral(
            &self.established.connection,
            &self.stream_send_scratch,
            stream_id,
            request_options,
            self.options,
            self.control.settings.peer,
        );
        self.next_stream_id = next_stream_id;
        if (!lifecycle_exists) self.request_lifecycle.markAllocated(stream_id);
        return stream_id;
    }

    /// Publish the complete critical-stream preface with configured packet
    /// limits, retaining the ordinary transport pacing/recovery behavior.
    pub fn ensureSettingsSent(self: *HandshakeClient) Error!void {
        try sendConnectionSettings(&self.established.connection, &self.critical_stream_send_scratch, &self.control, &self.control_send, &self.qpack_encoder_send, &self.qpack_encoder_prefix_sent, &self.qpack_decoder_send, &self.qpack_decoder_prefix_sent, self.options, client_control_stream_id);
    }

    pub fn ensureSettingsSentWithDeadline(self: *HandshakeClient, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try sendConnectionSettingsWithDeadline(&self.established.connection, &self.critical_stream_send_scratch, &self.control, &self.control_send, &self.qpack_encoder_send, &self.qpack_encoder_prefix_sent, &self.qpack_decoder_send, &self.qpack_decoder_prefix_sent, self.options, client_control_stream_id, deadline);
    }

    /// Send the local SETTINGS/control preface without waiting for pacing.
    pub fn ensureSettingsSentOnce(self: *HandshakeClient) Error!void {
        try trySendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
    }

    fn requireEndpointCriticalStreamsReady(
        self: HandshakeClient,
    ) Error!void {
        if (!self.control.settings.sent or
            !self.qpack_encoder_prefix_sent or
            !self.qpack_decoder_prefix_sent)
        {
            return error.MissingSettings;
        }
    }

    pub const RequestHeadOptions = struct {
        body_length: ?usize = null,
        trailers_pending: bool = false,
    };

    pub fn startRequestWithOptions(self: *HandshakeClient, request_options: http3.Request, options: RequestHeadOptions) Error!u62 {
        return self.startRequestUntilReportingOwner(request_options, options.body_length, null, null, options.trailers_pending) catch |err| return @errorCast(err);
    }

    pub fn startRequestWithOptionsAndDeadline(self: *HandshakeClient, request_options: http3.Request, options: RequestHeadOptions, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.startRequestUntilReportingOwner(request_options, options.body_length, deadline, null, options.trailers_pending);
    }

    pub fn startRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        return self.startRequestUntil(
            request_options,
            body_length,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn startRequestWithTimeout(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startRequestWithDeadline(
            request_options,
            body_length,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send a streaming request head under one absolute deadline. Stream
    /// admission, SETTINGS/QPACK progress, and HEADERS share the same budget.
    pub fn startRequestWithDeadline(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.startRequestUntil(
            request_options,
            body_length,
            deadline,
        );
    }

    fn startRequestUntil(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.startRequestUntilReportingOwner(request_options, body_length, deadline, null, false);
    }

    /// Begin a request whose caller owns any allocated stream even when
    /// HEADERS submission fails. Such failures require scoped cancellation;
    /// they never replay a partial head or close the connection to roll back.
    pub fn startRequestOwned(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        owner: *?u62,
    ) Error!u62 {
        owner.* = null;
        return self.startRequestUntilReportingOwner(request_options, body_length, null, owner, false) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn startRequestOwnedWithDeadline(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        owner: *?u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        owner.* = null;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.startRequestUntilReportingOwner(request_options, body_length, deadline, owner, false);
    }

    /// Convenience form of `startRequestOwnedWithDeadline` using an awake-clock
    /// budget. A non-positive budget clears `owner` before returning Timeout.
    pub fn startRequestOwnedWithTimeout(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        owner: *?u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        owner.* = null;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startRequestOwnedWithDeadline(
            request_options,
            body_length,
            owner,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn startRequestUntilReportingOwner(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
        owner: ?*?u62,
        trailers_pending: bool,
    ) ReceiveTimeoutError!u62 {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        const lifecycle_exists = self.request_lifecycle.contains(stream_id);
        const extended_connect = requestHasProtocol(request_options.headers);
        if (!lifecycle_exists) {
            try self.request_lifecycle.open(
                stream_id,
                request_options.method,
                extended_connect,
            );
        } else if (!self.request_lifecycle.matchesRequest(
            stream_id,
            request_options.method,
            extended_connect,
        )) {
            return error.UnexpectedStream;
        }
        if (lifecycle_exists and
            !self.requestStreamSendRetryable(stream_id, next_stream_id))
        {
            return error.UnexpectedStream;
        }
        var transport_reserved = lifecycle_exists;
        const qpack_checkpoint = self.qpack_encode.checkpoint();
        var head_sent = false;
        errdefer {
            if (owner != null and transport_reserved) {
                owner.?.* = stream_id;
                self.next_stream_id = next_stream_id;
            } else {
                if (!head_sent) self.qpack_encode.rollbackAfter(qpack_checkpoint);
                if (transport_reserved and self.requestStreamSendRetryable(
                    stream_id,
                    next_stream_id,
                )) {
                    self.next_stream_id = stream_id;
                } else {
                    if (transport_reserved and self.established.connection
                        .nextLocalBidirectionalStreamId() == next_stream_id)
                    {
                        self.next_stream_id = next_stream_id;
                    }
                    _ = self.request_lifecycle.finish(stream_id) catch false;
                    _ = self.outbound_bodies.finish(stream_id);
                }
            }
        }
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        if (deadline) |absolute| {
            while (true) {
                sendConnectionSettingsWithDeadline(
                    &self.established.connection,
                    &self.critical_stream_send_scratch,
                    &self.control,
                    &self.control_send,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.qpack_decoder_send,
                    &self.qpack_decoder_prefix_sent,
                    self.options,
                    client_control_stream_id,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        if (self.established.connection.closed()) return err;
                        try self.receiveResponseProgressForSendUntil(
                            stream_id,
                            absolute,
                        );
                        continue;
                    },
                    else => |other| return other,
                };
                break;
            }
        } else {
            try sendConnectionSettings(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
            );
        }
        if (!lifecycle_exists) {
            const transport_id = if (deadline) |absolute|
                try self.openClientBidirectionalStreamWithDeadline(absolute)
            else
                try self.openClientBidirectionalStream();
            std.debug.assert(transport_id == stream_id);
            transport_reserved = true;
        }
        if (owner) |retained| {
            retained.* = stream_id;
            var committed: usize = 0;
            while (true) {
                sendConnectionStreamingHeadProgress(
                    &self.established.connection,
                    &self.stream_send_scratch,
                    &self.critical_stream_send_scratch,
                    stream_id,
                    streaming.expected_length,
                    streaming.body_allowed,
                    trailers_pending,
                    self.options,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.outbound_bodies,
                    0,
                    &committed,
                    deadline,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        if (self.established.connection.closed()) return err;
                        if (deadline) |absolute| try self.receiveResponseProgressForSendUntil(stream_id, absolute) else try self.receiveResponseProgressForSend(stream_id);
                        continue;
                    },
                    else => return err,
                };
                break;
            }
        } else if (deadline) |absolute| {
            while (true) {
                sendConnectionStreamingHeadWithDeadline(
                    &self.established.connection,
                    &self.stream_send_scratch,
                    &self.critical_stream_send_scratch,
                    stream_id,
                    streaming.expected_length,
                    streaming.body_allowed,
                    trailers_pending,
                    self.options,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.outbound_bodies,
                    0,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        if (self.established.connection.closed()) return err;
                        try self.receiveResponseProgressForSendUntil(
                            stream_id,
                            absolute,
                        );
                        continue;
                    },
                    else => |other| return other,
                };
                break;
            }
        } else {
            try sendConnectionStreamingHead(
                &self.established.connection,
                &self.stream_send_scratch,
                &self.critical_stream_send_scratch,
                stream_id,
                streaming.expected_length,
                streaming.body_allowed,
                trailers_pending,
                self.options,
                &self.qpack_encode,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.outbound_bodies,
                0,
            );
        }
        head_sent = true;
        self.next_stream_id = next_stream_id;
        return stream_id;
    }

    /// Begin an incrementally-written request without waiting for pacing or
    /// reading UDP. The literal/static QPACK head must fit in one transport
    /// packet; a failed send retains a zero-byte stream for identical retry.
    pub fn tryStartRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        const lifecycle_exists = self.request_lifecycle.contains(stream_id);
        const transport_next = self.established.connection
            .nextLocalBidirectionalStreamId();
        const retrying_reserved_stream =
            transport_next == next_stream_id and lifecycle_exists;
        if (transport_next != stream_id and !retrying_reserved_stream) {
            return error.StreamCreationError;
        }
        if (retrying_reserved_stream and
            !self.requestStreamSendRetryable(stream_id, next_stream_id))
        {
            return error.UnexpectedStream;
        }
        const extended_connect = requestHasProtocol(request_options.headers);
        if (!lifecycle_exists) {
            try self.request_lifecycle.open(
                stream_id,
                request_options.method,
                extended_connect,
            );
        } else if (!self.request_lifecycle.matchesRequest(
            stream_id,
            request_options.method,
            extended_connect,
        )) {
            return error.UnexpectedStream;
        }
        errdefer if (!lifecycle_exists) {
            const keep_for_retry = if (self.established.connection
                .sendStreamStats(stream_id)) |stats|
                stats.highest_sent_offset == 0 and stats.final_size == null
            else
                false;
            if (!keep_for_retry) {
                _ = self.request_lifecycle.finish(stream_id) catch false;
            }
        };
        try self.ensureSettingsSentOnce();
        try trySendConnectionStreamingRequestHeadLiteral(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.outbound_bodies,
            stream_id,
            request_options,
            body_length,
            self.options,
            self.control.settings.peer,
        );
        self.next_stream_id = next_stream_id;
        if (!lifecycle_exists) self.request_lifecycle.markAllocated(stream_id);
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
    }

    /// Submit one complete request DATA contribution without waiting for
    /// pacing or reading the connection socket.
    pub fn trySendRequestBody(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try trySendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
    }

    /// Submit one packet-sized STREAM fragment of a retained DATA
    /// contribution. The caller keeps `data` and `state` until completion;
    /// this method neither waits for pacing nor reads the UDP endpoint.
    pub fn trySendRequestBodyFragment(self: *HandshakeClient, stream_id: u62, data: []const u8, fin: bool, state: *runtime.BodyWriteState) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) return error.UnexpectedStream;
        return runtime.body_fragment.write(&self.established.connection, &self.outbound_bodies, stream_id, data, fin, state, self.options);
    }

    /// Submit several borrowed slices as one DATA frame and one QUIC packet
    /// without waiting for pacing or reading UDP. The entire contribution is
    /// retryable after backpressure because no offset is committed unless the
    /// packet reaches the endpoint.
    pub fn trySendRequestBodyParts(
        self: *HandshakeClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try trySendConnectionBodyParts(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            parts,
            fin,
            self.options,
        );
    }

    /// Send request DATA and synchronously pump peer packets when QUIC
    /// congestion or flow-control state is not yet writable.
    ///
    /// This mirrors production event loops (quicz/tquic style): a failed write
    /// due to `CongestionLimited` or `FlowControlBlocked` is not terminal, it
    /// means the connection must process ACK/MAX_* frames before retrying. The
    /// method keeps aggregate `receiveResponse` usable by routing those packets
    /// through the normal response queues instead of activating the streaming
    /// response reader.
    pub fn sendRequestBodyPaced(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        var progress: BodyWriteProgress = .{};
        return self.sendRequestBodyPacedTracked(stream_id, data, fin, &progress);
    }

    /// Report the accepted application prefix even on caller cancellation.
    pub fn sendRequestBodyPacedTracked(self: *HandshakeClient, stream_id: u62, data: []const u8, fin: bool, progress: *BodyWriteProgress) Error!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = paced_body.write(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, data, fin, null, progress, paced_request_hooks) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    const paced_request_hooks = .{ .before = beforePacedRequestBody, .receive = receivePacedRequestBody, .finish = finishPacedRequestBody };

    fn beforePacedRequestBody(self: *HandshakeClient, id: u62, _: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!bool {
        try self.failIfRequestResetForSend(id);
        return false;
    }
    fn receivePacedRequestBody(self: *HandshakeClient, id: u62, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (deadline) |absolute| try self.receiveResponseProgressForSendUntil(id, absolute) else try self.receiveResponseProgressForSend(id);
    }
    fn finishPacedRequestBody(_: *HandshakeClient, _: u62) ReceiveTimeoutError!void {}

    pub fn sendRequestBodyPacedWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyPacedWithDeadline(
            stream_id,
            data,
            fin,
            progress,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send one request DATA sequence under one absolute deadline. Progress
    /// reports the exact socket-visible application prefix and FIN state, so a
    /// caller can continue only the unsent suffix after a timeout.
    pub fn sendRequestBodyPacedWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        _ = try paced_body.write(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, data, fin, deadline, progress, paced_request_hooks);
    }

    /// Client counterpart to `sendResponseBodyPartsPaced`; packet-sized
    /// contributions span application-slice boundaries without joining them.
    pub fn sendRequestBodyPartsPaced(
        self: *HandshakeClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id)) return error.UnexpectedStream;
        var progress: BodyWriteProgress = .{};
        _ = paced_body.writeParts(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, parts, fin, null, &progress, paced_request_hooks) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn sendRequestBodyPartsPacedWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            parts,
            fin,
            progress,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send borrowed request slices under one absolute deadline without
    /// joining them. Progress is the exact socket-visible byte prefix across
    /// all slices, allowing the caller to retry only the remaining suffix.
    pub fn sendRequestBodyPartsPacedWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id)) return error.UnexpectedStream;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        _ = try paced_body.writeParts(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, parts, fin, deadline, progress, paced_request_hooks);
    }

    /// Send one DATA contribution per active request stream as a stateful QUIC
    /// packet batch.
    ///
    /// The input order determines packet order and each stream may appear at
    /// most once. Congestion, flow control, and pacing are handled like
    /// `sendRequestBodyPaced`, but socket-visible packet prefixes are committed
    /// together so multi-stream schedulers can amortize protection and
    /// sendmmsg/GSO overhead without sharing mutable DATA payload storage.
    pub fn sendRequestBodyBatchPaced(
        self: *HandshakeClient,
        chunks: []const BodyChunk,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        try sendConnectionBodyBatchPaced(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeClient.receiveBatchProgressForSend,
            HandshakeClient.finishBatchRequestStream,
        );
    }

    pub fn sendRequestBodyBatchPacedWithTimeout(
        self: *HandshakeClient,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        committed_chunks.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyBatchPacedWithDeadline(
            chunks,
            committed_chunks,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send one DATA contribution per request stream under one caller-owned
    /// deadline. `committed_chunks` is the exact socket-visible input prefix
    /// and remains valid on timeout or a socket error.
    pub fn sendRequestBodyBatchPacedWithDeadline(
        self: *HandshakeClient,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        committed_chunks.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        return sendConnectionBodyBatchPacedWithDeadline(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeClient.receiveBatchProgressForSendUntil,
            HandshakeClient.finishBatchRequestStream,
            committed_chunks,
            deadline,
        );
    }

    /// Submit at most one socket-visible prefix of independent request body
    /// chunks without waiting for pacing or reading UDP. On a partial socket
    /// send, `sent_count` identifies the committed prefix even when
    /// `send_error` is non-null; retry only `chunks[sent_count..]`.
    pub fn trySendRequestBodyBatch(
        self: *HandshakeClient,
        chunks: []const BodyChunk,
    ) Error!BodyBatchProgress {
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        return sendConnectionBodyBatchPacedProgress(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeClient.finishBatchRequestStream,
        );
    }

    fn receiveBatchProgressForSend(self: *HandshakeClient) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        try receiveConnectionResponsePacket(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
        );
        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) return;
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(reset.stream_id);
            _ = self.request_lifecycle.finishAssumeCapacity(reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            self.sendQpackFeedback() catch {};
            return responseResetError(reset.application_error_code);
        }
    }

    fn receiveBatchProgressForSendUntil(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        try self.failIfAnyRequestResetForBatchSend();
        try receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        );
        try self.failIfAnyRequestResetForBatchSend();
    }

    fn failIfAnyRequestResetForBatchSend(
        self: *HandshakeClient,
    ) Error!void {
        const reset = self.response_streams.firstReset() orelse return;
        if (!self.request_lifecycle.contains(reset.stream_id)) return;
        try self.request_lifecycle.prepareFinish();
        _ = self.response_streams.takeReset(reset.stream_id);
        _ = self.request_lifecycle.finishAssumeCapacity(reset.stream_id);
        _ = self.outbound_bodies.finish(reset.stream_id);
        self.sendQpackFeedback() catch {};
        return responseResetError(reset.application_error_code);
    }

    fn finishBatchRequestStream(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        _ = self;
        _ = stream_id;
        // A request remains outstanding until its response is consumed. The
        // shared batch helper already retires only the outbound body state.
    }

    fn sendRequestBodyPacedChunk(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendRequestBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponseProgressForSend(stream_id);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn finishRequestTrailers(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendConnectionTrailers(
            &self.established.connection,
            &self.outbound_bodies,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            self.options,
        );
    }

    /// Finish a streaming request with literal/static-QPACK trailers in one
    /// nonblocking transport attempt.
    pub fn tryFinishRequestTrailers(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try trySendConnectionTrailersLiteral(
            &self.established.connection,
            &self.outbound_bodies,
            &self.stream_send_scratch,
            stream_id,
            trailers,
            self.control.settings.peer,
            self.options,
        );
    }

    /// Blocking counterpart to `finishRequestTrailers` that keeps processing
    /// response-side ACK/MAX_* packets until the trailer section is writable.
    pub fn finishRequestTrailersPaced(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.finishRequestTrailersPacedUntil(
            stream_id,
            trailers,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn finishRequestTrailersPacedWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestTrailersPacedWithDeadline(
            stream_id,
            trailers,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Finish a streaming request with trailers under one absolute deadline.
    /// A timeout before any packet is visible is retryable; a timeout after a
    /// multi-packet QPACK/trailer prefix uses the packetizer's fail-closed rule.
    pub fn finishRequestTrailersPacedWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.finishRequestTrailersPacedUntil(
            stream_id,
            trailers,
            deadline,
        );
    }

    fn finishRequestTrailersPacedUntil(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        while (true) {
            if (deadline) |absolute| {
                if (!self.request_lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
                try self.failIfRequestResetForSend(stream_id);
                sendConnectionTrailersWithDeadline(
                    &self.established.connection,
                    &self.outbound_bodies,
                    &self.stream_send_scratch,
                    &self.critical_stream_send_scratch,
                    stream_id,
                    trailers,
                    self.control.settings.peer,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    self.options,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        try self.receiveResponseProgressForSendUntil(
                            stream_id,
                            absolute,
                        );
                        continue;
                    },
                    else => |other| return other,
                };
                return;
            }
            self.finishRequestTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponseProgressForSend(stream_id);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn receiveResponse(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!OwnedHandshakeResponse {
        return self.receiveResponseWithInformational(stream_id, null);
    }

    pub fn receiveResponseWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            null,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveResponseWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            null,
            deadline,
        );
    }

    /// Aggregate a response while observing ordered, callback-scoped 1xx heads.
    pub fn receiveResponseWithInformational(
        self: *HandshakeClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveResponseWithInformationalInternal(
            stream_id,
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveResponseWithInformationalAndTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            informational,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveResponseWithInformationalAndDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveResponseWithInformationalInternal(
            stream_id,
            informational,
            deadline,
        );
    }

    fn receiveResponseWithInformationalInternal(
        self: *HandshakeClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponse {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        var prepared = receiveConnectionResponseStreamBytesUntil(
            &self.established.connection,
            &self.receive_packets,
            stream_id,
            self.options,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                _ = try self.established.connection
                    .requestCompletedLocalStreamRelease(stream_id);
                _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.sendQpackFeedback() catch {};
                self.flushFinalResponseAckIfIdle();
                return err;
            },
            else => {
                closeConnectionForHttp3Error(
                    &self.established.connection,
                    err,
                ) catch {};
                return err;
            },
        };
        defer prepared.deinit(
            self.established.connection.endpoint.allocator,
        );
        if (prepared.bytes.len == 0) {
            self.failReceivedResponse(
                stream_id,
                prepared.bytes,
                error.MissingStatus,
                true,
            ) catch {};
            return error.MissingStatus;
        }
        http3.validateResponsePushPromises(
            self.control,
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                prepared.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        const section_count = responseFieldSectionCount(
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                prepared.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        try self.qpack_decode.prepareSectionAcknowledgments(section_count);
        try self.request_lifecycle.prepareFinish();
        const promise_checkpoint = self.push_streams.promiseCount();
        errdefer self.push_streams.rollbackPromises(promise_checkpoint);
        registerResponsePushPromises(
            &self.push_streams,
            prepared.stream_id,
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                prepared.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        var guarded_informational: ?InformationalCallbackGuard =
            if (informational) |observer| .{
                .observer = observer,
                .callback_reader_active = &self.callback_reader_active,
            } else null;
        var response = http3.decodeResponseWithDynamicTableAndOptions(
            self.established.connection.endpoint.allocator,
            prepared.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.options.max_informational_responses;
                options.informational = if (guarded_informational) |*guard|
                    .{
                        .context = guard,
                        .on_response = InformationalCallbackGuard.notify,
                    }
                else
                    null;
                break :blk options;
            },
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                prepared.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        errdefer response.deinit(self.established.connection.endpoint.allocator);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            prepared.stream_id,
            response.qpack_section_acknowledgments,
        );
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(stream_id);
        const assembled = self.response_streams.commitPreparedReady(
            &prepared,
        );
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        if (deadline) |absolute|
            self.sendQpackFeedbackWithDeadline(absolute) catch {}
        else
            self.sendQpackFeedback() catch {};
        self.flushFinalResponseAckIfIdle();
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn receiveNextResponse(
        self: *HandshakeClient,
    ) Error!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveNextResponseWithInformational(null);
    }

    /// Aggregate whichever outstanding response becomes ready within one
    /// relative budget. A timeout leaves every request eligible for later
    /// aggregate or incremental consumption.
    pub fn receiveNextResponseWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveNextResponseWithInformationalAndDeadline(
            null,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveNextResponseWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveNextResponseWithInformationalAndDeadline(
            null,
            deadline,
        );
    }

    /// Aggregate whichever outstanding response becomes ready first and
    /// correlate every callback-scoped 1xx head with its request stream.
    pub fn receiveNextResponseWithInformational(
        self: *HandshakeClient,
        informational: ?MultiplexedInformationalObserver,
    ) Error!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveNextResponseWithInformationalInternal(
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveNextResponseWithInformationalAndTimeout(
        self: *HandshakeClient,
        informational: ?MultiplexedInformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveNextResponseWithInformationalAndDeadline(
            informational,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveNextResponseWithInformationalAndDeadline(
        self: *HandshakeClient,
        informational: ?MultiplexedInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        // Callback ordering is preserved across all packets consumed before
        // the timeout, including unrelated response streams.
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveNextResponseWithInformationalInternal(
            informational,
            deadline,
        );
    }

    fn receiveNextResponseWithInformationalInternal(
        self: *HandshakeClient,
        informational: ?MultiplexedInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (self.response_streams.firstReset()) |reset| {
                if (self.request_lifecycle.contains(reset.stream_id)) {
                    try self.request_lifecycle.prepareFinish();
                    _ = self.response_streams.takeReset(reset.stream_id);
                    _ = self.request_lifecycle.finishAssumeCapacity(
                        reset.stream_id,
                    );
                    _ = self.outbound_bodies.finish(reset.stream_id);
                    self.sendQpackFeedback() catch {};
                    self.flushFinalResponseAckIfIdle();
                    return .{ .reset = .{
                        .stream_id = reset.stream_id,
                        .application_error_code = reset.application_error_code,
                    } };
                }
            }
            const ready_stream_id = self.response_streams.firstReadyStream(
                self.qpack_decode.table,
                self.options.local_settings.qpack_blocked_streams,
            ) catch |err| {
                closeConnectionForHttp3Error(
                    &self.established.connection,
                    err,
                ) catch {};
                return err;
            };
            if (ready_stream_id) |stream_id| {
                if (!self.request_lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
                if (informational) |observer| {
                    // Aggregate decoding is synchronous, so this stack adapter
                    // remains alive for every callback and cannot escape.
                    var adapter = MultiplexedInformationalContext{
                        .observer = observer,
                        .stream_id = stream_id,
                    };
                    return .{ .response = .{
                        .stream_id = stream_id,
                        .value = try self.receiveResponseWithInformationalInternal(
                            stream_id,
                            .{
                                .context = &adapter,
                                .on_response = MultiplexedInformationalContext.notify,
                            },
                            deadline,
                        ),
                    } };
                }
                return .{ .response = .{
                    .stream_id = stream_id,
                    .value = try self.receiveResponseWithInformationalInternal(
                        stream_id,
                        null,
                        deadline,
                    ),
                } };
            }
            try receiveConnectionResponsePacketUntil(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                self.options.local_settings.qpack_blocked_streams,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
                null,
                &self.connect_datagrams,
                &self.ticket_receiver,
                &self.established,
                deadline,
            );
        }
    }

    /// Process one peer packet and retain any HTTP/3 events for the normal
    /// response and push APIs.
    ///
    /// Applications normally make progress implicitly through a blocking
    /// response call. A control-only exchange, such as waiting for the
    /// server GOAWAY that acknowledges a client-initiated shutdown, has no
    /// response stream to drive that path. This explicit pump also permits
    /// event loops to observe GOAWAY while an accepted response remains
    /// buffered and available to `receiveResponse`.
    pub fn receiveProgress(self: *HandshakeClient) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
        try self.flushResponsePacketFeedback();
    }

    /// Wait for the peer's mandatory HTTP/3 SETTINGS while preserving any
    /// concurrently received request-stream bytes for their normal readers.
    /// Extended CONNECT adapters use this before depending on advertised
    /// protocol capabilities.
    pub fn receivePeerSettings(self: *HandshakeClient) Error!http3.Settings {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receivePeerSettingsInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Return already-received peer SETTINGS without reading UDP. Connection
    /// pools use this after a completed response to retain the exact origin-
    /// scoped settings required by a future 0-RTT request.
    pub fn peerSettings(self: *const HandshakeClient) ?http3.Settings {
        return if (self.control.settings.received)
            self.control.settings.peer
        else
            null;
    }

    pub fn receivePeerSettingsWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!http3.Settings {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerSettingsInternal(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receivePeerSettingsWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!http3.Settings {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receivePeerSettingsInternal(deadline);
    }

    fn receivePeerSettingsInternal(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!http3.Settings {
        if (self.callback_reader_active) return error.ConcurrentRead;
        while (!self.control.settings.received) {
            try receiveConnectionResponsePacketUntil(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                self.options.local_settings.qpack_blocked_streams,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
                null,
                &self.connect_datagrams,
                &self.ticket_receiver,
                &self.established,
                deadline,
            );
            try self.flushResponsePacketFeedback();
        }
        return self.control.settings.peer;
    }

    /// Apply one already-authenticated packet selected by an endpoint-wide
    /// dispatcher. The packet remains caller-owned and no UDP read occurs.
    /// Responses, pushes, control frames, and QPACK state remain available to
    /// the normal aggregate or incremental receive APIs.
    pub fn processResponsePacket(
        self: *HandshakeClient,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.processResponsePacketPreserving(null, packet, true);
    }

    /// Advance one response stream without assembling its DATA payload.
    ///
    /// The first call transfers any already-buffered STREAM ranges into the
    /// incremental reader without copying. Subsequent packet pumping keeps
    /// other active response streams in their own bounded windows, so callers
    /// may interleave this API across multiple outstanding requests.
    pub fn receiveResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveResponseEventInternal(stream_id, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    /// Return one event already buffered for `stream_id` without reading UDP.
    /// Once a response enters streaming mode, its remaining events must be
    /// consumed through the streaming APIs rather than aggregate receive.
    pub fn pollResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.pollResponseEventInternal(stream_id, false);
    }

    /// Return one buffered response event without waiting for receive credit
    /// or QPACK feedback pacing. A null result preserves all pending work for
    /// a later dispatcher turn.
    pub fn pollResponseEventOnce(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        return self.pollResponseEventInternal(stream_id, true);
    }

    fn pollResponseEventInternal(
        self: *HandshakeClient,
        stream_id: u62,
        single_attempt: bool,
    ) Error!?StreamingEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.progressResponsePollFailures(stream_id, null);
        if (self.streaming_responses.find(stream_id)) |entry| {
            if (entry.message_failure_pending) return null;
        }
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (single_attempt) {
            self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
        }
        if (self.streaming_responses.find(stream_id)) |active| {
            if (single_attempt) {
                releaseStreamingReaderCapacityOnce(
                    &self.established.connection,
                    &active.reader,
                ) catch |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => return null,
                    else => return err,
                };
                if (active.reader.finished()) {
                    try self.finishStreamingResponse(stream_id);
                    return .finished;
                }
            } else {
                try releaseStreamingReaderCapacity(
                    &self.established.connection,
                    &active.reader,
                );
            }
        }
        if (self.response_streams.resetFor(stream_id)) |code| {
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(stream_id);
            try self.finishStreamingResponse(stream_id);
            if (single_attempt)
                self.flushResponsePacketFeedbackOnce() catch {}
            else
                self.flushResponsePacketFeedback() catch {};
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        try self.request_lifecycle.prepareFinish();
        const entry = try self.streaming_responses.activateResponse(
            &self.response_streams,
            stream_id,
        );
        applyResponseReaderSemantics(
            self.request_lifecycle,
            stream_id,
            &entry.reader,
        );
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        try self.pending_response_failures.reserve(self.allocator);
        const event = (entry.reader.next(self.qpack_decode.table) catch |err| {
            try self.retainResponsePollFailure(stream_id, err, null);
            return err;
        }) orelse return null;
        const owned_event = event;
        var event_owned = true;
        errdefer if (event_owned) {
            var dropped = owned_event;
            dropped.deinit(
                self.established.connection.endpoint.allocator,
            );
        };
        const committed = self.applyStreamingResponseEvent(
            stream_id,
            owned_event,
            single_attempt,
        ) catch |err| {
            try self.retainResponsePollFailure(stream_id, err, null);
            return err;
        };
        if (!committed) return null;
        event_owned = false;
        return owned_event;
    }

    pub fn receiveResponseEventWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveResponseEventInternal(stream_id, deadline);
    }

    pub fn receiveResponseEventWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseEventInternal(
            stream_id,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveResponseEventInternal(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (try self.pollResponseEvent(stream_id)) |event| return event;
        try receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        );
        try self.flushResponsePacketFeedback();
        return self.pollResponseEvent(stream_id);
    }

    pub fn connectionIo(self: *const HandshakeClient) std.Io {
        return self.established.connection.endpoint.io;
    }

    fn accessResponseData(
        self: *HandshakeClient,
        stream_id: u62,
        out: []u8,
        comptime operation: message_data.Operation,
        comptime single_attempt: bool,
    ) Error!?usize {
        return message_data.access(
            self,
            &self.established.connection,
            &self.streaming_responses,
            &self.pending_response_failures,
            self.allocator,
            stream_id,
            out,
            operation,
            single_attempt,
            HandshakeClient.progressResponsePollFailures,
            HandshakeClient.retainResponsePollFailure,
        );
    }

    /// Copy currently available DATA bytes into caller-owned storage.
    ///
    /// Returning zero means more STREAM bytes or cancellation progress is
    /// needed. Consumed bytes are credited on the next read or event poll,
    /// preserving the returned count if receive-credit submission fails.
    pub fn readResponseData(
        self: *HandshakeClient,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try self.accessResponseData(stream_id, out, .read, false)) orelse 0;
    }

    /// Return DATA bytes currently readable without receiving another packet.
    pub fn availableResponseData(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try self.accessResponseData(stream_id, &.{}, .available, false)) orelse 0;
    }

    /// Copy available DATA without waiting for receive-credit pacing. `null`
    /// means previously consumed bytes still need a retry; a successful read
    /// is never rolled back or delivered twice when its new credit is paced.
    pub fn readResponseDataOnce(
        self: *HandshakeClient,
        stream_id: u62,
        out: []u8,
    ) Error!?usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        return self.accessResponseData(stream_id, out, .read, true);
    }

    pub fn skipResponseData(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try self.accessResponseData(stream_id, &.{}, .skip, false)) orelse 0;
    }

    /// Detach an established Extended CONNECT response stream from HTTP/3
    /// message parsing after final response HEADERS have been consumed.
    pub fn detachResponseStream(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.detachResponseStreamInternal(stream_id, false);
    }

    /// Detach an established response stream without waiting for receive
    /// credit. Backpressure leaves the reader and association unchanged.
    pub fn detachResponseStreamOnce(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        return self.detachResponseStreamInternal(stream_id, true);
    }

    fn detachResponseStreamInternal(
        self: *HandshakeClient,
        stream_id: u62,
        single_attempt: bool,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachResponse()) {
            return error.UnexpectedStream;
        }
        const already_registered = self.connect_datagrams.contains(stream_id);
        if (!already_registered) try self.connect_datagrams.register(stream_id);
        errdefer if (!already_registered) {
            self.connect_datagrams.unregister(stream_id);
        };
        if (single_attempt)
            try releaseStreamingReaderCapacityOnce(
                &self.established.connection,
                &entry.reader,
            )
        else
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        try self.connect_datagrams.markStreamDetached(stream_id);
        var removed = self.streaming_responses.takeEntry(stream_id) orelse
            return error.UnexpectedStream;
        removed.deinit();
    }

    /// Whether a pending protocol adapter already reserved this Extended
    /// CONNECT association before the final response was decoded.
    pub fn hasConnectDatagramAssociation(
        self: HandshakeClient,
        stream_id: u62,
    ) bool {
        return self.connect_datagrams.contains(stream_id);
    }

    /// Client counterpart to `receiveDetachedRequestProgress`.
    pub fn receiveDetachedResponseProgress(
        self: *HandshakeClient,
        detached_stream_id: u62,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        self.receiveDetachedResponseProgressInternal(
            detached_stream_id,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveDetachedResponseProgressWithTimeout(
        self: *HandshakeClient,
        detached_stream_id: u62,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDetachedResponseProgressWithDeadline(
            detached_stream_id,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveDetachedResponseProgressWithDeadline(
        self: *HandshakeClient,
        detached_stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.receiveDetachedResponseProgressInternal(
            detached_stream_id,
            deadline,
            null,
        );
    }

    fn receiveDetachedResponseProgressInternal(
        self: *HandshakeClient,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        datagram_target: ?*connect_datagram.ReceiveIntoTarget,
    ) ReceiveTimeoutError!void {
        return ConnectDatagramProgress.run(self, detached_stream_id, deadline, datagram_target);
    }

    fn receiveDetachedResponsePacketInto(
        self: *HandshakeClient,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        datagram_target: ?*connect_datagram.ReceiveIntoTarget,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.connect_datagrams.contains(detached_stream_id)) return error.UnexpectedStream;
        var context: ConnectionResponseReceiveContext = .{
            .connection = &self.established.connection,
            .control = &self.control,
            .qpack_decode = &self.qpack_decode,
            .qpack_encode = &self.qpack_encode,
            .max_blocked_streams = self.options.local_settings.qpack_blocked_streams,
            .response_streams = &self.response_streams,
            .streaming_responses = &self.streaming_responses,
            .push_streams = &self.push_streams,
            .request_lifecycle = &self.request_lifecycle,
            .detached_stream_id = detached_stream_id,
            .detached_streams = &self.connect_datagrams,
            .datagram_target = datagram_target,
            .ticket_receiver = &self.ticket_receiver,
            .established = &self.established,
        };
        if (deadline) |absolute| {
            try self.receive_packets.visitWithDeadline(
                &self.established.connection,
                absolute,
                &context,
                visitConnectionResponsePacket,
            );
        } else {
            try self.receive_packets.visit(
                &self.established.connection,
                &context,
                visitConnectionResponsePacket,
            );
        }
    }

    pub fn receiveDetachedResponseProgressInto(
        self: *HandshakeClient,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        datagram_target: *connect_datagram.ReceiveIntoTarget,
    ) ReceiveTimeoutError!void {
        return self.receiveDetachedResponseProgressInternal(
            detached_stream_id,
            deadline,
            datagram_target,
        );
    }

    pub fn receiveAttachedConnectDatagramProgress(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return ConnectDatagramProgress.run(self, null, deadline, @as(?*connect_datagram.ReceiveIntoTarget, null));
    }

    fn receiveAttachedConnectDatagramPacket(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        );
    }

    pub fn connectDatagramsNegotiated(self: HandshakeClient) bool {
        return self.control.settings.sent and
            self.control.settings.received and
            self.control.settings.local.h3_datagram and
            self.control.settings.peer.h3_datagram and
            self.established.connection.datagramsEnabled();
    }

    pub fn startConnectUdp(
        self: *HandshakeClient,
        target: http3.connect_udp.Target,
        authority: []const u8,
        path_storage: []u8,
    ) Error!u62 {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const stream_id = try self.startRequest(
            try http3.connect_udp.requestInto(
                path_storage,
                target,
                authority,
            ),
            null,
        );
        errdefer self.cancelPendingConnectDatagramAssociation(stream_id);
        try self.registerPendingConnectDatagramAssociation(stream_id);
        return stream_id;
    }

    pub fn startConnectIp(
        self: *HandshakeClient,
        scope: http3.connect_ip.Scope,
        authority: []const u8,
        path_storage: []u8,
    ) Error!u62 {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const stream_id = try self.startRequest(
            try http3.connect_ip.requestInto(
                path_storage,
                scope,
                authority,
            ),
            null,
        );
        errdefer self.cancelPendingConnectDatagramAssociation(stream_id);
        try self.registerPendingConnectDatagramAssociation(stream_id);
        return stream_id;
    }

    pub fn startConnectIpWithTemplate(
        self: *HandshakeClient,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        path_storage: []u8,
    ) Error!u62 {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const stream_id = try self.startRequest(
            try http3.connect_ip.requestWithTemplateInto(
                path_storage,
                template,
                scope,
                variables,
            ),
            null,
        );
        errdefer self.cancelPendingConnectDatagramAssociation(stream_id);
        try self.registerPendingConnectDatagramAssociation(stream_id);
        return stream_id;
    }

    /// Validate the final response head without detaching the CONNECT stream;
    /// reliable configuration Capsules continue through the streaming reader.
    pub fn acceptConnectIpResponse(
        self: *HandshakeClient,
        stream_id: u62,
        response: http3.DecodedResponseHead,
    ) Error!ConnectIpClientSession {
        try http3.connect_ip.validateResponseHead(
            response.status,
            response.headers,
        );
        if (response.content_length != null) return error.InvalidHeader;
        if (!self.connect_datagrams.contains(stream_id) or
            self.connect_datagrams.streamDetached(stream_id) or
            self.streaming_responses.find(stream_id) == null)
        {
            return error.UnexpectedStream;
        }
        return ConnectIpClientSession.init(
            self.allocator,
            self.connectionIo(),
            self,
            stream_id,
        );
    }

    pub fn startConnectUdpWithTemplate(
        self: *HandshakeClient,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        path_storage: []u8,
    ) Error!u62 {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const stream_id = try self.startRequest(
            try http3.connect_udp.requestWithTemplateInto(
                path_storage,
                template,
                target,
                variables,
            ),
            null,
        );
        errdefer self.cancelPendingConnectDatagramAssociation(stream_id);
        try self.registerPendingConnectDatagramAssociation(stream_id);
        return stream_id;
    }

    pub fn acceptConnectUdpResponse(
        self: *HandshakeClient,
        stream_id: u62,
        response: http3.DecodedResponseHead,
    ) Error!ConnectUdpClientSession {
        try http3.connect_udp.validateResponseHead(
            response.status,
            response.headers,
        );
        if (response.content_length != null) return error.InvalidHeader;
        try self.detachResponseStream(stream_id);
        return ConnectUdpClientSession.init(
            self.allocator,
            self.connectionIo(),
            self,
            stream_id,
        );
    }

    pub fn maxConnectDatagramPayloadSize(
        self: HandshakeClient,
        stream_id: u62,
    ) ?usize {
        connect_datagram.validateStreamId(stream_id) catch return null;
        if (!self.connect_datagrams.contains(stream_id)) return null;
        ensureConnectDatagramSendSideOpen(
            self.established.connection,
            stream_id,
        ) catch return null;
        ensureConnectDatagramsNegotiated(
            self.control.settings,
            self.established.connection,
            .send,
        ) catch return null;
        const quic_payload = self.established.connection
            .maxDatagramPayloadSize() orelse return null;
        const prefix = quic.varint.length(stream_id / 4) catch return null;
        if (prefix > quic_payload) return null;
        return quic_payload - prefix;
    }

    /// Storage sufficient for one peer HTTP Datagram after its Quarter
    /// Stream ID has been removed. Unlike the send maximum, this remains
    /// available after the local stream send side is closed.
    pub fn connectDatagramReceiveBufferSize(
        self: HandshakeClient,
        stream_id: u62,
    ) ?usize {
        connect_datagram.validateStreamId(stream_id) catch return null;
        if (!self.connect_datagrams.contains(stream_id)) return null;
        ensureConnectDatagramsNegotiated(
            self.control.settings,
            self.established.connection,
            .receive,
        ) catch return null;
        const capacity = self.established.connection.endpoint.limits
            .max_datagram_size;
        const prefix = quic.varint.length(stream_id / 4) catch return null;
        if (prefix > capacity) return null;
        return capacity - prefix;
    }

    pub fn sendConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        return self.sendConnectDatagramWithProgress(stream_id, payload, null, NoConnectProgress{}) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn sendConnectDatagrams(
        self: *HandshakeClient,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        return self.sendConnectDatagramsWithProgress(stream_id, payloads, committed_count, null, NoConnectProgress{}) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    /// Submit one CONNECT DATAGRAM without sleeping or reading UDP.
    pub fn trySendConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.trySendDatagram(encoded);
    }

    pub fn sendConnectDatagramWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendConnectDatagramWithDeadline(
            stream_id,
            payload,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn sendConnectDatagramWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendConnectDatagramWithProgress(stream_id, payload, deadline, NoConnectProgress{});
    }

    /// Advance application-protocol progress before every send retry.
    /// The progress owner shares the HTTP/3 reader and optional deadline.
    pub fn sendConnectDatagramWithProgress(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
        progress: anytype,
    ) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        return ConnectDatagramSend.single(self, stream_id, payload, deadline, progress);
    }

    pub fn sendConnectDatagramsWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        committed_count.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendConnectDatagramsWithDeadline(
            stream_id,
            payloads,
            committed_count,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendConnectDatagramsWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendConnectDatagramsWithProgress(stream_id, payloads, committed_count, deadline, NoConnectProgress{});
    }

    /// Advance application-protocol progress before every send retry.
    /// The progress owner shares the HTTP/3 reader and optional deadline.
    pub fn sendConnectDatagramsWithProgress(
        self: *HandshakeClient,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: ?std.Io.Clock.Timestamp,
        progress: anytype,
    ) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        return ConnectDatagramSend.batch(self, stream_id, payloads, committed_count, deadline, progress);
    }

    pub fn trySendConnectDatagrams(
        self: *HandshakeClient,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        for (payloads) |payload| {
            try self.validateConnectDatagramSend(stream_id, payload);
        }
        const encoded = try self.connect_datagrams.encodeBatch(
            stream_id,
            payloads,
        );
        return self.established.connection.trySendDatagrams(
            encoded.datagrams,
            committed_count,
        );
    }

    /// One deadline-checked attempt for a shared endpoint owner. This method
    /// never reads UDP or sleeps while preserving retryability on backpressure.
    pub fn trySendConnectDatagramWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.trySendDatagramOnceWithDeadline(
            encoded,
            deadline,
        );
    }

    fn validateConnectDatagramSend(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        try connect_datagram.validateStreamId(stream_id);
        if (!self.connect_datagrams.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        observeConnectDatagramTerminal(
            &self.connect_datagrams,
            &self.established.connection,
            stream_id,
        );
        if (try self.connect_datagrams.terminal(stream_id)) |terminal| {
            if (terminal == .connection_closed) {
                return error.ConnectionClosed;
            }
        }
        try ensureConnectDatagramSendSideOpen(
            self.established.connection,
            stream_id,
        );
        try ensureConnectDatagramsNegotiated(
            self.control.settings,
            self.established.connection,
            .send,
        );
        const maximum = self.maxConnectDatagramPayloadSize(stream_id) orelse
            return error.DatagramTooLarge;
        if (payload.len > maximum) return error.DatagramTooLarge;
    }

    pub fn pollConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!?OwnedConnectDatagram {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try connect_datagram.validateStreamId(stream_id);
        if (!self.connect_datagrams.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try ensureConnectDatagramsNegotiated(
            self.control.settings,
            self.established.connection,
            .receive,
        );
        if (self.established.connection.closing() or
            self.established.connection.draining() or
            self.established.connection.closed())
        {
            observeConnectDatagramTerminal(
                &self.connect_datagrams,
                &self.established.connection,
                stream_id,
            );
            if (try self.connect_datagrams.poll(stream_id)) |datagram| {
                return datagram;
            }
            if (try self.connect_datagrams.drainedTerminal(stream_id)) |terminal| {
                return connectDatagramTerminalError(terminal);
            }
        }
        return pollConnectDatagramRegistry(
            &self.connect_datagrams,
            &self.established.connection,
            stream_id,
        );
    }

    pub fn pollConnectDatagramInto(
        self: *HandshakeClient,
        stream_id: u62,
        output: []u8,
    ) Error!?[]u8 {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try connect_datagram.validateStreamId(stream_id);
        if (!self.connect_datagrams.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try ensureConnectDatagramsNegotiated(
            self.control.settings,
            self.established.connection,
            .receive,
        );
        return pollConnectDatagramRegistryInto(
            &self.connect_datagrams,
            &self.established.connection,
            stream_id,
            output,
        );
    }

    /// Receive while servicing an owning protocol's maintenance callback.
    /// The callback provides ErrorSet and maintain(?Timestamp), runs before an
    /// idle socket wait, and retains this operation's receive ownership.
    /// Callback errors and the original absolute deadline are preserved.
    pub fn receiveConnectDatagramWithProgress(self: *HandshakeClient, stream_id: u62, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramFromSession(self, stream_id, deadline, progress);
    }

    pub fn receiveConnectDatagramIntoWithProgress(self: *HandshakeClient, stream_id: u62, output: []u8, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)![]u8 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramIntoFromSession(self, stream_id, output, deadline, progress);
    }

    pub fn receiveConnectDatagramsIntoWithProgress(self: *HandshakeClient, stream_id: u62, outputs: [][]u8, received_count: *usize, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        received_count.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramsIntoFromSession(self, stream_id, outputs, received_count, deadline, progress);
    }

    pub fn receiveConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return receiveConnectDatagramFromSession(self, stream_id, null, NoConnectProgress{}) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveConnectDatagramWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveConnectDatagramFromSession(self, stream_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ), NoConnectProgress{});
    }

    pub fn receiveConnectDatagramWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramFromSession(self, stream_id, deadline, NoConnectProgress{});
    }

    pub fn receiveConnectDatagramInto(
        self: *HandshakeClient,
        stream_id: u62,
        output: []u8,
    ) Error![]u8 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return receiveConnectDatagramIntoFromSession(
            self,
            stream_id,
            output,
            null,
            NoConnectProgress{},
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveConnectDatagramIntoWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        output: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError![]u8 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveConnectDatagramIntoWithDeadline(
            stream_id,
            output,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveConnectDatagramIntoWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        output: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError![]u8 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramIntoFromSession(
            self,
            stream_id,
            output,
            deadline,
            NoConnectProgress{},
        );
    }

    /// Fill an arrival-ordered batch of CONNECT DATAGRAM payloads in caller
    /// storage. `received_count` retains the exact completed prefix on error.
    pub fn receiveConnectDatagramsInto(
        self: *HandshakeClient,
        stream_id: u62,
        outputs: [][]u8,
        received_count: *usize,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return receiveConnectDatagramsIntoFromSession(
            self,
            stream_id,
            outputs,
            received_count,
            null,
            NoConnectProgress{},
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveConnectDatagramsIntoWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        outputs: [][]u8,
        received_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveConnectDatagramsIntoWithDeadline(
            stream_id,
            outputs,
            received_count,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveConnectDatagramsIntoWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        outputs: [][]u8,
        received_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramsIntoFromSession(
            self,
            stream_id,
            outputs,
            received_count,
            deadline,
            NoConnectProgress{},
        );
    }

    pub fn closeConnectDatagramAssociation(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try connect_datagram.validateStreamId(stream_id);
        if (!self.connect_datagrams.contains(stream_id)) return error.UnexpectedStream;
        self.connect_datagrams.unregister(stream_id);
    }

    /// Undo only the provisional registration installed before an Extended
    /// CONNECT response is accepted. Established detached associations must
    /// use `closeConnectDatagramAssociation` instead.
    pub fn cancelPendingConnectDatagramAssociation(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        if (self.callback_reader_active) return;
        if (self.request_lifecycle.contains(stream_id)) {
            self.connect_datagrams.unregister(stream_id);
        }
    }

    /// Decode the final response head already buffered on a detached Extended
    /// CONNECT stream without reading UDP or claiming later tunnel bytes.
    pub fn pollDetachedResponseHead(
        self: *HandshakeClient,
        detached_stream_id: u62,
    ) Error!?http3.DecodedResponseHead {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.pollDetachedResponseHeadInternal(
            detached_stream_id,
            false,
        );
    }

    /// Decode a detached CONNECT response head without waiting for feedback
    /// or receive-credit pacing. On backpressure the QUIC bytes and HTTP/3
    /// parser state remain available for an identical retry.
    pub fn pollDetachedResponseHeadOnce(
        self: *HandshakeClient,
        detached_stream_id: u62,
    ) Error!?http3.DecodedResponseHead {
        return self.pollDetachedResponseHeadInternal(
            detached_stream_id,
            true,
        );
    }

    fn pollDetachedResponseHeadInternal(
        self: *HandshakeClient,
        detached_stream_id: u62,
        single_attempt: bool,
    ) Error!?http3.DecodedResponseHead {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        if (single_attempt) {
            self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
        }
        const bytes = self.established.connection.availableReceivedStream(
            detached_stream_id,
        ) orelse return null;
        const input_complete = receivedInputComplete(
            &self.established.connection,
            detached_stream_id,
            bytes.len,
        );
        if (bytes.len == 0) {
            if (!input_complete) return null;
            try self.request_lifecycle.prepareFinish();
            if (single_attempt)
                self.failReceivedResponseOnce(
                    detached_stream_id,
                    bytes,
                    error.MissingStatus,
                    true,
                ) catch {}
            else
                self.failReceivedResponse(
                    detached_stream_id,
                    bytes,
                    error.MissingStatus,
                    true,
                ) catch {};
            return error.MissingStatus;
        }
        try self.request_lifecycle.prepareFinish();
        var head = http3.decodeResponseHeadWithDynamicTableAndOptions(
            self.allocator,
            bytes,
            self.options.local_settings,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    detached_stream_id,
                );
                options.max_informational_responses =
                    self.options.max_informational_responses;
                break :blk options;
            },
        ) catch |err| switch (err) {
            error.BufferTooShort => {
                if (!input_complete) return null;
                const final_error = responseHeadErrorAtFin(bytes);
                if (single_attempt)
                    self.failReceivedResponseOnce(
                        detached_stream_id,
                        bytes,
                        final_error,
                        true,
                    ) catch {}
                else
                    self.failReceivedResponse(
                        detached_stream_id,
                        bytes,
                        final_error,
                        true,
                    ) catch {};
                return final_error;
            },
            error.QpackBlocked => return null,
            else => {
                if (single_attempt)
                    self.failReceivedResponseOnce(
                        detached_stream_id,
                        bytes,
                        err,
                        true,
                    ) catch {}
                else
                    self.failReceivedResponse(
                        detached_stream_id,
                        bytes,
                        err,
                        true,
                    ) catch {};
                return err;
            },
        };
        var head_owned = true;
        defer if (head_owned) head.deinit(self.allocator);
        http3.validateResponsePushPromises(
            self.control,
            bytes[0..head.consumed],
        ) catch |err| {
            if (single_attempt)
                self.failReceivedResponseOnce(
                    detached_stream_id,
                    bytes[0..head.consumed],
                    err,
                    true,
                ) catch {}
            else
                self.failReceivedResponse(
                    detached_stream_id,
                    bytes[0..head.consumed],
                    err,
                    true,
                ) catch {};
            return err;
        };
        // Activate the response reader before consuming the encoded head from
        // QUIC. This is the only potentially allocating local-state mutation;
        // failures therefore leave the head bytes available for retry.
        const entry = try self.streaming_responses.activateResponse(
            &self.response_streams,
            detached_stream_id,
        );
        var rejection_receive = if (head.status < 200 or head.status >= 300)
            (try self.established.connection.cloneReceivedStreamState(
                self.allocator,
                detached_stream_id,
            )) orelse return error.UnexpectedStream
        else
            null;
        defer if (rejection_receive) |*receive| receive.deinit();
        if (rejection_receive) |*receive| {
            try receive.consume(head.consumed);
        }
        try self.qpack_decode.decoder_instructions.ensureUnusedCapacity(
            self.qpack_decode.allocator,
            11 *| head.qpack_section_acknowledgments,
        );
        const promise_checkpoint = self.push_streams.promiseCount();
        var promises_committed = false;
        defer if (!promises_committed) {
            self.push_streams.rollbackPromises(promise_checkpoint);
        };
        registerResponsePushPromises(
            &self.push_streams,
            detached_stream_id,
            bytes[0..head.consumed],
        ) catch |err| {
            if (single_attempt)
                self.failReceivedResponseOnce(
                    detached_stream_id,
                    bytes[0..head.consumed],
                    err,
                    true,
                ) catch {}
            else
                self.failReceivedResponse(
                    detached_stream_id,
                    bytes[0..head.consumed],
                    err,
                    true,
                ) catch {};
            return err;
        };
        if (single_attempt) {
            self.established.connection.tryReleaseReceivedCapacity(
                detached_stream_id,
                head.consumed,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
        } else {
            try self.established.connection.releaseReceivedCapacity(
                detached_stream_id,
                head.consumed,
            );
        }
        // Capacity was reserved before transport consumption. Canonical QPACK
        // Section Acknowledgments are at most 11 bytes apiece, so these writes
        // cannot allocate or fail once the request stream ID is known valid.
        for (0..head.qpack_section_acknowledgments) |_| {
            http3.Qpack.writeDecoderInstruction(
                &self.qpack_decode.decoder_instructions,
                self.qpack_decode.allocator,
                .{ .section_acknowledgment = detached_stream_id },
            ) catch unreachable;
        }
        const extended_connect = self.request_lifecycle.responseDecodeOptions(
            detached_stream_id,
        ).extended_connect;
        if (rejection_receive) |receive| {
            entry.reader.adoptDecodedResponseHeadFromReceive(
                head,
                extended_connect,
                receive,
            );
            rejection_receive = null;
            self.cancelPendingConnectDatagramAssociation(detached_stream_id);
        } else {
            entry.reader.adoptDecodedResponseHead(head, extended_connect);
        }
        head_owned = false;
        promises_committed = true;
        // The head is committed now. Feedback remains queued if its socket send
        // cannot make progress; later packet/control operations retry it. A
        // transient feedback failure must not turn a successfully consumed
        // final response into an unreturnable error.
        if (single_attempt)
            self.flushResponsePacketFeedbackOnce() catch {}
        else
            self.flushResponsePacketFeedback() catch {};
        return head;
    }

    /// Apply a dispatcher-owned packet while preserving bytes on one detached
    /// Extended CONNECT stream for its WebTransport owner. The packet remains
    /// caller-owned and this method never reads the UDP socket.
    pub fn processDetachedResponsePacket(
        self: *HandshakeClient,
        detached_stream_id: u62,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.processResponsePacketPreserving(
            detached_stream_id,
            packet,
            true,
        );
    }

    /// Apply a routed packet while an Extended CONNECT response head is still
    /// pending. This narrow pre-detach entry point preserves only the selected
    /// request stream and the WebTransport extension streams needed by its
    /// handshake; established generic CONNECT users must call the validated
    /// `processDetachedResponsePacket` API instead.
    pub fn processPendingExtendedConnectPacket(
        self: *HandshakeClient,
        stream_id: u62,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id) or
            !self.request_lifecycle.responseDecodeOptions(stream_id)
                .extended_connect)
        {
            return error.UnexpectedStream;
        }
        try self.processResponsePacketPreserving(stream_id, packet, true);
    }

    /// Temporary compatibility hook for protocol adapters that detach only
    /// after constructing their higher-level session object. The stream must
    /// already be a locally opened Extended CONNECT request.
    pub fn registerPendingConnectDatagramAssociation(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id) or
            !self.request_lifecycle.responseDecodeOptions(stream_id)
                .extended_connect)
        {
            return error.UnexpectedStream;
        }
        if (self.connect_datagrams.contains(stream_id)) return;
        try self.connect_datagrams.register(stream_id);
    }

    fn processResponsePacketPreserving(
        self: *HandshakeClient,
        detached_stream_id: ?u62,
        packet: *const quic.one_rtt.ReceivedPacket,
        single_attempt: bool,
    ) Error!void {
        if (self.receive_packets.ack_pending) {
            try self.established.connection.sendAck(0);
            self.receive_packets.ack_pending = false;
        }
        _ = self.established.connection.sendAckForPacketIfNeeded(
            packet.packet.packet_number,
            packet.frames,
        ) catch {
            self.receive_packets.ack_pending = true;
        };
        var context: ConnectionResponseReceiveContext = .{
            .connection = &self.established.connection,
            .control = &self.control,
            .qpack_decode = &self.qpack_decode,
            .qpack_encode = &self.qpack_encode,
            .max_blocked_streams = self.options.local_settings.qpack_blocked_streams,
            .response_streams = &self.response_streams,
            .streaming_responses = &self.streaming_responses,
            .push_streams = &self.push_streams,
            .request_lifecycle = &self.request_lifecycle,
            .detached_stream_id = detached_stream_id,
            .detached_streams = &self.connect_datagrams,
            .ticket_receiver = &self.ticket_receiver,
            .established = &self.established,
        };
        try visitConnectionResponsePacket(&context, packetView(packet.*));
        if (single_attempt) {
            _ = try self.applyPendingPushCancellationOnce();
        } else {
            try self.applyPendingPushCancellations();
        }
        if (single_attempt) {
            self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => {},
                else => return err,
            };
        } else {
            try self.flushResponsePacketFeedback();
        }
    }

    fn flushResponsePacketFeedback(self: *HandshakeClient) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    /// Submit at most one packet-sized prefix of queued QPACK decoder
    /// feedback without waiting for transport pacing.
    pub fn flushResponsePacketFeedbackOnce(
        self: *HandshakeClient,
    ) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len == 0) return;
        try trySendConnectionQpackFeedback(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
        );
    }

    fn releaseStreamingResponseCapacity(self: *HandshakeClient) Error!void {
        var index: usize = 0;
        while (self.streaming_responses.entryAt(index)) |entry| : (index += 1) {
            if (entry.message_failure_pending) continue;
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    fn releaseStreamingResponseCapacityOnce(
        self: *HandshakeClient,
    ) Error!bool {
        var index: usize = 0;
        while (self.streaming_responses.entryAt(index)) |entry| : (index += 1) {
            if (entry.message_failure_pending) continue;
            releaseStreamingReaderCapacityOnce(
                &self.established.connection,
                &entry.reader,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return false,
                else => return err,
            };
        }
        return true;
    }

    /// Poll one promised response without aggregating its DATA payload.
    pub fn receivePushEvent(
        self: *HandshakeClient,
    ) Error!StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(null, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Return one promised-response event already buffered by packet
    /// injection without reading UDP.
    pub fn pollPushEvent(
        self: *HandshakeClient,
    ) Error!?StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.pollPushEventMatching(null, false, null);
    }

    /// Return one buffered push event without waiting for pacing, congestion,
    /// flow-control credit, or a socket receive. Pending transport feedback
    /// remains queued and a terminal event remains reconstructible on retry.
    pub fn pollPushEventOnce(
        self: *HandshakeClient,
    ) Error!?StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.pollPushEventMatching(null, true, null);
    }

    /// Return a buffered push event or transfer an identified stream-local
    /// failure. The caller retries tryRejectPush; connection and local errors
    /// retain their ordinary error scope.
    pub fn pollPushEventOnceWithFailure(self: *HandshakeClient) Error!?PushEventResult {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        var failed: ?PushFailure = null;
        const event = self.pollPushEventMatching(null, true, &failed) catch |err| {
            if (failed) |value| return .{ .failure = value };
            return err;
        } orelse return null;
        return .{ .event = event };
    }

    /// Wait for an event from any promised push within one relative budget.
    pub fn receivePushEventWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(
            null,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receivePushEventWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(null, deadline);
    }

    fn receivePushEventMatching(
        self: *HandshakeClient,
        target_push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        while (true) {
            if (try self.pollPushEventMatching(
                target_push_id,
                false,
                null,
            )) |event| {
                return event;
            }
            try receiveConnectionResponsePacketUntil(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                self.options.local_settings.qpack_blocked_streams,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
                null,
                &self.connect_datagrams,
                &self.ticket_receiver,
                &self.established,
                deadline,
            );
            try self.flushResponsePacketFeedback();
        }
    }

    fn pollPushEventMatching(
        self: *HandshakeClient,
        target_push_id: ?u64,
        single_attempt: bool,
        failure_out: ?*?PushFailure,
    ) Error!?StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (failure_out) |output| output.* = null;
        try push_read_failure.progress(self, target_push_id, failure_out);
        if (single_attempt) {
            self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
        }
        var index: usize = 0;
        while (self.push_streams.entryAt(index)) |entry| : (index += 1) {
            if (PushStreamSet.entryFailurePending(entry)) continue;
            if (PushStreamSet.entryReader(entry)) |reader| {
                if (single_attempt) {
                    releaseStreamingReaderCapacityOnce(
                        &self.established.connection,
                        reader,
                    ) catch |err| switch (err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        => return null,
                        else => return err,
                    };
                } else {
                    try releaseStreamingReaderCapacity(
                        &self.established.connection,
                        reader,
                    );
                }
            }
        }
        if (single_attempt) {
            if (!try self.applyPendingPushCancellationOnce()) return null;
        } else {
            try self.applyPendingPushCancellations();
        }
        if (single_attempt) {
            if (self.push_streams.nextFinished(target_push_id)) |ready| {
                _ = try self.established.connection
                    .requestCompletedPeerStreamRelease(ready.event.stream_id);
                self.push_streams.removeFinished(ready.index);
                self.flushTerminalReceiveAck();
                return ready.event;
            }
        }
        if (failure_out == null) try self.pending_push_failures.reserve(self.allocator);
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        const ready = self.push_streams.next(
            self.qpack_decode.table,
            self.options.local_settings.qpack_blocked_streams,
            target_push_id,
        ) catch |err| {
            try push_read_failure.retain(self, self.push_streams.lastErrorStreamId(), err, failure_out);
            return err;
        } orelse return null;
        var event = ready.event;
        errdefer event.deinit(self.allocator);
        if (event.value == .push_promise) return error.UnexpectedFrame;
        if (try streamingResponseSectionAcknowledgments(
            event.value,
        )) |count| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                event.stream_id,
                count,
            );
            if (single_attempt)
                self.flushResponsePacketFeedbackOnce() catch {}
            else
                self.flushResponsePacketFeedback() catch {};
        }
        if (event.value == .finished) {
            if (self.push_streams.readerForStream(event.stream_id)) |reader| {
                if (single_attempt) {
                    releaseStreamingReaderCapacityOnce(
                        &self.established.connection,
                        reader,
                    ) catch |err| switch (err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        => return null,
                        else => return err,
                    };
                } else {
                    try releaseStreamingReaderCapacity(
                        &self.established.connection,
                        reader,
                    );
                }
            }
            _ = try self.established.connection
                .requestCompletedPeerStreamRelease(event.stream_id);
            self.push_streams.removeFinished(ready.index);
            self.flushTerminalReceiveAck();
        }
        return event;
    }

    fn applyPendingPushCancellationOnce(
        self: *HandshakeClient,
    ) Error!bool {
        const stream_id = self.push_streams.firstCancelledStream() orelse
            return true;
        const cancel_qpack =
            self.control.settings.local.qpack_max_table_capacity != 0;
        if (cancel_qpack) try self.qpack_decode.prepareStreamCancellation();
        self.established.connection.trySendStopSending(
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ) catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => return false,
            else => return err,
        };
        if (cancel_qpack) {
            self.qpack_decode.recordStreamCancellationAssumeCapacity(
                stream_id,
            );
        }
        std.debug.assert(
            self.push_streams.takeCancelledStream().? == stream_id,
        );
        return true;
    }

    fn applyPendingPushCancellations(
        self: *HandshakeClient,
    ) Error!void {
        return self.applyPendingPushCancellationsUntil(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn applyPendingPushCancellationsWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.applyPendingPushCancellationsUntil(deadline);
    }

    fn applyPendingPushCancellationsUntil(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        while (self.push_streams.firstCancelledStream()) |stream_id| {
            const cancel_qpack =
                self.control.settings.local.qpack_max_table_capacity != 0;
            if (cancel_qpack) try self.qpack_decode.prepareStreamCancellation();
            if (deadline) |absolute| {
                try self.established.connection.sendStopSendingWithDeadline(
                    stream_id,
                    http3.ApplicationErrorCode.request_cancelled,
                    absolute,
                );
            } else {
                try self.established.connection.sendStopSending(
                    stream_id,
                    http3.ApplicationErrorCode.request_cancelled,
                );
            }
            if (cancel_qpack) {
                self.qpack_decode.recordStreamCancellationAssumeCapacity(
                    stream_id,
                );
            }
            std.debug.assert(
                self.push_streams.takeCancelledStream().? == stream_id,
            );
        }
    }

    pub fn readPushData(
        self: *HandshakeClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try push_read_failure.access(self, push_id, out, .read, false)) orelse 0;
    }

    /// Copy available push DATA without waiting for receive-credit pacing.
    /// `null` leaves both the reader cursor and transport credit retryable.
    pub fn readPushDataOnce(
        self: *HandshakeClient,
        push_id: u64,
        out: []u8,
    ) Error!?usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        return push_read_failure.access(self, push_id, out, .read, true);
    }

    pub fn skipPushData(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try push_read_failure.access(self, push_id, &.{}, .skip, false)) orelse 0;
    }

    /// Discard available push DATA without waiting for receive-credit pacing.
    pub fn skipPushDataOnce(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!?usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        return push_read_failure.access(self, push_id, &.{}, .skip, true);
    }

    pub fn receivePush(
        self: *HandshakeClient,
    ) Error!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receivePushWithInformational(null);
    }

    /// Aggregate one promised response within a relative budget. The partial
    /// head, body, trailers, and reader remain owned by the client on timeout.
    pub fn receivePushWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePushWithInformationalAndDeadline(
            null,
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receivePushWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receivePushWithInformationalAndDeadline(null, deadline);
    }

    /// Aggregate one promised response while reporting its ordered 1xx heads.
    pub fn receivePushWithInformational(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
    ) Error!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receivePushWithInformationalAttempt(
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receivePushWithInformationalAndTimeout(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePushWithInformationalAndDeadline(
            informational,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receivePushWithInformationalAndDeadline(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receivePushWithInformationalAttempt(
            informational,
            deadline,
        );
    }

    fn receivePushWithInformationalAttempt(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        return self.receivePushWithInformationalInternal(
            informational,
            deadline,
        ) catch |err| switch (err) {
            // These are retryable transport outcomes. Retain aggregation state
            // so a later aggregate call can continue the same push exactly.
            error.Timeout, error.ConcurrencyUnavailable => return err,
            else => {
                self.push_aggregate.deinit(self.allocator);
                return err;
            },
        };
    }

    fn receivePushWithInformationalInternal(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        if (self.callback_reader_active) return error.ConcurrentRead;
        var guarded_informational: ?PushInformationalCallbackGuard =
            if (informational) |observer| .{
                .observer = observer,
                .callback_reader_active = &self.callback_reader_active,
            } else null;
        return push_aggregate.receive(
            self,
            &self.push_aggregate,
            self.allocator,
            if (guarded_informational) |*guard| .{
                .context = guard,
                .on_response = PushInformationalCallbackGuard.notify,
            } else null,
            deadline,
            HandshakeClient.nextPushEventForAggregate,
            HandshakeClient.readPushDataForAggregate,
            HandshakeClient.pushStreamPendingForAggregate,
        );
    }

    fn nextPushEventForAggregate(
        self: *HandshakeClient,
        push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        return self.receivePushEventMatching(push_id, deadline);
    }

    fn readPushDataForAggregate(
        self: *HandshakeClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        return self.readPushData(push_id, out);
    }

    fn pushStreamPendingForAggregate(
        self: *HandshakeClient,
        push_id: u64,
    ) bool {
        const entry = self.push_streams.findByPushId(push_id) orelse
            return false;
        return entry.reader != null and entry.reader.?.current_frame != null;
    }

    /// Poll one incremental event from any outstanding response stream.
    ///
    /// The first call selects streaming mode for all currently buffered
    /// responses. Continue using streaming APIs for those stream IDs; aggregate
    /// `receiveResponse` cannot reclaim a reader whose head/body has advanced.
    pub fn receiveNextResponseEvent(
        self: *HandshakeClient,
    ) Error!StreamingResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        return self.receiveNextResponseEventInternal(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    /// Return the next response event already buffered on any outstanding
    /// request without reading UDP. The selected stream ID is included in the
    /// result so one dispatcher loop can fairly service many requests.
    pub fn pollNextResponseEvent(
        self: *HandshakeClient,
    ) Error!?StreamingResponseEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.pollNextResponseEventInternal(false, null);
    }

    /// Return one buffered event from any response stream without waiting for
    /// pacing, congestion, flow-control credit, or a socket receive.
    pub fn pollNextResponseEventOnce(
        self: *HandshakeClient,
    ) Error!?StreamingResponseEvent {
        return self.pollNextResponseEventInternal(true, null);
    }

    /// Transfer a stream-local response failure to the caller, including a
    /// failure retained by default polling. The caller owns cancellation and
    /// retry; local operations and connection protocol errors still propagate.
    pub fn pollNextResponseEventOnceWithFailure(self: *HandshakeClient) Error!?ResponseEventResult {
        var failure: ?ResponseFailure = null;
        const event = self.pollNextResponseEventInternal(true, &failure) catch |err| {
            if (failure) |owned| return .{ .failure = owned };
            return err;
        } orelse return null;
        return .{ .event = event };
    }

    fn pollNextResponseEventInternal(
        self: *HandshakeClient,
        single_attempt: bool,
        failure_out: ?*?ResponseFailure,
    ) Error!?StreamingResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (failure_out) |output| output.* = null;
        try self.progressResponsePollFailures(null, failure_out);
        if (self.request_lifecycle.isEmpty()) {
            return null;
        }
        if (single_attempt) {
            self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => return err,
            };
            if (!try self.releaseStreamingResponseCapacityOnce()) return null;
            var index: usize = 0;
            while (self.streaming_responses.entryAt(index)) |entry| : (index += 1) {
                if (entry.message_failure_pending) continue;
                if (!entry.reader.finished()) continue;
                const stream_id = entry.reader.streamId();
                try self.finishStreamingResponse(stream_id);
                return .{ .message = .{
                    .stream_id = stream_id,
                    .value = .finished,
                } };
            }
        } else {
            try self.releaseStreamingResponseCapacity();
        }
        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) {
                return error.UnexpectedStream;
            }
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(reset.stream_id);
            try self.finishStreamingResponse(reset.stream_id);
            if (single_attempt)
                self.flushResponsePacketFeedbackOnce() catch {}
            else
                self.flushResponsePacketFeedback() catch {};
            return .{ .reset = .{
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.request_lifecycle.prepareFinish();
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        if (failure_out == null) try self.pending_response_failures.reserve(self.allocator);
        const ready_value = self.streaming_responses.nextResponse(
            &self.response_streams,
            self.qpack_decode.table,
            self.options.local_settings.qpack_blocked_streams,
        ) catch |err| {
            try self.retainResponsePollFailure(self.streaming_responses.lastErrorStreamId(), err, failure_out);
            return err;
        } orelse return null;
        var ready = ready_value;
        var event_owned = true;
        errdefer if (event_owned) ready.event.deinit(
            self.established.connection.endpoint.allocator,
        );
        const stream_id: u62 = @intCast(
            ready.entry.reader.streamId(),
        );
        applyResponseReaderSemantics(
            self.request_lifecycle,
            stream_id,
            &ready.entry.reader,
        );
        // `nextResponse` decoded this head before the request context was
        // applied. Revalidate it before exposing request-sensitive semantics.
        if (ready.event == .head and ready.event.head == .response) {
            ready.entry.reader.applyDecodedResponseHead(
                &ready.event.head.response,
            ) catch |err| {
                try self.retainResponsePollFailure(stream_id, err, failure_out);
                return err;
            };
        }
        const owned_event = ready.event;
        const committed = self.applyStreamingResponseEvent(
            stream_id,
            owned_event,
            single_attempt,
        ) catch |err| {
            try self.retainResponsePollFailure(stream_id, err, failure_out);
            return err;
        };
        if (!committed) return null;
        event_owned = false;
        return .{ .message = .{
            .stream_id = stream_id,
            .value = owned_event,
        } };
    }

    /// Wait for the next event from any outstanding response within one
    /// relative budget without retiring active response readers on timeout.
    pub fn receiveNextResponseEventWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        return self.receiveNextResponseEventInternal(
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveNextResponseEventWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        return self.receiveNextResponseEventInternal(deadline);
    }

    fn receiveNextResponseEventInternal(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        while (true) {
            if (try self.pollNextResponseEvent()) |event| return event;
            try self.releaseStreamingResponseCapacity();
            try receiveConnectionResponsePacketUntil(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                self.options.local_settings.qpack_blocked_streams,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
                null,
                &self.connect_datagrams,
                &self.ticket_receiver,
                &self.established,
                deadline,
            );
            try self.flushResponsePacketFeedback();
        }
    }

    pub fn sendGoAway(self: *HandshakeClient, stream_id: u64) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try validateClientGoAwayPushId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    pub fn sendGoAwayWithTimeout(
        self: *HandshakeClient,
        stream_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendGoAwayWithDeadline(stream_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendGoAwayWithDeadline(
        self: *HandshakeClient,
        stream_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try validateClientGoAwayPushId(stream_id);
        try sendConnectionSettingsWithDeadline(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
            deadline,
        );
        try sendConnectionControlFrameWithDeadline(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .goaway,
            stream_id,
            deadline,
        );
    }

    /// Submit a client GOAWAY once without waiting for pacing or reading UDP.
    /// The local GOAWAY ID and control-stream offset roll back on failure.
    pub fn trySendGoAway(
        self: *HandshakeClient,
        stream_id: u64,
    ) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try self.requireEndpointCriticalStreamsReady();
        try trySendConnectionControlFrame(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .goaway,
            stream_id,
        );
    }

    pub fn peerOrigins(self: HandshakeClient) []const http3.OriginKey {
        return self.control.peerOrigins();
    }

    pub fn peerOriginSetInitialized(self: HandshakeClient) bool {
        return self.control.peerOriginSetInitialized();
    }

    pub fn peerOriginGeneration(self: HandshakeClient) u64 {
        return self.control.peerOriginGeneration();
    }

    pub fn peerOriginKnown(
        self: HandshakeClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginKnown(origin);
    }

    pub fn peerOriginExcluded(
        self: HandshakeClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginExcluded(origin);
    }

    pub fn peerOriginSetAllows(
        self: HandshakeClient,
        initial_origin: http3.Origin,
        requested_origin: http3.Origin,
    ) ?bool {
        return self.control.peerOriginSetAllows(
            initial_origin,
            requested_origin,
        );
    }

    /// Apply RFC 8336's 421 Misdirected Request removal rule. The caller
    /// supplies the request origin because response state intentionally stores
    /// no redundant authority copy after dispatch.
    pub fn removePeerOriginAfterMisdirected(
        self: *HandshakeClient,
        origin: http3.Origin,
    ) Error!void {
        try self.control.removePeerOrigin(self.allocator, origin);
    }

    /// Process one transport packet for SETTINGS/ORIGIN/GOAWAY progress
    /// without waiting for an application response event.
    pub fn pollControl(self: *HandshakeClient) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try self.receiveProgress();
    }

    pub fn pollControlWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.pollControlWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn pollControlWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        );
        try self.flushResponsePacketFeedback();
    }

    /// Client-side counterpart to `HandshakeServerSession`'s recovery drain.
    /// It preserves response, push, and detached CONNECT routing while waiting
    /// for application and control delivery to be acknowledged. Pure receive-
    /// credit updates remain under QUIC's normal recovery timer, matching the
    /// server drain without delaying a short-lived client.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForRecoveryIdleWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        while (self.established.connection.pendingDeliveryRecovery()) {
            try self.pollControlWithDeadline(deadline);
        }
    }

    pub fn waitForStreamRecoveryIdleWithTimeout(self: *HandshakeClient, stream_id: u62, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForStreamRecoveryIdleWithDeadline(stream_id, .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }));
    }

    /// Drain one stream's reliable delivery without waiting for siblings.
    pub fn waitForStreamRecoveryIdleWithDeadline(self: *HandshakeClient, stream_id: u62, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return @import("stream/recovery.zig").wait(ReceiveTimeoutError, self, stream_id, deadline, HandshakeClient.pollControlWithDeadline);
    }

    /// Advertise the inclusive server-push ID limit.
    pub fn sendMaxPushId(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        return self.sendMaxPushIdUntil(push_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendMaxPushIdWithTimeout(
        self: *HandshakeClient,
        push_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendMaxPushIdWithDeadline(push_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendMaxPushIdWithDeadline(
        self: *HandshakeClient,
        push_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendMaxPushIdUntil(push_id, deadline);
    }

    fn sendMaxPushIdUntil(
        self: *HandshakeClient,
        push_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try self.push_streams.reservePromisesThrough(push_id);
        if (deadline) |absolute| {
            try sendConnectionSettingsWithDeadline(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
                absolute,
            );
            try sendConnectionPushControlWithDeadline(
                &self.established.connection,
                &self.control,
                &self.control_send,
                self.options,
                .max_push_id,
                push_id,
                absolute,
            );
        } else {
            try sendConnectionSettings(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
            );
            try sendConnectionPushControl(
                &self.established.connection,
                &self.control,
                &self.control_send,
                self.options,
                .max_push_id,
                push_id,
            );
        }
    }

    /// Submit MAX_PUSH_ID once without waiting for transport progress.
    pub fn trySendMaxPushId(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        try self.push_streams.reservePromisesThrough(push_id);
        try self.requireEndpointCriticalStreamsReady();
        try trySendConnectionPushControl(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .max_push_id,
            push_id,
        );
    }

    pub fn cancelPush(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        return self.cancelPushUntil(push_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn cancelPushWithTimeout(
        self: *HandshakeClient,
        push_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelPushWithDeadline(push_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn cancelPushWithDeadline(
        self: *HandshakeClient,
        push_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.cancelPushUntil(push_id, deadline);
    }

    fn cancelPushUntil(
        self: *HandshakeClient,
        push_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        defer if (self.push_streams.isCancelledPush(push_id)) {
            push_read_failure.discard(self, push_id);
        };
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const max_push_id = self.control.local_max_push_id orelse
            return error.PushIdExceeded;
        if (push_id > max_push_id) return error.PushIdExceeded;
        if (self.push_streams.isCancelledPush(push_id)) {
            if (deadline) |absolute| {
                try self.applyPendingPushCancellationsWithDeadline(absolute);
                return self.sendQpackFeedbackWithDeadline(absolute);
            }
            try self.applyPendingPushCancellations();
            return self.sendQpackFeedback();
        }
        if (self.push_streams.pendingLocalCancellation(push_id)) {
            if (deadline) |absolute| {
                try self.applyPendingPushCancellationsWithDeadline(absolute);
                return self.sendQpackFeedbackWithDeadline(absolute);
            }
            try self.applyPendingPushCancellations();
            return self.sendQpackFeedback();
        }
        const push_stream_id = self.push_streams.streamIdForPush(push_id);
        try self.push_streams.preparePeerCancellation(push_id);
        if (deadline) |absolute| {
            try sendConnectionSettingsWithDeadline(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
                absolute,
            );
            try sendConnectionPushControlWithDeadline(
                &self.established.connection,
                &self.control,
                &self.control_send,
                self.options,
                .cancel_push,
                push_id,
                absolute,
            );
        } else {
            try sendConnectionSettings(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
            );
            try sendConnectionPushControl(
                &self.established.connection,
                &self.control,
                &self.control_send,
                self.options,
                .cancel_push,
                push_id,
            );
        }
        if (push_stream_id) |stream_id| {
            self.qpack_decode.discardPeerUniStream(stream_id);
        }
        self.push_streams.observePeerCancellation(push_id) catch unreachable;
        defer if (self.push_aggregate.push_id == push_id) {
            self.push_aggregate.deinit(self.allocator);
        };
        if (deadline) |absolute| {
            try self.applyPendingPushCancellationsWithDeadline(absolute);
            try self.sendQpackFeedbackWithDeadline(absolute);
        } else {
            try self.applyPendingPushCancellations();
            try self.sendQpackFeedback();
        }
    }

    /// Retry scoped rejection for a failure returned by push polling. A
    /// failed submission preserves the stream, promise and original identity.
    pub fn tryRejectPush(self: *HandshakeClient, failed: PushFailure) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try push_read_failure.submit(self, failed);
        push_read_failure.discard(self, failed.push_id);
    }

    /// Submit CANCEL_PUSH once without waiting for pacing or reading UDP. All
    /// fallible push-state capacity is reserved before the frame reaches the
    /// socket; a failed send leaves the promise and control cursor unchanged.
    pub fn tryCancelPush(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        defer if (self.push_streams.isCancelledPush(push_id)) {
            push_read_failure.discard(self, push_id);
        };
        if (self.callback_reader_active) return error.ConcurrentRead;
        const push_stream_id = self.push_streams.streamIdForPush(push_id);
        try self.push_streams.preparePeerCancellation(push_id);
        try self.requireEndpointCriticalStreamsReady();
        try trySendConnectionPushControl(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .cancel_push,
            push_id,
        );
        if (push_stream_id) |stream_id| {
            self.qpack_decode.discardPeerUniStream(stream_id);
        }
        self.push_streams.observePeerCancellation(push_id) catch unreachable;
        defer if (self.push_aggregate.push_id == push_id) {
            self.push_aggregate.deinit(self.allocator);
        };
        // An active push stream is queued for STOP_SENDING and serviced by a
        // later poll turn. Keep this method to one socket submission.
    }

    pub fn cancelRequest(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        defer if (!self.request_lifecycle.contains(stream_id)) {
            _ = self.pending_response_failures.take(stream_id);
        };
        return self.cancelRequestInternal(
            stream_id,
            application_error_code,
            false,
        );
    }

    pub fn cancelRequestWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelRequestWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn cancelRequestWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.established.connection.endpoint.io,
            deadline,
        );
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        defer if (!self.request_lifecycle.contains(stream_id)) {
            _ = self.pending_response_failures.take(stream_id);
        };
        return cancelHandshakeRequestWithDeadline(
            self,
            stream_id,
            application_error_code,
            deadline,
        );
    }

    /// Cancel one request without waiting for transport pacing.
    pub fn tryCancelRequest(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        defer if (!self.request_lifecycle.contains(stream_id)) {
            _ = self.pending_response_failures.take(stream_id);
        };
        return self.cancelRequestInternalOnce(
            stream_id,
            application_error_code,
            false,
        );
    }

    fn cancelRequestInternal(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
        decoded_dynamic_section: bool,
    ) Error!void {
        const cancel_qpack = decoded_dynamic_section or self.qpack_decode.table.max_capacity != 0;
        defer {
            self.connect_datagrams.unregister(stream_id);
            self.response_streams.remove(stream_id);
            self.streaming_responses.remove(stream_id);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            _ = self.outbound_bodies.finish(stream_id);
            self.retireReservedRequestStreamId(stream_id);
        }
        errdefer self.established.connection.failClosedApplication(
            http3.ApplicationErrorCode.internal_error,
            "request-cancellation-failed",
        );
        try cancelConnectionRequest(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            stream_id,
            application_error_code,
            cancel_qpack,
        );
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(stream_id);
    }

    pub fn cancelRequestInternalOnce(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
        decoded_dynamic_section: bool,
    ) Error!void {
        const cancel_qpack = decoded_dynamic_section or self.qpack_decode.table.max_capacity != 0;
        if (cancel_qpack) {
            try self.qpack_decode.prepareStreamCancellation();
        }
        try self.established.connection.tryCancelStream(
            stream_id,
            application_error_code,
        );
        if (cancel_qpack) {
            self.qpack_decode.recordStreamCancellationAssumeCapacity(
                stream_id,
            );
        }
        self.connect_datagrams.unregister(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = self.request_lifecycle.finish(stream_id) catch false;
        _ = self.outbound_bodies.finish(stream_id);
        self.retireReservedRequestStreamId(stream_id);
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(stream_id);
    }

    /// Best-effort cleanup for an Extended CONNECT adapter that is abandoned
    /// after receiving its response head. Unlike `cancelRequest`, local stream
    /// state is always released so an infallible adapter destructor can return
    /// ownership of this HTTP/3 connection to its caller.
    pub fn abandonExtendedConnect(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        if (self.callback_reader_active) return;
        if (self.dispatcher_bound) {
            self.abandonExtendedConnectOnce(stream_id);
            return;
        }
        const cancel_qpack = self.qpack_decode.table.max_capacity != 0;
        cancelConnectionRequest(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
            cancel_qpack,
        ) catch {
            self.established.connection.failClosedApplication(
                http3.ApplicationErrorCode.internal_error,
                "request-cancellation-failed",
            );
        };
        _ = self.established.connection
            .requestCompletedLocalStreamRelease(stream_id) catch false;
        self.connect_datagrams.unregister(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = self.request_lifecycle.finish(stream_id) catch false;
        _ = self.outbound_bodies.finish(stream_id);
        self.retireReservedRequestStreamId(stream_id);
    }

    /// Best-effort Extended CONNECT cleanup for a dispatcher-owned endpoint.
    /// At most one UDP send is attempted; pacing, congestion, or flow-control
    /// refusal never sleeps or reads the shared socket. Local HTTP/3 ownership
    /// is retired even when the wire cancellation cannot be submitted.
    pub fn abandonExtendedConnectOnce(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        if (self.callback_reader_active) return;
        const cancel_qpack = self.qpack_decode.table.max_capacity != 0;
        const qpack_prepared = !cancel_qpack or blk: {
            self.qpack_decode.prepareStreamCancellation() catch break :blk false;
            break :blk true;
        };
        const cancelled = blk: {
            self.established.connection.tryCancelStream(
                stream_id,
                http3.ApplicationErrorCode.request_cancelled,
            ) catch break :blk false;
            break :blk true;
        };
        // The decoder instruction is queued, not sent here: a second send
        // would violate this method's one-packet bound. isReusable() keeps the
        // connection out of an idle pool until a later dispatcher turn flushes
        // it. Allocation or QUIC-send failure makes reuse permanently unsafe.
        if (cancelled and cancel_qpack and qpack_prepared) {
            self.qpack_decode.recordStreamCancellationAssumeCapacity(
                stream_id,
            );
        }
        if (!cancelled or !qpack_prepared) {
            self.reuse_safe = false;
        }
        _ = self.established.connection
            .requestCompletedLocalStreamRelease(stream_id) catch false;
        self.connect_datagrams.unregister(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = self.request_lifecycle.finish(stream_id) catch false;
        _ = self.outbound_bodies.finish(stream_id);
        self.retireReservedRequestStreamId(stream_id);
    }

    pub fn sendPriorityUpdate(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        return self.sendPriorityUpdateUntil(
            stream_id,
            priority,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendPriorityUpdateWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPriorityUpdateWithDeadline(
            stream_id,
            priority,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPriorityUpdateWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendPriorityUpdateUntil(stream_id, priority, deadline);
    }

    fn sendPriorityUpdateUntil(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        // PRIORITY_UPDATE can precede the request itself, which is essential
        // for this synchronous request API: `next_stream_id` is the one request
        // stream that may be prioritized before request() opens it.
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        if (deadline) |absolute| {
            try sendConnectionSettingsWithDeadline(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
                absolute,
            );
            try sendConnectionPriorityUpdateRawWithDeadline(
                &self.established.connection,
                &self.control_send,
                self.options,
                http3.FrameType.priority_update_request,
                stream_id,
                priority,
                absolute,
            );
        } else {
            try sendConnectionSettings(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
            );
            try sendConnectionPriorityUpdate(
                &self.established.connection,
                &self.control_send,
                self.options,
                stream_id,
                priority,
            );
        }
    }

    /// Submit one request PRIORITY_UPDATE without waiting for pacing.
    pub fn trySendPriorityUpdate(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        try self.requireEndpointCriticalStreamsReady();
        try trySendConnectionPriorityUpdateRaw(
            &self.established.connection,
            &self.control_send,
            self.options,
            http3.FrameType.priority_update_request,
            stream_id,
            priority,
        );
    }

    pub fn sendPushPriorityUpdate(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        return self.sendPushPriorityUpdateUntil(
            push_id,
            priority,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendPushPriorityUpdateWithTimeout(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPushPriorityUpdateWithDeadline(
            push_id,
            priority,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPushPriorityUpdateWithDeadline(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendPushPriorityUpdateUntil(push_id, priority, deadline);
    }

    fn sendPushPriorityUpdateUntil(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.push_streams.hasPromise(push_id)) {
            return error.UnexpectedStream;
        }
        if (deadline) |absolute| {
            try sendConnectionSettingsWithDeadline(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
                absolute,
            );
            try sendConnectionPriorityUpdateRawWithDeadline(
                &self.established.connection,
                &self.control_send,
                self.options,
                http3.FrameType.priority_update_push,
                push_id,
                priority,
                absolute,
            );
        } else {
            try sendConnectionSettings(
                &self.established.connection,
                &self.critical_stream_send_scratch,
                &self.control,
                &self.control_send,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                &self.qpack_decoder_send,
                &self.qpack_decoder_prefix_sent,
                self.options,
                client_control_stream_id,
            );
            try sendConnectionPriorityUpdateRaw(
                &self.established.connection,
                &self.control_send,
                self.options,
                http3.FrameType.priority_update_push,
                push_id,
                priority,
            );
        }
    }

    /// Submit one push PRIORITY_UPDATE without waiting for pacing.
    pub fn trySendPushPriorityUpdate(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        if (!self.push_streams.hasPromise(push_id)) {
            return error.UnexpectedStream;
        }
        try self.requireEndpointCriticalStreamsReady();
        try trySendConnectionPriorityUpdateRaw(
            &self.established.connection,
            &self.control_send,
            self.options,
            http3.FrameType.priority_update_push,
            push_id,
            priority,
        );
    }

    fn sendQpackFeedback(self: *HandshakeClient) Error!void {
        try sendConnectionQpackFeedback(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
        );
    }

    fn sendQpackFeedbackWithDeadline(
        self: *HandshakeClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try sendConnectionQpackFeedbackWithDeadline(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            deadline,
        );
    }

    fn receiveResponseProgressForSend(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.failIfRequestResetForSend(stream_id);
        try receiveConnectionResponsePacket(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
        );
        try self.failIfRequestResetForSend(stream_id);
    }

    fn receiveResponseProgressForSendUntil(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.failIfRequestResetForSend(stream_id);
        try receiveConnectionResponsePacketUntil(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            self.options.local_settings.qpack_blocked_streams,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
            null,
            &self.connect_datagrams,
            &self.ticket_receiver,
            &self.established,
            deadline,
        );
        try self.failIfRequestResetForSend(stream_id);
    }

    fn failIfRequestResetForSend(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        const code = self.response_streams.resetFor(stream_id) orelse return;
        try self.request_lifecycle.prepareFinish();
        _ = self.response_streams.takeReset(stream_id);
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(stream_id);
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.sendQpackFeedback() catch {};
        return responseResetError(code);
    }

    fn applyStreamingResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
        event: StreamingEvent,
        single_attempt: bool,
    ) Error!bool {
        const section = try streamingResponseSectionAcknowledgments(event);
        if (event == .push_promise) {
            try http3.validatePushPromise(
                self.control,
                event.push_promise.push_id,
            );
            try self.push_streams.registerPromise(
                event.push_promise.push_id,
                stream_id,
            );
        }
        if (section) |acknowledgments| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                stream_id,
                acknowledgments,
            );
            // Encoder-stream insert count increments are also queued in the
            // decoder feedback buffer. Flush on every decoded field section,
            // even when that section itself used only static entries.
            if (single_attempt)
                self.flushResponsePacketFeedbackOnce() catch {}
            else
                self.sendQpackFeedback() catch {};
        }
        if (event == .finished) {
            if (single_attempt) {
                const active = self.streaming_responses.find(stream_id) orelse
                    return error.UnexpectedStream;
                releaseStreamingReaderCapacityOnce(
                    &self.established.connection,
                    &active.reader,
                ) catch |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => return false,
                    else => return err,
                };
            }
            try self.finishStreamingResponse(stream_id);
        }
        return true;
    }

    fn finishStreamingResponse(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        if (self.streaming_responses.find(stream_id)) |active| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &active.reader,
            );
        }
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(stream_id);
        // Detached CONNECT readers are removed from `streaming_responses` and
        // retain their association until explicit close or peer FIN/reset.
        if (self.streaming_responses.find(stream_id) != null) {
            self.connect_datagrams.unregister(stream_id);
        }
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.streaming_responses.remove(stream_id);
        self.flushFinalResponseAckIfIdle();
    }

    fn flushFinalResponseAckIfIdle(self: *HandshakeClient) void {
        if (!self.request_lifecycle.isEmpty()) return;
        self.flushTerminalReceiveAck();
    }

    fn flushTerminalReceiveAck(self: *HandshakeClient) void {
        // A caller may stop driving receive as soon as the terminal event is
        // delivered. Do not leave its final STREAM/FIN behind the delayed ACK
        // timer: a short-lived peer draining reliable bytes would otherwise
        // retransmit until its application deadline.
        _ = self.established.connection.tryFlushPendingAck() catch {};
    }

    fn submitResponsePollFailure(self: *HandshakeClient, failure: ResponseFailure) Error!void {
        try self.request_lifecycle.prepareFinish();
        try self.cancelRequestInternalOnce(failure.stream_id, failure.application_error_code, false);
    }

    fn progressResponsePollFailures(self: *HandshakeClient, target: ?u62, failure_out: ?*?ResponseFailure) Error!void {
        if (self.pending_response_failures.count() == 0) return;
        const connection = &self.established.connection;
        if (connection.closing() or connection.draining() or connection.closed()) {
            self.pending_response_failures.clear();
            return error.ConnectionClosed;
        }
        if (failure_out) |output| {
            if (self.pending_response_failures.take(target)) |failure| {
                output.* = failure;
                return failure.err;
            }
        } else if (try self.pending_response_failures.poll(self, target, submitResponsePollFailure)) |failure| {
            return failure.err;
        }
    }

    fn retainResponsePollFailure(self: *HandshakeClient, id: ?u62, err: Error, failure_out: ?*?ResponseFailure) Error!void {
        if (ResponseFailure.fromError(id, err)) |failure| {
            self.streaming_responses.suspendFailedMessage(failure.stream_id);
            if (failure_out) |output| {
                output.* = failure;
                return;
            }
            self.pending_response_failures.append(failure);
            try self.progressResponsePollFailures(failure.stream_id, null);
            return;
        }
        try closeConnectionForHttp3Error(&self.established.connection, err);
    }

    fn failReceivedResponse(
        self: *HandshakeClient,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) Error!void {
        if (stream_id) |id| {
            if (messageStreamErrorCode(err)) |code| {
                const uses_dynamic = if (assembled)
                    messageUsesDynamicQpack(
                        assembled_bytes orelse &.{},
                        self.qpack_decode.table,
                    ) catch false
                else
                    false;
                try self.cancelRequestInternal(id, code, uses_dynamic);
                try self.sendQpackFeedback();
                return;
            }
        }
        if (runtime_error.protocolClose(err) != null) {
            try closeConnectionForHttp3Error(
                &self.established.connection,
                err,
            );
            return;
        }
    }

    fn failReceivedResponseOnce(
        self: *HandshakeClient,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) Error!void {
        if (stream_id) |id| {
            if (messageStreamErrorCode(err)) |code| {
                const uses_dynamic = if (assembled)
                    messageUsesDynamicQpack(
                        assembled_bytes orelse &.{},
                        self.qpack_decode.table,
                    ) catch false
                else
                    false;
                try self.cancelRequestInternalOnce(id, code, uses_dynamic);
                return;
            }
        }
        if (runtime_error.protocolClose(err) != null) {
            try closeConnectionForHttp3Error(
                &self.established.connection,
                err,
            );
        }
    }

    /// Apply an authenticated response packet view from a caller-buffer
    /// dispatcher. Frame payloads are borrowed only for this call; response,
    /// push, control, QPACK, and DATAGRAM state needed later is retained by
    /// the client before returning.
    pub fn processResponsePacketView(
        self: *HandshakeClient,
        packet: quic.one_rtt.ReceivedPacketView,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.receive_packets.ack_pending) {
            try self.established.connection.sendAck(0);
            self.receive_packets.ack_pending = false;
        }
        _ = self.established.connection.sendAckForPacketIfNeeded(
            packet.packet_number,
            packet.frames,
        ) catch {
            self.receive_packets.ack_pending = true;
        };
        var context: ConnectionResponseReceiveContext = .{
            .connection = &self.established.connection,
            .control = &self.control,
            .qpack_decode = &self.qpack_decode,
            .qpack_encode = &self.qpack_encode,
            .max_blocked_streams = self.options.local_settings.qpack_blocked_streams,
            .response_streams = &self.response_streams,
            .streaming_responses = &self.streaming_responses,
            .push_streams = &self.push_streams,
            .request_lifecycle = &self.request_lifecycle,
            .detached_stream_id = null,
            .detached_streams = &self.connect_datagrams,
            .ticket_receiver = &self.ticket_receiver,
            .established = &self.established,
        };
        try visitConnectionResponsePacket(&context, packet);
        _ = try self.applyPendingPushCancellationOnce();
        self.flushResponsePacketFeedbackOnce() catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {},
            else => return err,
        };
    }
};
