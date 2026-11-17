//! HTTP/3 server handshake session over QUIC.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const BodyChunk = runtime.BodyChunk;
const BodyWriteProgress = runtime.BodyWriteProgress;
const BodyWriteState = runtime.BodyWriteState;
const ConnectIpServerSession = runtime.ConnectIpServerSession;
const ConnectUdpServerSession = runtime.ConnectUdpServerSession;
const ConnectionPacketCursor = runtime.ConnectionPacketCursor;
const CriticalStreamSendScratch = runtime.CriticalStreamSendScratch;
const DetachedServerRequestContext = runtime.DetachedServerRequestContext;
const Error = runtime.Error;
const HandshakeConcurrentEngine = runtime.HandshakeConcurrentEngine;
const HandshakeSessionOptions = runtime.HandshakeSessionOptions;
const NoConnectProgress = runtime.NoConnectProgress;
const OutboundBodySet = runtime.OutboundBodySet;
const OwnedConnectDatagram = runtime.OwnedConnectDatagram;
const OwnedHandshakeRequest = runtime.OwnedHandshakeRequest;
const PeerResponseCancellation = runtime.PeerResponseCancellation;
const PushSendScratch = runtime.PushSendScratch;
const QpackDecodeState = runtime.QpackDecodeState;
const QpackEncodeState = runtime.QpackEncodeState;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const RequestEventResult = runtime.RequestEventResult;
const RequestFailure = runtime.RequestFailure;
const RequestStreamReset = runtime.RequestStreamReset;
const RequestStreamSet = runtime.RequestStreamSet;
const ResponseBody = runtime.ResponseBody;
const ServerPush = runtime.ServerPush;
const ServerPushIdSet = runtime.ServerPushIdSet;
const ServerRequestLifecycle = runtime.ServerRequestLifecycle;
const StreamMessageSendScratch = runtime.StreamMessageSendScratch;
const StreamingEvent = runtime.StreamingEvent;
const StreamingRequestEvent = runtime.StreamingRequestEvent;
const StreamingRequestSet = runtime.StreamingRequestSet;
const applyServerRequestPacketFrames = runtime.applyServerRequestPacketFrames;
const body_fragment = runtime.body_fragment;
const cancelConnectionRequest = runtime.cancelConnectionRequest;
const cancelHandshakeRequestWithDeadline = runtime.cancelHandshakeRequestWithDeadline;
const closeConnectionForHttp3Error = runtime.closeConnectionForHttp3Error;
const complete_response = runtime.complete_response;
const concurrent = runtime.concurrent;
const connectDatagramTerminalError = runtime.connectDatagramTerminalError;
const connect_datagram = runtime.connect_datagram;
const connect_datagram_progress = runtime.connect_datagram_progress;
const connect_datagram_send = runtime.connect_datagram_send;
const deadline_policy = runtime.deadline_policy;
const default_paced_response_body_chunk_bytes = runtime.default_paced_response_body_chunk_bytes;
const ensureConnectDatagramSendSideOpen = runtime.ensureConnectDatagramSendSideOpen;
const ensureConnectDatagramsNegotiated = runtime.ensureConnectDatagramsNegotiated;
const finishServerRequest = runtime.finishServerRequest;
const first_server_push_stream_id = runtime.first_server_push_stream_id;
const messageStreamErrorCode = runtime.messageStreamErrorCode;
const messageUsesDynamicQpack = runtime.messageUsesDynamicQpack;
const message_data = runtime.message_data;
const normalizeHandlerResponse = runtime.normalizeHandlerResponse;
const observeConnectDatagramTerminal = runtime.observeConnectDatagramTerminal;
const pacedBodyChunkLimit = runtime.pacedBodyChunkLimit;
const paced_body = runtime.paced_body;
const packetView = runtime.packetView;
const pollConnectDatagramRegistry = runtime.pollConnectDatagramRegistry;
const pollConnectDatagramRegistryInto = runtime.pollConnectDatagramRegistryInto;
const prepareServerRequestReceived = runtime.prepareServerRequestReceived;
const receiveConnectDatagramFromSession = runtime.receiveConnectDatagramFromSession;
const receiveConnectDatagramIntoFromSession = runtime.receiveConnectDatagramIntoFromSession;
const receiveConnectDatagramsIntoFromSession = runtime.receiveConnectDatagramsIntoFromSession;
const receiveConnectionRequestStreamBytesUntil = runtime.receiveConnectionRequestStreamBytesUntil;
const releaseStreamingReaderCapacity = runtime.releaseStreamingReaderCapacity;
const releaseStreamingReaderCapacityOnce = runtime.releaseStreamingReaderCapacityOnce;
const requestEndedBeforeHeaders = runtime.requestEndedBeforeHeaders;
const requestHasProtocol = runtime.requestHasProtocol;
const requestPriority = runtime.requestPriority;
const requestResetError = runtime.requestResetError;
const request_failure = runtime.request_failure;
const resolvePacedBodyChunkBytes = runtime.resolvePacedBodyChunkBytes;
const responseBodySendCapacity = runtime.responseBodySendCapacity;
const responseResetError = runtime.responseResetError;
const response_scheduler = runtime.response_scheduler;
const runtime_error = runtime.runtime_error;
const sendConnectionBodyBatchPaced = runtime.sendConnectionBodyBatchPaced;
const sendConnectionBodyBatchPacedProgress = runtime.sendConnectionBodyBatchPacedProgress;
const sendConnectionBodyBatchPacedWithDeadline = runtime.sendConnectionBodyBatchPacedWithDeadline;
const sendConnectionBodyChunk = runtime.sendConnectionBodyChunk;
const sendConnectionBodyChunkWithDeadline = runtime.sendConnectionBodyChunkWithDeadline;
const sendConnectionControlFrame = runtime.sendConnectionControlFrame;
const sendConnectionControlFrameWithDeadline = runtime.sendConnectionControlFrameWithDeadline;
const sendConnectionFrames = runtime.sendConnectionFrames;
const sendConnectionFramesWithDeadline = runtime.sendConnectionFramesWithDeadline;
const sendConnectionPush = runtime.sendConnectionPush;
const sendConnectionPushStreamingHeads = runtime.sendConnectionPushStreamingHeads;
const sendConnectionPushStreamingHeadsWithDeadline = runtime.sendConnectionPushStreamingHeadsWithDeadline;
const sendConnectionPushWithDeadline = runtime.sendConnectionPushWithDeadline;
const sendConnectionQpackFeedback = runtime.sendConnectionQpackFeedback;
const sendConnectionQpackFeedbackWithDeadline = runtime.sendConnectionQpackFeedbackWithDeadline;
const sendConnectionSettings = runtime.sendConnectionSettings;
const sendConnectionSettingsWithDeadline = runtime.sendConnectionSettingsWithDeadline;
const sendConnectionStreamingHead = runtime.sendConnectionStreamingHead;
const sendConnectionStreamingHeadWithDeadline = runtime.sendConnectionStreamingHeadWithDeadline;
const sendConnectionTrailers = runtime.sendConnectionTrailers;
const sendConnectionTrailersWithDeadline = runtime.sendConnectionTrailersWithDeadline;
const serverRequestReceivedAssumeCapacity = runtime.serverRequestReceivedAssumeCapacity;
const server_control_stream_id = runtime.server_control_stream_id;
const server_qpack_decoder_stream_id = runtime.server_qpack_decoder_stream_id;
const server_qpack_encoder_stream_id = runtime.server_qpack_encoder_stream_id;
const server_response = runtime.server_response;
const sleepResponseSchedulerDelayUntil = runtime.sleepResponseSchedulerDelayUntil;
const streamingRequestSectionAcknowledgments = runtime.streamingRequestSectionAcknowledgments;
const trySendConnectionBodyChunk = runtime.trySendConnectionBodyChunk;
const trySendConnectionBodyParts = runtime.trySendConnectionBodyParts;
const trySendConnectionControlFrame = runtime.trySendConnectionControlFrame;
const trySendConnectionQpackFeedback = runtime.trySendConnectionQpackFeedback;
const trySendConnectionResponseLiteral = runtime.trySendConnectionResponseLiteral;
const trySendConnectionStreamingResponseHeadLiteral = runtime.trySendConnectionStreamingResponseHeadLiteral;
const trySendConnectionTrailersLiteral = runtime.trySendConnectionTrailersLiteral;
const validateHandshakeSessionOptions = runtime.validateHandshakeSessionOptions;
const validateNewServerPush = runtime.validateNewServerPush;
const validateServerGoAwayStreamId = runtime.validateServerGoAwayStreamId;
const visitDetachedServerRequestPacket = runtime.visitDetachedServerRequestPacket;
const visitStreamingServerRequestPacket = runtime.visitStreamingServerRequestPacket;

pub const HandshakeServerSession = struct {
    const ConnectDatagramProgress = connect_datagram_progress.Pump(.{
        .Error = ReceiveTimeoutError,
        .check_callback = false,
        .io = connectionIo,
        .receive = receiveDetachedRequestPacketInto,
        .receiveAttached = receiveAttachedConnectDatagramPacket,
        .feedback = flushRequestPacketFeedbackOnce,
    });
    const ConnectDatagramSend = connect_datagram_send.Controller(.{
        .Error = ReceiveTimeoutError,
        .check_callback = false,
        .validate = validateConnectDatagramSend,
        .io = connectionIo,
        .receive = receiveDetachedRequestPacketInto,
        .feedback = flushRequestPacketFeedbackOnce,
    });
    established: quic.handshake.EstablishedConnection,
    /// True while an endpoint dispatcher is the sole UDP receive owner.
    dispatcher_bound: bool = false,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    request_streams: RequestStreamSet,
    streaming_requests: StreamingRequestSet,
    pending_request_failures: request_failure.Pending = .{},
    pending_response_cancellations: std.ArrayList(complete_response.Cancellation) = .empty,
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ServerRequestLifecycle,
    connect_datagrams: connect_datagram.Registry,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    push_send_scratch: PushSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
    promised_push_ids: ServerPushIdSet = .{},
    next_push_stream_id: u62 = first_server_push_stream_id,
    /// The QUIC handshake can authenticate and retain 0-RTT STREAM bytes
    /// before this HTTP/3 session exists. Route that snapshot exactly once
    /// before the first application request poll.
    preexisting_streams_routed: bool = false,

    pub fn initEstablished(
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeServerSession {
        const resolved_options = resolvePacedBodyChunkBytes(
            options,
            default_paced_response_body_chunk_bytes,
        );
        try validateHandshakeSessionOptions(resolved_options);
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            resolved_options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        const allocator = established.connection.endpoint.allocator;
        var session: HandshakeServerSession = .{
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
            .request_streams = .init(
                allocator,
                resolved_options.max_stream_buffer,
                resolved_options.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                allocator,
                resolved_options.max_concurrent_request_streams,
                resolved_options.max_stream_buffer,
                resolved_options.local_settings,
                .request,
            ),
            .receive_packets = .{
                .max_datagrams = resolved_options.max_receive_batch_datagrams,
            },
            .request_lifecycle = .init(allocator),
            .connect_datagrams = .initWithEarly(allocator, .{
                .max_associations = resolved_options.max_concurrent_request_streams,
                .max_queued_per_association = resolved_options.max_queued_connect_datagrams,
                .max_queued_bytes_per_association = resolved_options.max_queued_connect_datagram_bytes,
            }, established.connection.endpoint.io, resolved_options.early_connect_datagrams),
            .outbound_bodies = .init(
                allocator,
                resolved_options.max_concurrent_request_streams,
            ),
        };
        session.streaming_requests.setMaxBodyBytes(resolved_options.max_body_bytes);
        return session;
    }

    pub fn bindDispatcher(self: *HandshakeServerSession) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        self.dispatcher_bound = true;
    }

    pub fn dispatcherBound(self: *const HandshakeServerSession) bool {
        return self.dispatcher_bound;
    }

    pub fn initPreconfigured(
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        options: HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!HandshakeServerSession {
        try validateHandshakeSessionOptions(options);
        var established = try quic.handshake.establishPreconfigured(
            endpoint,
            peer,
            .server,
            transport,
        );
        errdefer established.deinit();
        return initEstablished(established, options);
    }

    /// Reserve one server-initiated unidirectional stream ID.
    ///
    /// HTTP/3 push streams and WebTransport unidirectional streams share this
    /// QUIC ID space. Keeping allocation here prevents sibling protocol
    /// adapters from independently selecting the same stream.
    pub fn reserveServerUnidirectionalStreamId(
        self: *HandshakeServerSession,
    ) Error!u62 {
        const stream_id = self.next_push_stream_id;
        self.next_push_stream_id = std.math.add(
            u62,
            stream_id,
            4,
        ) catch return error.StreamCreationError;
        return stream_id;
    }

    /// Reserve a server-initiated unidirectional ID in both HTTP/3's shared
    /// push-stream namespace and the underlying QUIC transport. The caller
    /// must complete any fallible application bookkeeping before invoking
    /// this method: a successful transport reservation cannot be rolled back.
    pub fn openServerUnidirectionalStream(
        self: *HandshakeServerSession,
    ) Error!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const expected = self.next_push_stream_id;
        _ = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection
            .nextLocalUnidirectionalStreamId() != expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection
            .openUnidirectionalStream();
        const stream_id = try self.reserveServerUnidirectionalStreamId();
        std.debug.assert(stream_id == expected and stream_id == transport_id);
        return stream_id;
    }

    /// Reserve the next server unidirectional stream without waiting for a
    /// paced STREAMS_BLOCKED notification.
    pub fn tryOpenServerUnidirectionalStream(
        self: *HandshakeServerSession,
    ) Error!u62 {
        const expected = self.next_push_stream_id;
        _ = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection
            .nextLocalUnidirectionalStreamId() != expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection
            .tryOpenUnidirectionalStream();
        const stream_id = try self.reserveServerUnidirectionalStreamId();
        std.debug.assert(stream_id == expected and stream_id == transport_id);
        return stream_id;
    }

    /// Reserve the shared push/extension namespace with an atomic QUIC reset
    /// prefix binding. All fallible prefix allocation precedes ID consumption.
    pub fn tryOpenServerUnidirectionalStreamWithResetPrefix(self: *HandshakeServerSession, prefix: []const u8) Error!u62 {
        const expected = self.next_push_stream_id;
        _ = std.math.add(u62, expected, 4) catch return error.StreamCreationError;
        if (self.established.connection.nextLocalUnidirectionalStreamId() != expected) return error.StreamCreationError;
        const actual = try self.established.connection.tryOpenStreamWithResetPrefix(.unidirectional, prefix);
        const id = try self.reserveServerUnidirectionalStreamId();
        std.debug.assert(actual == expected and id == expected);
        return id;
    }

    pub fn openServerUnidirectionalStreamWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openServerUnidirectionalStreamWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openServerUnidirectionalStreamWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const expected = self.next_push_stream_id;
        _ = std.math.add(u62, expected, 4) catch
            return error.StreamCreationError;
        if (self.established.connection
            .nextLocalUnidirectionalStreamId() != expected)
        {
            return error.StreamCreationError;
        }
        const transport_id = try self.established.connection
            .openUnidirectionalStreamWithDeadline(deadline);
        const stream_id = try self.reserveServerUnidirectionalStreamId();
        std.debug.assert(stream_id == expected and stream_id == transport_id);
        return stream_id;
    }

    /// Advertise local HTTP/3 settings before waiting for a request.
    ///
    /// Some event-driven clients wait for the server control stream before
    /// opening their first extended CONNECT. Ordinary request/response calls
    /// invoke the same idempotent helper automatically, while protocol
    /// adapters can use this to avoid a peer-settings/request deadlock.
    pub fn ensureSettingsSent(self: *HandshakeServerSession) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
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
            server_control_stream_id,
        );
    }

    pub fn deinit(self: *HandshakeServerSession) void {
        self.pending_response_cancellations.deinit(self.established.connection.endpoint.allocator);
        self.pending_request_failures.deinit(self.established.connection.endpoint.allocator);
        self.critical_stream_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.push_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.stream_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.outbound_bodies.deinit();
        self.promised_push_ids.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.receive_packets.deinit();
        self.connect_datagrams.deinit();
        self.control.deinit(self.established.connection.endpoint.allocator);
        self.request_lifecycle.deinit();
        self.streaming_requests.deinit();
        self.request_streams.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.established.deinit();
        self.* = undefined;
    }

    pub fn negotiatedAlpn(self: HandshakeServerSession) []const u8 {
        return self.established.alpn;
    }

    pub fn negotiatedCipherSuite(
        self: HandshakeServerSession,
    ) quic.tls.cipher_suite.Suite {
        return self.established.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: HandshakeServerSession,
    ) quic.tls.secret.Hash {
        return self.established.negotiatedTranscriptHash();
    }

    pub fn peerCertificates(
        self: *const HandshakeServerSession,
    ) ?[]const []const u8 {
        return self.established.peerCertificates();
    }

    pub fn exportKeyingMaterial(
        self: *const HandshakeServerSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.established.exportKeyingMaterial(label, context, out);
    }

    pub fn initiateKeyUpdate(self: *HandshakeServerSession) Error!void {
        try self.established.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: HandshakeServerSession) u64 {
        return self.established.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: HandshakeServerSession) u64 {
        return self.established.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: HandshakeServerSession) bool {
        return self.established.keyUpdateAwaitingAck();
    }

    fn routePreexistingRequestStreams(
        self: *HandshakeServerSession,
        streaming: bool,
    ) Error!?RequestStreamReset {
        if (self.preexisting_streams_routed) return null;
        self.preexisting_streams_routed = true;
        if (self.established.early_data_status != .accepted) {
            return null;
        }
        var first_reset: ?RequestStreamReset = null;
        var stream_ids: [16]u62 = undefined;
        // SETTINGS and QPACK streams must be applied before request streams,
        // independent of numeric stream ID or the order in the 0-RTT packet.
        for ([_]bool{ true, false }) |route_unidirectional| {
            var after: ?u62 = null;
            while (true) {
                const ids = self.established.connection
                    .receivedStreamIdsAfterInto(after, &stream_ids);
                if (ids.len == 0) break;
                for (ids) |stream_id| {
                    if (((stream_id & 0x02) != 0) != route_unidirectional) {
                        continue;
                    }
                    const stats = self.established.connection
                        .recvStreamStats(stream_id) orelse continue;
                    const reset = stats.reset;
                    const bytes = self.established.connection
                        .retainedReceivedStream(stream_id) orelse &.{};
                    const end = std.math.add(
                        u64,
                        stats.bytes_read,
                        std.math.cast(u64, bytes.len) orelse
                            return error.InvalidStreamRange,
                    ) catch return error.InvalidStreamRange;
                    const frames = if (reset) |info|
                        [_]quic.Frame{.{ .reset_stream = .{
                            .stream_id = stream_id,
                            .application_error_code = info.application_error_code,
                            .final_size = info.final_size,
                        } }}
                    else
                        [_]quic.Frame{.{ .stream = .{
                            .stream_id = stream_id,
                            .offset = stats.bytes_read,
                            .data = bytes,
                            .fin = stats.final_size != null and
                                stats.final_size.? == end,
                        } }};
                    if (reset == null and bytes.len == 0 and
                        stats.final_size == null)
                    {
                        continue;
                    }
                    const routed_reset = try applyServerRequestPacketFrames(
                        self.established.connection.peerAddress(),
                        &frames,
                        self.established.connection.endpoint.allocator,
                        &self.control,
                        &self.qpack_decode,
                        &self.qpack_encode,
                        self.options.local_settings.qpack_blocked_streams,
                        &self.request_streams,
                        if (streaming) &self.streaming_requests else null,
                        &self.request_lifecycle,
                        .{ .connection = &self.established.connection },
                        .{ .set = &self.promised_push_ids },
                        null,
                        &self.connect_datagrams,
                    );
                    if (first_reset == null) first_reset = routed_reset;
                }
                after = ids[ids.len - 1];
                if (ids.len != stream_ids.len) break;
            }
        }
        return first_reset;
    }

    pub fn receiveRequest(self: *HandshakeServerSession) Error!OwnedHandshakeRequest {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveRequestInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Aggregate the next request within one relative application budget. A
    /// timeout preserves all received STREAM and QPACK state for a later call.
    pub fn receiveRequestWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeRequest {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestInternal(
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Aggregate the next request before `deadline` without resetting or
    /// completing a partially received request when the deadline expires.
    pub fn receiveRequestWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeRequest {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveRequestInternal(deadline);
    }

    fn receiveRequestInternal(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeRequest {
        const preexisting_reset = self.routePreexistingRequestStreams(false) catch |err| {
            closeConnectionForHttp3Error(
                &self.established.connection,
                err,
            ) catch {};
            return err;
        };
        if (preexisting_reset) |reset| {
            return requestResetError(reset.application_error_code);
        }
        if (self.streaming_requests.retainedCount() != 0) {
            return error.UnexpectedStream;
        }
        var prepared = receiveConnectionRequestStreamBytesUntil(
            &self.established.connection,
            &self.receive_packets,
            self.options,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.request_streams,
            &self.request_lifecycle,
            .{ .set = &self.promised_push_ids },
            &self.connect_datagrams,
            deadline,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                try self.sendQpackFeedback();
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
        if (requestEndedBeforeHeaders(prepared.bytes)) {
            self.failReceivedRequest(
                prepared.stream_id,
                prepared.bytes,
                error.RequestIncomplete,
                true,
            ) catch {};
            return error.RequestIncomplete;
        }
        var request = http3.decodeRequestWithDynamicTable(
            self.established.connection.endpoint.allocator,
            prepared.bytes,
            self.options.local_settings,
            self.qpack_decode.table,
        ) catch |err| {
            self.failReceivedRequest(
                prepared.stream_id,
                prepared.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        errdefer request.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.prepareSectionAcknowledgments(
            request.qpack_section_acknowledgments,
        );
        const was_early_data = self.established.connection
            .recvStreamReceivedEarlyData(prepared.stream_id);
        try prepareServerRequestReceived(&self.request_lifecycle);
        _ = try self.established.connection
            .requestCompletedPeerStreamRelease(prepared.stream_id);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            prepared.stream_id,
            request.qpack_section_acknowledgments,
        );
        const assembled = self.request_streams.commitPreparedReady(
            &prepared,
        );
        serverRequestReceivedAssumeCapacity(
            &self.control,
            &self.request_lifecycle,
            assembled.stream_id,
            requestPriority(request.headers),
        );
        self.sendQpackFeedback() catch {};
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .was_early_data = was_early_data,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    /// Receive one complete request, invoke the handler, and send its complete
    /// response. Request storage remains valid for the duration of the handler
    /// and is released after the response has been copied into QUIC recovery
    /// storage. Use the streaming APIs for bodies that should not be aggregated.
    pub fn serveOne(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
    ) Error!u62 {
        var request = try self.receiveRequest();
        defer request.deinit(
            self.established.connection.endpoint.allocator,
        );
        var response = try handler(context, request);
        const invalid_final = normalizeHandlerResponse(
            &response,
            request.request.method,
            requestHasProtocol(request.request.headers),
        );
        try self.sendResponsePaced(request.stream_id, response);
        if (invalid_final) return error.InvalidStatus;
        return request.stream_id;
    }

    /// Serve a bounded number of requests on one authenticated connection and
    /// then send the two-phase HTTP/3 GOAWAY sequence. Existing accepted
    /// requests finish normally; a peer cannot start a later request stream
    /// after the final GOAWAY identifier.
    pub fn serve(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
        max_requests: usize,
    ) Error!usize {
        const served = try self.serveRequests(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
        if (served == 0) return 0;
        // Announce graceful shutdown only after the bounded loop has accepted
        // its last request. Sending the maximum-ID GOAWAY up front is useful
        // for externally-triggered shutdown, but may legitimately cause a
        // client to stop creating requests before this convenience loop has
        // reached its caller-selected count.
        try self.initiateShutdown();
        try self.completeShutdown();
        return served;
    }

    pub fn serveRequests(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
        max_requests: usize,
    ) Error!usize {
        if (max_requests == 0) return 0;
        var served: usize = 0;
        while (served < max_requests) : (served += 1) {
            _ = try self.serveOne(HandlerContext, context, handler);
        }
        return served;
    }

    /// Poll one event from any multiplexed request stream without aggregating
    /// DATA payloads. The returned stream ID is then used with
    /// `readRequestData`, matching tquic's poll/recv_body split while retaining
    /// netz's owned decoded heads and dynamic trailers.
    pub fn receiveRequestEvent(
        self: *HandshakeServerSession,
    ) Error!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveRequestEventInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Wait for one multiplexed request event within a relative application
    /// budget. Active incremental readers remain resumable after timeout.
    pub fn receiveRequestEventWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventInternal(
            .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Wait for one multiplexed request event until an absolute deadline.
    pub fn receiveRequestEventWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveRequestEventInternal(deadline);
    }

    fn receiveRequestEventInternal(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        while (true) {
            if (try self.pollRequestEvent()) |event| return event;
            try self.receiveRequestPacketUntil(deadline);
        }
    }

    /// Wait for an event from one request stream without consuming ready
    /// events from sibling streams. Protocol adapters that own a long-lived
    /// Extended CONNECT stream use this to share the HTTP/3 connection safely.
    pub fn receiveRequestEventFor(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.receiveRequestEventForInternal(
            stream_id,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveRequestEventForWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventForInternal(
            stream_id,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveRequestEventForWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveRequestEventForInternal(stream_id, deadline);
    }

    fn receiveRequestEventForInternal(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        while (true) {
            if (try self.pollRequestEventFor(stream_id)) |event| return event;
            try self.receiveRequestPacketUntil(deadline);
        }
    }

    /// Return the next request event already present in QUIC stream state.
    ///
    /// This method never reads the UDP socket. Endpoint-wide dispatchers call
    /// `processRequestPacket` after their sole socket receive, then poll each
    /// affected HTTP/3 session without allowing per-connection readers to race.
    pub fn pollRequestEvent(
        self: *HandshakeServerSession,
    ) Error!?StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.pollRequestEventMatchingInternal(null, false, null);
    }

    /// Poll buffered request state without sleeping on receive-credit or QPACK
    /// feedback. Backpressure leaves all pending work queued and returns null.
    pub fn pollRequestEventOnce(
        self: *HandshakeServerSession,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatchingInternal(null, true, null);
    }

    /// Poll once while transferring stream-scoped message failures to the
    /// caller. A failure result has not been canceled: its owner must submit
    /// and retain RESET_STREAM/STOP_SENDING until socket submission succeeds.
    /// Connection protocol and local operation errors still propagate normally.
    pub fn pollRequestEventOnceWithFailure(self: *HandshakeServerSession) Error!?RequestEventResult {
        var failure: ?RequestFailure = null;
        const event = self.pollRequestEventMatchingInternal(null, true, &failure) catch |err| {
            if (failure) |owned| return .{ .failure = owned };
            return err;
        } orelse return null;
        return .{ .event = event };
    }

    /// Return an already-buffered event for one request stream without
    /// advancing another stream's event cursor.
    pub fn pollRequestEventFor(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?StreamingRequestEvent {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.pollRequestEventMatchingInternal(stream_id, false, null);
    }

    /// Poll one buffered event for a specific request stream without waiting
    /// for transport pacing. Shared endpoint adapters use this only after
    /// classifying the stream prefix, so extension-owned bidirectional streams
    /// remain outside the HTTP/3 message parser.
    pub fn pollRequestEventForOnce(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatchingInternal(stream_id, true, null);
    }

    fn pollRequestEventMatchingInternal(
        self: *HandshakeServerSession,
        target_stream_id: ?u62,
        single_attempt: bool,
        failure_out: ?*?RequestFailure,
    ) Error!?StreamingRequestEvent {
        if (failure_out) |output| output.* = null;
        try self.progressRequestPollFailures(target_stream_id, failure_out);
        _ = self.routePreexistingRequestStreams(true) catch |err| {
            closeConnectionForHttp3Error(
                &self.established.connection,
                err,
            ) catch {};
            return err;
        };
        if (single_attempt) {
            self.flushRequestPacketFeedbackOnce() catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                else => |other| return other,
            };
            if (!try self.releaseStreamingRequestCapacityOnce()) return null;
        } else {
            try self.releaseStreamingRequestCapacity();
        }
        if (if (target_stream_id) |stream_id|
            self.streaming_requests.takeReset(stream_id)
        else
            self.streaming_requests.takeFirstReset()) |reset|
        {
            finishServerRequest(&self.control, &self.request_lifecycle, reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            return .{ .reset = .{
                .from = reset.from,
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        if (failure_out == null) try self.pending_request_failures.reserve(self.established.connection.endpoint.allocator);
        if (self.streaming_requests.mightProduceRequestHead(
            &self.request_streams,
            target_stream_id,
        )) {
            try prepareServerRequestReceived(&self.request_lifecycle);
        }
        const ready = self.streaming_requests.nextMatchingEvent(
            &self.request_streams,
            self.qpack_decode.table,
            self.options.local_settings.qpack_blocked_streams,
            target_stream_id,
            false,
        ) catch |err| {
            const stream_id = self.streaming_requests.lastErrorStreamId();
            if (request_failure.capture(failure_out, stream_id, err, &self.streaming_requests)) return err;
            if (RequestFailure.fromError(stream_id, err)) |failure| {
                self.pending_request_failures.append(failure);
                self.streaming_requests.suspendFailedMessage(failure.stream_id);
                try self.progressRequestPollFailures(target_stream_id, null);
                return err;
            }
            if (single_attempt)
                self.failReceivedRequestOnce(
                    stream_id,
                    null,
                    err,
                    false,
                ) catch {}
            else
                self.failReceivedRequest(
                    stream_id,
                    null,
                    err,
                    false,
                ) catch {};
            return err;
        };
        if (ready) |value| {
            return self.applyStreamingRequestEvent(
                value.entry,
                value.event,
                single_attempt,
            ) catch |err| {
                if (request_failure.capture(failure_out, value.entry.reader.streamId(), err, &self.streaming_requests)) return err;
                if (RequestFailure.fromError(value.entry.reader.streamId(), err)) |failure| {
                    self.pending_request_failures.append(failure);
                    self.streaming_requests.suspendFailedMessage(failure.stream_id);
                    try self.progressRequestPollFailures(target_stream_id, null);
                    return err;
                }
                if (single_attempt)
                    self.failReceivedRequestOnce(
                        value.entry.reader.streamId(),
                        null,
                        err,
                        false,
                    ) catch {}
                else
                    self.failReceivedRequest(
                        value.entry.reader.streamId(),
                        null,
                        err,
                        false,
                    ) catch {};
                return err;
            };
        }
        return null;
    }

    fn submitRequestPollFailure(self: *HandshakeServerSession, failure: RequestFailure) Error!void {
        try self.cancelRequestInternalOnce(failure.stream_id, failure.application_error_code, false);
    }

    fn progressRequestPollFailures(self: *HandshakeServerSession, target: ?u62, failure_out: ?*?RequestFailure) Error!void {
        if (self.pending_request_failures.count() == 0) return;
        const connection = &self.established.connection;
        if (connection.closing() or connection.draining() or connection.closed()) {
            self.pending_request_failures.clear();
            return error.ConnectionClosed;
        }
        if (failure_out) |output| {
            if (self.pending_request_failures.take(target)) |failure| {
                output.* = failure;
                return failure.err;
            }
        } else if (try self.pending_request_failures.poll(self, target, submitRequestPollFailure)) |failure| {
            return failure.err;
        }
    }

    fn retainRequestDataFailure(self: *HandshakeServerSession, stream_id: ?u62, err: Error, failure_out: ?*?RequestFailure) Error!void {
        if (RequestFailure.fromError(stream_id, err)) |failure| {
            if (request_failure.capture(failure_out, stream_id, err, &self.streaming_requests)) return;
            self.pending_request_failures.append(failure);
            self.streaming_requests.suspendFailedMessage(failure.stream_id);
            try self.progressRequestPollFailures(failure.stream_id, null);
            return;
        }
        try closeConnectionForHttp3Error(&self.established.connection, err);
    }

    fn failReceivedRequest(
        self: *HandshakeServerSession,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) Error!void {
        if (stream_id) |id| {
            if (err == error.RequestIncomplete) {
                try self.cancelRequestInternal(
                    id,
                    http3.ApplicationErrorCode.request_incomplete,
                    false,
                );
                return;
            }
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

    fn failReceivedRequestOnce(
        self: *HandshakeServerSession,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) Error!void {
        if (stream_id) |id| {
            if (err == error.RequestIncomplete) {
                try self.cancelRequestInternalOnce(
                    id,
                    http3.ApplicationErrorCode.request_incomplete,
                    false,
                );
                return;
            }
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

    /// Apply an already authenticated packet delivered by the endpoint-wide
    /// QUIC dispatcher. The packet remains caller-owned. ACK policy and QPACK
    /// feedback match the blocking receive path, but no socket read occurs.
    pub fn processRequestPacket(
        self: *HandshakeServerSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        return self.processRequestPacketView(packetView(packet.*));
    }

    /// Apply an authenticated packet view from a caller-buffer dispatcher.
    /// The frame payloads are borrowed only for this call; all HTTP/3 state
    /// required afterward is retained by the session before returning.
    pub fn processRequestPacketView(
        self: *HandshakeServerSession,
        packet: quic.one_rtt.ReceivedPacketView,
    ) Error!void {
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
        try visitStreamingServerRequestPacket(
            self,
            packet,
        );
        self.flushRequestPacketFeedbackOnce() catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {},
            else => return err,
        };
    }

    fn accessRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
        out: []u8,
        comptime operation: message_data.Operation,
        comptime single_attempt: bool,
    ) Error!?usize {
        return message_data.access(
            self,
            &self.established.connection,
            &self.streaming_requests,
            &self.pending_request_failures,
            self.established.connection.endpoint.allocator,
            stream_id,
            out,
            operation,
            single_attempt,
            HandshakeServerSession.progressRequestPollFailures,
            HandshakeServerSession.retainRequestDataFailure,
        );
    }

    /// Copy available request DATA, retaining stream-local cancellation after
    /// malformed content. Consumed bytes are credited on the next read or poll.
    pub fn readRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try self.accessRequestData(stream_id, out, .read, false)) orelse 0;
    }

    /// Copy currently available request DATA without waiting for receive-credit
    /// pacing. `null` leaves the reader cursor unchanged until the dispatcher
    /// services the connection's pending transport work. Newly consumed bytes
    /// are reported before their receive credit is advertised.
    pub fn readRequestDataOnce(
        self: *HandshakeServerSession,
        stream_id: u62,
        out: []u8,
    ) Error!?usize {
        return self.accessRequestData(stream_id, out, .read, true);
    }

    /// Return DATA bytes currently readable without receiving another packet.
    /// A consumed DATA frame reports `error.UnexpectedFrame`; streaming
    /// adapters treat that as "no resident bytes" because the next
    /// `.data_available` event carries the following frame.
    pub fn availableRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!usize {
        return (try self.accessRequestData(stream_id, &.{}, .available, false)) orelse 0;
    }

    pub fn skipRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!usize {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return (try self.accessRequestData(stream_id, &.{}, .skip, false)) orelse 0;
    }

    /// Discard currently available request DATA without waiting for
    /// receive-credit pacing.
    pub fn skipRequestDataOnce(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?usize {
        return self.accessRequestData(stream_id, &.{}, .skip, true);
    }

    /// Detach an established Extended CONNECT receive stream from HTTP/3
    /// message parsing.
    ///
    /// Protocol adapters such as WebTransport parse their own long-lived DATA
    /// payload after HTTP semantics establish the tunnel. The initial HEADERS
    /// must already have been consumed with `receiveRequestEvent`; detaching
    /// before that point would bypass QPACK acknowledgments and request
    /// validation.
    pub fn detachRequestStream(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.detachRequestStreamInternal(stream_id, false);
    }

    /// Detach an Extended CONNECT request without waiting for receive-credit
    /// pacing. Backpressure leaves the reader and association retryable.
    pub fn detachRequestStreamOnce(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        return self.detachRequestStreamInternal(stream_id, true);
    }

    fn requestStreamPendingDetach(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!*StreamingRequestSet.Entry {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) != null)
        {
            return error.UnexpectedStream;
        }
        return entry;
    }

    fn validateConnectAcceptance(response: http3.Response) Error!void {
        if (response.status < 200 or response.status >= 300) {
            return error.InvalidStatus;
        }
        if (!response.extended_connect or
            response.request_method == null or
            !std.mem.eql(u8, response.request_method.?, "CONNECT"))
        {
            return error.InvalidHeader;
        }
        if (response.body.len != 0 or response.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        // RFC 9110 section 8.6 forbids Content-Length on a successful CONNECT
        // response, including an explicit zero. Reject it here instead of
        // allowing response serialization to silently discard caller input.
        for (response.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                return error.InvalidContentLength;
            }
        }
        try response.validateBodySemantics();
        if (response.suppressesBody()) return error.InvalidStatus;
    }

    /// Send a successful Extended CONNECT response and detach its request
    /// reader as one ownership transaction. Receive-credit work completes
    /// before the response becomes visible, so no fallible operation remains
    /// after the peer can observe acceptance.
    pub fn acceptConnectResponse(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.acceptConnectResponseUntil(
            stream_id,
            response,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn acceptConnectResponseWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptConnectResponseWithDeadline(
            stream_id,
            response,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Deadline-bounded successful Extended CONNECT admission. The caller's
    /// one absolute budget covers receive-credit pacing, SETTINGS/QPACK, the
    /// response head, and the final local ownership transition.
    pub fn acceptConnectResponseWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.acceptConnectResponseUntil(
            stream_id,
            response,
            deadline,
        );
    }

    fn acceptConnectResponseUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try validateConnectAcceptance(response);
        const entry = try self.requestStreamPendingDetach(stream_id);
        self.connect_datagrams.pruneClosedAssociations(&self.established.connection);
        if (self.connect_datagrams.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try self.connect_datagrams.reserve(stream_id);
        errdefer self.connect_datagrams.unregister(stream_id);

        const release_received = entry.reader.uncreditedConsumed();
        if (deadline) |absolute| {
            try self.established.connection
                .releaseReceivedCapacityWithDeadline(
                stream_id,
                release_received,
                absolute,
            );
        } else {
            try self.established.connection.releaseReceivedCapacity(
                stream_id,
                release_received,
            );
        }
        entry.reader.markCredited(release_received);

        if (deadline) |absolute|
            try self.startResponseWithDeadline(
                stream_id,
                response,
                null,
                absolute,
            )
        else
            try self.startResponse(stream_id, response, null);

        std.debug.assert(self.outbound_bodies.find(stream_id) != null);
        try self.connect_datagrams.markStreamDetached(stream_id);
        var removed = self.streaming_requests.takeEntry(stream_id) orelse
            unreachable;
        removed.deinit();
    }

    fn detachRequestStreamInternal(
        self: *HandshakeServerSession,
        stream_id: u62,
        single_attempt: bool,
    ) Error!void {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) == null)
        {
            return error.UnexpectedStream;
        }
        const already_registered = self.connect_datagrams.contains(stream_id);
        // WebTransport reserves the association before emitting its successful
        // response so the post-200 detach transition is allocation-free.
        // Generic CONNECT callers can still use this one-shot form.
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
        var removed = self.streaming_requests.takeEntry(stream_id) orelse
            return error.UnexpectedStream;
        removed.deinit();
    }

    /// Atomically submit one successful Extended CONNECT response for a
    /// shared endpoint and detach its request reader. All allocation and
    /// receive-credit work completes before the single packet send; after the
    /// packet is visible, the remaining local transition cannot fail.
    pub fn tryAcceptConnectResponse(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
        try validateConnectAcceptance(response);
        self.connect_datagrams.pruneClosedAssociations(&self.established.connection);
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) != null or
            self.connect_datagrams.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        try self.connect_datagrams.reserve(stream_id);
        errdefer self.connect_datagrams.unregister(stream_id);
        const release_received = entry.reader.uncreditedConsumed();
        try self.tryStartResponseLiteral(
            stream_id,
            response,
            release_received,
        );

        const committed = self.streaming_requests.find(stream_id) orelse
            unreachable;
        std.debug.assert(committed.reader.canDetachRequest());
        committed.reader.markCredited(release_received);
        std.debug.assert(self.outbound_bodies.find(stream_id) != null);
        try self.connect_datagrams.markStreamDetached(stream_id);
        var removed = self.streaming_requests.takeEntry(stream_id) orelse
            unreachable;
        removed.deinit();
    }

    /// Reserve receive routing for a validated Extended CONNECT request before
    /// the server commits its successful response. The registration alone does
    /// not authorize datagram APIs; the stream remains attached until
    /// `detachRequestStream` completes.
    pub fn prepareConnectDatagramAssociation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) != null or
            self.connect_datagrams.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        try self.connect_datagrams.reserve(stream_id);
    }

    pub fn cancelPreparedConnectDatagramAssociation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) void {
        if (self.streaming_requests.find(stream_id) != null and
            self.outbound_bodies.find(stream_id) == null)
        {
            self.connect_datagrams.unregister(stream_id);
        }
    }

    /// Pump one packet after an Extended CONNECT stream has been detached.
    ///
    /// The QUIC connection still assembles all STREAM data. This adapter keeps
    /// HTTP/3 control/QPACK and unrelated request streams progressing while
    /// leaving the detached CONNECT stream's bytes for its protocol owner.
    pub fn receiveDetachedRequestProgress(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
    ) Error!void {
        return self.receiveDetachedRequestProgressInto(
            detached_stream_id,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveDetachedRequestProgressWithTimeout(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDetachedRequestProgressWithDeadline(
            detached_stream_id,
            .fromNow(
                self.connectionIo(),
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveDetachedRequestProgressWithDeadline(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveDetachedRequestProgressInto(
            detached_stream_id,
            deadline,
            null,
        );
    }

    pub fn receiveDetachedRequestProgressInto(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        datagram_target: ?*connect_datagram.ReceiveIntoTarget,
    ) ReceiveTimeoutError!void {
        return ConnectDatagramProgress.run(self, detached_stream_id, deadline, datagram_target);
    }

    fn receiveDetachedRequestPacketInto(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
        datagram_target: ?*connect_datagram.ReceiveIntoTarget,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        const context = DetachedServerRequestContext{
            .session = self,
            .detached_stream_id = detached_stream_id,
            .datagram_target = datagram_target,
        };
        if (deadline) |absolute| {
            try self.receive_packets.visitWithDeadline(
                &self.established.connection,
                absolute,
                context,
                visitDetachedServerRequestPacket,
            );
        } else {
            try self.receive_packets.visit(
                &self.established.connection,
                context,
                visitDetachedServerRequestPacket,
            );
        }
    }

    /// Apply a dispatcher-owned packet while preserving bytes on one detached
    /// Extended CONNECT stream for its protocol adapter.
    pub fn processDetachedRequestPacket(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
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
        try visitDetachedServerRequestPacket(
            .{
                .session = self,
                .detached_stream_id = detached_stream_id,
            },
            packetView(packet.*),
        );
        self.flushRequestPacketFeedbackOnce() catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {},
            else => return err,
        };
    }

    /// True only after both peers enabled RFC 9297 and QUIC permits DATAGRAM
    /// frames in both directions. A missing peer SETTINGS frame is therefore
    /// never mistaken for negotiation.
    pub fn connectDatagramsNegotiated(self: HandshakeServerSession) bool {
        return self.control.settings.sent and
            self.control.settings.received and
            self.control.settings.local.h3_datagram and
            self.control.settings.peer.h3_datagram and
            self.established.connection.datagramsEnabled();
    }

    pub fn acceptConnectUdp(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target_host_storage: []u8,
    ) Error!http3.connect_udp.Target {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const target = try http3.connect_udp.validateDecodedDefaultRequest(
            request,
            target_host_storage,
        );
        try self.acceptConnectResponse(
            stream_id,
            http3.connect_udp.successResponse(),
        );
        return target;
    }

    /// Dispatcher-safe single-attempt CONNECT-UDP acceptance. The caller
    /// owns transport progress and must refresh the connection timer after
    /// this method, including after pacing/congestion errors.
    pub fn tryAcceptConnectUdp(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target_host_storage: []u8,
    ) Error!http3.connect_udp.Target {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const target = try http3.connect_udp.validateDecodedDefaultRequest(
            request,
            target_host_storage,
        );
        try self.tryAcceptConnectResponse(
            stream_id,
            http3.connect_udp.successResponse(),
        );
        return target;
    }

    /// Accept a CONNECT-UDP request routed through an application-configured
    /// RFC 9298 URI Template. The application owns reverse template matching
    /// and supplies the already validated target selected by that route.
    pub fn acceptConnectUdpForTarget(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target: http3.connect_udp.Target,
    ) Error!void {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        try http3.connect_udp.validateDecodedRequest(request);
        try target.validate();
        try self.acceptConnectResponse(
            stream_id,
            http3.connect_udp.successResponse(),
        );
    }

    pub fn tryAcceptConnectUdpForTarget(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target: http3.connect_udp.Target,
    ) Error!void {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        try http3.connect_udp.validateDecodedRequest(request);
        try target.validate();
        try self.tryAcceptConnectResponse(
            stream_id,
            http3.connect_udp.successResponse(),
        );
    }

    pub fn connectUdpSession(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!ConnectUdpServerSession {
        if (!self.connect_datagrams.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        return ConnectUdpServerSession.init(
            self.established.connection.endpoint.allocator,
            self.connectionIo(),
            self,
            stream_id,
        );
    }

    /// Accept an RFC 9484 CONNECT-IP request while retaining its request
    /// stream reader for reliable configuration Capsules.
    pub fn acceptConnectIp(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target_storage: []u8,
    ) Error!http3.connect_ip.Scope {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const scope = try http3.connect_ip.validateDecodedDefaultRequest(
            request,
            target_storage,
        );
        try self.acceptConnectIpResponseAttached(stream_id);
        return scope;
    }

    pub fn acceptConnectIpForScope(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        scope: http3.connect_ip.Scope,
    ) Error!void {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        try http3.connect_ip.validateDecodedRequest(request);
        try scope.validate();
        try self.acceptConnectIpResponseAttached(stream_id);
    }

    pub fn tryAcceptConnectIp(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        target_storage: []u8,
    ) Error!http3.connect_ip.Scope {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        const scope = try http3.connect_ip.validateDecodedDefaultRequest(
            request,
            target_storage,
        );
        try self.tryAcceptConnectIpResponseAttached(stream_id);
        return scope;
    }

    pub fn tryAcceptConnectIpForScope(
        self: *HandshakeServerSession,
        stream_id: u62,
        request: http3.DecodedRequestHead,
        scope: http3.connect_ip.Scope,
    ) Error!void {
        if (!self.connectDatagramsNegotiated()) return error.InvalidSetting;
        try http3.connect_ip.validateDecodedRequest(request);
        try scope.validate();
        try self.tryAcceptConnectIpResponseAttached(stream_id);
    }

    pub fn connectIpSession(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!ConnectIpServerSession {
        if (!self.connect_datagrams.contains(stream_id) or
            self.connect_datagrams.streamDetached(stream_id))
        {
            return error.UnexpectedStream;
        }
        return ConnectIpServerSession.init(
            self.established.connection.endpoint.allocator,
            self.connectionIo(),
            self,
            stream_id,
        );
    }

    fn acceptConnectIpResponseAttached(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const response = http3.connect_ip.successResponse();
        try validateConnectAcceptance(response);
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) != null or
            self.connect_datagrams.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        try self.connect_datagrams.register(stream_id);
        errdefer self.connect_datagrams.unregister(stream_id);
        const release_received = entry.reader.uncreditedConsumed();
        try self.established.connection.releaseReceivedCapacity(
            stream_id,
            release_received,
        );
        entry.reader.markCredited(release_received);
        try self.startResponse(stream_id, response, null);
        std.debug.assert(self.outbound_bodies.find(stream_id) != null);
        std.debug.assert(!self.connect_datagrams.streamDetached(stream_id));
    }

    fn tryAcceptConnectIpResponseAttached(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        const response = http3.connect_ip.successResponse();
        try validateConnectAcceptance(response);
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (!entry.reader.canDetachRequest() or
            self.outbound_bodies.find(stream_id) != null or
            self.connect_datagrams.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        try self.connect_datagrams.register(stream_id);
        errdefer self.connect_datagrams.unregister(stream_id);
        const release_received = entry.reader.uncreditedConsumed();
        try self.tryStartResponseLiteral(
            stream_id,
            response,
            release_received,
        );
        entry.reader.markCredited(release_received);
        std.debug.assert(self.outbound_bodies.find(stream_id) != null);
        std.debug.assert(!self.connect_datagrams.streamDetached(stream_id));
    }

    pub fn maxConnectDatagramPayloadSize(
        self: HandshakeServerSession,
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
        self: HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        return self.sendConnectDatagramWithProgress(stream_id, payload, null, NoConnectProgress{}) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn sendConnectDatagrams(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.trySendDatagram(encoded);
    }

    pub fn sendConnectDatagramWithTimeout(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendConnectDatagramWithProgress(stream_id, payload, deadline, NoConnectProgress{});
    }

    /// Advance application-protocol progress before every send retry.
    /// The progress owner shares the HTTP/3 reader and optional deadline.
    pub fn sendConnectDatagramWithProgress(
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
        progress: anytype,
    ) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        return ConnectDatagramSend.single(self, stream_id, payload, deadline, progress);
    }

    pub fn sendConnectDatagramsWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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

    /// Send an ordered batch of CONNECT DATAGRAMs under one deadline. All
    /// payloads are validated and encoded before the first packet is emitted;
    /// `committed_count` is the exact socket-visible input prefix.
    pub fn sendConnectDatagramsWithDeadline(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: ?std.Io.Clock.Timestamp,
        progress: anytype,
    ) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        return ConnectDatagramSend.batch(self, stream_id, payloads, committed_count, deadline, progress);
    }

    /// One socket-batch attempt for shared endpoint owners.
    pub fn trySendConnectDatagrams(
        self: *HandshakeServerSession,
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

    /// One deadline-bounded attempt for a shared endpoint owner. This method
    /// never reads UDP or sleeps; congestion and pacing backpressure tell the
    /// dispatcher loop to route packets or service its timer before retrying
    /// with the same deadline.
    pub fn trySendConnectDatagramWithDeadline(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?OwnedConnectDatagram {
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
        self: *HandshakeServerSession,
        stream_id: u62,
        output: []u8,
    ) Error!?[]u8 {
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
    pub fn receiveConnectDatagramWithProgress(self: *HandshakeServerSession, stream_id: u62, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramFromSession(self, stream_id, deadline, progress);
    }

    pub fn receiveConnectDatagramIntoWithProgress(self: *HandshakeServerSession, stream_id: u62, output: []u8, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)![]u8 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramIntoFromSession(self, stream_id, output, deadline, progress);
    }

    pub fn receiveConnectDatagramsIntoWithProgress(self: *HandshakeServerSession, stream_id: u62, outputs: [][]u8, received_count: *usize, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
        received_count.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return receiveConnectDatagramsIntoFromSession(self, stream_id, outputs, received_count, deadline, progress);
    }

    pub fn receiveConnectDatagram(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedConnectDatagram {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramFromSession(self, stream_id, deadline, NoConnectProgress{});
    }

    pub fn receiveConnectDatagramInto(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        try connect_datagram.validateStreamId(stream_id);
        if (!self.connect_datagrams.contains(stream_id)) return error.UnexpectedStream;
        self.connect_datagrams.unregister(stream_id);
    }

    pub fn sendResponse(self: *HandshakeServerSession, stream_id: u62, response: http3.Response) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try self.sendResponseWithInformational(stream_id, &.{}, response);
    }

    pub fn sendResponseWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithDeadline(
            stream_id,
            response,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendResponseWithInformationalAndDeadline(
            stream_id,
            &.{},
            response,
            deadline,
        );
    }

    /// Submit one complete static-QPACK response in one QUIC packet without
    /// waiting for pacing or reading UDP. HEADERS, optional DATA/trailers, and
    /// FIN commit transactionally, so an endpoint callback can retry after
    /// pacing, congestion, flow-control, or size rejection.
    pub fn trySendResponseLiteral(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
        try self.requireEndpointCriticalStreamsReady();
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.options.auto_date_header,
                self.established.connection.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(
            self.established.connection.endpoint.allocator,
        );
        _ = try trySendConnectionResponseLiteral(
            &self.established.connection,
            &self.stream_send_scratch,
            stream_id,
            prepared.value,
            self.control.settings.peer,
            true,
            0,
        );
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    /// Submit one static-QPACK response head without waiting for pacing or
    /// reading UDP. The encoded head must fit in one QUIC packet. A successful
    /// call retains body state for `trySendResponseBody` or
    /// `tryFinishResponseTrailers`; a failed call leaves it retryable.
    pub fn tryStartResponse(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        trailers_pending: bool,
    ) Error!void {
        try self.requireEndpointCriticalStreamsReady();
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.options.auto_date_header,
                self.established.connection.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(
            self.established.connection.endpoint.allocator,
        );
        const retained = try trySendConnectionStreamingResponseHeadLiteral(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.outbound_bodies,
            stream_id,
            prepared.value,
            body_length,
            trailers_pending,
            self.options,
            self.control.settings.peer,
        );
        if (!retained) {
            finishServerRequest(
                &self.control,
                &self.request_lifecycle,
                stream_id,
            );
        }
    }

    /// Blocking aggregate-response helper for convenience serving loops. It
    /// sends the response body in bounded chunks and pumps ACK and MAX_*
    /// packets whenever body or trailer transmission exhausts peer credit.
    pub fn sendResponsePaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.sendResponsePacedUntil(
            stream_id,
            response,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponsePacedWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponsePacedWithDeadline(
            stream_id,
            response,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponsePacedWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponsePacedUntil(stream_id, response, deadline);
    }

    fn sendResponsePacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendCompleteResponseUntil(stream_id, &.{}, response, deadline);
    }

    fn sendCompleteResponseUntil(self: *HandshakeServerSession, id: u62, informational: []const http3.InformationalResponse, response: http3.Response, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        return complete_response.send(self, id, informational, response, deadline, .{
            .before = beforePacedResponseBody,
            .receive = receivePacedResponseBody,
            .body = sendResponseBodyPacedUntil,
            .finish = finishCompleteResponse,
            .abandon = abandonCompleteResponse,
            .flush = flushResponseCancellations,
        });
    }

    fn finishCompleteResponse(self: *HandshakeServerSession, id: u62) void {
        finishServerRequest(&self.control, &self.request_lifecycle, id);
    }

    /// Send a parent response and one promised response while advancing both
    /// bodies under QUIC flow-control and congestion backpressure. Unlike the
    /// atomic compatibility helper below, this path never requires the whole
    /// pushed body to fit the peer's current connection or stream credit.
    pub fn sendResponseWithPushPaced(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        return self.sendResponseWithPushPacedUntil(
            request_stream_id,
            response,
            push,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseWithPushPacedAndTimeout(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithPushPacedAndDeadline(
            request_stream_id,
            response,
            push,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Deadline-bounded aggregate server push. A timeout after the heads are
    /// visible resets only the affected push or parent stream, preserves the
    /// connection and any completed sibling response, and returns the original
    /// error. A peer push cancellation still returns RequestCancelled after the
    /// parent response completes.
    pub fn sendResponseWithPushPacedAndDeadline(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponseWithPushPacedUntil(
            request_stream_id,
            response,
            push,
            deadline,
        );
    }

    fn sendResponseWithPushPacedUntil(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.connectionIo(), absolute);
        }
        const allocator = self.established.connection.endpoint.allocator;
        // Reserve parent-response cancellation storage before either response
        // becomes visible, so a later timeout can retire only that stream.
        try self.pending_response_cancellations.ensureUnusedCapacity(allocator, 1);
        const push_stream_id = self.next_push_stream_id;
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
                server_control_stream_id,
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
                server_control_stream_id,
            );
        }
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try validateNewServerPush(
            self.control,
            self.promised_push_ids,
            push.push_id,
        );
        try self.promised_push_ids.prepareInsertValue(
            self.established.connection.endpoint.allocator,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;

        const automatic_date = if (self.options.auto_date_header and
            (server_response.headerValue(response.headers, "date") == null or
                server_response.headerValue(push.response.headers, "date") == null))
            server_response.cachedDate(
                true,
                self.established.connection.endpoint.io,
            )
        else
            null;
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_response = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            automatic_date,
            &response_headers_stack,
        );
        defer prepared_response.deinit(
            self.established.connection.endpoint.allocator,
        );
        var push_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_push_response = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            push.response,
            automatic_date,
            &push_headers_stack,
        );
        defer prepared_push_response.deinit(
            self.established.connection.endpoint.allocator,
        );
        var prepared_push = push;
        prepared_push.response = prepared_push_response.value;

        var heads_committed = false;
        var push_scoped = false;
        var parent_scoped = false;
        errdefer if (heads_committed and !push_scoped and !parent_scoped) {
            self.established.connection.failClosedApplication(
                http3.ApplicationErrorCode.internal_error,
                "partial-http3-push",
            );
        };
        while (true) {
            if (deadline) |absolute| {
                sendConnectionPushStreamingHeadsWithDeadline(
                    &self.established.connection,
                    &self.push_send_scratch,
                    &self.critical_stream_send_scratch,
                    self.options,
                    self.control.settings.peer,
                    request_stream_id,
                    prepared_response.value,
                    push_stream_id,
                    prepared_push,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.outbound_bodies,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        if (self.established.connection.closed()) {
                            return error.ConnectionClosed;
                        }
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    else => |other| return @errorCast(other),
                };
            } else {
                sendConnectionPushStreamingHeads(
                    &self.established.connection,
                    &self.push_send_scratch,
                    &self.critical_stream_send_scratch,
                    self.options,
                    self.control.settings.peer,
                    request_stream_id,
                    prepared_response.value,
                    push_stream_id,
                    prepared_push,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.outbound_bodies,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        if (self.established.connection.closed()) {
                            return error.ConnectionClosed;
                        }
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    else => |other| return @errorCast(other),
                };
            }
            break;
        }
        heads_committed = true;
        self.promised_push_ids.insertAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;

        var push_cancelled = false;
        var push_timeout: ?ReceiveTimeoutError = null;
        if (self.outbound_bodies.find(push_stream_id) != null) {
            if (prepared_push.response.body.len != 0) {
                push_cancelled = self.sendPushBodyPacedUntil(
                    push.push_id,
                    push_stream_id,
                    prepared_push.response.body,
                    prepared_push.response.trailers.len == 0,
                    deadline,
                ) catch |err| blk: {
                    if (err != error.Timeout or
                        !self.tryAbandonPush(push.push_id, push_stream_id))
                    {
                        return err;
                    }
                    push_scoped = true;
                    push_timeout = err;
                    break :blk true;
                };
            }
            if (!push_cancelled and prepared_push.response.trailers.len != 0) {
                push_cancelled = self.finishPushTrailersPacedUntil(
                    push.push_id,
                    push_stream_id,
                    prepared_push.response.trailers,
                    deadline,
                ) catch |err| blk: {
                    if (err != error.Timeout or
                        !self.tryAbandonPush(push.push_id, push_stream_id))
                    {
                        return err;
                    }
                    push_scoped = true;
                    push_timeout = err;
                    break :blk true;
                };
            }
        } else {
            _ = try self.established.connection
                .requestCompletedLocalStreamRelease(push_stream_id);
        }
        if (push_cancelled) push_scoped = true;
        if (self.outbound_bodies.find(request_stream_id) != null) {
            self.sendParentResponsePacedUntil(
                request_stream_id,
                prepared_response.value,
                deadline,
            ) catch |err| {
                // The parent HEAD is already visible. Retire only this request;
                // the push is already complete or scoped above.
                self.abandonCompleteResponse(request_stream_id);
                parent_scoped = true;
                return err;
            };
        } else {
            finishServerRequest(
                &self.control,
                &self.request_lifecycle,
                request_stream_id,
            );
        }
        self.control.retirePushPriority(
            self.established.connection.endpoint.allocator,
            push.push_id,
        );
        if (push_timeout) |err| return err;
        if (push_cancelled) return error.RequestCancelled;
        return push_stream_id;
    }

    fn sendParentResponsePacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (response.body.len != 0) {
            try self.sendResponseBodyPacedUntil(
                stream_id,
                response.body,
                response.trailers.len == 0,
                deadline,
            );
        }
        if (response.trailers.len != 0) {
            try self.finishResponseTrailersPacedUntil(
                stream_id,
                response.trailers,
                deadline,
            );
        }
    }

    fn tryAbandonPush(
        self: *HandshakeServerSession,
        push_id: u64,
        push_stream_id: u62,
    ) bool {
        const application_error_code =
            if (self.established.connection.streamStopped(push_stream_id)) |stopped|
                stopped.application_error_code
            else
                http3.ApplicationErrorCode.request_cancelled;
        self.established.connection.tryResetStream(
            push_stream_id,
            application_error_code,
        ) catch return false;
        _ = self.outbound_bodies.finish(push_stream_id);
        _ = self.established.connection.requestCompletedLocalStreamRelease(
            push_stream_id,
        ) catch false;
        self.control.retirePushPriority(
            self.established.connection.endpoint.allocator,
            push_id,
        );
        return true;
    }

    fn sendPushBodyPacedUntil(
        self: *HandshakeServerSession,
        push_id: u64,
        push_stream_id: u62,
        data: []const u8,
        fin: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!bool {
        const Context = struct {
            owner: *HandshakeServerSession,
            push_id: u64,
            fn before(context: *@This(), id: u62, before_deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!bool {
                if (context.owner.control.pushCancelled(context.push_id) or context.owner.established.connection.streamStopped(id) != null) {
                    try context.owner.finishCancelledPacedPush(context.push_id, id, before_deadline);
                    return true;
                }
                return false;
            }
            fn receive(context: *@This(), _: u62, before_deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
                try context.owner.receiveRequestPacketUntil(before_deadline);
            }
            fn finish(context: *@This(), id: u62) ReceiveTimeoutError!void {
                _ = try context.owner.established.connection.requestCompletedLocalStreamRelease(id);
            }
        };
        var context = Context{ .owner = self, .push_id = push_id };
        var progress: BodyWriteProgress = .{};
        return try paced_body.write(&self.established.connection, &self.outbound_bodies, self.options, &context, push_stream_id, data, fin, deadline, &progress, .{ .before = Context.before, .receive = Context.receive, .finish = Context.finish }) == .cancelled;
    }

    fn finishPushTrailersPacedUntil(
        self: *HandshakeServerSession,
        push_id: u64,
        push_stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!bool {
        while (true) {
            if (self.control.pushCancelled(push_id) or
                self.established.connection.streamStopped(push_stream_id) != null)
            {
                try self.finishCancelledPacedPush(
                    push_id,
                    push_stream_id,
                    deadline,
                );
                return true;
            }
            if (deadline) |absolute| {
                sendConnectionTrailersWithDeadline(
                    &self.established.connection,
                    &self.outbound_bodies,
                    &self.stream_send_scratch,
                    &self.critical_stream_send_scratch,
                    push_stream_id,
                    trailers,
                    self.control.settings.peer,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    self.options,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    error.StreamStopped => {
                        try self.finishCancelledPacedPush(
                            push_id,
                            push_stream_id,
                            deadline,
                        );
                        return true;
                    },
                    else => |other| return @errorCast(other),
                };
            } else {
                sendConnectionTrailers(
                    &self.established.connection,
                    &self.outbound_bodies,
                    &self.stream_send_scratch,
                    &self.critical_stream_send_scratch,
                    push_stream_id,
                    trailers,
                    self.control.settings.peer,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    self.options,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    error.StreamStopped => {
                        try self.finishCancelledPacedPush(
                            push_id,
                            push_stream_id,
                            deadline,
                        );
                        return true;
                    },
                    else => |other| return @errorCast(other),
                };
            }
            _ = try self.established.connection
                .requestCompletedLocalStreamRelease(push_stream_id);
            return false;
        }
    }

    fn finishCancelledPacedPush(
        self: *HandshakeServerSession,
        push_id: u64,
        push_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        const application_error_code =
            if (self.established.connection.streamStopped(push_stream_id)) |stopped|
                stopped.application_error_code
            else
                http3.ApplicationErrorCode.request_cancelled;
        if (deadline) |absolute| {
            try self.established.connection.resetStreamWithDeadline(
                push_stream_id,
                application_error_code,
                absolute,
            );
        } else {
            try self.established.connection.resetStream(
                push_stream_id,
                application_error_code,
            );
        }
        _ = self.outbound_bodies.finish(push_stream_id);
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(push_stream_id);
        self.control.retirePushPriority(
            self.established.connection.endpoint.allocator,
            push_id,
        );
    }

    pub fn sendResponseWithPush(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        return self.sendResponseWithPushUntil(
            request_stream_id,
            response,
            push,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseWithPushAndTimeout(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithPushAndDeadline(
            request_stream_id,
            response,
            push,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithPushAndDeadline(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponseWithPushUntil(
            request_stream_id,
            response,
            push,
            deadline,
        );
    }

    fn sendResponseWithPushUntil(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const push_stream_id = self.next_push_stream_id;
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
                server_control_stream_id,
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
                server_control_stream_id,
            );
        }
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try validateNewServerPush(
            self.control,
            self.promised_push_ids,
            push.push_id,
        );
        try self.promised_push_ids.prepareInsertValue(
            self.established.connection.endpoint.allocator,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
        const automatic_date = if (self.options.auto_date_header and
            (server_response.headerValue(response.headers, "date") == null or
                server_response.headerValue(push.response.headers, "date") == null))
            server_response.cachedDate(
                true,
                self.established.connection.endpoint.io,
            )
        else
            null;
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_response = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            automatic_date,
            &response_headers_stack,
        );
        defer prepared_response.deinit(
            self.established.connection.endpoint.allocator,
        );
        var push_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_push_response = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            push.response,
            automatic_date,
            &push_headers_stack,
        );
        defer prepared_push_response.deinit(
            self.established.connection.endpoint.allocator,
        );
        var prepared_push = push;
        prepared_push.response = prepared_push_response.value;
        if (deadline) |absolute| {
            try sendConnectionPushWithDeadline(
                &self.established.connection,
                &self.push_send_scratch,
                &self.critical_stream_send_scratch,
                self.options,
                self.control.settings.peer,
                request_stream_id,
                prepared_response.value,
                push_stream_id,
                prepared_push,
                &self.qpack_encode,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
                absolute,
            );
        } else {
            try sendConnectionPush(
                &self.established.connection,
                &self.push_send_scratch,
                &self.critical_stream_send_scratch,
                self.options,
                self.control.settings.peer,
                request_stream_id,
                prepared_response.value,
                push_stream_id,
                prepared_push,
                &self.qpack_encode,
                &self.qpack_encoder_send,
                &self.qpack_encoder_prefix_sent,
            );
        }
        _ = try self.established.connection
            .requestCompletedLocalStreamRelease(push_stream_id);
        self.promised_push_ids.insertAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;
        finishServerRequest(&self.control, &self.request_lifecycle, request_stream_id);
        self.control.retirePushPriority(
            self.established.connection.endpoint.allocator,
            push.push_id,
        );
        return push_stream_id;
    }

    pub fn startResponse(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.startResponseInternalUntil(
            stream_id,
            response,
            body_length,
            false,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn startResponseWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(
            stream_id,
            response,
            body_length,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send a streaming response head under one absolute deadline. The same
    /// budget covers SETTINGS/QPACK progress, pacing, and flow-control waits.
    pub fn startResponseWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        while (true) {
            self.startResponseInternalUntil(
                stream_id,
                response,
                body_length,
                false,
                deadline,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    if (self.established.connection.closed()) return err;
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    fn startResponseInternalUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        trailers_pending: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
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
                server_control_stream_id,
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
                server_control_stream_id,
            );
        }
        self.stream_send_scratch.reset();
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.options.auto_date_header,
                self.established.connection.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(
            self.established.connection.endpoint.allocator,
        );
        const qpack_checkpoint = self.qpack_encode.checkpoint();
        const streaming = try prepared.value.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.established.connection.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.rollbackAfter(qpack_checkpoint);
        if (deadline) |absolute| {
            try sendConnectionStreamingHeadWithDeadline(
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
                absolute,
            );
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
            );
        }
        if (!streaming.body_allowed or
            (!trailers_pending and streaming.expected_length == 0))
        {
            finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        }
    }

    fn tryStartResponseLiteral(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        release_received: usize,
    ) Error!void {
        try self.requireEndpointCriticalStreamsReady();
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.established.connection.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.options.auto_date_header,
                self.established.connection.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(
            self.established.connection.endpoint.allocator,
        );
        if (prepared.value.suppressesBody()) {
            return error.InvalidContentLength;
        }
        try self.outbound_bodies.reserveOpen(stream_id);
        const next_offset = try trySendConnectionResponseLiteral(
            &self.established.connection,
            &self.stream_send_scratch,
            stream_id,
            prepared.value,
            self.control.settings.peer,
            false,
            release_received,
        );
        var body_send = quic.stream_state.SendState.init(stream_id);
        body_send.next_offset = next_offset;
        self.outbound_bodies.appendOpenAssumeCapacity(
            stream_id,
            body_send,
            null,
        );
    }

    fn requireEndpointCriticalStreamsReady(
        self: HandshakeServerSession,
    ) Error!void {
        if (!self.control.settings.sent or
            !self.qpack_encoder_prefix_sent or
            !self.qpack_decoder_prefix_sent)
        {
            return error.MissingSettings;
        }
    }

    pub fn sendResponseBody(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
        }
        try sendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
        if (fin) finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    /// Submit one complete response DATA contribution in one QUIC packet,
    /// without waiting for pacing or reading the connection socket.
    pub fn trySendResponseBody(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (try self.finishPeerResponseCancellationOnce(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
        }
        try trySendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
        if (fin) {
            finishServerRequest(
                &self.control,
                &self.request_lifecycle,
                stream_id,
            );
        }
    }

    /// Commit at most one STREAM fragment of a retained DATA contribution.
    /// The same payload and cursor resume partial framing after backpressure.
    pub fn tryWriteResponseBody(self: *HandshakeServerSession, stream_id: u62, data: []const u8, fin: bool, state: *BodyWriteState) Error!void {
        if (!state.complete) {
            if (try self.finishPeerResponseCancellationOnce(stream_id)) |cancel| return responseResetError(cancel.application_error_code);
        }
        try body_fragment.write(&self.established.connection, &self.outbound_bodies, stream_id, data, fin, state, self.options);
        if (state.complete and fin) finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    /// Submit several borrowed response slices as one DATA contribution and
    /// one QUIC packet without waiting or reading the shared endpoint socket.
    /// Failure is transactional for HTTP/3 body and QUIC stream state.
    pub fn trySendResponseBodyParts(
        self: *HandshakeServerSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        if (try self.finishPeerResponseCancellationOnce(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
        }
        try trySendConnectionBodyParts(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            parts,
            fin,
            self.options,
        );
        if (fin) {
            finishServerRequest(
                &self.control,
                &self.request_lifecycle,
                stream_id,
            );
        }
    }

    /// Send response DATA while driving the receive side when QUIC
    /// backpressure says the peer must first ACK or extend flow-control
    /// credit.
    ///
    /// The plain `sendResponseBody` API intentionally exposes
    /// `CongestionLimited`/`FlowControlBlocked` for event-loop integrations
    /// that already own their writable scheduling. This helper is the blocking
    /// counterpart for simple runtimes and benchmarks: it processes
    /// request-side packets, preserving ACK/MAX_* progress, then retries the
    /// same small DATA chunk.
    pub fn sendResponseBodyPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.sendResponseBodyPacedUntil(
            stream_id,
            data,
            fin,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseBodyPacedWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyPacedWithDeadline(
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

    /// Send one response DATA sequence under one absolute deadline. Progress
    /// reports the exact socket-visible application prefix and FIN state, so a
    /// caller can continue only the unsent suffix after a timeout.
    pub fn sendResponseBodyPacedWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        _ = try paced_body.write(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, data, fin, deadline, progress, paced_response_hooks);
    }

    const paced_response_hooks = .{ .before = beforePacedResponseBody, .receive = receivePacedResponseBody, .finish = finishPacedResponseBody };

    fn beforePacedResponseBody(self: *HandshakeServerSession, id: u62, _: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!bool {
        if (try self.finishPeerResponseCancellation(id)) |cancel| return responseResetError(cancel.application_error_code);
        return false;
    }
    fn receivePacedResponseBody(self: *HandshakeServerSession, _: u62, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        try self.receiveRequestPacketUntil(deadline);
    }
    fn finishPacedResponseBody(self: *HandshakeServerSession, id: u62) ReceiveTimeoutError!void {
        finishServerRequest(&self.control, &self.request_lifecycle, id);
    }

    fn sendResponseBodyPacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        var progress: BodyWriteProgress = .{};
        _ = try paced_body.write(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, data, fin, deadline, &progress, paced_response_hooks);
    }

    /// Send one logical Extended CONNECT byte sequence as packet-sized HTTP/3
    /// DATA contributions. Each contribution spans caller-slice boundaries
    /// when capacity permits, avoiding both a plaintext join and one transport
    /// submission per application slice. The cursor advances only after a
    /// successful send, retaining the normal paced retry behavior.
    pub fn sendResponseBodyPartsPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        var progress: BodyWriteProgress = .{};
        _ = paced_body.writeParts(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, parts, fin, null, &progress, paced_response_hooks) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn sendResponseBodyPartsPacedWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyPartsPacedWithDeadline(
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

    /// Send borrowed response slices under one absolute deadline without
    /// joining them. Progress is the exact socket-visible byte prefix across
    /// all slices, allowing the caller to retry only the remaining suffix.
    pub fn sendResponseBodyPartsPacedWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        _ = try paced_body.writeParts(&self.established.connection, &self.outbound_bodies, self.options, self, stream_id, parts, fin, deadline, progress, paced_response_hooks);
    }

    /// Batched counterpart to `sendResponseBodyPaced` for concurrent response
    /// streams. Each contribution becomes one QUIC packet and the socket-visible
    /// prefix commits atomically into the corresponding body stream states.
    pub fn sendResponseBodyBatchPaced(
        self: *HandshakeServerSession,
        chunks: []const BodyChunk,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try sendConnectionBodyBatchPaced(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeServerSession.receiveBatchProgressForSend,
            HandshakeServerSession.finishBatchResponseStream,
        );
    }

    pub fn sendResponseBodyBatchPacedWithTimeout(
        self: *HandshakeServerSession,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_chunks.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyBatchPacedWithDeadline(
            chunks,
            committed_chunks,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send one DATA contribution per response stream under one caller-owned
    /// deadline. `committed_chunks` is the exact socket-visible input prefix
    /// and remains valid on timeout or a socket error.
    pub fn sendResponseBodyBatchPacedWithDeadline(
        self: *HandshakeServerSession,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_chunks.* = 0;
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return sendConnectionBodyBatchPacedWithDeadline(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeServerSession.receiveBatchProgressForSendUntil,
            HandshakeServerSession.finishBatchResponseStream,
            committed_chunks,
            deadline,
        );
    }

    /// Send complete response bodies using RFC 9218 request priorities.
    ///
    /// This is the multi-stream blocking counterpart to
    /// `sendResponseBodyPaced`. The scheduler evaluates current QUIC credit
    /// before each packet pass, gives a received PRIORITY_UPDATE precedence
    /// over the request's Priority field, serializes non-incremental responses
    /// by stream ID, and round-robins incremental peers. Processing packets
    /// between blocked passes also makes live priority updates affect the next
    /// unsent DATA packet rather than only future API calls.
    pub fn sendResponseBodiesPaced(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.sendResponseBodiesPacedUntil(
            responses,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseBodiesPacedWithTimeout(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
        committed_bytes: []usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (committed_bytes.len < responses.len) return error.BufferTooShort;
        @memset(committed_bytes[0..responses.len], 0);
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodiesPacedWithDeadline(
            responses,
            committed_bytes,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Priority-schedule complete response bodies under one absolute deadline.
    /// Each `committed_bytes[index]` value is updated only after the
    /// corresponding DATA packet is accepted by the socket and remains valid
    /// on every error return.
    pub fn sendResponseBodiesPacedWithDeadline(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
        committed_bytes: []usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (committed_bytes.len < responses.len) return error.BufferTooShort;
        @memset(committed_bytes[0..responses.len], 0);
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponseBodiesPacedUntil(
            responses,
            committed_bytes,
            deadline,
        );
    }

    fn sendResponseBodiesPacedUntil(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
        committed_bytes: ?[]usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (responses.len == 0) return;
        const allocator =
            self.established.connection.endpoint.allocator;
        var workspace: response_scheduler.Workspace(
            quic.one_rtt.max_batch_packets,
        ) = .{};
        try workspace.init(allocator, responses.len);
        defer workspace.deinit(allocator);
        const candidates = workspace.candidates();

        for (responses, 0..) |response, index| {
            const body = self.outbound_bodies.find(response.stream_id) orelse
                return error.UnexpectedStream;
            var staged = body.*;
            try self.outbound_bodies.prepareChunkForEntry(
                &staged,
                response.data.len,
                true,
            );
            if (!workspace.registerResponse(index, response.stream_id)) {
                return error.UnexpectedStream;
            }
        }

        var remaining_responses = responses.len;
        for (responses) |response| {
            if (response.data.len == 0) remaining_responses -= 1;
        }
        // Empty fixed-length bodies are normally closed by startResponse.
        // Reject an accidental open zero-length body rather than spinning
        // without a DATA contribution that can carry FIN.
        if (remaining_responses != responses.len) {
            return error.InvalidFrame;
        }

        const chunk_limit = pacedBodyChunkLimit(self.options);
        const max_batch_packets = response_scheduler.batchPacketLimit(
            self.options.response_scheduler_max_batch_packets,
            quic.one_rtt.max_batch_packets,
        );
        var next_stream: usize = 0;
        var delay_budget = response_scheduler.DelayBudget{};
        while (remaining_responses != 0) {
            if (deadline) |absolute| {
                _ = try deadline_policy.usableAwake(
                    self.connectionIo(),
                    absolute,
                );
            }
            const selection = self.refreshResponseCandidates(
                responses,
                candidates,
                chunk_limit,
            ) orelse {
                try self.receiveRequestPacketUntil(deadline);
                continue;
            };

            workspace.stageSelected(
                responses,
                selection,
                next_stream,
                chunk_limit,
                max_batch_packets,
            );
            if (workspace.chunks().len == 0) {
                try self.receiveRequestPacketUntil(deadline);
                continue;
            }

            const progress = sendConnectionBodyBatchPacedProgress(
                &self.established.connection,
                &self.outbound_bodies,
                workspace.chunks(),
                self.options,
                self,
                HandshakeServerSession.finishBatchResponseStream,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                error.PacingLimited => {
                    if (deadline) |absolute| {
                        try self.established.connection
                            .waitForPacingAvailabilityWithDeadline(absolute);
                    } else {
                        try self.established.connection
                            .waitForPacingAvailability();
                    }
                    continue;
                },
                else => return err,
            };
            if (committed_bytes) |counts| {
                for (workspace.chunks()[0..progress.sent_count], 0..) |chunk, batch_index| {
                    const response_index = workspace.responseIndex(batch_index);
                    counts[response_index] += chunk.data.len;
                }
            }
            const commit = workspace.commitSentPrefix(progress.sent_count);
            remaining_responses -= commit.completed_responses;
            delay_budget.record(commit.body_bytes, progress.sent_count);
            if (progress.send_error) |err| return err;
            if (remaining_responses != 0 and
                self.options.response_scheduler_batch_delay_ns != 0 and
                delay_budget.due(
                    self.options.response_scheduler_batch_delay_bytes,
                    self.options.response_scheduler_batch_delay_packets,
                ))
            {
                const delay_ns = std.math.cast(
                    i64,
                    self.options.response_scheduler_batch_delay_ns,
                ) orelse std.math.maxInt(i64);
                try sleepResponseSchedulerDelayUntil(
                    self.connectionIo(),
                    delay_ns,
                    deadline,
                );
                delay_budget.reset();
            }
            if (selection.exclusive_index == null) {
                // Rotate only incremental passes. An exclusive stream retains
                // ownership until completion unless it becomes blocked or a
                // live PRIORITY_UPDATE changes the selected class.
                next_stream = (commit.last_response_index.? + 1) %
                    responses.len;
            }
        }
    }

    fn refreshResponseCandidates(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
        candidates: []response_scheduler.Candidate,
        chunk_limit: usize,
    ) ?response_scheduler.Selection {
        std.debug.assert(responses.len == candidates.len);
        var selection: response_scheduler.SelectionAccumulator = .{};
        const quic_connection = &self.established.connection;
        const connection_available = std.math.cast(
            usize,
            quic_connection.connectionSendAvailable(),
        ) orelse std.math.maxInt(usize);
        const congestion_available = quic_connection.congestionAvailable();
        const max_datagram_size = quic_connection.currentSendDatagramSize();
        for (responses, candidates, 0..) |response, *candidate, index| {
            const offset = candidate.offset;
            const remaining = response.data.len - offset;
            const stream_available = std.math.cast(
                usize,
                quic_connection.streamSendAvailable(
                    response.stream_id,
                ),
            ) orelse std.math.maxInt(usize);
            candidate.* = .{
                .stream_id = response.stream_id,
                .offset = offset,
                .remaining = remaining,
                .send_capacity = responseBodySendCapacity(
                    remaining,
                    connection_available,
                    stream_available,
                    congestion_available,
                    max_datagram_size,
                    chunk_limit,
                ),
                .priority = self.effectiveResponsePriority(
                    response.stream_id,
                ),
            };
            selection.consider(candidate.*, index);
        }
        return selection.result();
    }

    fn effectiveResponsePriority(
        self: HandshakeServerSession,
        stream_id: u62,
    ) http3.Priority {
        return self.request_lifecycle.priority(stream_id);
    }

    fn receiveBatchProgressForSend(
        self: *HandshakeServerSession,
    ) Error!void {
        try self.receiveRequestPacket();
    }

    fn receiveBatchProgressForSendUntil(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.receiveRequestPacketUntil(deadline);
    }

    fn finishBatchResponseStream(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) void {
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    fn sendResponseBodyPacedChunk(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        return self.sendResponseBodyPacedChunkUntil(
            stream_id,
            data,
            fin,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn sendResponseBodyPacedChunkUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        while (true) {
            if (deadline) |absolute| {
                if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
                    return responseResetError(cancel.application_error_code);
                }
                sendConnectionBodyChunkWithDeadline(
                    &self.established.connection,
                    &self.outbound_bodies,
                    stream_id,
                    data,
                    fin,
                    self.options,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    else => |other| return other,
                };
                if (fin) finishServerRequest(
                    &self.control,
                    &self.request_lifecycle,
                    stream_id,
                );
                return;
            }
            self.sendResponseBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    pub fn finishResponseTrailers(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
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
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    /// Submit response trailers without waiting for pacing or reading UDP.
    /// Static QPACK encoding and stream state commit only after the one-packet
    /// send succeeds, so an endpoint loop may retry after dispatcher progress.
    pub fn tryFinishResponseTrailers(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (try self.finishPeerResponseCancellationOnce(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
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
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    /// Wait until the peer cancels the response direction of `stream_id`.
    ///
    /// The request itself can already be complete: closing an unread response
    /// body sends STOP_SENDING, not RESET_STREAM, so it must be observed from
    /// the local QUIC send state. Packets for unrelated request streams remain
    /// routed while this blocking convenience method waits.
    pub fn receivePeerResponseCancellation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!PeerResponseCancellation {
        return self.receivePeerResponseCancellationUntil(
            stream_id,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receivePeerResponseCancellationWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PeerResponseCancellation {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerResponseCancellationWithDeadline(
            stream_id,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Wait for peer STOP_SENDING under one absolute deadline. Cancellation
    /// delivery registers stream retirement without waiting for a paced
    /// MAX_STREAMS update; the connection timer completes that retry.
    pub fn receivePeerResponseCancellationWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PeerResponseCancellation {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receivePeerResponseCancellationUntil(
            stream_id,
            deadline,
        );
    }

    fn receivePeerResponseCancellationUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PeerResponseCancellation {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        while (true) {
            const cancellation = if (deadline != null)
                try self.finishPeerResponseCancellationOnce(stream_id)
            else
                try self.finishPeerResponseCancellation(stream_id);
            if (cancellation) |cancel| {
                return cancel;
            }
            try self.receiveRequestPacketUntil(deadline);
        }
    }

    fn finishPeerResponseCancellation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?PeerResponseCancellation {
        const code = self.peerResponseCancellationCode(stream_id) orelse return null;
        // Do the only fallible cleanup first. If sending MAX_STREAMS is
        // temporarily blocked, the caller can retry without losing the
        // cancellation or partially retiring HTTP/3 bookkeeping.
        _ = try self.established.connection.releaseCompletedPeerStream(
            stream_id,
        );
        _ = self.outbound_bodies.finish(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        return .{
            .stream_id = stream_id,
            .application_error_code = code,
        };
    }

    /// Cancellation cleanup for event-loop send attempts. Stream retirement
    /// is registered for timer-driven retry so this path cannot wait for
    /// pacing while reporting that the response direction was cancelled.
    fn finishPeerResponseCancellationOnce(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?PeerResponseCancellation {
        const code = self.peerResponseCancellationCode(stream_id) orelse return null;
        _ = try self.established.connection.requestCompletedPeerStreamRelease(
            stream_id,
        );
        _ = self.outbound_bodies.finish(stream_id);
        finishServerRequest(
            &self.control,
            &self.request_lifecycle,
            stream_id,
        );
        return .{
            .stream_id = stream_id,
            .application_error_code = code,
        };
    }

    fn peerResponseCancellationCode(self: *HandshakeServerSession, id: u62) ?u64 {
        return self.request_lifecycle.peerResponseCancellation(id) orelse
            if (self.established.connection.streamStopped(id)) |stopped| stopped.application_error_code else null;
    }

    /// Blocking counterpart to `finishResponseTrailers` that keeps receiving
    /// request-side packets until the response trailers can be written.
    pub fn finishResponseTrailersPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return self.finishResponseTrailersPacedUntil(
            stream_id,
            trailers,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn finishResponseTrailersPacedWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseTrailersPacedWithDeadline(
            stream_id,
            trailers,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Finish a streaming response with trailers under one absolute deadline.
    /// A timeout before any packet is visible is retryable; a timeout after a
    /// multi-packet QPACK/trailer prefix uses the packetizer's fail-closed rule.
    pub fn finishResponseTrailersPacedWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.finishResponseTrailersPacedUntil(
            stream_id,
            trailers,
            deadline,
        );
    }

    fn finishResponseTrailersPacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        while (true) {
            if (deadline) |absolute| {
                if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
                    return responseResetError(cancel.application_error_code);
                }
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
                        try self.receiveRequestPacketUntil(deadline);
                        continue;
                    },
                    else => |other| return other,
                };
                finishServerRequest(
                    &self.control,
                    &self.request_lifecycle,
                    stream_id,
                );
                return;
            }
            self.finishResponseTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    pub fn sendResponseWithInformational(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        return self.sendResponseWithInformationalUntil(
            stream_id,
            informational,
            response,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseWithInformationalAndTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithInformationalAndDeadline(
            stream_id,
            informational,
            response,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithInformationalAndDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponseWithInformationalUntil(
            stream_id,
            informational,
            response,
            deadline,
        );
    }

    fn sendResponseWithInformationalUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendCompleteResponseUntil(stream_id, informational, response, deadline);
    }

    pub fn sendGoAway(self: *HandshakeServerSession, stream_id: u64) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try validateServerGoAwayStreamId(stream_id);
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
            server_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    pub fn sendGoAwayWithTimeout(
        self: *HandshakeServerSession,
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
        self: *HandshakeServerSession,
        stream_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try validateServerGoAwayStreamId(stream_id);
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
            server_control_stream_id,
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

    /// Submit GOAWAY once without waiting for pacing or reading UDP. Promoted
    /// endpoint sessions retry after dispatcher progress.
    pub fn trySendGoAway(
        self: *HandshakeServerSession,
        stream_id: u64,
    ) Error!void {
        try validateServerGoAwayStreamId(stream_id);
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

    /// Advertise RFC 9412 origins on the server control stream. Clients must
    /// still validate certificate authority before coalescing requests.
    pub fn sendOrigins(
        self: *HandshakeServerSession,
        origins: []const []const u8,
    ) Error!void {
        return self.sendOriginsUntil(origins, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendOriginsWithTimeout(
        self: *HandshakeServerSession,
        origins: []const []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendOriginsWithDeadline(
            origins,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendOriginsWithDeadline(
        self: *HandshakeServerSession,
        origins: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendOriginsUntil(origins, deadline);
    }

    fn sendOriginsUntil(
        self: *HandshakeServerSession,
        origins: []const []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
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
                server_control_stream_id,
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
                server_control_stream_id,
            );
        }
        const previous_sent = self.control.local_origin_set_sent;
        errdefer self.control.local_origin_set_sent = previous_sent;
        self.critical_stream_send_scratch.reset();
        try self.control.writeOrigins(
            &self.critical_stream_send_scratch.payload,
            self.established.connection.endpoint.allocator,
            origins,
        );
        const previous_send = self.control_send;
        errdefer self.control_send = previous_send;
        try self.control_send.appendFrames(
            &self.critical_stream_send_scratch.frames,
            self.established.connection.endpoint.allocator,
            self.critical_stream_send_scratch.payload.items,
            self.options.max_stream_frame_data,
            false,
        );
        if (deadline) |absolute| {
            try sendConnectionFramesWithDeadline(
                &self.established.connection,
                self.critical_stream_send_scratch.frames.items,
                self.options.max_frames_per_packet,
                absolute,
            );
        } else {
            try sendConnectionFrames(
                &self.established.connection,
                self.critical_stream_send_scratch.frames.items,
                self.options.max_frames_per_packet,
            );
        }
    }

    /// Submit one complete RFC 9412 ORIGIN frame without waiting for pacing
    /// or reading UDP. The advertisement marker and control-stream offset are
    /// committed only after the packet reaches the socket.
    pub fn trySendOrigins(
        self: *HandshakeServerSession,
        origins: []const []const u8,
    ) Error!void {
        try self.requireEndpointCriticalStreamsReady();
        const previous_sent = self.control.local_origin_set_sent;
        errdefer self.control.local_origin_set_sent = previous_sent;
        self.critical_stream_send_scratch.reset();
        try self.control.writeOrigins(
            &self.critical_stream_send_scratch.payload,
            self.established.connection.endpoint.allocator,
            origins,
        );
        const previous_send = self.control_send;
        errdefer self.control_send = previous_send;
        try self.control_send.appendFrames(
            &self.critical_stream_send_scratch.frames,
            self.established.connection.endpoint.allocator,
            self.critical_stream_send_scratch.payload.items,
            self.options.max_stream_frame_data,
            false,
        );
        if (self.critical_stream_send_scratch.frames.items.len >
            @max(@as(usize, 1), self.options.max_frames_per_packet) or
            try self.established.connection.packetLenForFramesAtOffset(
                0,
                self.critical_stream_send_scratch.frames.items,
            ) > self.established.connection.currentSendDatagramSize())
        {
            return error.DatagramTooLarge;
        }
        try self.established.connection.trySend(
            self.critical_stream_send_scratch.frames.items,
        );
    }

    pub fn initiateShutdown(self: *HandshakeServerSession) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.request_lifecycle.state() != .active) return;
        try self.sendGoAway(@as(u64, quic.varint.max_value) & ~@as(u64, 0x3));
        self.request_lifecycle.markInitialGoAwaySent();
    }

    pub fn initiateShutdownWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.initiateShutdownWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn initiateShutdownWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.request_lifecycle.state() != .active) return;
        try self.sendGoAwayWithDeadline(
            @as(u64, quic.varint.max_value) & ~@as(u64, 0x3),
            deadline,
        );
        self.request_lifecycle.markInitialGoAwaySent();
    }

    pub fn tryInitiateShutdown(
        self: *HandshakeServerSession,
    ) Error!void {
        if (self.request_lifecycle.state() != .active) return;
        try self.trySendGoAway(
            @as(u64, quic.varint.max_value) & ~@as(u64, 0x3),
        );
        self.request_lifecycle.markInitialGoAwaySent();
    }

    pub fn completeShutdown(self: *HandshakeServerSession) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (self.pending_response_cancellations.items.len != 0 or
            !self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAway(try self.request_lifecycle.finalGoAwayId());
        self.request_lifecycle.markFinalGoAwaySent();
    }

    pub fn completeShutdownWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.completeShutdownWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn completeShutdownWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (self.pending_response_cancellations.items.len != 0 or
            !self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAwayWithDeadline(
            try self.request_lifecycle.finalGoAwayId(),
            deadline,
        );
        self.request_lifecycle.markFinalGoAwaySent();
    }

    pub fn tryCompleteShutdown(
        self: *HandshakeServerSession,
    ) Error!void {
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (!self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.trySendGoAway(try self.request_lifecycle.finalGoAwayId());
        self.request_lifecycle.markFinalGoAwaySent();
    }

    pub fn drainComplete(self: HandshakeServerSession) bool {
        return self.pending_response_cancellations.items.len == 0 and self.request_lifecycle.drainComplete(
            self.request_streams.lowestStream(),
            self.streaming_requests.lowestEntryStream(),
            self.streaming_requests.lowestResetStream(),
            self.control.local_goaway_id,
        );
    }

    pub fn cancelRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        defer if (!self.request_lifecycle.contains(stream_id) and
            !self.request_streams.contains(stream_id) and
            !self.streaming_requests.contains(stream_id))
        {
            _ = self.pending_request_failures.take(stream_id);
        };
        return self.cancelRequestInternal(
            stream_id,
            application_error_code,
            false,
        );
    }

    pub fn cancelRequestWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelRequestWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Cancel RESET_STREAM and STOP_SENDING under one caller-owned deadline.
    /// Backpressure drives only this connection's ACK/loss/PTO owner; before
    /// socket submission the request and QPACK cancellation stay retryable.
    pub fn cancelRequestWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        defer if (!self.request_lifecycle.contains(stream_id) and
            !self.request_streams.contains(stream_id) and
            !self.streaming_requests.contains(stream_id))
        {
            _ = self.pending_request_failures.take(stream_id);
        };
        return cancelHandshakeRequestWithDeadline(
            self,
            stream_id,
            application_error_code,
            deadline,
        );
    }

    /// Cancel one request without waiting for transport pacing. Endpoint-wide
    /// protocol adapters retry this after dispatcher progress so they retain a
    /// single UDP receive owner and never sleep inside packet routing.
    pub fn tryCancelRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        defer if (!self.request_lifecycle.contains(stream_id) and
            !self.request_streams.contains(stream_id) and
            !self.streaming_requests.contains(stream_id))
        {
            _ = self.pending_request_failures.take(stream_id);
        };
        return self.cancelRequestInternalOnce(
            stream_id,
            application_error_code,
            false,
        );
    }

    fn cancelRequestInternal(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
        decoded_dynamic_section: bool,
    ) Error!void {
        const cancel_qpack = decoded_dynamic_section or self.qpack_decode.table.max_capacity != 0;
        defer {
            self.request_streams.remove(stream_id);
            self.streaming_requests.remove(stream_id);
            finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
            _ = self.outbound_bodies.finish(stream_id);
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
        _ = try self.established.connection.requestCompletedPeerStreamRelease(stream_id);
    }

    pub fn cancelRequestInternalOnce(
        self: *HandshakeServerSession,
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
        self.request_streams.remove(stream_id);
        self.streaming_requests.remove(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        _ = try self.established.connection.requestCompletedPeerStreamRelease(stream_id);
    }

    fn abandonCompleteResponse(self: *HandshakeServerSession, id: u62) void {
        if (!self.request_lifecycle.contains(id)) return;
        var pending = complete_response.Cancellation{ .stream_id = id };
        self.tryCancelRequest(id, http3.ApplicationErrorCode.internal_error) catch {
            pending.needs_cancel = self.request_lifecycle.contains(id);
        };
        if (!self.request_lifecycle.contains(id)) pending.needs_cancel = false;
        const release_ready = !pending.needs_cancel and
            (self.established.connection.requestCompletedPeerStreamRelease(id) catch false);
        if (!release_ready and !self.established.connection.closed()) self.pending_response_cancellations.appendAssumeCapacity(pending);
        self.request_streams.remove(id);
        self.streaming_requests.remove(id);
        _ = self.pending_request_failures.take(id);
        finishServerRequest(&self.control, &self.request_lifecycle, id);
        _ = self.outbound_bodies.finish(id);
    }

    pub fn flushResponseCancellations(self: *HandshakeServerSession) void {
        var index: usize = 0;
        while (index < self.pending_response_cancellations.items.len) {
            const pending = &self.pending_response_cancellations.items[index];
            if (pending.needs_cancel) {
                self.tryCancelRequest(pending.stream_id, http3.ApplicationErrorCode.internal_error) catch {
                    pending.needs_cancel = self.request_lifecycle.contains(pending.stream_id);
                    index += 1;
                    continue;
                };
                pending.needs_cancel = false;
            }
            if (!(self.established.connection.requestCompletedPeerStreamRelease(pending.stream_id) catch false)) {
                index += 1;
                continue;
            }
            _ = self.pending_response_cancellations.swapRemove(index);
        }
    }

    pub fn rejectRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try self.cancelRequest(
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
        );
    }

    pub fn rejectRequestWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectRequestWithDeadline(
            stream_id,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn rejectRequestWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.cancelRequestWithDeadline(
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
            deadline,
        );
    }

    /// Stop and retire the request direction after a complete final response
    /// has already closed the response direction. Late STREAM/RESET frames are
    /// retained by QUIC for final-size validation but no longer re-enter the
    /// HTTP/3 request queues.
    pub fn finishRejectedRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        return self.finishRejectedRequestUntil(stream_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn finishRejectedRequestWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRejectedRequestWithDeadline(
            stream_id,
            .fromNow(self.connectionIo(), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Bound the STOP_SENDING, receive-credit return and QPACK feedback that
    /// follow a rejected CONNECT or error response. A timeout before socket
    /// submission leaves the request, streaming reader and receive half
    /// untouched so the caller can retry the identical rejection cleanup.
    pub fn finishRejectedRequestWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.finishRejectedRequestUntil(stream_id, deadline);
    }

    fn finishRejectedRequestUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        const exists = self.request_lifecycle.contains(stream_id) or
            self.request_streams.contains(stream_id) or
            self.streaming_requests.contains(stream_id) or
            self.outbound_bodies.find(stream_id) != null;
        if (!exists) return error.UnexpectedStream;
        const cancel_qpack = self.qpack_decode.table.max_capacity != 0;
        if (self.streaming_requests.find(stream_id)) |entry| {
            if (deadline) |absolute| {
                try message_data.releaseCapacityWithDeadline(
                    &self.established.connection,
                    &entry.reader,
                    absolute,
                );
            } else {
                try releaseStreamingReaderCapacity(
                    &self.established.connection,
                    &entry.reader,
                );
            }
        }
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
            try self.qpack_decode.recordStreamCancellation(stream_id);
        }
        self.request_streams.remove(stream_id);
        self.streaming_requests.remove(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        if (deadline) |absolute| {
            try self.sendQpackFeedbackWithDeadline(absolute);
        } else {
            try self.sendQpackFeedback();
        }
    }

    /// Release local request bookkeeping after a final non-success response
    /// has closed the response direction. No RESET_STREAM or STOP_SENDING is
    /// emitted; callers use `cancelRequest` when peer-visible cancellation is
    /// required.
    pub fn finishRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        const exists = self.request_lifecycle.contains(stream_id) or
            self.request_streams.contains(stream_id) or
            self.streaming_requests.contains(stream_id) or
            self.outbound_bodies.find(stream_id) != null;
        if (!exists) return error.UnexpectedStream;
        self.request_streams.remove(stream_id);
        self.streaming_requests.remove(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn receiveRequestPacket(self: *HandshakeServerSession) Error!void {
        return self.receiveRequestPacketUntil(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn receiveRequestPacketUntil(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.receiveAttachedConnectDatagramPacket(deadline);
        // Encoder-stream inserts and reset cancellations both queue decoder
        // instructions. Flush them at the packet boundary so a peer does not
        // remain artificially blocked until another HEADERS event appears.
        if (deadline) |absolute| {
            try self.flushRequestPacketFeedbackWithDeadline(absolute);
        } else {
            try self.flushRequestPacketFeedback();
        }
    }

    pub fn receiveAttachedConnectDatagramProgress(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return ConnectDatagramProgress.run(self, null, deadline, @as(?*connect_datagram.ReceiveIntoTarget, null));
    }

    fn receiveAttachedConnectDatagramPacket(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline) |absolute| {
            try self.receive_packets.visitWithDeadline(
                &self.established.connection,
                absolute,
                self,
                visitStreamingServerRequestPacket,
            );
        } else {
            try self.receive_packets.visit(
                &self.established.connection,
                self,
                visitStreamingServerRequestPacket,
            );
        }
    }

    fn flushRequestPacketFeedback(self: *HandshakeServerSession) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    fn flushRequestPacketFeedbackWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.qpack_decode.pendingDecoderInstructions().len == 0) return;
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

    /// Process one transport packet for control-stream progress without
    /// requiring a complete application request to become ready.
    pub fn pollControl(self: *HandshakeServerSession) Error!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        try self.receiveRequestPacket();
    }

    pub fn pollControlWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestPacketUntil(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn pollControlWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveRequestPacketUntil(deadline);
    }

    /// Drive ACK, loss, PTO, flow-control, and HTTP/3 control processing until
    /// every packet required to deliver the completed response has been
    /// acknowledged. Pure MAX_DATA/MAX_STREAMS updates remain under QUIC's
    /// normal recovery timer but do not prolong a short-lived server whose
    /// final application data is already safe.
    /// Response writers return after socket submission so persistent servers
    /// do not pay an ACK round trip per response; short-lived owners should
    /// drain before destroying the session so a dropped final DATA/FIN remains
    /// recoverable. Incoming request bytes stay routed to their normal queues.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForRecoveryIdleWithDeadline(.fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *HandshakeServerSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        while (self.established.connection.pendingDeliveryRecovery()) {
            try self.receiveRequestPacketUntil(deadline);
        }
    }

    pub fn waitForStreamRecoveryIdleWithTimeout(self: *HandshakeServerSession, stream_id: u62, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForStreamRecoveryIdleWithDeadline(stream_id, .fromNow(self.connectionIo(), .{ .raw = timeout, .clock = .awake }));
    }

    /// Wait only for the selected stream's submitted DATA/FIN/RESET delivery.
    /// Other requests remain routed while ACK, loss and PTO processing runs.
    pub fn waitForStreamRecoveryIdleWithDeadline(self: *HandshakeServerSession, stream_id: u62, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (self.dispatcher_bound) return error.InvalidDispatcherState;
        return @import("stream/recovery.zig").wait(ReceiveTimeoutError, self, stream_id, deadline, HandshakeServerSession.receiveRequestPacketUntil);
    }

    fn applyStreamingRequestEvent(
        self: *HandshakeServerSession,
        entry: *StreamingRequestSet.Entry,
        event: StreamingEvent,
        single_attempt: bool,
    ) Error!StreamingRequestEvent {
        const stream_id = entry.reader.streamId();
        const from = entry.from orelse unreachable;
        // Capture provenance before a finished event can release and compact
        // a stream whose response send half is already acknowledged.
        const was_early_data = self.established.connection
            .recvStreamReceivedEarlyData(stream_id);
        if (try streamingRequestSectionAcknowledgments(event)) |count| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                stream_id,
                count,
            );
            if (single_attempt)
                self.flushRequestPacketFeedbackOnce() catch {}
            else
                self.sendQpackFeedback() catch {};
        }
        if (event == .head) {
            serverRequestReceivedAssumeCapacity(
                &self.control,
                &self.request_lifecycle,
                stream_id,
                switch (event) {
                    .head => |head| switch (head) {
                        .request => |request| requestPriority(
                            request.headers,
                        ),
                        .response => .{},
                    },
                    else => .{},
                },
            );
        } else if (event == .finished) {
            _ = try self.established.connection
                .requestCompletedPeerStreamRelease(stream_id);
            self.streaming_requests.remove(stream_id);
        }
        return .{ .message = .{
            .from = from,
            .stream_id = stream_id,
            .was_early_data = was_early_data,
            .value = event,
        } };
    }

    fn releaseStreamingRequestCapacity(
        self: *HandshakeServerSession,
    ) Error!void {
        var index: usize = 0;
        while (self.streaming_requests.entryAt(index)) |entry| : (index += 1) {
            if (entry.message_failure_pending) continue;
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    fn releaseStreamingRequestCapacityOnce(
        self: *HandshakeServerSession,
    ) Error!bool {
        var index: usize = 0;
        while (self.streaming_requests.entryAt(index)) |entry| : (index += 1) {
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

    pub fn connectionIo(self: *const HandshakeServerSession) std.Io {
        return self.established.connection.endpoint.io;
    }

    fn sendQpackFeedback(self: *HandshakeServerSession) Error!void {
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
        self: *HandshakeServerSession,
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

    fn flushRequestPacketFeedbackOnce(
        self: *HandshakeServerSession,
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

    pub const ConcurrentStream = HandshakeConcurrentEngine.Stream;

    /// Continuously accept request streams, run one handler task per stream,
    /// and serialize every session mutation through this owner. Handlers may
    /// start a streaming response and emit DATA/trailers with `ConcurrentStream`.
    pub fn serveConcurrentStreams(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *ConcurrentStream,
        ) anyerror!void,
        options: concurrent.Options,
    ) anyerror!concurrent.Summary {
        var engine = HandshakeConcurrentEngine.init(
            self,
            self.established.connection.endpoint.allocator,
            self.connectionIo(),
            options,
        );
        defer engine.deinit();
        return engine.serve(HandlerContext, context, handler);
    }
};
