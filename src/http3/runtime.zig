const std = @import("std");
const round_robin = @import("../internal/round_robin.zig");
const deadline_policy = @import("../internal/deadline.zig");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");
const body_batch = @import("runtime/body_batch.zig");
const client_uri = @import("runtime/client/uri.zig");
const connect_datagram = @import("runtime/datagram.zig");
const connect_datagram_routing = @import("runtime/datagram/routing.zig");
const development_datagram_queue =
    @import("runtime/development/datagram_queue.zig");
const development_send = @import("runtime/development/send.zig");
const development_receive = @import("runtime/development/receive.zig");
const development_message = @import("runtime/development/message.zig");
const development_request_buffer =
    @import("runtime/development/request_buffer.zig");
const development_server_peer =
    @import("runtime/development/server_peer/state.zig");
const handshake_client_pool = @import("runtime/handshake_client_pool.zig");
const runtime_error = @import("runtime/error.zig");
const server_response = @import("runtime/server/response.zig");
const body_sender = @import("runtime/send/body.zig");
const message_sender = @import("runtime/send/message.zig");
const send_packetizer = @import("runtime/send/packetizer.zig");
const protected_send_module = @import("runtime/send/protected.zig");
const send_scratch = @import("runtime/send/scratch.zig");
const receive_cursor = @import("runtime/receive/cursor.zig");
const receive_connection_error =
    @import("runtime/receive/connection_error.zig");
const request_routing = @import("runtime/receive/routing/request.zig");
const response_routing = @import("runtime/receive/routing/response.zig");
const response_scheduler = @import("runtime/response_scheduler/core.zig");
const control_receive = @import("runtime/control/receive.zig");
const control_sender = @import("runtime/control/send.zig");
const stream_lifecycle = @import("runtime/stream/lifecycle.zig");
const buffered_common = @import("runtime/stream/buffered/common.zig");
const buffered_request = @import("runtime/stream/buffered/request.zig");
const buffered_response = @import("runtime/stream/buffered/response.zig");
const outbound_body = @import("runtime/stream/outbound_body.zig");
const stream_reader = @import("runtime/stream/reader.zig");
const streaming_set = @import("runtime/stream/set.zig");
const stream_events = @import("runtime/stream/events.zig");
const push_state = @import("runtime/stream/push/state.zig");
const push_aggregate = @import("runtime/stream/push/aggregate.zig");

const net = std.Io.net;

// The cleartext runtime intentionally has no HTTP/3 control stream. Its
// historical aggregate codec accepts Extended CONNECT, so its incremental
// parser must model that same capability instead of the default disabled
// SETTINGS value. Dynamic QPACK remains disabled by the zero-capacity state.
const development_settings: http3.Settings = .{
    .enable_connect_protocol = true,
};

const development_streams = @import("runtime/development/streams.zig");

pub const DevelopmentStream = development_streams.Stream;
pub const DevelopmentStreamDirection = development_streams.Direction;
pub const DevelopmentStreamMatch = development_streams.Match;
pub const DevelopmentEndpointRole = development_streams.EndpointRole;
pub const DevelopmentStreamDebugCounts = development_streams.DebugCounts;

const DevelopmentStreamSet = development_streams.ReceiveSet;
const DevelopmentStreamSendSet = development_streams.SendSet;
const DevelopmentPeerStreamSendSet = development_streams.PeerSendSet;
const DevelopmentRequestStreamSet = development_request_buffer.Set;
const RuntimeAssembledStream = development_request_buffer.AssembledStream;
pub const OwnedRequest = development_message.OwnedRequest;
pub const OwnedRequestBatch = development_message.OwnedRequestBatch;
pub const ConcurrentServeResult = OwnedRequestBatch;
pub const OwnedResponse = development_message.OwnedResponse;
const DevelopmentServerPeerSet = development_server_peer.Set;
const developmentStreamDirection = development_streams.direction;
const developmentStreamMayBelongTo = development_streams.mayBelongTo;
const webtransport_bidi_stream_type =
    development_streams.webtransport_bidi_stream_type;

pub const InformationalResponseHead = http3.InformationalResponseHead;
pub const InformationalObserver = http3.InformationalObserver;

/// Reports a callback-scoped informational response together with the request
/// stream selected by `receiveNextResponseWithInformational`. The header
/// fields borrow decoder storage and must not be retained after the callback.
pub const MultiplexedInformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        stream_id: u62,
        response: InformationalResponseHead,
    ) void,
};

/// Reports a callback-scoped pushed informational response with every identity
/// needed to correlate it to both the PUSH_PROMISE and its QUIC stream.
pub const PushInformationalObserver = push_aggregate.InformationalObserver;

const MultiplexedInformationalContext = struct {
    observer: MultiplexedInformationalObserver,
    stream_id: u62,

    fn notify(
        context: *anyopaque,
        response: InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.observer.on_response(
            self.observer.context,
            self.stream_id,
            response,
        );
    }
};

pub const Error = runtime_error.Error;
pub const HandshakeWorkerError = runtime_error.HandshakeWorkerError;
pub const HandshakeAdmissionError = runtime_error.HandshakeAdmissionError;
pub const ReceiveTimeoutError = runtime_error.ReceiveTimeoutError;
pub const OwnedConnectDatagram = connect_datagram.Owned;
pub const ShutdownState = stream_lifecycle.ShutdownState;
pub const GoAwayRetryDisposition = stream_lifecycle.GoAwayRetryDisposition;

const ClientRequestLifecycle = stream_lifecycle.Client;
const ServerRequestLifecycle = stream_lifecycle.Server;
const RequestStreamSet = buffered_request.Set;
const ResponseStreamSet = buffered_response.Set;
const OutboundBodySet = outbound_body.Set;
const AssembledStream = buffered_common.AssembledStream;
pub const StreamingHead = stream_reader.Head;
pub const StreamingEvent = stream_reader.Event;
pub const StreamingMessageReader = stream_reader.Reader;
pub const StreamingRequestEvent = stream_events.Request;
pub const StreamingResponseEvent = stream_events.Response;
pub const PeerResponseCancellation = stream_events.PeerResponseCancellation;
const StreamingMessageSet = streaming_set.Set;
const StreamingRequestSet = streaming_set.Set;
const StreamingResponseSet = streaming_set.Set;
const PushStreamSet = push_state.Set;
const ControlStreamRole = control_receive.ControlStreamRole;
const ServerRequestIdValidator = control_receive.ServerRequestIdValidator;
const MessageStreamDisposition = control_receive.MessageStreamDisposition;
const validateServerGoAwayStreamId = control_receive.validateServerGoAwayStreamId;
const validateClientGoAwayPushId = control_receive.validateClientGoAwayPushId;
const validateNewServerPush = control_receive.validateNewServerPush;
const rejectByLocalGoAway = control_receive.rejectByLocalGoAway;
const configureQpackEncoderFromPeerSettings =
    control_receive.configureQpackEncoderFromPeerSettings;
const isPeerQpackStreamFrame = control_receive.isPeerQpackStreamFrame;
const applyControlStreamFrameForRole =
    control_receive.applyControlStreamFrameForRole;
const applyControlStreamFrameForRoleWithPushes =
    control_receive.applyControlStreamFrameForRoleWithPushes;
const peekUniStreamType = control_receive.peekUniStreamType;
const applyControlStreamFrame = control_receive.applyControlStreamFrame;
const applyControlStreamFrameValidated =
    control_receive.applyControlStreamFrameValidated;
const isRegisteredCriticalStream = control_receive.isRegisteredCriticalStream;
const rejectCriticalStreamClosureFrame =
    control_receive.rejectCriticalStreamClosureFrame;
const rejectClosedCriticalStream = control_receive.rejectClosedCriticalStream;
const messageStreamDisposition = control_receive.messageStreamDisposition;
const ControlFrameKind = control_sender.ControlFrameKind;
const PushControlFrameKind = control_sender.PushControlFrameKind;
const controlFramesInto = control_sender.controlFramesInto;
const sendConnectionControlFrame = control_sender.sendConnectionControlFrame;
const sendConnectionPushControl = control_sender.sendConnectionPushControl;
const sendConnectionPriorityUpdate = control_sender.sendConnectionPriorityUpdate;
const sendConnectionPriorityUpdateRaw =
    control_sender.sendConnectionPriorityUpdateRaw;
const sendProtectedControlFrame = control_sender.sendProtectedControlFrame;
const sendProtectedPushControl = control_sender.sendProtectedPushControl;
const sendProtectedPriorityUpdate = control_sender.sendProtectedPriorityUpdate;
const sendProtectedPriorityUpdateRaw =
    control_sender.sendProtectedPriorityUpdateRaw;
const sendConnectionSettings = control_sender.sendConnectionSettings;
const sendConnectionQpackEncoderInstructions =
    control_sender.sendConnectionQpackEncoderInstructions;
const sendConnectionQpackFeedback = control_sender.sendConnectionQpackFeedback;
const cancelConnectionRequest = control_sender.cancelConnectionRequest;
const sendProtectedSettings = control_sender.sendProtectedSettings;
const sendProtectedQpackEncoderInstructions =
    control_sender.sendProtectedQpackEncoderInstructions;
const sendProtectedQpackFeedback = control_sender.sendProtectedQpackFeedback;
const sendProtectedRequestCancellation =
    control_sender.sendProtectedRequestCancellation;
const writeDataFrame = body_sender.writeDataFrame;
const pacedBodyChunkLimit = body_sender.pacedBodyChunkLimit;
const responseBodySendCapacity = body_sender.responseBodySendCapacity;
const pacedProtectedBodyChunkLimit = body_sender.pacedProtectedBodyChunkLimit;
const sendConnectionBodyChunk = body_sender.sendConnectionBodyChunk;
const sendConnectionBodyBatchPaced = body_sender.sendConnectionBodyBatchPaced;
const sendConnectionBodyBatchPacedProgress =
    body_sender.sendConnectionBodyBatchPacedProgress;
const sendProtectedBodyBatchPaced = body_sender.sendProtectedBodyBatchPaced;
const sendProtectedBodyBatchProgress =
    body_sender.sendProtectedBodyBatchProgress;
const sendProtectedBodyChunk = body_sender.sendProtectedBodyChunk;
const sendConnectionMessage = message_sender.sendConnectionMessage;
const sendConnectionResponseSequence =
    message_sender.sendConnectionResponseSequence;
const sendProtectedMessage = message_sender.sendProtectedMessage;
const sendProtectedResponseSequence =
    message_sender.sendProtectedResponseSequence;
const encodePushMessages = message_sender.encodePushMessages;
const sendConnectionPush = message_sender.sendConnectionPush;
const sendProtectedPush = message_sender.sendProtectedPush;
const sendConnectionStreamingHead = message_sender.sendConnectionStreamingHead;
const sendProtectedStreamingHead = message_sender.sendProtectedStreamingHead;
const sendConnectionTrailers = message_sender.sendConnectionTrailers;
const sendProtectedTrailers = message_sender.sendProtectedTrailers;
const RequestStreamReset = request_routing.RequestStreamReset;
const requestResetError = request_routing.requestResetError;
const serverRequestReceived = request_routing.serverRequestReceived;
const prepareServerRequestReceived =
    request_routing.prepareServerRequestReceived;
const serverRequestReceivedAssumeCapacity =
    request_routing.serverRequestReceivedAssumeCapacity;
const finishServerRequest = request_routing.finishServerRequest;
const reconcileServerRequestPriorities =
    request_routing.reconcileServerRequestPriorities;
const applyServerRequestPacketFrames =
    request_routing.applyServerRequestPacketFrames;
const closeConnectionForHttp3Error =
    receive_connection_error.closeConnection;
const sendProtectedHttp3Close =
    receive_connection_error.sendProtectedClose;
const messageStreamErrorCode = runtime_error.messageStreamErrorCode;
const messageUsesDynamicQpack = buffered_common.messageUsesDynamicQpack;

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: *ProtectedSendState,
) Error!void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

const ensureConnectDatagramsNegotiated =
    connect_datagram_routing.ensureNegotiated;

fn receiveConnectDatagramFromSession(
    session: anytype,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!OwnedConnectDatagram {
    while (true) {
        if (try session.pollConnectDatagram(stream_id)) |datagram| {
            return datagram;
        }
        if (deadline) |absolute| {
            if (@TypeOf(session) == *HandshakeServerSession) {
                try session.receiveDetachedRequestProgressWithDeadline(
                    stream_id,
                    absolute,
                );
            } else {
                try session.receiveDetachedResponseProgressWithDeadline(
                    stream_id,
                    absolute,
                );
            }
        } else {
            if (@TypeOf(session) == *HandshakeServerSession) {
                try session.receiveDetachedRequestProgress(stream_id);
            } else {
                try session.receiveDetachedResponseProgress(stream_id);
            }
        }
    }
}

const observeConnectDatagramTerminal = connect_datagram_routing.observeTerminal;
const ensureConnectDatagramSendSideOpen =
    connect_datagram_routing.ensureSendSideOpen;
const connectDatagramTerminalError = connect_datagram_routing.terminalError;
const pollConnectDatagramRegistry = connect_datagram_routing.poll;
const drainConnectDatagrams = connect_datagram_routing.drain;

/// Replay HTTP DATAGRAM frames in their authenticated QUIC packet order. The
/// transport queue itself is intentionally connection-wide and does not retain
/// ordering metadata relative to RESET_STREAM/FIN, so adapters must mark the
/// affected association as soon as a terminal stream frame is crossed. A later
/// DATAGRAM in that same packet is then dropped by `Registry.route`, while a
/// preceding one remains queued for delivery.
const routeConnectDatagramsFromPacket = connect_datagram_routing.routePacket;

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;
const first_server_push_stream_id: u62 = 15;

const StreamMessageSendScratch = send_scratch.Message;
const PushSendScratch = send_scratch.Push;
const CriticalStreamSendScratch = send_scratch.Critical;
const sendRuntimeStreamMessage = development_send.streamMessage;
const retainDevelopmentDatagramFrames = development_send.retainDatagramFrames;
const sendRuntimeStreamingHead = development_send.streamingHead;
const sendRuntimeStreamingHeadAtOffset = development_send.streamingHeadAtOffset;
const sendRuntimeResponsePrefix = development_send.responsePrefix;
const sendRuntimeRequestCancellation = development_send.requestCancellation;
const sendRuntimeBodyChunk = development_send.bodyChunk;
const appendRuntimeStreamMessageFrames =
    development_send.appendStreamMessageFrames;
const receiveRuntimeStreamBytes = development_receive.streamBytes;
const receiveRuntimeStreamBytesUntil = development_receive.streamBytesUntil;

pub const UriEndpoint = client_uri.Endpoint;
pub const UriRequestOptions = client_uri.RequestOptions;
pub const uriEndpoint = client_uri.parseEndpoint;
pub const uriRequestTargetAlloc = client_uri.requestTargetAlloc;

const connectDeadline = client_uri.connectDeadline;
const cappedConnectDeadline = client_uri.cappedConnectDeadline;
const resolveEndpointBefore = client_uri.resolveEndpointBefore;
const resolveHostPortAddressesBefore =
    client_uri.resolveHostPortAddressesBefore;
const handshakeRecoveryBefore = client_uri.handshakeRecoveryBefore;

const ProtectedSendState = protected_send_module.State;
const ConnectionPacketCursor = receive_cursor.Connection;
const ProtectedPacketCursor = receive_cursor.Protected;
const packetView = receive_cursor.packetView;

pub const Limits = struct {
    quic: quic.runtime.Limits = .{},
    /// Add a current IMF-fixdate `date` field to cleartext-development server
    /// final responses that do not already contain one.
    auto_date_header: bool = true,
    /// Maximum bytes buffered while reassembling one HTTP/3 request/response
    /// stream in the cleartext development runtime.  Protected/handshake
    /// runtimes already expose this via their session options; keeping the
    /// cleartext path explicit prevents large STREAM offsets from turning the
    /// UDP frame endpoint into an unbounded message buffer.
    max_stream_buffer: usize = 64 * 1024,
    /// Maximum request streams retained concurrently by server runtimes.
    /// This bounds both incomplete interleaved streams and complete streams
    /// waiting for the application or a QPACK Required Insert Count.
    max_concurrent_request_streams: usize = 128,
    /// Maximum payload bytes per QUIC STREAM frame emitted by the cleartext
    /// development runtime.  Keeping this separate from UDP datagram size lets
    /// tests and callers exercise normal HTTP/3 body fragmentation like tquic's
    /// `send_body` path instead of requiring one whole message to fit in a
    /// single UDP frame datagram.
    max_stream_frame_data: usize = 1200,
    /// Development-runtime retained raw QUIC datagram count.
    ///
    /// Streaming request/response readers in this lightweight runtime own the
    /// shared UDP socket. Packets that also carry QUIC DATAGRAM frames must be
    /// retained here after their STREAM/RESET frames are parsed so protocol
    /// adapters such as WebTransport can later observe the datagram without
    /// racing the socket or losing mixed packets.
    max_queued_runtime_datagrams: usize = 16,
    /// Development-runtime retained raw QUIC datagram byte budget.
    ///
    /// The queue owns whole parsed UDP packets, not only DATAGRAM payloads, so
    /// the byte limit is charged against each retained packet's raw receive
    /// storage. Oldest-drop semantics match QUIC DATAGRAM unreliability and
    /// prevent a slow adapter from turning the shared reader into an unbounded
    /// packet cache.
    max_queued_runtime_datagram_bytes: usize = 64 * 1024,
    /// Maximum number of 1xx response heads accepted on one request or push
    /// stream before the final response. The bound applies in aggregate and
    /// incremental modes even when the application ignores those heads. This
    /// is configurable rather than quic-go's hard-coded limit of five.
    max_informational_responses: usize =
        http3.default_max_informational_responses,
};

/// One incremental event from a server-initiated push stream.
///
/// Push ID and QUIC stream ID are intentionally both exposed: the former
/// correlates the response with PUSH_PROMISE/CANCEL_PUSH, while the latter is
/// the QPACK section-acknowledgment and transport flow-control identity.
pub const StreamingPushEvent = push_state.PushEvent;

pub const PushedResponse = push_aggregate.Response;
const ClientPushAggregateState = push_aggregate.State;

pub const ServerPush = message_sender.ServerPush;

const qpack_state = @import("runtime/qpack/state.zig");

pub const QpackDecodeState = qpack_state.QpackDecodeState;
pub const QpackEncodeState = qpack_state.QpackEncodeState;

pub const Server = struct {
    quic_server: quic.runtime.Server,
    limits: Limits = .{},
    /// Serializes ownership of the UDP receive loop. It is deliberately not
    /// held while a response is sent, so an accept waiter cannot block an
    /// established session's outbound control traffic.
    request_receive_mutex: std.Io.Mutex = .init,
    /// Protects the per-peer parser, lifecycle, and retained-DATAGRAM state.
    /// Receive loops take this only while polling or applying one packet.
    peer_state_mutex: std.Io.Mutex = .init,
    request_streams: DevelopmentRequestStreamSet,
    /// The development endpoint may receive stream zero from many peers. Each
    /// peer therefore owns an independent HTTP/3 parser/lifecycle namespace;
    /// keying only by stream ID would merge unrelated clients.
    streaming_peers: DevelopmentServerPeerSet,
    /// Raw extension streams share the request receive loop. Keeping their
    /// reassembly here prevents WebTransport from becoming a second UDP
    /// reader and preserves peer identity for identical stream IDs.
    development_streams: DevelopmentStreamSet,
    development_stream_sends: DevelopmentPeerStreamSendSet,
    runtime_datagrams: DevelopmentRetainedDatagramQueue,
    /// Monotonic development-runtime mode flag. Both reads and writes are
    /// protected by `peer_state_mutex`; receive ownership alone is not enough
    /// because response and nonblocking poll APIs may inspect it concurrently.
    streaming_mode: bool = false,
    response_send_mutex: std.Io.Mutex = .init,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        var quic_server = try quic.runtime.Server.bind(
            allocator,
            io,
            bind_address,
            limits.quic,
        );
        errdefer quic_server.deinit();
        return .{
            .quic_server = quic_server,
            .limits = limits,
            .request_streams = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_peers = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .development_streams = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .development_stream_sends = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .runtime_datagrams = .init(
                allocator,
                limits.max_queued_runtime_datagrams,
                limits.max_queued_runtime_datagram_bytes,
            ),
        };
    }

    pub fn deinit(self: *Server) void {
        self.runtime_datagrams.deinit();
        self.development_stream_sends.deinit();
        self.development_streams.deinit();
        self.streaming_peers.deinit();
        self.request_streams.deinit();
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *Server) Error!OwnedRequest {
        return self.receiveRequestInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Aggregate the next development-runtime request within one relative
    /// awake-clock budget. Any partial STREAM state remains owned by the
    /// server and can be completed by a later receive call.
    pub fn receiveRequestWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestWithDeadline(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Aggregate the next development-runtime request before `deadline`. The
    /// original absolute timestamp is reused for every datagram so unrelated
    /// traffic and fragmented STREAM frames cannot renew the caller's budget.
    pub fn receiveRequestWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedRequest {
        const absolute = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestInternal(absolute);
    }

    fn receiveRequestInternal(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedRequest {
        if (deadline != null) {
            // A bounded receive must not spend an unbounded interval behind
            // another task that currently owns the shared endpoint reader.
            if (!self.request_receive_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.request_receive_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
        }
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        {
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
            defer self.peer_state_mutex.unlock(
                self.quic_server.endpoint.io,
            );
            if (self.streaming_mode) return error.UnexpectedStream;
        }

        var ready = while (true) {
            if (try self.request_streams.prepareReady(
                self.quic_server.endpoint.allocator,
            )) |value| break value;
            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            var owned = true;
            defer if (owned) datagram.deinit(
                self.quic_server.endpoint.allocator,
            );
            if (try self.request_streams.insertDatagram(&datagram)) {
                owned = false;
            }
        };
        errdefer ready.deinit(self.quic_server.endpoint.allocator);
        var request = http3.decodeRequest(
            self.quic_server.endpoint.allocator,
            ready.bytes,
        ) catch |err| {
            if (err != error.OutOfMemory) {
                self.request_streams.discardReady(
                    ready.from,
                    ready.stream_id,
                );
            }
            return err;
        };
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        const from = ready.from;
        const stream_id = ready.stream_id;
        const owned_parts = self.request_streams.commitPreparedReady(&ready);
        return .{
            .from = from,
            .stream_id = stream_id,
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .request = request,
        };
    }

    /// Receive one event from the persistent cleartext request-stream parser.
    /// The first streaming receive adopts any aggregate-mode partial streams
    /// before it reads more UDP packets, so a timed-out aggregate receive does
    /// not strand its bytes when a protocol adapter takes over the endpoint.
    pub fn receiveRequestEvent(self: *Server) Error!StreamingRequestEvent {
        return self.receiveRequestEventInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveRequestEventWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventInternal(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveRequestEventWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestEventInternal(deadline);
    }

    /// Wait for the initial HEADERS of the next request without repeatedly
    /// surfacing unread DATA from already-active streams. Protocol adapters
    /// use this while accepting additional long-lived CONNECT sessions.
    pub fn receiveRequestHead(self: *Server) Error!StreamingRequestEvent {
        return self.receiveRequestHeadInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveRequestHeadWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestHeadInternal(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveRequestHeadWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestHeadInternal(deadline);
    }

    fn receiveRequestHeadInternal(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        try self.lockRequestReceive(deadline);
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        try self.enterStreamingMode();
        while (true) {
            const ready = blk: {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                break :blk self.streaming_peers.pollRequestHead();
            };
            if (try ready) |event| {
                return event;
            }
            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            defer datagram.deinit(self.quic_server.endpoint.allocator);
            {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                try self.processDevelopmentRequestDatagram(&datagram);
            }
        }
    }

    pub fn receiveRequestEventFor(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!StreamingRequestEvent {
        return self.receiveRequestEventForInternal(from, stream_id, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveRequestEventForWithTimeout(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventForInternal(from, stream_id, .fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveRequestEventForWithDeadline(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestEventForInternal(from, stream_id, deadline);
    }

    fn receiveRequestEventForInternal(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        try self.lockRequestReceive(deadline);
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        try self.enterStreamingMode();
        while (true) {
            const ready = blk: {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                break :blk self.streaming_peers.pollRequestEventFor(
                    from,
                    stream_id,
                );
            };
            if (try ready) |event| return event;
            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            defer datagram.deinit(self.quic_server.endpoint.allocator);
            {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                try self.processDevelopmentRequestDatagram(&datagram);
            }
        }
    }

    fn lockRequestReceive(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline != null) {
            if (!self.request_receive_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.request_receive_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
        }
    }

    /// Enter streaming mode while the caller owns `request_receive_mutex`.
    ///
    /// Aggregate receives retain partial request streams across deadlines. A
    /// later long-lived CONNECT adapter must be able to take over that same
    /// endpoint without either rejecting the call or abandoning those bytes.
    /// Transfer every aggregate receive state into the per-peer incremental
    /// parser before publishing the mode switch. The transfer is transactional
    /// under allocation failure, and `peer_state_mutex` owns both the flag and
    /// the destination parser state observed by response/poll APIs.
    fn enterStreamingMode(self: *Server) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        try self.streaming_peers.adoptBufferedRequests(&self.request_streams);
        self.streaming_mode = true;
    }

    fn receiveRequestEventInternal(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        try self.lockRequestReceive(deadline);
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        try self.enterStreamingMode();

        while (true) {
            const ready = blk: {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                break :blk self.streaming_peers.pollRequestEvent();
            };
            if (try ready) |event| {
                return event;
            }
            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            defer datagram.deinit(self.quic_server.endpoint.allocator);
            {
                self.peer_state_mutex.lockUncancelable(
                    self.quic_server.endpoint.io,
                );
                defer self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                try self.processDevelopmentRequestDatagram(&datagram);
            }
        }
    }

    /// Return an already-buffered request event without reading UDP.
    pub fn pollRequestEvent(self: *Server) Error!?StreamingRequestEvent {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        if (!self.streaming_mode) return null;
        return self.streaming_peers.pollRequestEvent();
    }

    /// Return one retained raw QUIC datagram without reading UDP.
    ///
    /// Development STREAM/Capsule readers remain the sole endpoint receive
    /// owner. Packets that also carry QUIC DATAGRAM frames are queued here
    /// after their stream frames are parsed so adapters such as WebTransport
    /// can observe datagrams without racing the socket or losing mixed-frame
    /// packets.
    pub fn pollDatagram(self: *Server) ?quic.runtime.OwnedDatagram {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        return self.runtime_datagrams.pop();
    }

    pub fn receiveDatagram(self: *Server) Error!quic.runtime.OwnedDatagram {
        return self.receiveDatagramInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveDatagramWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramInternal(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveDatagramInternal(deadline);
    }

    fn receiveDatagramInternal(
        self: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        try self.lockRequestReceive(deadline);
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        try self.enterStreamingMode();
        while (true) {
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
            if (self.runtime_datagrams.pop()) |datagram| {
                self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
                return datagram;
            }
            self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            defer datagram.deinit(self.quic_server.endpoint.allocator);
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
            defer self.peer_state_mutex.unlock(
                self.quic_server.endpoint.io,
            );
            try self.processDevelopmentRequestDatagram(&datagram);
        }
    }

    pub fn readRequestData(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        return self.streaming_peers.readRequestData(from, stream_id, out);
    }

    pub fn skipRequestData(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!usize {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        return self.streaming_peers.skipRequestData(from, stream_id);
    }

    fn processDevelopmentRequestDatagram(
        self: *Server,
        datagram: *const quic.runtime.OwnedDatagram,
    ) Error!void {
        for (datagram.frames) |frame| {
            if (frame == .reset_stream and
                (try messageStreamDisposition(
                    frame.reset_stream.stream_id,
                )) == .request_response)
            {
                const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
                // A reset for a stream that this peer never opened is not an
                // application event. In particular, do not let an unrelated
                // datagram consume one slot from the bounded request set.
                try self.streaming_peers.recordReset(
                    datagram.from,
                    stream_id,
                    frame.reset_stream.application_error_code,
                );
                continue;
            }
            if (frame != .stream) continue;
            const stream_id: u62 = std.math.cast(
                u62,
                frame.stream.stream_id,
            ) orelse return error.UnexpectedStream;
            if ((stream_id & 0x03) == 0x01 and
                self.development_stream_sends.sessionId(
                    datagram.from,
                    stream_id,
                ) != null)
            {
                // Reverse direction of a server-opened WT bidi stream has no
                // second association prefix and is known by its send entry.
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            if (stream_id % 4 == 0 and
                self.streaming_peers.containsRequest(
                    datagram.from,
                    stream_id,
                ))
            {
                try self.streaming_peers.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            // Non-request streams belong to extensions. A client-initiated
            // bidi ID is ambiguous until enough offset-zero bytes identify
            // either an H3 frame or the modern WT 0x41 association prefix.
            if (stream_id % 4 != 0) {
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            if (self.development_streams.contains(
                datagram.from,
                stream_id,
            )) {
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                switch (try self.development_streams
                    .classifyBidirectional(datagram.from, stream_id)) {
                    .incomplete, .webtransport => continue,
                    .other => {
                        var buffered = self.development_streams.takeEntry(
                            datagram.from,
                            stream_id,
                        ).?;
                        defer buffered.deinit();
                        // Once classified as HTTP/3, feed every contiguous
                        // byte range into its ordinary request reassembler.
                        try self.streaming_peers.insert(
                            datagram.from,
                            .{
                                .stream_id = stream_id,
                                .offset = buffered.receive.storage_offset,
                                .data = buffered.receive.buffer.items,
                                .fin = buffered.receive.final_size != null,
                            },
                        );
                        continue;
                    },
                }
            }
            if (frame.stream.offset != 0 or frame.stream.data.len == 0) {
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            const first = quic.varint.decodeSlice(frame.stream.data) catch |err|
                switch (err) {
                    error.BufferTooShort => {
                        try self.development_streams.insert(
                            datagram.from,
                            frame.stream,
                        );
                        continue;
                    },
                    else => return err,
                };
            if (first.value == webtransport_bidi_stream_type) {
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            if ((try messageStreamDisposition(
                frame.stream.stream_id,
            )) == .ignore) continue;
            try self.streaming_peers.insert(
                datagram.from,
                frame.stream,
            );
        }
        try retainDevelopmentDatagramFrames(
            &self.runtime_datagrams,
            datagram.*,
        );
    }

    /// Poll one FIN-complete extension stream for a peer/session without
    /// reading UDP. The caller supplies locally-opened bidi IDs so reverse
    /// directions can be recognized without an association prefix.
    pub fn pollDevelopmentStream(
        self: *Server,
        from: net.IpAddress,
        match: DevelopmentStreamMatch,
    ) Error!?DevelopmentStream {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        return self.development_streams.takeMatchingComplete(from, match);
    }

    pub fn closeDevelopmentSession(
        self: *Server,
        peer: net.IpAddress,
        match: DevelopmentStreamMatch,
    ) void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        self.development_streams.removeMatching(peer, match);
        self.development_stream_sends.removeMatching(
            peer,
            match.session_id,
        );
        self.retireDevelopmentPeerIfInactive(peer);
    }

    /// Reclaim connection-scoped extension state only after the peer has no
    /// request parser/lifecycle, response body, or associated-stream sender.
    /// Until that point the cursor is part of the live peer's QUIC stream-ID
    /// namespace and resetting it could collide with another active session.
    fn retireDevelopmentPeerIfInactive(
        self: *Server,
        peer: net.IpAddress,
    ) void {
        if (self.streaming_peers.peerHasOwnedState(peer)) return;
        if (self.streaming_peers.hasPeer(peer)) {
            // `unusable` records a prior socket-visible send failure, not live
            // protocol ownership. Once every state container is empty, keeping
            // that flag would retain this address and its cursor forever.
            self.streaming_peers.removePeer(peer);
        }
        if (self.development_stream_sends.hasPeerEntries(peer)) return;
        _ = self.development_stream_sends.retirePeer(peer);
        // A partial association prefix has no Session ID, so it cannot be
        // removed during ordinary session cleanup. Once both request and send
        // ownership prove the peer retired, no live session can claim it.
        self.development_streams.removePeer(peer);
    }

    pub fn developmentStreamDebugCounts(
        self: *Server,
        peer: net.IpAddress,
        session_id: u62,
    ) DevelopmentStreamDebugCounts {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        var sends: usize = 0;
        for (self.development_stream_sends.entries.items) |entry| {
            sends += @intFromBool(entry.to.eql(&peer) and
                entry.session_id == session_id);
        }
        var receives: usize = 0;
        var peer_receives: usize = 0;
        for (self.development_streams.entries.items) |entry| {
            if (!entry.from.eql(&peer)) continue;
            peer_receives += 1;
            const stream_id: u62 = @intCast(entry.receive.stream_id);
            receives += @intFromBool(developmentStreamMayBelongTo(
                entry.receive.available(),
                stream_id,
                .{
                    .session_id = session_id,
                    .local_role = .server,
                },
            ));
        }
        return .{
            .receives = receives,
            .sends = sends,
            .peer_receives = peer_receives,
        };
    }

    /// Atomically allocate the peer-scoped transport ID after the caller has
    /// preflighted its session registry. Holding one lock across selection and
    /// commit prevents concurrent CONNECT sessions from claiming the same ID.
    pub fn reserveDevelopmentStream(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        direction: DevelopmentStreamDirection,
    ) Error!u62 {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        if (!self.streaming_peers.hasPeer(to)) {
            return error.UnexpectedStream;
        }
        return self.development_stream_sends.reserve(
            to,
            session_id,
            direction,
        );
    }

    pub fn sendDevelopmentStream(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        var send_entry = self.development_stream_sends.findEntry(
            to,
            stream_id,
        );
        var opened_reverse = false;
        if (send_entry == null and (stream_id & 0x03) == 0) {
            // Reverse direction of a client-created bidirectional WT stream.
            try self.development_stream_sends.open(
                to,
                session_id,
                stream_id,
            );
            send_entry = self.development_stream_sends.findEntry(to, stream_id);
            opened_reverse = true;
        }
        if (self.development_stream_sends.sessionId(to, stream_id) !=
            session_id) return error.UnexpectedStream;
        const entry = send_entry orelse return error.UnexpectedStream;
        if (entry.unusable) return error.ConnectionUnusable;
        const state = &entry.send;
        const previous = state.*;
        var send_attempted = false;
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_server.endpoint.allocator);
        errdefer if (!send_attempted) {
            state.* = previous;
            if (opened_reverse) {
                self.development_stream_sends.removeLast(to, stream_id);
            }
        };
        state.appendFrames(
            &frames,
            self.quic_server.endpoint.allocator,
            data,
            self.limits.max_stream_frame_data,
            fin,
        ) catch |err| return err;
        send_packetizer.sendEndpoint(
            self.quic_server.endpoint.allocator,
            &self.quic_server.endpoint,
            to,
            frames.items,
            1,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) entry.unusable = true;
            return err;
        };
    }

    pub fn sendDevelopmentStreamParts(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        send_attempted: *bool,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        const entry = self.development_stream_sends.findEntry(
            to,
            stream_id,
        ) orelse return error.UnexpectedStream;
        if (entry.unusable) return error.ConnectionUnusable;
        const state = &entry.send;
        if (self.development_stream_sends.sessionId(to, stream_id) !=
            session_id) return error.UnexpectedStream;
        const previous = state.*;
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_server.endpoint.allocator);
        errdefer {
            if (!send_attempted.*) state.* = previous;
        }
        try state.appendFrames(
            &frames,
            self.quic_server.endpoint.allocator,
            prefix,
            self.limits.max_stream_frame_data,
            false,
        );
        try state.appendFrames(
            &frames,
            self.quic_server.endpoint.allocator,
            payload,
            self.limits.max_stream_frame_data,
            fin,
        );
        send_packetizer.sendEndpoint(
            self.quic_server.endpoint.allocator,
            &self.quic_server.endpoint,
            to,
            frames.items,
            1,
            send_attempted,
        ) catch |err| {
            if (send_attempted.*) entry.unusable = true;
            return err;
        };
    }

    pub fn receiveDevelopmentStream(
        self: *Server,
        from: net.IpAddress,
        match: DevelopmentStreamMatch,
    ) Error!DevelopmentStream {
        return self.receiveDevelopmentStreamInternal(from, match, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveDevelopmentStreamWithDeadline(
        self: *Server,
        from: net.IpAddress,
        match: DevelopmentStreamMatch,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!DevelopmentStream {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveDevelopmentStreamInternal(from, match, deadline);
    }

    pub fn receiveDevelopmentStreamWithTimeout(
        self: *Server,
        from: net.IpAddress,
        match: DevelopmentStreamMatch,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!DevelopmentStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDevelopmentStreamWithDeadline(
            from,
            match,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn receiveDevelopmentStreamInternal(
        self: *Server,
        from: net.IpAddress,
        match: DevelopmentStreamMatch,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!DevelopmentStream {
        try self.lockRequestReceive(deadline);
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);
        try self.enterStreamingMode();
        while (true) {
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
            const ready = self.development_streams.takeMatchingComplete(
                from,
                match,
            ) catch |err| {
                self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
                return err;
            };
            if (ready) |stream| {
                self.peer_state_mutex.unlock(
                    self.quic_server.endpoint.io,
                );
                return stream;
            }
            self.peer_state_mutex.unlock(self.quic_server.endpoint.io);

            var datagram = if (deadline) |absolute|
                try self.quic_server.receiveWithDeadline(absolute)
            else
                try self.quic_server.receive();
            defer datagram.deinit(self.quic_server.endpoint.allocator);
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
            defer self.peer_state_mutex.unlock(
                self.quic_server.endpoint.io,
            );
            try self.processDevelopmentRequestDatagram(&datagram);
        }
    }

    pub fn receiveRequestsConcurrent(self: *Server, count: usize) Error!OwnedRequestBatch {
        var group: std.Io.Group = .init;
        var batch = try OwnedRequestBatch.init(
            self.quic_server.endpoint.allocator,
            count,
        );
        errdefer batch.deinit();

        for (batch.requests, batch.errors) |*request, *err_slot| {
            const task = RequestTask{
                .server = self,
                .request = request,
                .err = err_slot,
            };
            group.async(self.quic_server.endpoint.io, RequestTask.run, .{task});
        }

        try group.await(self.quic_server.endpoint.io);
        return batch;
    }

    /// Receive, handle, and respond to exactly `count` requests with bounded
    /// concurrency. Each worker owns one request for the whole callback/send
    /// cycle, while the returned result retains that request so callers can
    /// correlate handler or transport failures with peer and stream metadata.
    ///
    /// The same `context` may be entered concurrently. Applications that
    /// mutate it must provide their own synchronization. The `OwnedRequest`
    /// passed by value is borrowed from the result: the handler must not
    /// deinitialize it or retain slices after the result is deinitialized.
    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!http3.Response,
        count: usize,
    ) Error!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        var result = try OwnedRequestBatch.init(
            self.quic_server.endpoint.allocator,
            count,
        );
        errdefer result.deinit();

        for (result.requests, result.errors) |*request, *err_slot| {
            const task = ServeRequestTask(HandlerContext){
                .server = self,
                .context = context,
                .handler = handler,
                .request = request,
                .err = err_slot,
            };
            group.async(
                self.quic_server.endpoint.io,
                ServeRequestTask(HandlerContext).run,
                .{task},
            );
        }

        try group.await(self.quic_server.endpoint.io);
        return result;
    }

    pub fn sendResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithInformational(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.limits.auto_date_header,
                self.quic_server.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(self.quic_server.endpoint.allocator);
        try http3.writeResponseSequence(
            &encoded,
            self.quic_server.endpoint.allocator,
            informational,
            prepared.value,
        );
        // A response may span several UDP datagrams. Keep its STREAM frames
        // contiguous on the shared development endpoint and protect mutable
        // send-interceptor state from concurrent serving workers.
        self.response_send_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        try sendRuntimeStreamMessage(&self.quic_server.endpoint, to, stream_id, encoded.items, self.limits.max_stream_frame_data);
    }

    /// Emit one informational response on an admitted streaming request. The
    /// next final response continues at the recorded stream offset.
    pub fn sendInformationalResponse(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.InformationalResponse,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const response_context = try peer.prepareInformational(
            stream_id,
            self.streaming_mode,
        );
        self.response_send_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        try response.writeDynamic(
            &response_context.scratch.encoded,
            self.quic_server.endpoint.allocator,
            development_settings,
            stream_id,
            response_context.qpack_encode,
        );
        sendRuntimeResponsePrefix(
            &self.quic_server.endpoint,
            to,
            response_context.scratch,
            stream_id,
            self.limits.max_stream_frame_data,
            response_context.response_send_offsets,
        ) catch |err| {
            peer.markSendFailed();
            return err;
        };
    }

    pub fn startResponse(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(
            self.quic_server.endpoint.io,
        );
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const response_context = try peer.prepareResponseHead(
            stream_id,
            self.streaming_mode,
        );
        self.response_send_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.limits.auto_date_header,
                self.quic_server.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(self.quic_server.endpoint.allocator);
        const streaming = try prepared.value.writeStreamingHeadDynamic(
            &response_context.scratch.encoded,
            self.quic_server.endpoint.allocator,
            development_settings,
            stream_id,
            body_length,
            response_context.qpack_encode,
        );
        // Successful Extended CONNECT keeps HTTP/3 DATA enabled even though
        // it intentionally has no Content-Length and remains open until the
        // adapted protocol closes it.
        const keep_extended_connect_open = prepared.value.extended_connect and
            prepared.value.status >= 200 and prepared.value.status < 300;
        const body_allowed = streaming.body_allowed or
            keep_extended_connect_open;
        const expected_length = if (keep_extended_connect_open)
            null
        else
            streaming.expected_length;
        const response_prefix_offset = peer.responsePrefixOffset(stream_id);
        errdefer peer.abandonEncodedResponse(stream_id);
        var send_attempted = false;
        sendRuntimeStreamingHeadAtOffset(
            &self.quic_server.endpoint,
            to,
            response_context.scratch,
            stream_id,
            response_prefix_offset,
            expected_length,
            body_allowed,
            self.limits.max_stream_frame_data,
            response_context.outbound_bodies,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) {
                peer.markSendFailed();
            } else {
                peer.discardResponseBody(stream_id);
            }
            return err;
        };
        peer.commitResponseHead(stream_id, body_allowed, expected_length);
    }

    pub fn sendResponseBody(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(
            self.quic_server.endpoint.io,
        );
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const outbound_bodies = try peer.prepareResponseBody(stream_id);
        self.response_send_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        var send_attempted = false;
        sendRuntimeBodyChunk(
            &self.quic_server.endpoint,
            to,
            outbound_bodies,
            stream_id,
            data,
            fin,
            self.limits.max_stream_frame_data,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) peer.markSendFailed();
            return err;
        };
        peer.commitResponseBody(stream_id, fin);
    }

    /// Abort both directions of a development request stream. If no response
    /// has started, the local final size is zero; otherwise the retained send
    /// state supplies the exact offset required by RESET_STREAM. Cleanup is
    /// committed before the control datagram is sent because a socket error
    /// cannot make a malformed application protocol stream usable again.
    pub fn cancelRequest(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(
            self.quic_server.endpoint.io,
        );
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const cancellation = try peer.cancelRequest(stream_id);
        sendRuntimeRequestCancellation(
            &self.quic_server.endpoint,
            to,
            stream_id,
            application_error_code,
            cancellation.local_final_size,
            cancellation.send_reset,
        ) catch |err| {
            self.retireDevelopmentPeerIfInactive(to);
            return err;
        };
        self.retireDevelopmentPeerIfInactive(to);
    }

    /// Retire a development request without emitting RESET_STREAM or
    /// STOP_SENDING. Protocol adapters use this after a final non-success
    /// response has already closed the response direction.
    pub fn finishRequest(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!void {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(
            self.quic_server.endpoint.io,
        );
        if (!self.streaming_peers.retireRequest(from, stream_id)) {
            return error.UnexpectedStream;
        }
        self.retireDevelopmentPeerIfInactive(from);
    }
};

const RequestTask = struct {
    server: *Server,
    request: *?OwnedRequest,
    err: *?anyerror,

    fn run(task: RequestTask) std.Io.Cancelable!void {
        task.request.* = task.server.receiveRequest() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

fn ServeRequestTask(comptime HandlerContext: type) type {
    return struct {
        server: *Server,
        context: *HandlerContext,
        handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!http3.Response,
        request: *?OwnedRequest,
        err: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            task.request.* = task.server.receiveRequest() catch |err| {
                task.err.* = err;
                return;
            };
            const request = task.request.*.?;
            var response = task.handler(task.context, request) catch |err| {
                task.err.* = err;
                return;
            };
            if (response.request_method == null) {
                response.request_method = request.request.method;
                response.extended_connect = requestHasProtocol(
                    request.request.headers,
                );
            }
            task.server.sendResponse(
                request.from,
                request.stream_id,
                response,
            ) catch |err| {
                task.err.* = err;
                return;
            };
            task.err.* = null;
        }
    };
}

pub const Client = struct {
    quic_client: quic.runtime.Client,
    limits: Limits = .{},
    next_stream_id: u62 = 0,
    response_receive_mutex: std.Io.Mutex = .init,
    response_streams: ResponseStreamSet,
    streaming_responses: StreamingResponseSet,
    development_streams: DevelopmentStreamSet,
    development_stream_sends: DevelopmentStreamSendSet,
    request_lifecycle: ClientRequestLifecycle,
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    outbound_bodies: OutboundBodySet,
    runtime_datagrams: DevelopmentRetainedDatagramQueue,
    stream_send_scratch: StreamMessageSendScratch = .{},
    streaming_mode: bool = false,
    /// The development request API assembles a response in call-local state.
    /// Once a request has been committed to the wire, any subsequent failure
    /// can leave protocol progress or response ownership unavailable to a
    /// retry, so later requests fail closed instead of risking misassociation.
    request_unusable: bool = false,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits) Error!Client {
        var quic_client = try quic.runtime.Client.connect(
            allocator,
            io,
            local_address,
            server,
            limits.quic,
        );
        errdefer quic_client.deinit();
        return .{
            .quic_client = quic_client,
            .limits = limits,
            .response_streams = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                limits.max_concurrent_request_streams,
                limits.max_stream_buffer,
                limits.max_informational_responses,
                development_settings,
                .response,
            ),
            .development_streams = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .development_stream_sends = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .request_lifecycle = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .qpack_decode = .init(allocator, 0, limits.max_stream_buffer),
            .qpack_encode = .init(allocator, 0, limits.max_stream_buffer),
            .outbound_bodies = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .runtime_datagrams = .init(
                allocator,
                limits.max_queued_runtime_datagrams,
                limits.max_queued_runtime_datagram_bytes,
            ),
        };
    }

    pub fn deinit(self: *Client) void {
        self.development_stream_sends.deinit();
        self.development_streams.deinit();
        self.stream_send_scratch.deinit(self.quic_client.endpoint.allocator);
        self.runtime_datagrams.deinit();
        self.outbound_bodies.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.request_lifecycle.deinit();
        self.streaming_responses.deinit();
        self.response_streams.deinit();
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.quic_client.address();
    }

    pub fn request(self: *Client, request_options: http3.Request) Error!OwnedResponse {
        return self.requestWithInformational(request_options, null);
    }

    pub fn requestWithTimeout(
        self: *Client,
        request_options: http3.Request,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(request_options, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn requestWithDeadline(
        self: *Client,
        request_options: http3.Request,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedResponse {
        return self.requestWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
        );
    }

    /// Send a development-runtime request and report each borrowed 1xx head.
    pub fn requestWithInformational(
        self: *Client,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedResponse {
        return self.requestWithInformationalInternal(
            request_options,
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn requestWithInformationalAndTimeout(
        self: *Client,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Bound response receipt with one absolute awake-clock deadline. The
    /// deadline is validated before allocating a stream ID or sending bytes
    /// and rechecked before every UDP send plus every response receive. An
    /// individual UDP syscall still uses the endpoint's ordinary unbounded
    /// send path. A failure after the first send attempt makes this client
    /// unusable because response reassembly is intentionally call-local.
    pub fn requestWithInformationalAndDeadline(
        self: *Client,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedResponse {
        const absolute = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.requestWithInformationalInternal(
            request_options,
            informational,
            absolute,
        );
    }

    fn requestWithInformationalInternal(
        self: *Client,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedResponse {
        if (self.request_unusable) return error.ConnectionUnusable;
        if (self.streaming_mode) return error.UnexpectedStream;

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);

        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        try appendRuntimeStreamMessageFrames(
            &frames,
            self.quic_client.endpoint.allocator,
            stream_id,
            encoded.items,
            self.limits.max_stream_frame_data,
        );
        std.debug.assert(frames.items.len != 0);
        if (deadline) |absolute| {
            // Encoding and frame construction can allocate. Recheck the same
            // absolute budget before committing anything to the wire.
            _ = try deadline_policy.usableAwake(
                self.quic_client.endpoint.io,
                absolute,
            );
        }

        var committed = false;
        errdefer {
            if (committed) {
                self.next_stream_id = next_stream_id;
                self.request_unusable = true;
            }
        }
        try send_packetizer.sendEndpointUntil(
            self.quic_client.endpoint.allocator,
            &self.quic_client.endpoint,
            self.quic_client.peer,
            frames.items,
            1,
            &committed,
            deadline,
        );
        self.next_stream_id = next_stream_id;
        self.request_lifecycle.markAllocated(stream_id);
        std.debug.assert(committed);

        var assembled = try receiveRuntimeStreamBytesUntil(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            stream_id,
            self.limits.max_stream_buffer,
            deadline,
        );
        errdefer assembled.deinit(self.quic_client.endpoint.allocator);
        try http3.validateResponsePushPromises(.{}, assembled.bytes);
        var response = try http3.decodeResponseWithOptions(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            .{
                .max_informational_responses = self.limits.max_informational_responses,
                .informational = informational,
                .request_method = request_options.method,
                .extended_connect = requestHasProtocol(
                    request_options.headers,
                ),
            },
        );
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        const owned_parts = try assembled.intoOwnedParts(self.quic_client.endpoint.allocator);
        return .{
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .response = response,
        };
    }

    /// Start a persistent cleartext request stream. `body_length == null`
    /// leaves the message body FIN-delimited, which is required by long-lived
    /// development CONNECT-style protocols.
    pub fn startRequest(
        self: *Client,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        if (self.request_unusable) return error.ConnectionUnusable;
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        var send_attempted = false;
        errdefer {
            if (send_attempted) {
                // A failed UDP send cannot prove non-observation. Retire this
                // request ID and retain its stream state rather than risk
                // associating a later request with a late response.
                self.next_stream_id = next_stream_id;
                self.request_lifecycle.markAllocated(stream_id);
                self.streaming_mode = true;
            } else {
                _ = self.request_lifecycle.finish(stream_id) catch false;
                _ = self.outbound_bodies.finish(stream_id);
                self.qpack_encode.abandonStream(stream_id);
            }
        }
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.quic_client.endpoint.allocator,
            development_settings,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        sendRuntimeStreamingHead(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            &self.stream_send_scratch,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            self.limits.max_stream_frame_data,
            &self.outbound_bodies,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) {
                self.request_unusable = true;
            }
            return err;
        };
        self.next_stream_id = next_stream_id;
        self.request_lifecycle.markAllocated(stream_id);
        self.streaming_mode = true;
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *Client,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.request_unusable) return error.ConnectionUnusable;
        if (self.outbound_bodies.find(stream_id) == null) {
            return error.UnexpectedStream;
        }
        if (self.outbound_bodies.find(stream_id).?.send.fin_sent) {
            return error.UnexpectedStream;
        }
        var send_attempted = false;
        sendRuntimeBodyChunk(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.limits.max_stream_frame_data,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) self.request_unusable = true;
            return err;
        };
    }

    /// Reserve a client-initiated raw extension stream while sharing the
    /// bidirectional ID cursor with ordinary HTTP/3 requests. Unidirectional
    /// IDs begin after the three conventional HTTP/3 critical streams.
    pub fn openDevelopmentStream(
        self: *Client,
        session_id: u62,
        direction: DevelopmentStreamDirection,
    ) Error!u62 {
        if (self.request_unusable) return error.ConnectionUnusable;
        const stream_id: u62 = switch (direction) {
            .bidirectional => self.next_stream_id,
            .unidirectional => blk: {
                var next: u62 = 14;
                for (self.development_stream_sends.entries.items) |entry| {
                    const id: u62 = @intCast(entry.send.stream_id);
                    if ((id & 0x03) == 0x02 and id >= next) {
                        next = std.math.add(u62, id, 4) catch
                            return error.StreamCreationError;
                    }
                }
                break :blk next;
            },
        };
        try self.development_stream_sends.prepareOpen(stream_id);
        if (direction == .bidirectional) {
            const next = std.math.add(u62, stream_id, 4) catch
                return error.StreamCreationError;
            self.development_stream_sends.commitPreparedOpen(
                session_id,
                stream_id,
            );
            self.next_stream_id = next;
            self.request_lifecycle.markAllocated(stream_id);
        } else {
            self.development_stream_sends.commitPreparedOpen(
                session_id,
                stream_id,
            );
        }
        return stream_id;
    }

    /// Atomic counterpart used by protocol adapters after capacity-only
    /// registry preflight. Client request and extension streams share one bidi
    /// cursor, so selection and commit remain inside this method.
    pub fn reserveDevelopmentStream(
        self: *Client,
        session_id: u62,
        direction: DevelopmentStreamDirection,
    ) Error!u62 {
        return self.openDevelopmentStream(session_id, direction);
    }

    /// Send raw stream bytes at the retained offset. Offset/FIN state commits
    /// before the first UDP send because a socket error cannot prove that an
    /// earlier fragment was invisible to the peer.
    pub fn sendDevelopmentStream(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        var send_entry = self.development_stream_sends.findEntry(stream_id);
        var opened_reverse = false;
        if (send_entry == null and (stream_id & 0x03) == 0x01) {
            // Reverse direction of a server-created bidirectional WT stream.
            try self.development_stream_sends.open(session_id, stream_id);
            send_entry = self.development_stream_sends.findEntry(stream_id);
            opened_reverse = true;
        }
        if (self.development_stream_sends.sessionId(stream_id) !=
            session_id) return error.UnexpectedStream;
        const entry = send_entry orelse return error.UnexpectedStream;
        if (entry.unusable) return error.ConnectionUnusable;
        const state = &entry.send;
        const previous = state.*;
        var send_attempted = false;
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        errdefer if (!send_attempted) {
            state.* = previous;
            if (opened_reverse) {
                self.development_stream_sends.removeLast(stream_id);
            }
        };
        state.appendFrames(
            &frames,
            self.quic_client.endpoint.allocator,
            data,
            self.limits.max_stream_frame_data,
            fin,
        ) catch |err| return err;
        send_packetizer.sendEndpoint(
            self.quic_client.endpoint.allocator,
            &self.quic_client.endpoint,
            self.quic_client.peer,
            frames.items,
            1,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) entry.unusable = true;
            return err;
        };
    }

    pub fn sendDevelopmentStreamParts(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        send_attempted: *bool,
    ) Error!void {
        const entry = self.development_stream_sends.findEntry(stream_id) orelse
            return error.UnexpectedStream;
        if (entry.unusable) return error.ConnectionUnusable;
        const state = &entry.send;
        if (self.development_stream_sends.sessionId(stream_id) !=
            session_id) return error.UnexpectedStream;
        const previous = state.*;
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        errdefer {
            if (!send_attempted.*) state.* = previous;
        }
        try state.appendFrames(
            &frames,
            self.quic_client.endpoint.allocator,
            prefix,
            self.limits.max_stream_frame_data,
            false,
        );
        try state.appendFrames(
            &frames,
            self.quic_client.endpoint.allocator,
            payload,
            self.limits.max_stream_frame_data,
            fin,
        );
        send_packetizer.sendEndpoint(
            self.quic_client.endpoint.allocator,
            &self.quic_client.endpoint,
            self.quic_client.peer,
            frames.items,
            1,
            send_attempted,
        ) catch |err| {
            if (send_attempted.*) entry.unusable = true;
            return err;
        };
    }

    pub fn pollDevelopmentStream(
        self: *Client,
        match: DevelopmentStreamMatch,
    ) Error!?DevelopmentStream {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        return self.development_streams.takeMatchingComplete(
            self.quic_client.peer,
            match,
        );
    }

    pub fn receiveDevelopmentStream(
        self: *Client,
        match: DevelopmentStreamMatch,
    ) Error!DevelopmentStream {
        return self.receiveDevelopmentStreamInternal(match, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn closeDevelopmentSession(
        self: *Client,
        match: DevelopmentStreamMatch,
    ) void {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        self.development_streams.removeMatching(
            self.quic_client.peer,
            match,
        );
        self.development_stream_sends.removeSession(match.session_id);
    }

    pub fn clearDevelopmentStreams(self: *Client) void {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        self.development_streams.clear();
        self.development_stream_sends.clear();
    }

    pub fn receiveDevelopmentStreamWithDeadline(
        self: *Client,
        match: DevelopmentStreamMatch,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!DevelopmentStream {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveDevelopmentStreamInternal(match, deadline);
    }

    pub fn receiveDevelopmentStreamWithTimeout(
        self: *Client,
        match: DevelopmentStreamMatch,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!DevelopmentStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDevelopmentStreamWithDeadline(
            match,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn receiveDevelopmentStreamInternal(
        self: *Client,
        match: DevelopmentStreamMatch,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!DevelopmentStream {
        if (deadline != null) {
            if (!self.response_receive_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.response_receive_mutex.lockUncancelable(
                self.quic_client.endpoint.io,
            );
        }
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        while (true) {
            if (try self.development_streams.takeMatchingComplete(
                self.quic_client.peer,
                match,
            )) |stream| return stream;
            var datagram = if (deadline) |absolute|
                try self.quic_client.receiveWithDeadline(absolute)
            else
                try self.quic_client.receive();
            defer datagram.deinit(self.quic_client.endpoint.allocator);
            if (!datagram.from.eql(&self.quic_client.peer)) continue;
            try self.processDevelopmentResponseDatagram(&datagram);
        }
    }

    pub fn receiveResponseEvent(
        self: *Client,
        stream_id: u62,
    ) Error!?StreamingEvent {
        return self.receiveResponseEventInternal(stream_id, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receiveResponseEventWithTimeout(
        self: *Client,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseEventInternal(
            stream_id,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveResponseEventWithDeadline(
        self: *Client,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveResponseEventInternal(stream_id, deadline);
    }

    fn receiveResponseEventInternal(
        self: *Client,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (!self.streaming_mode or
            !self.request_lifecycle.contains(stream_id))
        {
            return error.UnexpectedStream;
        }
        if (deadline != null) {
            if (!self.response_receive_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.response_receive_mutex.lockUncancelable(
                self.quic_client.endpoint.io,
            );
        }
        defer self.response_receive_mutex.unlock(self.quic_client.endpoint.io);

        if (try self.pollResponseEventUnlocked(stream_id)) |event| return event;
        while (true) {
            var datagram = if (deadline) |absolute|
                try self.quic_client.receiveWithDeadline(absolute)
            else
                try self.quic_client.receive();
            defer datagram.deinit(self.quic_client.endpoint.allocator);
            if (!datagram.from.eql(&self.quic_client.peer)) continue;
            try self.processDevelopmentResponseDatagram(&datagram);
            if (try self.pollResponseEventUnlocked(stream_id)) |event| return event;
        }
    }

    /// Return an already-buffered response event without reading UDP.
    pub fn pollResponseEvent(
        self: *Client,
        stream_id: u62,
    ) Error!?StreamingEvent {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(self.quic_client.endpoint.io);
        return self.pollResponseEventUnlocked(stream_id);
    }

    fn pollResponseEventUnlocked(
        self: *Client,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        if (self.response_streams.takeReset(stream_id)) |code| {
            _ = try self.request_lifecycle.finish(stream_id);
            _ = self.outbound_bodies.finish(stream_id);
            self.qpack_encode.abandonStream(stream_id);
            self.streaming_responses.remove(stream_id);
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        const entry = try self.streaming_responses.activateResponse(
            &self.response_streams,
            stream_id,
        );
        applyResponseReaderSemantics(
            self.request_lifecycle,
            stream_id,
            &entry.reader,
        );
        const event = (try entry.reader.next(self.qpack_decode.table)) orelse
            return null;
        if (event == .finished) {
            _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
            _ = self.outbound_bodies.finish(stream_id);
            self.qpack_encode.abandonStream(stream_id);
            self.streaming_responses.remove(stream_id);
        }
        return event;
    }

    /// Return one retained raw QUIC datagram without reading UDP.
    pub fn pollDatagram(self: *Client) ?quic.runtime.OwnedDatagram {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(self.quic_client.endpoint.io);
        return self.runtime_datagrams.pop();
    }

    pub fn receiveDatagram(self: *Client) Error!quic.runtime.OwnedDatagram {
        return self.receiveDatagramInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveDatagramWithTimeout(
        self: *Client,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramInternal(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramWithDeadline(
        self: *Client,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveDatagramInternal(deadline);
    }

    fn receiveDatagramInternal(
        self: *Client,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.runtime.OwnedDatagram {
        if (deadline != null) {
            if (!self.response_receive_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.response_receive_mutex.lockUncancelable(
                self.quic_client.endpoint.io,
            );
        }
        defer self.response_receive_mutex.unlock(self.quic_client.endpoint.io);
        self.streaming_mode = true;
        while (true) {
            if (self.runtime_datagrams.pop()) |datagram| return datagram;
            var datagram = if (deadline) |absolute|
                try self.quic_client.receiveWithDeadline(absolute)
            else
                try self.quic_client.receive();
            defer datagram.deinit(self.quic_client.endpoint.allocator);
            if (!datagram.from.eql(&self.quic_client.peer)) continue;
            try self.processDevelopmentResponseDatagram(&datagram);
        }
    }

    pub fn readResponseData(
        self: *Client,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.readData(out);
    }

    pub fn skipResponseData(self: *Client, stream_id: u62) Error!usize {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.skipData();
    }

    pub fn cancelRequest(
        self: *Client,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        const body = self.outbound_bodies.find(stream_id);
        if (body == null and !self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        const local_final_size = if (body) |entry| entry.send.next_offset else 0;
        const send_reset = if (body) |entry| !entry.send.fin_sent else false;
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        try sendRuntimeRequestCancellation(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            stream_id,
            application_error_code,
            local_final_size,
            send_reset,
        );
    }

    /// Release local bookkeeping after the final response for a streaming
    /// request whose request direction the adapter no longer intends to use.
    /// No cancellation frame is emitted.
    pub fn finishRequest(self: *Client, stream_id: u62) Error!void {
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        const exists = self.request_lifecycle.contains(stream_id) or
            self.outbound_bodies.find(stream_id) != null or
            self.streaming_responses.contains(stream_id) or
            self.response_streams.contains(stream_id);
        if (!exists) return error.UnexpectedStream;
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    fn processDevelopmentResponseDatagram(
        self: *Client,
        datagram: *const quic.runtime.OwnedDatagram,
    ) Error!void {
        for (datagram.frames) |frame| {
            if (frame == .reset_stream and
                (try messageStreamDisposition(
                    frame.reset_stream.stream_id,
                )) == .request_response)
            {
                const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
                if (!self.request_lifecycle.contains(stream_id)) continue;
                try self.response_streams.recordReset(
                    stream_id,
                    frame.reset_stream.application_error_code,
                );
                continue;
            }
            if (frame != .stream) continue;
            const stream_id: u62 = std.math.cast(
                u62,
                frame.stream.stream_id,
            ) orelse return error.UnexpectedStream;
            if ((stream_id & 0x03) == 0 and
                self.development_stream_sends.sessionId(stream_id) != null)
            {
                // Reverse direction of a client-opened WT bidi stream has no
                // second association prefix and is known by its send entry.
                try self.development_streams.insert(
                    datagram.from,
                    frame.stream,
                );
                continue;
            }
            const disposition = messageStreamDisposition(
                frame.stream.stream_id,
            ) catch |err| switch (err) {
                // Server-initiated bidirectional streams are legal only for
                // negotiated extensions; retain them for adapter validation.
                error.StreamCreationError => {
                    try self.development_streams.insert(
                        datagram.from,
                        frame.stream,
                    );
                    continue;
                },
                else => return err,
            };
            if (disposition == .ignore) {
                // HTTP/3 critical/push streams use fixed IDs below 15. The
                // cleartext runtime does not otherwise support them, while WT
                // extension uni streams start after those reserved IDs.
                if (stream_id >= 15 or
                    self.development_streams.contains(
                        datagram.from,
                        stream_id,
                    ))
                {
                    try self.development_streams.insert(
                        datagram.from,
                        frame.stream,
                    );
                }
                continue;
            }
            if (stream_id % 4 != 0) return error.UnexpectedStream;
            if (!self.request_lifecycle.contains(stream_id)) continue;
            if (try self.streaming_responses.insert(
                datagram.from,
                frame.stream,
            )) continue;
            try self.response_streams.insert(datagram.from, frame.stream);
        }
        try retainDevelopmentDatagramFrames(
            &self.runtime_datagrams,
            datagram.*,
        );
    }
};

const DevelopmentRetainedDatagramQueue = development_datagram_queue.Queue;

/// Options for the preconfigured-key protected HTTP/3 runtime.
///
/// This runtime intentionally bypasses the integrated QUIC handshake and does
/// not own a full `one_rtt.Connection`; it is best suited for deterministic
/// packet-protection, QPACK, and HTTP/3 stream-state tests.  Use the
/// handshake-backed runtime for production-like large transfers that require
/// complete QUIC recovery, pacing, and flow-control feedback loops.
pub const ProtectedConfig = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    /// Maximum retained bytes for one protected HTTP/3 streaming reader. This
    /// is a local memory bound for the lightweight runtime, not a replacement
    /// for full QUIC receive-window negotiation.
    max_stream_buffer: usize = 64 * 1024,
    /// Optional peer receive window for protected streaming body senders.
    ///
    /// A real QUIC handshake exchanges transport parameters and `MAX_STREAM_DATA`
    /// frames through `one_rtt.Connection`.  The preconfigured-key runtime has
    /// no transport-parameter handshake, so callers that want deterministic
    /// small-window streaming can seed the peer window explicitly here.
    peer_stream_flow_window: ?usize = null,
    max_stream_frame_data: usize = 1200,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    /// Add a current IMF-fixdate `date` field to final server responses that
    /// do not already contain one. Informational responses are unchanged.
    auto_date_header: bool = true,
    /// Maximum distinct RFC 9218 request/push priorities retained for this
    /// connection. Replacements do not consume another slot.
    max_priority_updates: usize = http3.default_max_priority_updates,
    /// Receive-side QUIC MAX_STREAMS limit used by this lightweight runtime
    /// when validating request IDs carried by PRIORITY_UPDATE. Unlike the
    /// application retention cap in `Limits`, this models protocol credit.
    max_client_bidirectional_streams: u64 = quic.max_stream_count,
    /// Maximum number of protected response DATA packets submitted in one
    /// lightweight multi-stream batch. Zero retains sequential submission.
    response_scheduler_max_batch_packets: usize =
        quic.one_rtt.max_batch_packets,
};

pub const HandshakeSessionOptions = struct {
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_concurrent_request_streams: usize = 128,
    /// Per-CONNECT receive queue bound for unreliable HTTP Datagrams.
    max_queued_connect_datagrams: usize = 16,
    /// Per-CONNECT byte bound shared by its queued application payloads.
    max_queued_connect_datagram_bytes: usize = 64 * 1024,
    max_stream_frame_data: usize = 1200,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    /// Add a current IMF-fixdate `date` field to final server responses that
    /// do not already contain one. Informational responses are unchanged.
    auto_date_header: bool = true,
    /// Maximum distinct RFC 9218 request/push priorities retained for this
    /// connection. Replacements do not consume another slot.
    max_priority_updates: usize = http3.default_max_priority_updates,
    /// Maximum HTTP/3 DATA bytes one paced helper attempt may hand to QUIC.
    ///
    /// The default remains conservative for callers using the standard 1200B
    /// path MTU. Loopback/high-throughput callers can raise this together with
    /// `max_stream_frame_data`, `max_frames_per_packet`, and the handshake
    /// one_rtt max datagram size to reduce ACK/flow-control pump iterations.
    paced_body_chunk_bytes: usize = 1024,
    /// Experimental DATA-frame send path that emits the DATA prefix from
    /// per-packet scratch and borrows immutable application body slices until
    /// QUIC takes stable recovery ownership. Multi-stream batches keep one
    /// prefix buffer per packet, so their descriptors do not alias.
    enable_data_prefix_fast_path: bool = false,
    /// Optional delay after this many socket-visible response body bytes.
    ///
    /// A zero byte threshold disables the delay. Production event loops should
    /// leave both fields at zero and resume sends from their normal writable or
    /// timer callbacks. Same-process loopback workloads using jumbo UDP
    /// datagrams may set them so the peer thread periodically drains a small
    /// kernel receive queue without delaying every packet-sized scheduler pass.
    response_scheduler_batch_delay_bytes: usize = 0,
    /// Optional delay after this many socket-visible response DATA packets.
    ///
    /// Packet-count pacing is preferable for same-process benchmarks because
    /// it stays stable when the DATA chunk size changes. Either threshold may
    /// be enabled; reaching the first one resets both counters.
    response_scheduler_batch_delay_packets: usize = 0,
    response_scheduler_batch_delay_ns: u64 = 0,
    /// Maximum number of independently prioritized response streams submitted
    /// in one transport batch. One preserves sequential UDP writes while still
    /// rotating incremental streams; larger values enable sendmmsg/GSO-style
    /// cross-stream batches on hosts with suitably sized receive queues.
    response_scheduler_max_batch_packets: usize =
        quic.one_rtt.max_batch_packets,
};

pub const BodyChunk = body_batch.Chunk;
pub const ResponseBody = body_batch.ResponseBody;

/// Narrow white-box surface for runtime tests kept in focused modules.
pub const testing = struct {
    pub fn handshakeRecoveryBeforeForTest(
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        configured: @FieldType(
            quic.handshake.ClientOptions,
            "handshake_recovery",
        ),
    ) Error!@FieldType(
        quic.handshake.ClientOptions,
        "handshake_recovery",
    ) {
        return handshakeRecoveryBefore(io, deadline, configured);
    }
};

pub const HandshakeServerOptions = struct {
    handshake: quic.handshake.ServerOptions,
    session: HandshakeSessionOptions = .{},
    /// Maximum time `serveConnection` keeps the sole connection pump alive
    /// after the final response/GOAWAY until reliable QUIC recovery is empty.
    /// This protects short-lived convenience servers from losing a dropped
    /// tail DATA/FIN packet when their session storage is destroyed.
    serve_connection_recovery_drain_timeout: std.Io.Duration =
        .fromSeconds(5),
};

pub const HandshakeAdmissionOptions = struct {
    max_pending_handshakes: usize = 128,
    /// Aggregate pending plus established connection budget for the endpoint.
    /// Zero inherits `max_pending_handshakes` for compatibility.
    max_connections: usize = 0,
    inbox_capacity: usize = 16,
    /// Absolute lifetime for one pending TLS/QUIC handshake. Zero derives the
    /// existing bounded PTO budget from `ServerOptions.handshake_recovery`.
    handshake_timeout_ms: u32 = 0,
};

fn handshakeAdmissionDeadlineNs(
    io: std.Io,
    configured_ms: u32,
    recovery_ms: u64,
) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    const now_ns = if (now <= 0)
        0
    else
        std.math.cast(u64, now) orelse std.math.maxInt(u64);
    const milliseconds = if (configured_ms != 0)
        @as(u64, configured_ms)
    else
        recovery_ms;
    const duration_ns = std.math.mul(
        u64,
        milliseconds,
        std.time.ns_per_ms,
    ) catch std.math.maxInt(u64);
    return now_ns +| duration_ns;
}

/// Prepared dispatcher registration for one HTTP/3 handshake worker.
///
/// `beginHandshakeAdmission` allocates stable inbox storage and chooses a
/// unique server CID. The caller transfers `initial` to a worker, passing
/// `datagramSource()`, and must call `deinit` after promotion or failure.
pub const HandshakeAdmission = struct {
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
    inbox: *quic.handshake_inbox.Inbox,
    initial: quic.runtime.OwnedBytes,
    server_connection_id: [quic.endpoint_dispatcher.default_server_connection_id_len]u8,
    deadline_ns: u64,
    registered: bool = true,
    initial_owned: bool = true,

    pub fn datagramSource(self: *HandshakeAdmission) quic.runtime.DatagramSource {
        return self.inbox.datagramSource();
    }

    pub fn serverConnectionId(self: *const HandshakeAdmission) []const u8 {
        return &self.server_connection_id;
    }

    pub fn deadlineNs(self: *const HandshakeAdmission) u64 {
        return self.deadline_ns;
    }

    pub fn deadline(self: *const HandshakeAdmission) std.Io.Clock.Timestamp {
        return .{
            .raw = .{ .nanoseconds = @intCast(@min(
                self.deadline_ns,
                @as(u64, @intCast(std.math.maxInt(i64))),
            )) },
            .clock = .awake,
        };
    }

    pub fn takeInitial(self: *HandshakeAdmission) quic.runtime.OwnedBytes {
        std.debug.assert(self.initial_owned);
        self.initial_owned = false;
        return self.initial;
    }

    fn abandonRegistration(self: *HandshakeAdmission) void {
        if (!self.registered) return;
        _ = self.dispatcher.unregisterPendingHandshake(
            self.handle,
        ) catch {};
        self.registered = false;
    }

    pub fn deinit(self: *HandshakeAdmission) void {
        const allocator = self.inbox.allocator;
        self.abandonRegistration();
        if (self.initial_owned) self.initial.deinit(allocator);
        self.inbox.deinit();
        allocator.destroy(self.inbox);
        self.* = undefined;
    }
};

pub const HandshakeCompletion = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    admission: *HandshakeAdmission,
    result: union(enum) {
        session: HandshakeServerSession,
        failure: HandshakeWorkerError,
    },

    pub fn deinit(self: *HandshakeCompletion) void {
        const allocator = self.admission.inbox.allocator;
        switch (self.result) {
            .session => |*session| session.deinit(),
            .failure => {},
        }
        self.admission.deinit();
        allocator.destroy(self.admission);
        self.* = undefined;
    }
};

/// Stable heap-backed session registered in the endpoint dispatcher. Moving
/// this handle never invalidates the connection pointer retained by routing.
/// `deinit` must run on the dispatcher-owning task.
pub const PromotedHandshakeSession = struct {
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    allocator: std.mem.Allocator,
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    session: *HandshakeServerSession,
    registered: bool = true,

    pub fn value(self: *PromotedHandshakeSession) *HandshakeServerSession {
        return self.session;
    }

    pub fn deinit(self: *PromotedHandshakeSession) void {
        if (self.registered) {
            _ = self.dispatcher.unregisterConnection(self.handle) catch {};
        }
        self.session.deinit();
        self.allocator.destroy(self.session);
        self.* = undefined;
    }
};

pub const HandshakeSupervisorEvent = union(enum) {
    consumed,
    completed: HandshakeCompletion,
    endpoint: quic.endpoint_dispatcher.Event,

    pub fn deinit(self: *HandshakeSupervisorEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .consumed => {},
            .completed => |*completion| completion.deinit(),
            .endpoint => |*event| event.deinit(allocator),
        }
        self.* = undefined;
    }

    pub fn takeCompletion(self: *HandshakeSupervisorEvent) ?HandshakeCompletion {
        if (self.* != .completed) return null;
        const completion = self.completed;
        self.* = .consumed;
        return completion;
    }

    pub fn takeEndpoint(
        self: *HandshakeSupervisorEvent,
    ) ?quic.endpoint_dispatcher.Event {
        if (self.* != .endpoint) return null;
        const event = self.endpoint;
        self.* = .consumed;
        return event;
    }
};

const HandshakeWorkerContext = struct {
    server: *HandshakeServer,
    io: std.Io,
    completed: *std.Io.Queue(HandshakeCompletion),
};

/// Owns bounded HTTP/3 handshake workers while the caller remains the sole
/// UDP receive owner. `pollCompleted` never blocks: the endpoint loop routes a
/// packet, then drains completions and promotes successful connections.
pub const HandshakeSupervisor = struct {
    server: *HandshakeServer,
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    allocator: std.mem.Allocator,
    io: std.Io,
    admission_options: HandshakeAdmissionOptions,
    next_handle: quic.endpoint_dispatcher.ConnectionHandle = 1,
    workers: std.Io.Group = .init,
    worker_context: *HandshakeWorkerContext,
    active_workers: std.atomic.Value(usize) = .init(0),
    next_handle_mutex: std.Io.Mutex = .init,
    completed_storage: []HandshakeCompletion,
    completed: *std.Io.Queue(HandshakeCompletion),
    admissions_mutex: std.Io.Mutex = .init,
    admissions: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.PendingHandshakeHandle,
        *HandshakeAdmission,
    ) = .empty,
    /// Active handshake CIDs are intentionally non-migratable. Same-IP port
    /// rebinding is allowed, matching QUIC's authenticated migration rules.
    pub fn init(
        server: *HandshakeServer,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        options: HandshakeAdmissionOptions,
    ) HandshakeAdmissionError!HandshakeSupervisor {
        if (options.max_pending_handshakes == 0 or
            options.inbox_capacity == 0)
        {
            return error.PendingHandshakeLimitReached;
        }
        const storage = try server.allocator.alloc(
            HandshakeCompletion,
            options.max_pending_handshakes,
        );
        errdefer server.allocator.free(storage);
        const completed = try server.allocator.create(
            std.Io.Queue(HandshakeCompletion),
        );
        errdefer server.allocator.destroy(completed);
        completed.* = .init(storage);
        const context = try server.allocator.create(HandshakeWorkerContext);
        errdefer server.allocator.destroy(context);
        const supervisor: HandshakeSupervisor = .{
            .server = server,
            .dispatcher = dispatcher,
            .allocator = server.allocator,
            .io = server.quic_server.endpoint.io,
            .admission_options = options,
            .worker_context = context,
            .completed_storage = storage,
            .completed = completed,
        };
        context.* = .{
            .server = server,
            .io = supervisor.io,
            .completed = completed,
        };
        return supervisor;
    }

    pub fn deinit(self: *HandshakeSupervisor) void {
        self.workers.cancel(self.io);
        while (self.pollCompleted()) |completion| {
            self.destroyCompletion(completion);
        }
        self.completed.close(self.io);
        self.admissions.deinit(self.allocator);
        self.allocator.destroy(self.worker_context);
        self.allocator.destroy(self.completed);
        self.allocator.free(self.completed_storage);
        self.* = undefined;
    }

    pub fn admit(
        self: *HandshakeSupervisor,
        event: *quic.endpoint_dispatcher.Event,
    ) HandshakeAdmissionError!quic.endpoint_dispatcher.PendingHandshakeHandle {
        const max_connections = if (self.admission_options.max_connections == 0) self.admission_options.max_pending_handshakes else self.admission_options.max_connections;
        if (self.dispatcher.connectionCount() +|
            self.active_workers.load(.acquire) >= max_connections)
        {
            return error.PendingHandshakeLimitReached;
        }
        var active = self.active_workers.load(.acquire);
        while (true) {
            if (active >= self.admission_options.max_pending_handshakes) {
                return error.PendingHandshakeLimitReached;
            }
            if (self.active_workers.cmpxchgWeak(
                active,
                active + 1,
                .acq_rel,
                .acquire,
            )) |observed| {
                active = observed;
                continue;
            }
            break;
        }
        errdefer {
            const previous = self.active_workers.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
        }
        const handle = self.reserveHandle();
        const admission = try self.allocator.create(HandshakeAdmission);
        errdefer self.allocator.destroy(admission);
        admission.* = try self.server.beginHandshakeAdmission(
            self.dispatcher,
            handle,
            event,
            self.admission_options,
        );
        errdefer admission.deinit();
        self.admissions_mutex.lockUncancelable(self.io);
        self.admissions.put(
            self.allocator,
            handle,
            admission,
        ) catch |err| {
            self.admissions_mutex.unlock(self.io);
            return err;
        };
        self.admissions_mutex.unlock(self.io);
        errdefer {
            self.admissions_mutex.lockUncancelable(self.io);
            _ = self.admissions.remove(handle);
            self.admissions_mutex.unlock(self.io);
        }
        try self.workers.concurrent(
            self.io,
            HandshakeSupervisor.runWorker,
            .{ self.worker_context, admission },
        );
        return handle;
    }

    pub fn pollCompleted(
        self: *HandshakeSupervisor,
    ) ?HandshakeCompletion {
        var completion: [1]HandshakeCompletion = undefined;
        const count = self.completed.get(
            self.io,
            &completion,
            0,
        ) catch return null;
        if (count == 0) return null;
        const previous = self.active_workers.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        self.admissions_mutex.lockUncancelable(self.io);
        _ = self.admissions.remove(completion[0].handle);
        self.admissions_mutex.unlock(self.io);
        return completion[0];
    }

    /// Receive and route one endpoint datagram while periodically waking to
    /// report worker completion. A completed handshake is returned before any
    /// later socket event so the caller can promote its CID routes promptly.
    pub fn receive(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!HandshakeSupervisorEvent {
        while (true) {
            if (try self.receiveOnce(
                supported_versions,
                poll_interval,
            )) |event| return event;
        }
    }

    /// Wait for one supervisor event under a relative awake-clock budget.
    pub fn receiveWithTimeout(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        timeout: std.Io.Duration,
    ) HandshakeAdmissionError!HandshakeSupervisorEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(supported_versions, .fromNow(
            self.io,
            .{ .clock = .awake, .raw = timeout },
        ));
    }

    /// Perform one bounded receive iteration. A null result means the poll
    /// interval elapsed after pending-handshake expiry was serviced.
    pub fn receiveOnce(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!?HandshakeSupervisorEvent {
        if (poll_interval.raw.nanoseconds <= 0) {
            return error.InvalidHandshakeRecovery;
        }
        return self.receiveOnceUntil(
            supported_versions,
            .{ .duration = poll_interval },
        ) catch |err| switch (err) {
            error.Timeout => null,
            else => |other| return other,
        };
    }

    /// Perform one receive iteration under the caller's absolute deadline.
    /// Handshake expiry and QUIC transport timers may be serviced first, but
    /// neither can renew the outer endpoint-loop budget.
    pub fn receiveWithDeadline(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) HandshakeAdmissionError!HandshakeSupervisorEvent {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveOnceUntil(
            supported_versions,
            .{ .deadline = absolute },
        );
    }

    fn receiveOnceUntil(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) HandshakeAdmissionError!HandshakeSupervisorEvent {
        if (self.pollCompleted()) |completion| {
            return .{ .completed = completion };
        }
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        _ = self.expireAt(if (now <= 0)
            0
        else
            std.math.cast(u64, now) orelse std.math.maxInt(u64));
        return .{ .endpoint = try self.dispatcher.receiveTimeout(
            supported_versions,
            timeout,
        ) };
    }

    pub fn promote(
        self: *HandshakeSupervisor,
        completion: *HandshakeCompletion,
    ) HandshakeAdmissionError!PromotedHandshakeSession {
        const session = try self.allocator.create(HandshakeServerSession);
        errdefer self.allocator.destroy(session);
        session.* = switch (completion.result) {
            .session => |value| value,
            .failure => |err| return err,
        };
        // Transfer the successful value out of the completion before any later
        // error path can ask the caller to discard that completion.
        completion.result = .{ .failure = error.HandshakeReceiveFailed };
        errdefer session.deinit();
        try self.server.promoteAdmission(
            self.dispatcher,
            completion.admission,
            completion.handle,
            session,
        );
        const handle = completion.handle;
        completion.admission.deinit();
        self.allocator.destroy(completion.admission);
        completion.* = undefined;
        return .{
            .dispatcher = self.dispatcher,
            .allocator = self.allocator,
            .handle = handle,
            .session = session,
        };
    }

    pub fn discardCompletion(
        self: *HandshakeSupervisor,
        completion: *HandshakeCompletion,
    ) void {
        _ = self;
        completion.deinit();
    }

    pub fn pendingCount(self: *const HandshakeSupervisor) usize {
        return self.active_workers.load(.acquire);
    }

    pub fn connectionCount(self: *const HandshakeSupervisor) usize {
        return self.dispatcher.connectionCount();
    }

    pub fn expireAt(self: *HandshakeSupervisor, now_ns: u64) usize {
        var expired: [64]*HandshakeAdmission = undefined;
        var expired_len: usize = 0;
        self.admissions_mutex.lockUncancelable(self.io);
        var iterator = self.admissions.iterator();
        while (iterator.next()) |entry| {
            if (now_ns < entry.value_ptr.*.deadlineNs()) continue;
            if (expired_len == expired.len) break;
            expired[expired_len] = entry.value_ptr.*;
            expired_len += 1;
        }
        self.admissions_mutex.unlock(self.io);
        for (expired[0..expired_len]) |admission| admission.inbox.close();
        return expired_len;
    }

    fn reserveHandle(
        self: *HandshakeSupervisor,
    ) quic.endpoint_dispatcher.ConnectionHandle {
        self.next_handle_mutex.lockUncancelable(self.io);
        defer self.next_handle_mutex.unlock(self.io);
        const handle = self.next_handle;
        self.next_handle +%= 1;
        if (self.next_handle == 0) self.next_handle = 1;
        return handle;
    }

    fn runWorker(
        context: *HandshakeWorkerContext,
        admission: *HandshakeAdmission,
    ) std.Io.Cancelable!void {
        const result: @FieldType(HandshakeCompletion, "result") = blk: {
            const session = context.server.acceptAdmission(admission) catch |err| {
                break :blk .{ .failure = err };
            };
            break :blk .{ .session = session };
        };
        context.completed.putOneUncancelable(context.io, .{
            .handle = admission.handle,
            .admission = admission,
            .result = result,
        }) catch |err| switch (err) {
            // The queue is closed only after `workers.cancel` has joined every
            // worker, so closure here violates supervisor ownership.
            error.Closed => unreachable,
        };
    }

    fn destroyCompletion(
        self: *HandshakeSupervisor,
        completion: HandshakeCompletion,
    ) void {
        _ = self;
        var owned = completion;
        owned.deinit();
    }
};

pub const EndpointRequestEvent = struct {
    connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
    request: StreamingRequestEvent,

    pub fn deinit(self: *EndpointRequestEvent, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

/// Endpoint-level transport progress before an application protocol consumes
/// a routed packet. HTTP/3 and WebTransport share handshake ownership and CID
/// routing, but must apply established packets through different stream
/// parsers once an Extended CONNECT has been detached.
pub const HandshakeFailure = struct {
    handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
    err: HandshakeWorkerError,
};

pub const EndpointTransportEvent = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    closed: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        timer: quic.one_rtt.TimerDeadline,
    },
    handshake_failed: HandshakeFailure,
    packet: quic.endpoint_dispatcher.RoutedPacket,
    unrouted: quic.endpoint_dispatcher.Event,

    pub fn deinit(
        self: *EndpointTransportEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .packet => |*packet| packet.packet.deinit(allocator),
            .unrouted => |*event| event.deinit(allocator),
            .connected, .closed, .handshake_failed => {},
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
    handshake_failed: HandshakeFailure,
    request: EndpointRequestEvent,
    unrouted: quic.endpoint_dispatcher.Event,

    pub fn deinit(self: *EndpointServerEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .connected, .closed, .handshake_failed => {},
            .request => |*request| request.deinit(allocator),
            .unrouted => |*event| event.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const EndpointServeEvent = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    closed: struct {
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        timer: quic.one_rtt.TimerDeadline,
    },
    /// Both pointers borrow endpoint-owned storage and are valid only for the
    /// synchronous callback. The request payload remains owned by the outer
    /// receive loop and must not be retained or deinitialized by the handler.
    request: struct {
        session: *HandshakeServerSession,
        request: *StreamingRequestEvent,
    },
};

pub const EndpointServeOptions = struct {
    shutdown: *std.Io.Event,
    supported_versions: []const u32,
    poll_interval: std.Io.Clock.Duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(5),
    },
};

/// Event-driven, multi-connection HTTP/3 server over one UDP receive owner.
///
/// The supervisor admits Initials into bounded handshake workers, promotes
/// successful connections into stable heap-backed sessions, routes 1-RTT
/// packets, services connection timers, and emits application request events.
pub const EndpointServer = struct {
    server: *HandshakeServer,
    allocator: std.mem.Allocator,
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    handshakes: HandshakeSupervisor,
    sessions: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        PromotedHandshakeSession,
    ) = .empty,
    /// Last connection that yielded an application request. This stable-key
    /// cursor prevents a continuously ready connection from monopolizing the
    /// endpoint while remaining valid across hash-map rehashes.
    last_request_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null,

    pub fn init(
        server: *HandshakeServer,
        options: HandshakeAdmissionOptions,
    ) HandshakeAdmissionError!EndpointServer {
        const dispatcher = try server.allocator.create(
            quic.endpoint_dispatcher.Dispatcher,
        );
        errdefer server.allocator.destroy(dispatcher);
        dispatcher.* = .init(server.allocator, &server.quic_server.endpoint);
        errdefer dispatcher.deinit();
        const handshakes = try HandshakeSupervisor.init(
            server,
            dispatcher,
            options,
        );
        return .{
            .server = server,
            .allocator = server.allocator,
            .dispatcher = dispatcher,
            .handshakes = handshakes,
        };
    }

    pub fn deinit(self: *EndpointServer) void {
        self.handshakes.deinit();
        var iterator = self.sessions.valueIterator();
        while (iterator.next()) |promoted| promoted.deinit();
        self.sessions.deinit(self.allocator);
        self.dispatcher.deinit();
        self.allocator.destroy(self.dispatcher);
        self.* = undefined;
    }

    pub fn connectionCount(self: *const EndpointServer) usize {
        return self.sessions.count();
    }

    pub fn session(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*HandshakeServerSession {
        const promoted = self.sessions.getPtr(handle) orelse return null;
        return promoted.session;
    }

    /// Return the stable promoted-session owner without moving it. Higher
    /// protocol adapters can build state around `session` while the dispatcher
    /// continues to point at the same heap-resident QUIC connection.
    pub fn promotedSession(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*PromotedHandshakeSession {
        return self.sessions.getPtr(handle);
    }

    pub fn removeConnection(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) bool {
        var removed = self.sessions.fetchRemove(handle) orelse return false;
        removed.value.deinit();
        if (self.last_request_handle == handle) self.last_request_handle = null;
        return true;
    }

    /// Transfer one promoted HTTP/3 session to a higher-level protocol
    /// adapter while retaining its dispatcher registration. The caller must
    /// later unregister `handle` before destroying the moved session.
    pub fn takeSession(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?PromotedHandshakeSession {
        const removed = (self.sessions.fetchRemove(handle) orelse return null).value;
        if (self.last_request_handle == handle) self.last_request_handle = null;
        return removed;
    }

    pub fn receive(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!EndpointServerEvent {
        while (true) {
            if (try self.receiveOnce(
                supported_versions,
                poll_interval,
            )) |event| return event;
        }
    }

    /// Wait for one request/lifecycle event under one relative budget.
    pub fn receiveWithTimeout(
        self: *EndpointServer,
        supported_versions: []const u32,
        timeout: std.Io.Duration,
    ) HandshakeAdmissionError!EndpointServerEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(supported_versions, .fromNow(
            self.server.quic_server.endpoint.io,
            .{ .clock = .awake, .raw = timeout },
        ));
    }

    /// Perform one bounded endpoint iteration. A null result lets a caller
    /// inspect shutdown or maintenance state without introducing another UDP
    /// receive owner. Buffered request events are returned before socket work.
    pub fn receiveOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!?EndpointServerEvent {
        if (try self.pollRequestAcrossSessions()) |request| return request;
        const event = (try self.receiveTransportOnce(
            supported_versions,
            poll_interval,
        )) orelse return null;
        return self.processTransportEvent(event);
    }

    /// Receive one application event without renewing an outer operation's
    /// absolute deadline while processing unrelated packets and timers.
    pub fn receiveWithDeadline(
        self: *EndpointServer,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) HandshakeAdmissionError!EndpointServerEvent {
        const absolute = try deadline_policy.usableAwake(
            self.server.quic_server.endpoint.io,
            deadline,
        );
        if (try self.pollRequestAcrossSessions()) |request| return request;
        while (true) {
            const event = try self.receiveTransportWithDeadline(
                supported_versions,
                absolute,
            );
            if (try self.processTransportEvent(event)) |application_event| {
                return application_event;
            }
        }
    }

    fn processTransportEvent(
        self: *EndpointServer,
        event_value: EndpointTransportEvent,
    ) HandshakeAdmissionError!?EndpointServerEvent {
        var event = event_value;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |handle| return .{ .connected = handle },
            .closed => |closed| return .{ .closed = .{
                .handle = closed.handle,
                .timer = closed.timer,
            } },
            .handshake_failed => |failure| return .{
                .handshake_failed = .{
                    .handle = failure.handle,
                    .err = failure.err,
                },
            },
            .packet => |*packet| {
                const target = self.sessions.getPtr(
                    packet.connection_handle,
                ) orelse return error.UnknownConnectionHandle;
                try target.session.processRequestPacket(&packet.packet);
            },
            .unrouted => {
                const unrouted = event.unrouted;
                event = .{ .connected = 0 };
                return .{ .unrouted = unrouted };
            },
        }
        return self.pollRequestAcrossSessions();
    }

    /// Run the single-owner endpoint loop until `shutdown` is set. Request
    /// callbacks execute serially with borrowed event storage, which keeps all
    /// QUIC and QPACK mutation on this task while allowing applications to
    /// inspect a stable session and emit streaming or aggregate responses.
    pub fn serveUntil(
        self: *EndpointServer,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *EndpointServer,
            EndpointServeEvent,
        ) anyerror!void,
        options: EndpointServeOptions,
    ) anyerror!void {
        if (options.supported_versions.len == 0 or
            options.poll_interval.raw.nanoseconds <= 0)
        {
            return error.InvalidHandshakeRecovery;
        }
        while (!options.shutdown.isSet()) {
            const event_value = self.receiveOnce(
                options.supported_versions,
                options.poll_interval,
            ) catch |err| switch (err) {
                error.Canceled => if (options.shutdown.isSet()) return else return err,
                else => |other| return other,
            } orelse continue;
            var event = event_value;
            defer event.deinit(self.allocator);
            try self.dispatchServeEvent(
                Context,
                context,
                &event,
                handler,
            );
        }
    }

    fn dispatchServeEvent(
        self: *EndpointServer,
        comptime Context: type,
        context: *Context,
        event: *EndpointServerEvent,
        comptime handler: *const fn (
            *Context,
            *EndpointServer,
            EndpointServeEvent,
        ) anyerror!void,
    ) anyerror!void {
        switch (event.*) {
            .connected => |handle| {
                try handler(context, self, .{ .connected = handle });
                try self.refreshTimerIfOwned(handle);
            },
            .closed => |closed| try handler(
                context,
                self,
                .{ .closed = .{
                    .handle = closed.handle,
                    .timer = closed.timer,
                } },
            ),
            .request => |*request| {
                const handle = request.connection_handle;
                const session_value = self.session(handle) orelse
                    return error.UnknownConnectionHandle;
                try handler(context, self, .{ .request = .{
                    .session = session_value,
                    .request = &request.request,
                } });
                // The dispatcher refreshed this connection after the inbound
                // packet, before application code emitted its response. Mirror
                // the send-side loss/PTO deadline before the next socket wait.
                // A handler may remove or transfer the session; then it owns
                // future timer synchronization.
                try self.refreshTimerIfOwned(handle);
            },
            .handshake_failed => |failure| return failure.err,
            .unrouted => {},
        }
    }

    fn refreshTimerIfOwned(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) HandshakeAdmissionError!void {
        if (self.sessions.contains(handle)) {
            try self.dispatcher.refreshConnectionTimer(handle);
        }
    }

    fn pollRequestAcrossSessions(
        self: *EndpointServer,
    ) HandshakeAdmissionError!?EndpointServerEvent {
        return self.pollRequestAcrossSessionsWith({}, pollSessionRequestEntry);
    }

    fn pollRequestAcrossSessionsWith(
        self: *EndpointServer,
        context: anytype,
        comptime poll_request: anytype,
    ) HandshakeAdmissionError!?EndpointServerEvent {
        return round_robin.poll(
            quic.endpoint_dispatcher.ConnectionHandle,
            @TypeOf(self.sessions),
            EndpointServerEvent,
            &self.sessions,
            &self.last_request_handle,
            context,
            struct {
                fn run(
                    poll_context: anytype,
                    handle: quic.endpoint_dispatcher.ConnectionHandle,
                    promoted: *PromotedHandshakeSession,
                ) HandshakeAdmissionError!?EndpointServerEvent {
                    const request = (try poll_request(
                        poll_context,
                        handle,
                        promoted,
                    )) orelse return null;
                    return .{ .request = .{
                        .connection_handle = handle,
                        .request = request,
                    } };
                }
            }.run,
        );
    }

    fn pollSessionRequestEntry(
        _: void,
        _: quic.endpoint_dispatcher.ConnectionHandle,
        promoted: *PromotedHandshakeSession,
    ) HandshakeAdmissionError!?StreamingRequestEvent {
        return promoted.session.pollRequestEvent();
    }

    pub const testing = struct {
        const ReadyProbe = struct {
            ready: []const quic.endpoint_dispatcher.ConnectionHandle,

            fn poll(
                self: *const ReadyProbe,
                handle: quic.endpoint_dispatcher.ConnectionHandle,
                _: *PromotedHandshakeSession,
            ) HandshakeAdmissionError!?StreamingRequestEvent {
                if (std.mem.indexOfScalar(
                    quic.endpoint_dispatcher.ConnectionHandle,
                    self.ready,
                    handle,
                ) == null) return null;
                return .{ .reset = .{
                    .from = .{ .ip4 = .loopback(1) },
                    .stream_id = 0,
                    .application_error_code = 0,
                } };
            }
        };

        /// Apply production request scheduling to synthetic readiness without
        /// constructing HTTP/3 request bodies solely to test ordering.
        pub fn pollReadyRequestHandle(
            server: *EndpointServer,
            ready: []const quic.endpoint_dispatcher.ConnectionHandle,
        ) HandshakeAdmissionError!?quic.endpoint_dispatcher.ConnectionHandle {
            var probe = ReadyProbe{ .ready = ready };
            const event = (try server.pollRequestAcrossSessionsWith(
                &probe,
                ReadyProbe.poll,
            )) orelse return null;
            return event.request.connection_handle;
        }

        /// Expose completion adaptation without constructing a full QUIC/TLS
        /// exchange. Ownership follows the production path: this call always
        /// consumes `completion`, including when it contains a failure.
        pub fn finishTransportCompletion(
            server: *EndpointServer,
            completion: *HandshakeCompletion,
        ) HandshakeAdmissionError!EndpointTransportEvent {
            return server.finishTransportCompletion(completion);
        }

        pub fn dispatchServeEvent(
            server: *EndpointServer,
            comptime Context: type,
            context: *Context,
            event: *EndpointServerEvent,
            comptime handler: *const fn (
                *Context,
                *EndpointServer,
                EndpointServeEvent,
            ) anyerror!void,
        ) anyerror!void {
            return server.dispatchServeEvent(
                Context,
                context,
                event,
                handler,
            );
        }

        pub fn dispatchTransportServeEvent(
            server: *EndpointServer,
            comptime Context: type,
            context: *Context,
            event: *EndpointTransportEvent,
            comptime handler: *const fn (
                *Context,
                *EndpointServer,
                *EndpointTransportEvent,
            ) anyerror!void,
        ) anyerror!void {
            return server.dispatchTransportServeEvent(
                Context,
                context,
                event,
                handler,
            );
        }
    };

    /// Drive handshakes, timers, and the single UDP receive owner without
    /// interpreting established STREAM frames. Protocol adapters must process
    /// `.packet` before releasing the event; the dispatcher timer is already
    /// refreshed by its receive path.
    pub fn receiveTransport(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!EndpointTransportEvent {
        while (true) {
            if (try self.receiveTransportOnce(
                supported_versions,
                poll_interval,
            )) |event| return event;
        }
    }

    /// Wait for one transport event under one relative awake-clock budget.
    pub fn receiveTransportWithTimeout(
        self: *EndpointServer,
        supported_versions: []const u32,
        timeout: std.Io.Duration,
    ) HandshakeAdmissionError!EndpointTransportEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveTransportWithDeadline(
            supported_versions,
            .fromNow(self.server.quic_server.endpoint.io, .{
                .clock = .awake,
                .raw = timeout,
            }),
        );
    }

    /// Drive the endpoint until `shutdown` is set, exposing established
    /// packets without interpreting their HTTP/3 request streams. This is the
    /// safe outer-loop primitive for protocol adapters such as WebTransport.
    pub fn serveTransportUntil(
        self: *EndpointServer,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *EndpointServer,
            *EndpointTransportEvent,
        ) anyerror!void,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
        shutdown: *std.Io.Event,
    ) anyerror!void {
        if (supported_versions.len == 0 or
            poll_interval.raw.nanoseconds <= 0)
        {
            return error.InvalidHandshakeRecovery;
        }
        while (!shutdown.isSet()) {
            const event_value = self.receiveTransportOnce(
                supported_versions,
                poll_interval,
            ) catch |err| switch (err) {
                error.Canceled => if (shutdown.isSet()) return else return err,
                else => |other| return other,
            } orelse continue;
            var event = event_value;
            defer event.deinit(self.allocator);
            try self.dispatchTransportServeEvent(
                Context,
                context,
                &event,
                handler,
            );
        }
    }

    fn dispatchTransportServeEvent(
        self: *EndpointServer,
        comptime Context: type,
        context: *Context,
        event: *EndpointTransportEvent,
        comptime handler: *const fn (
            *Context,
            *EndpointServer,
            *EndpointTransportEvent,
        ) anyerror!void,
    ) anyerror!void {
        // Capture the identity before the adapter is allowed to consume or
        // rewrite the event. If it also removes/transfers the session, the
        // ownership check below deliberately skips the refresh.
        const handle = transportEventConnectionHandle(event.*);
        try handler(context, self, event);
        if (handle) |connection_handle| {
            try self.refreshTimerIfOwned(connection_handle);
        }
    }

    /// One bounded transport iteration for outer loops that also poll
    /// application shutdown or maintenance state.
    pub fn receiveTransportOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!?EndpointTransportEvent {
        if (poll_interval.raw.nanoseconds <= 0) {
            return error.InvalidHandshakeRecovery;
        }
        return self.receiveTransportUntil(
            supported_versions,
            .{ .duration = poll_interval },
        ) catch |err| switch (err) {
            error.Timeout => null,
            else => |other| return other,
        };
    }

    /// Drive one transport iteration under an existing absolute budget.
    pub fn receiveTransportWithDeadline(
        self: *EndpointServer,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) HandshakeAdmissionError!EndpointTransportEvent {
        const absolute = try deadline_policy.usableAwake(
            self.server.quic_server.endpoint.io,
            deadline,
        );
        while (true) {
            if (try self.receiveTransportUntil(
                supported_versions,
                .{ .deadline = absolute },
            )) |event| return event;
        }
    }

    fn receiveTransportUntil(
        self: *EndpointServer,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) HandshakeAdmissionError!?EndpointTransportEvent {
        var event = switch (timeout) {
            .none => unreachable,
            .duration => |duration| (try self.handshakes.receiveOnce(
                supported_versions,
                duration,
            )) orelse return error.Timeout,
            .deadline => |deadline| try self.handshakes
                .receiveWithDeadline(supported_versions, deadline),
        };
        switch (event) {
            .consumed => unreachable,
            .completed => {
                var completion = event.takeCompletion().?;
                return try self.finishTransportCompletion(&completion);
            },
            .endpoint => {
                var endpoint_event = event.takeEndpoint().?;
                var endpoint_owned = true;
                defer if (endpoint_owned) endpoint_event.deinit(
                    self.allocator,
                );
                switch (endpoint_event) {
                    .new_initial => {
                        _ = self.handshakes.admit(&endpoint_event) catch |err|
                            switch (err) {
                                error.PendingHandshakeLimitReached => {
                                    endpoint_owned = false;
                                    return .{ .unrouted = endpoint_event };
                                },
                                else => |other| return other,
                            };
                    },
                    .packet => |packet| {
                        endpoint_event = .consumed;
                        endpoint_owned = false;
                        return .{ .packet = packet };
                    },
                    .unrouted => {
                        endpoint_owned = false;
                        return .{ .unrouted = endpoint_event };
                    },
                    .timer => |timer| {
                        const target = self.sessions.getPtr(
                            timer.connection_handle,
                        ) orelse return error.UnknownConnectionHandle;
                        if (target.session.established.connection.closed()) {
                            const closed = EndpointTransportEvent{ .closed = .{
                                .handle = timer.connection_handle,
                                .timer = timer.timer,
                            } };
                            if (!self.removeConnection(timer.connection_handle)) {
                                return error.UnknownConnectionHandle;
                            }
                            return closed;
                        }
                    },
                    .pending_handshake,
                    .discarded_long_header,
                    .consumed,
                    => {},
                }
            },
        }
        return null;
    }

    fn finishTransportCompletion(
        self: *EndpointServer,
        completion: *HandshakeCompletion,
    ) HandshakeAdmissionError!EndpointTransportEvent {
        var completion_owned = true;
        defer if (completion_owned) completion.deinit();
        switch (completion.result) {
            .failure => |err| {
                const handle = completion.handle;
                completion.deinit();
                completion_owned = false;
                return .{ .handshake_failed = .{
                    .handle = handle,
                    .err = err,
                } };
            },
            .session => {},
        }
        var promoted = try self.handshakes.promote(completion);
        errdefer promoted.deinit();
        const handle = promoted.handle;
        const slot = try self.sessions.getOrPut(self.allocator, handle);
        if (slot.found_existing) return error.DuplicateConnectionHandle;
        slot.value_ptr.* = promoted;
        completion_owned = false;
        return .{ .connected = handle };
    }
};

fn transportEventConnectionHandle(
    event: EndpointTransportEvent,
) ?quic.endpoint_dispatcher.ConnectionHandle {
    return switch (event) {
        .connected => |handle| handle,
        .packet => |packet| packet.connection_handle,
        .closed, .handshake_failed, .unrouted => null,
    };
}

pub const HandshakeClientOptions = struct {
    handshake: quic.handshake.ClientOptions,
    session: HandshakeSessionOptions = .{},
    /// Absolute budget for the complete QUIC/TLS connection. URI entry points
    /// include hostname resolution and every address fallback in this same
    /// budget; direct-address and caller-owned-endpoint entry points begin it
    /// immediately before the handshake.
    connect_timeout: ?std.Io.Duration = null,
};

pub const HandshakeServer = struct {
    quic_server: quic.runtime.Server,
    allocator: std.mem.Allocator,
    handshake_options: quic.handshake.ServerOptions,
    session_options: HandshakeSessionOptions,
    local_connection_id: []u8,
    alpn_protocol: []u8,
    transport_parameters: []u8,
    serve_connection_recovery_drain_timeout: std.Io.Duration,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, options: HandshakeServerOptions) Error!HandshakeServer {
        try validateHandshakeSessionOptions(options.session);
        if (options.serve_connection_recovery_drain_timeout.nanoseconds <= 0) {
            return error.InvalidHandshakeRecovery;
        }
        try validateBlockedStreamLimit(
            options.session.local_settings,
            options.session.max_concurrent_request_streams,
        );
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();

        const local_connection_id = try allocator.dupe(u8, options.handshake.local_connection_id);
        errdefer allocator.free(local_connection_id);
        const alpn_protocol = try allocator.dupe(u8, options.handshake.alpn_protocol);
        errdefer allocator.free(alpn_protocol);
        const transport_parameters = try allocator.dupe(u8, options.handshake.transport_parameters);
        errdefer allocator.free(transport_parameters);

        var handshake_options = options.handshake;
        handshake_options.local_connection_id = local_connection_id;
        handshake_options.alpn_protocol = alpn_protocol;
        handshake_options.transport_parameters = transport_parameters;

        return .{
            .quic_server = quic_server,
            .allocator = allocator,
            .handshake_options = handshake_options,
            .session_options = options.session,
            .local_connection_id = local_connection_id,
            .alpn_protocol = alpn_protocol,
            .transport_parameters = transport_parameters,
            .serve_connection_recovery_drain_timeout = options.serve_connection_recovery_drain_timeout,
        };
    }

    pub fn deinit(self: *HandshakeServer) void {
        self.quic_server.deinit();
        self.allocator.free(self.local_connection_id);
        self.allocator.free(self.alpn_protocol);
        self.allocator.free(self.transport_parameters);
        self.* = undefined;
    }

    pub fn address(self: HandshakeServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn accept(self: *HandshakeServer) Error!HandshakeServerSession {
        return self.acceptBefore(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Complete the QUIC/TLS server handshake before one absolute awake-clock
    /// deadline. Unlike stream-listener servers, UDP accept is itself a packet
    /// receive, so the budget includes waiting for the first client Initial.
    pub fn acceptWithDeadline(
        self: *HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!HandshakeServerSession {
        const absolute = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.acceptBefore(absolute);
    }

    pub fn acceptWithTimeout(
        self: *HandshakeServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!HandshakeServerSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn acceptBefore(
        self: *HandshakeServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!HandshakeServerSession {
        var established = if (deadline) |absolute|
            try quic.handshake.acceptWithDeadline(
                &self.quic_server.endpoint,
                self.handshake_options,
                absolute,
            )
        else
            try quic.handshake.accept(
                &self.quic_server.endpoint,
                self.handshake_options,
            );
        errdefer established.deinit();
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    /// Accept from a client Initial already received/classified by the shared
    /// QUIC endpoint dispatcher. This prevents the HTTP/3 accept path from
    /// performing a second read for the first datagram.
    pub fn acceptFromInitial(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!HandshakeServerSession {
        return self.acceptFromInitialSource(
            .fromEndpoint(&self.quic_server.endpoint),
            initial,
        );
    }

    pub fn acceptFromInitialWithDeadline(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!HandshakeServerSession {
        return self.acceptFromInitialSourceWithDeadline(
            .fromEndpoint(&self.quic_server.endpoint),
            initial,
            deadline,
        );
    }

    pub fn acceptFromInitialWithTimeout(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!HandshakeServerSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptFromInitialWithDeadline(
            initial,
            .fromNow(
                self.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Accept a dispatcher-owned Initial while receiving every later QUIC
    /// handshake datagram from an injected source. A shared endpoint uses a
    /// bounded pending-handshake inbox here so this worker never competes with
    /// the endpoint's sole UDP receive owner.
    pub fn acceptFromInitialSource(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!HandshakeServerSession {
        const datagram = initial.takeNewInitial() orelse
            return error.InvalidHandshakeFlight;
        var established = try quic.handshake.acceptFromInitialSource(
            &self.quic_server.endpoint,
            source,
            datagram,
            self.handshake_options,
        );
        errdefer established.deinit();
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    pub fn acceptFromInitialSourceWithDeadline(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!HandshakeServerSession {
        const absolute = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        const datagram = initial.takeNewInitial() orelse
            return error.InvalidHandshakeFlight;
        var established = try quic.handshake
            .acceptFromInitialSourceWithDeadline(
            &self.quic_server.endpoint,
            source,
            datagram,
            self.handshake_options,
            absolute,
        );
        errdefer established.deinit();
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    pub fn acceptFromInitialSourceWithTimeout(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!HandshakeServerSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptFromInitialSourceWithDeadline(
            source,
            initial,
            .fromNow(
                self.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Bound and register one dispatcher-produced Initial for a handshake
    /// worker. This method transfers Initial ownership only after admission
    /// succeeds and overrides the per-connection server CID with the unique
    /// value registered in the dispatcher.
    pub fn beginHandshakeAdmission(
        self: *HandshakeServer,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
        event: *quic.endpoint_dispatcher.Event,
        options: HandshakeAdmissionOptions,
    ) HandshakeAdmissionError!HandshakeAdmission {
        if (event.* != .new_initial) return error.InvalidHandshakeFlight;
        const admitted = event.new_initial;
        const inbox = try dispatcher.admitPendingHandshake(
            handle,
            admitted,
            options.max_pending_handshakes,
            options.inbox_capacity,
        );
        errdefer {
            _ = dispatcher.unregisterPendingHandshake(handle) catch false;
            inbox.deinit();
            self.allocator.destroy(inbox);
        }
        var result = HandshakeAdmission{
            .dispatcher = dispatcher,
            .handle = handle,
            .inbox = inbox,
            .initial = event.takeNewInitial().?,
            .server_connection_id = undefined,
            .deadline_ns = handshakeAdmissionDeadlineNs(
                self.quic_server.endpoint.io,
                options.handshake_timeout_ms,
                self.handshake_options.handshake_recovery.budgetMillis(),
            ),
        };
        @memcpy(
            &result.server_connection_id,
            inbox.connectionIds()[1].slice(),
        );
        return result;
    }

    pub fn acceptAdmission(
        self: *HandshakeServer,
        admission: *HandshakeAdmission,
    ) HandshakeWorkerError!HandshakeServerSession {
        var options = self.handshake_options;
        options.local_connection_id = admission.serverConnectionId();
        var established = try quic.handshake
            .acceptFromInitialSourceWithDeadline(
            &self.quic_server.endpoint,
            admission.datagramSource(),
            admission.takeInitial(),
            options,
            admission.deadline(),
        );
        errdefer established.deinit();
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    pub fn promoteAdmission(
        self: *HandshakeServer,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        admission: *HandshakeAdmission,
        connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
        session: *HandshakeServerSession,
    ) HandshakeAdmissionError!void {
        _ = self;
        try dispatcher.promotePendingHandshake(
            admission.handle,
            connection_handle,
            &session.established.connection,
        );
        admission.registered = false;
    }

    /// Accept one authenticated QUIC connection and serve up to
    /// `max_requests` HTTP/3 requests on it. The handler runs serially because
    /// a `HandshakeServerSession` owns one mutable QUIC/QPACK state machine;
    /// multiplexed applications that need independent scheduling can retain
    /// the lower-level request-event APIs.
    pub fn serveConnection(
        self: *HandshakeServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
        max_requests: usize,
    ) Error!usize {
        var session = try self.accept();
        defer session.deinit();
        const served = try session.serve(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
        if (served != 0) {
            session.waitForRecoveryIdleWithTimeout(
                self.serve_connection_recovery_drain_timeout,
            ) catch |err| switch (err) {
                error.Timeout => return error.RecoveryDrainTimeout,
                error.ConcurrencyUnavailable => return error.RecoveryDrainUnavailable,
                else => |other| return @errorCast(other),
            };
        }
        return served;
    }
};

pub const HandshakeServerSession = struct {
    established: quic.handshake.EstablishedConnection,
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
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ServerRequestLifecycle,
    connect_datagrams: connect_datagram.Registry,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    push_send_scratch: PushSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
    sent_push_ids: std.ArrayList(u64) = .empty,
    peer_promised_push_ids: std.ArrayList(u64) = .empty,
    next_push_stream_id: u62 = first_server_push_stream_id,

    pub fn initEstablished(
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeServerSession {
        try validateHandshakeSessionOptions(options);
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        const allocator = established.connection.endpoint.allocator;
        return .{
            .established = established,
            .options = options,
            .control = try .init(.{
                .max_priority_updates = options.max_priority_updates,
            }),
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                options.max_stream_buffer,
            ),
            .request_streams = .init(
                allocator,
                options.max_stream_buffer,
                options.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.local_settings,
                .request,
            ),
            .request_lifecycle = .init(allocator),
            .connect_datagrams = .init(allocator, .{
                .max_associations = options.max_concurrent_request_streams,
                .max_queued_per_association = options.max_queued_connect_datagrams,
                .max_queued_bytes_per_association = options.max_queued_connect_datagram_bytes,
            }),
            .outbound_bodies = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
        };
    }

    pub fn initPreconfigured(
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        options: HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!HandshakeServerSession {
        try validateBlockedStreamLimit(
            options.local_settings,
            options.max_concurrent_request_streams,
        );
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

    pub fn openServerUnidirectionalStreamWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
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
        self.sent_push_ids.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.peer_promised_push_ids.deinit(
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

    pub fn receiveRequest(self: *HandshakeServerSession) Error!OwnedHandshakeRequest {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveRequestInternal(deadline);
    }

    fn receiveRequestInternal(
        self: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeRequest {
        if (self.streaming_requests.retainedCount() != 0) {
            return error.UnexpectedStream;
        }
        const assembled = receiveConnectionRequestStreamBytesUntil(
            &self.established.connection,
            &self.receive_packets,
            self.options,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.request_streams,
            &self.request_lifecycle,
            self.peer_promised_push_ids.items,
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
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        if (requestEndedBeforeHeaders(assembled.bytes)) {
            self.failReceivedRequest(
                assembled.stream_id,
                assembled.bytes,
                error.RequestIncomplete,
                true,
            ) catch {};
            return error.RequestIncomplete;
        }
        var request = http3.decodeRequestWithDynamicTable(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.options.local_settings,
            self.qpack_decode.table,
        ) catch |err| {
            self.failReceivedRequest(
                assembled.stream_id,
                assembled.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        errdefer request.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.prepareSectionAcknowledgments(
            request.qpack_section_acknowledgments,
        );
        try prepareServerRequestReceived(&self.request_lifecycle);
        _ = try self.established.connection
            .requestCompletedPeerStreamRelease(assembled.stream_id);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        self.request_streams.remove(assembled.stream_id);
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
        if (response.request_method == null) {
            response.request_method = request.request.method;
            response.extended_connect = requestHasProtocol(
                request.request.headers,
            );
        }
        try self.sendResponsePaced(request.stream_id, response);
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
        if (max_requests == 0) return 0;
        var served: usize = 0;
        while (served < max_requests) : (served += 1) {
            _ = try self.serveOne(HandlerContext, context, handler);
        }
        // Announce graceful shutdown only after the bounded loop has accepted
        // its last request. Sending the maximum-ID GOAWAY up front is useful
        // for externally-triggered shutdown, but may legitimately cause a
        // client to stop creating requests before this convenience loop has
        // reached its caller-selected count.
        try self.initiateShutdown();
        try self.completeShutdown();
        return served;
    }

    /// Poll one event from any multiplexed request stream without aggregating
    /// DATA payloads. The returned stream ID is then used with
    /// `readRequestData`, matching tquic's poll/recv_body split while retaining
    /// netz's owned decoded heads and dynamic trailers.
    pub fn receiveRequestEvent(
        self: *HandshakeServerSession,
    ) Error!StreamingRequestEvent {
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
        return self.pollRequestEventMatching(null);
    }

    /// Return an already-buffered event for one request stream without
    /// advancing another stream's event cursor.
    pub fn pollRequestEventFor(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(stream_id);
    }

    fn pollRequestEventMatching(
        self: *HandshakeServerSession,
        target_stream_id: ?u62,
    ) Error!?StreamingRequestEvent {
        try self.releaseStreamingRequestCapacity();
        if (if (target_stream_id) |stream_id|
            self.streaming_requests.takeReset(stream_id)
        else
            self.streaming_requests.takeFirstReset()) |reset|
        {
            finishServerRequest(&self.control, &self.request_lifecycle, reset.stream_id);
            self.qpack_encode.abandonStream(reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            return .{ .reset = .{
                .from = reset.from,
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.qpack_decode.prepareSectionAcknowledgments(1);
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
            ) catch |err| {
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

    /// Apply an already authenticated packet delivered by the endpoint-wide
    /// QUIC dispatcher. The packet remains caller-owned. ACK policy and QPACK
    /// feedback match the blocking receive path, but no socket read occurs.
    pub fn processRequestPacket(
        self: *HandshakeServerSession,
        packet: *const quic.one_rtt.ReceivedPacket,
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
        try visitStreamingServerRequestPacket(
            self,
            packetView(packet.*),
        );
        try self.flushRequestPacketFeedback();
    }

    pub fn readRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return read;
    }

    pub fn skipRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return skipped;
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
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        var removed = self.streaming_requests.takeEntry(stream_id) orelse
            return error.UnexpectedStream;
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
        try self.connect_datagrams.register(stream_id);
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
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.receive_packets.visit(
            &self.established.connection,
            .{ self, detached_stream_id },
            visitDetachedServerRequestPacket,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    pub fn receiveDetachedRequestProgressWithTimeout(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
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
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.receive_packets.visitWithDeadline(
            &self.established.connection,
            deadline,
            .{ self, detached_stream_id },
            visitDetachedServerRequestPacket,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
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
            .{ self, detached_stream_id },
            packetView(packet.*),
        );
        try self.flushRequestPacketFeedback();
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

    pub fn sendConnectDatagram(
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.sendDatagram(encoded);
    }

    pub fn sendConnectDatagramWithTimeout(
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        while (true) {
            // A packet processed while waiting can close/reset the detached
            // CONNECT stream. Recheck before every retry so congestion relief
            // cannot race a terminal association into a late send.
            try self.validateConnectDatagramSend(stream_id, payload);
            self.established.connection.trySendDatagramWithDeadline(
                encoded,
                deadline,
            ) catch |err| switch (err) {
                error.CongestionLimited => {
                    try self.receiveDetachedRequestProgressWithDeadline(
                        stream_id,
                        deadline,
                    );
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    /// One deadline-bounded attempt for a shared endpoint owner. This method
    /// never reads UDP; `CongestionLimited` tells the dispatcher loop to route
    /// more packets before retrying with the same deadline.
    pub fn trySendConnectDatagramWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.trySendDatagramWithDeadline(
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

    pub fn receiveConnectDatagram(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!OwnedConnectDatagram {
        return receiveConnectDatagramFromSession(self, stream_id, null) catch |err|
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
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveConnectDatagramFromSession(self, stream_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveConnectDatagramWithDeadline(
        self: *HandshakeServerSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedConnectDatagram {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramFromSession(self, stream_id, deadline);
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
        try self.sendResponseWithInformational(stream_id, &.{}, response);
    }

    /// Blocking aggregate-response helper for convenience serving loops. It
    /// sends the response body in bounded chunks and pumps ACK and MAX_*
    /// packets whenever body or trailer transmission exhausts peer credit.
    pub fn sendResponsePaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.sendResponsePacedUntil(stream_id, response, deadline);
    }

    fn sendResponsePacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try response.validateBodySemantics();
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connectionIo(),
                absolute,
            );
        }
        try self.startResponseInternal(
            stream_id,
            .{
                .status = response.status,
                .headers = response.headers,
                .request_method = response.request_method,
                .extended_connect = response.extended_connect,
            },
            response.body.len,
            response.trailers.len != 0,
        );
        if (!response.suppressesBody() and response.body.len != 0) {
            try self.sendResponseBodyPacedUntil(
                stream_id,
                response.body,
                response.trailers.len == 0,
                deadline,
            );
        }
        if (!response.suppressesBody() and response.trailers.len != 0) {
            try self.finishResponseTrailersPacedUntil(
                stream_id,
                response.trailers,
                deadline,
            );
        }
    }

    pub fn sendResponseWithPush(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        const push_stream_id = self.next_push_stream_id;
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
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try self.peer_promised_push_ids.ensureUnusedCapacity(
            self.established.connection.endpoint.allocator,
            1,
        );
        try validateNewServerPush(
            self.control,
            self.sent_push_ids.items,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
        try self.sent_push_ids.ensureUnusedCapacity(
            self.established.connection.endpoint.allocator,
            1,
        );
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
        self.sent_push_ids.appendAssumeCapacity(push.push_id);
        self.peer_promised_push_ids.appendAssumeCapacity(push.push_id);
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
        return self.startResponseInternal(
            stream_id,
            response,
            body_length,
            false,
        );
    }

    fn startResponseInternal(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        trailers_pending: bool,
    ) Error!void {
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
        const streaming = try prepared.value.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.established.connection.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
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
        if (!streaming.body_allowed or
            (!trailers_pending and streaming.expected_length == 0))
        {
            finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        }
    }

    pub fn sendResponseBody(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
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

    fn sendResponseBodyPacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (data.len == 0) {
            try self.sendResponseBodyPacedChunkUntil(
                stream_id,
                data,
                fin,
                deadline,
            );
            return;
        }
        const chunk_limit = pacedBodyChunkLimit(self.options);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendResponseBodyPacedChunkUntil(
                stream_id,
                data[offset..end],
                fin and end == data.len,
                deadline,
            );
            offset = end;
        }
    }

    /// Send one logical Extended CONNECT byte sequence as consecutive HTTP/3
    /// DATA contributions. This avoids joining a small protocol header and a
    /// borrowed payload in the adapter while retaining the normal paced send
    /// behavior and one final FIN decision.
    pub fn sendResponseBodyPartsPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        if (non_empty == 0) {
            try self.sendResponseBodyPaced(stream_id, &.{}, fin);
            return;
        }
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            try self.sendResponseBodyPaced(
                stream_id,
                part,
                fin and sent == non_empty,
            );
        }
    }

    /// Batched counterpart to `sendResponseBodyPaced` for concurrent response
    /// streams. Each contribution becomes one QUIC packet and the socket-visible
    /// prefix commits atomically into the corresponding body stream states.
    pub fn sendResponseBodyBatchPaced(
        self: *HandshakeServerSession,
        chunks: []const BodyChunk,
    ) Error!void {
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
            if (self.outbound_bodies.find(response.stream_id) == null) {
                return error.UnexpectedStream;
            }
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
            const selection = self.refreshResponseCandidates(
                responses,
                candidates,
                chunk_limit,
            ) orelse {
                try self.receiveRequestPacket();
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
                try self.receiveRequestPacket();
                continue;
            }

            const sent_count = sendConnectionBodyBatchPacedProgress(
                &self.established.connection,
                &self.outbound_bodies,
                workspace.chunks(),
                self.options,
                self,
                HandshakeServerSession.finishBatchResponseStream,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacket();
                    continue;
                },
                error.PacingLimited => {
                    try self.established.connection
                        .waitForPacingAvailability();
                    continue;
                },
                else => return err,
            };
            const commit = workspace.commitSentPrefix(sent_count);
            remaining_responses -= commit.completed_responses;
            delay_budget.record(commit.body_bytes, sent_count);
            if (self.options.response_scheduler_batch_delay_ns != 0 and
                delay_budget.due(
                    self.options.response_scheduler_batch_delay_bytes,
                    self.options.response_scheduler_batch_delay_packets,
                ))
            {
                const delay_ns = std.math.cast(
                    i64,
                    self.options.response_scheduler_batch_delay_ns,
                ) orelse std.math.maxInt(i64);
                try std.Io.sleep(
                    self.established.connection.endpoint.io,
                    .fromNanoseconds(delay_ns),
                    .awake,
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
            self.sendResponseBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn finishResponseTrailers(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
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
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
                return cancel;
            }
            try self.receiveRequestPacket();
        }
    }

    fn finishPeerResponseCancellation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?PeerResponseCancellation {
        const stopped = self.established.connection.streamStopped(stream_id) orelse
            return null;
        // Do the only fallible cleanup first. If sending MAX_STREAMS is
        // temporarily blocked, the caller can retry without losing the
        // cancellation or partially retiring HTTP/3 bookkeeping.
        _ = try self.established.connection.releaseCompletedPeerStream(
            stream_id,
        );
        self.qpack_encode.abandonStream(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        return .{
            .stream_id = stream_id,
            .application_error_code = stopped.application_error_code,
        };
    }

    /// Blocking counterpart to `finishResponseTrailers` that keeps receiving
    /// request-side packets until the response trailers can be written.
    pub fn finishResponseTrailersPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        return self.finishResponseTrailersPacedUntil(
            stream_id,
            trailers,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn finishResponseTrailersPacedUntil(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        while (true) {
            self.finishResponseTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketUntil(deadline);
                    continue;
                },
                else => return err,
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
        try sendConnectionResponseSequence(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
            stream_id,
            informational,
            prepared.value,
            self.options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    pub fn sendGoAway(self: *HandshakeServerSession, stream_id: u64) Error!void {
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

    /// Advertise RFC 9412 origins on the server control stream. Clients must
    /// still validate certificate authority before coalescing requests.
    pub fn sendOrigins(
        self: *HandshakeServerSession,
        origins: []const []const u8,
    ) Error!void {
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
        try sendConnectionFrames(
            &self.established.connection,
            self.critical_stream_send_scratch.frames.items,
            self.options.max_frames_per_packet,
        );
    }

    pub fn initiateShutdown(self: *HandshakeServerSession) Error!void {
        if (self.request_lifecycle.state() != .active) return;
        try self.sendGoAway(@as(u64, quic.varint.max_value) & ~@as(u64, 0x3));
        self.request_lifecycle.markInitialGoAwaySent();
    }

    pub fn completeShutdown(self: *HandshakeServerSession) Error!void {
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (!self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAway(try self.request_lifecycle.finalGoAwayId());
        self.request_lifecycle.markFinalGoAwaySent();
    }

    pub fn drainComplete(self: HandshakeServerSession) bool {
        return self.request_lifecycle.drainComplete(
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
        return self.cancelRequestInternal(
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
        var cancel_qpack = decoded_dynamic_section;
        if (!cancel_qpack) {
            cancel_qpack = try self.request_streams.requiresQpackCancellation(
                stream_id,
                self.qpack_decode.table,
            );
        }
        if (!cancel_qpack) {
            cancel_qpack =
                try self.streaming_requests.hasUnacknowledgedDynamicSection(
                    stream_id,
                    self.qpack_decode.table,
                );
        }
        defer {
            self.request_streams.remove(stream_id);
            self.streaming_requests.remove(stream_id);
            self.qpack_encode.abandonStream(stream_id);
            finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
            _ = self.outbound_bodies.finish(stream_id);
        }
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
    }

    pub fn rejectRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        try self.cancelRequest(
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
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
        const exists = self.request_lifecycle.contains(stream_id) or
            self.request_streams.contains(stream_id) or
            self.streaming_requests.contains(stream_id) or
            self.outbound_bodies.find(stream_id) != null;
        if (!exists) return error.UnexpectedStream;
        var cancel_qpack = try self.request_streams.requiresQpackCancellation(
            stream_id,
            self.qpack_decode.table,
        );
        cancel_qpack = cancel_qpack or
            try self.streaming_requests.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            );
        if (self.streaming_requests.find(stream_id)) |entry| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
        try self.established.connection.sendStopSending(
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        );
        if (cancel_qpack) {
            try self.qpack_decode.recordStreamCancellation(stream_id);
        }
        self.request_streams.remove(stream_id);
        self.streaming_requests.remove(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        try self.sendQpackFeedback();
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
        self.qpack_encode.abandonStream(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    fn receiveRequestPacket(self: *HandshakeServerSession) Error!void {
        return self.receiveRequestPacketUntil(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn receiveRequestPacketUntil(
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
        // Encoder-stream inserts and reset cancellations both queue decoder
        // instructions. Flush them at the packet boundary so a peer does not
        // remain artificially blocked until another HEADERS event appears.
        try self.flushRequestPacketFeedback();
    }

    fn flushRequestPacketFeedback(self: *HandshakeServerSession) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    /// Process one transport packet for control-stream progress without
    /// requiring a complete application request to become ready.
    pub fn pollControl(self: *HandshakeServerSession) Error!void {
        try self.receiveRequestPacket();
    }

    pub fn pollControlWithTimeout(
        self: *HandshakeServerSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        while (self.established.connection.pendingDeliveryRecovery()) {
            try self.receiveRequestPacketUntil(deadline);
        }
    }

    fn applyStreamingRequestEvent(
        self: *HandshakeServerSession,
        entry: *StreamingRequestSet.Entry,
        event: StreamingEvent,
    ) Error!StreamingRequestEvent {
        const stream_id = entry.reader.streamId();
        const from = entry.from orelse unreachable;
        if (try streamingRequestSectionAcknowledgments(event)) |count| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                stream_id,
                count,
            );
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
            .value = event,
        } };
    }

    fn releaseStreamingRequestCapacity(
        self: *HandshakeServerSession,
    ) Error!void {
        var index: usize = 0;
        while (self.streaming_requests.entryAt(index)) |entry| : (index += 1) {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    fn connectionIo(self: *const HandshakeServerSession) std.Io {
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
};

pub const HandshakeClient = struct {
    endpoint: *quic.runtime.Endpoint,
    owns_endpoint: bool,
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
    push_streams: PushStreamSet,
    push_aggregate: ClientPushAggregateState = .{},
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ClientRequestLifecycle,
    connect_datagrams: connect_datagram.Registry,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
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

    pub fn openClientBidirectionalStreamWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
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

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, options: HandshakeClientOptions) Error!HandshakeClient {
        return connectBefore(
            allocator,
            io,
            local_address,
            server,
            limits,
            options,
            try connectDeadline(io, options.connect_timeout),
        );
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
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options.session);
        try validateBlockedStreamLimit(
            options.session.local_settings,
            options.session.max_concurrent_request_streams,
        );
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
        return initOwnedEstablished(
            allocator,
            endpoint,
            server,
            established,
            options.session,
        );
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

    fn connectFromBefore(
        endpoint: *quic.runtime.Endpoint,
        source: quic.runtime.DatagramSource,
        server: net.IpAddress,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options.session);
        try validateBlockedStreamLimit(
            options.session.local_settings,
            options.session.max_concurrent_request_streams,
        );
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
        return initEstablishedWithEndpointOwnership(
            endpoint.allocator,
            endpoint,
            false,
            server,
            established,
            options.session,
        );
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
        try validateBlockedStreamLimit(
            options.local_settings,
            options.max_concurrent_request_streams,
        );
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
    ) Error!HandshakeClient {
        return initEstablishedWithEndpointOwnership(
            allocator,
            endpoint,
            true,
            peer,
            established,
            options,
        );
    }

    fn initEstablishedWithEndpointOwnership(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        owns_endpoint: bool,
        peer: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeClient {
        try validateHandshakeSessionOptions(options);
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .endpoint = endpoint,
            .owns_endpoint = owns_endpoint,
            .peer = peer,
            .allocator = allocator,
            .established = established,
            .options = options,
            .control = try .init(.{
                .max_priority_updates = options.max_priority_updates,
            }),
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                options.max_stream_buffer,
            ),
            .response_streams = .init(
                allocator,
                options.max_stream_buffer,
                options.max_concurrent_request_streams,
            ),
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.max_informational_responses,
                options.local_settings,
                .response,
            ),
            .push_streams = .initWithInformationalLimit(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.max_informational_responses,
                options.local_settings,
            ),
            .request_lifecycle = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
            .connect_datagrams = .init(allocator, .{
                .max_associations = options.max_concurrent_request_streams,
                .max_queued_per_association = options.max_queued_connect_datagrams,
                .max_queued_bytes_per_association = options.max_queued_connect_datagram_bytes,
            }),
            .outbound_bodies = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
        };
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
        try validateBlockedStreamLimit(
            options.local_settings,
            options.max_concurrent_request_streams,
        );
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
        );
    }

    /// Try every DNS result that can be reached from `local_address`.
    ///
    /// Public HTTP/3 origins often publish many CDN anycast addresses.  A
    /// single edge can temporarily black-hole UDP/443, which otherwise surfaces
    /// as a QUIC `HandshakeTimeout` even though another address from the same
    /// DNS answer is healthy.  This helper keeps protocol/authentication errors
    /// fail-fast, but treats path-level failures as per-address and falls back
    /// to the next resolved endpoint before giving up.
    fn connectAnyResolvedAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!HandshakeClient {
        if (servers.len == 0) return error.NoAddressReturned;

        var attempted = false;
        var last_err: ?Error = null;
        for (servers) |server| {
            if (!sameIpAddressFamily(local_address, server)) continue;
            attempted = true;
            var attempt_options = options;
            if (deadline) |absolute| {
                attempt_options.handshake.handshake_recovery =
                    try handshakeRecoveryBefore(
                        io,
                        absolute,
                        options.handshake.handshake_recovery,
                    );
            }
            return connect(
                allocator,
                io,
                local_address,
                server,
                limits,
                attempt_options,
            ) catch |err| {
                last_err = err;
                if (shouldTryNextResolvedAddress(err)) continue;
                return err;
            };
        }
        if (!attempted) return error.AddressFamilyUnsupported;
        return last_err orelse error.NoAddressReturned;
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
        const servers = try resolveEndpointBefore(
            endpoint,
            allocator,
            io,
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
        const servers = try resolveEndpointBefore(
            endpoint,
            allocator,
            io,
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
        const servers = try resolveEndpointBefore(
            endpoint,
            allocator,
            io,
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
        const deadline = try connectDeadline(io, options.connect_timeout);
        if (!http3.isHttp3Alpn(target.alpn)) return error.InvalidHeader;
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        const path = try uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);
        const servers = try resolveHostPortAddressesBefore(
            allocator,
            io,
            target.connect_host,
            target.port,
            deadline,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.connect_timeout = null;
        connect_options.handshake.server_name = origin.tls_host;
        connect_options.handshake.alpn_protocols = &.{target.alpn};
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
            .authority = origin.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        });
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
        self.critical_stream_send_scratch.deinit(self.allocator);
        self.stream_send_scratch.deinit(self.allocator);
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

    pub fn peerGoAwayId(self: HandshakeClient) ?u64 {
        return self.control.peer_goaway_id;
    }

    /// Return whether this connection can move into an exclusive idle pool.
    /// HTTP/3 compression/control state is intentionally retained, but no
    /// application request, response, push, reset, or outbound body may leak
    /// into the next lease. A GOAWAY or QUIC close state is never reusable.
    pub fn isReusable(self: *const HandshakeClient) bool {
        return self.control.peer_goaway_id == null and
            !self.established.connection.closed() and
            !self.established.connection.closing() and
            !self.established.connection.draining() and
            self.request_lifecycle.isEmpty() and
            self.outbound_bodies.isEmpty() and
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        const stream_id = try self.sendRequest(request_options);
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

    /// Send a request and observe ordered 1xx heads before the final response.
    pub fn requestWithInformational(
        self: *HandshakeClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedHandshakeResponse {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        const stream_id = try self.sendRequest(request_options);
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
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        const reserved = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(reserved == stream_id);

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
        try sendConnectionMessage(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
            stream_id,
            request_options,
            self.options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        return stream_id;
    }

    pub fn startRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        const reserved = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(reserved == stream_id);
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
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendConnectionStreamingHead(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            false,
            self.options,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.outbound_bodies,
        );
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
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
        if (data.len == 0) {
            try self.sendRequestBodyPacedChunk(stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedBodyChunkLimit(self.options);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendRequestBodyPacedChunk(
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    /// Client counterpart to `sendResponseBodyPartsPaced`.
    pub fn sendRequestBodyPartsPaced(
        self: *HandshakeClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        if (non_empty == 0) {
            try self.sendRequestBodyPaced(stream_id, &.{}, fin);
            return;
        }
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            try self.sendRequestBodyPaced(
                stream_id,
                part,
                fin and sent == non_empty,
            );
        }
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

    fn receiveBatchProgressForSend(self: *HandshakeClient) Error!void {
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
        );
        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) return;
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(reset.stream_id);
            _ = self.request_lifecycle.finishAssumeCapacity(reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            self.qpack_encode.abandonStream(reset.stream_id);
            self.sendQpackFeedback() catch {};
            return responseResetError(reset.application_error_code);
        }
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

    /// Blocking counterpart to `finishRequestTrailers` that keeps processing
    /// response-side ACK/MAX_* packets until the trailer section is writable.
    pub fn finishRequestTrailersPaced(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
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
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        const assembled = receiveConnectionResponseStreamBytesUntil(
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
            deadline,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.qpack_encode.abandonStream(stream_id);
                self.sendQpackFeedback() catch {};
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
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        if (assembled.bytes.len == 0) {
            self.failReceivedResponse(
                stream_id,
                assembled.bytes,
                error.MissingStatus,
                true,
            ) catch {};
            return error.MissingStatus;
        }
        http3.validateResponsePushPromises(
            self.control,
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                assembled.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        const section_count = responseFieldSectionCount(
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                assembled.bytes,
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
            assembled.stream_id,
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                assembled.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        var response = http3.decodeResponseWithDynamicTableAndOptions(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.options.max_informational_responses;
                options.informational = informational;
                break :blk options;
            },
        ) catch |err| {
            self.failReceivedResponse(
                stream_id,
                assembled.bytes,
                err,
                true,
            ) catch {};
            return err;
        };
        errdefer response.deinit(self.established.connection.endpoint.allocator);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        self.response_streams.remove(stream_id);
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.sendQpackFeedback() catch {};
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn receiveNextResponse(
        self: *HandshakeClient,
    ) Error!OwnedHandshakeResponseEvent {
        return self.receiveNextResponseWithInformational(null);
    }

    /// Aggregate whichever outstanding response becomes ready within one
    /// relative budget. A timeout leaves every request eligible for later
    /// aggregate or incremental consumption.
    pub fn receiveNextResponseWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeResponseEvent {
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
                    self.qpack_encode.abandonStream(reset.stream_id);
                    self.sendQpackFeedback() catch {};
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
        return self.receivePeerSettingsInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receivePeerSettingsWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!http3.Settings {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receivePeerSettingsInternal(deadline);
    }

    fn receivePeerSettingsInternal(
        self: *HandshakeClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!http3.Settings {
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
        try self.processResponsePacketPreserving(null, packet);
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
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id)) |active| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &active.reader,
            );
        }
        if (self.response_streams.resetFor(stream_id)) |code| {
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(stream_id);
            self.finishStreamingResponse(stream_id);
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
        const event = (entry.reader.next(self.qpack_decode.table) catch |err| {
            self.failReceivedResponse(stream_id, null, err, false) catch {};
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
        self.applyStreamingResponseEvent(stream_id, owned_event) catch |err| {
            self.failReceivedResponse(stream_id, null, err, false) catch {};
            return err;
        };
        event_owned = false;
        return owned_event;
    }

    pub fn receiveResponseEventWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return self.receiveResponseEventInternal(stream_id, deadline);
    }

    pub fn receiveResponseEventWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!?StreamingEvent {
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
            deadline,
        );
        try self.flushResponsePacketFeedback();
        return self.pollResponseEvent(stream_id);
    }

    fn connectionIo(self: *const HandshakeClient) std.Io {
        return self.established.connection.endpoint.io;
    }

    /// Copy currently available DATA bytes into caller-owned storage.
    ///
    /// Returning zero means the current DATA frame needs more STREAM bytes;
    /// call `receiveResponseEvent` again to pump another packet.
    pub fn readResponseData(
        self: *HandshakeClient,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return read;
    }

    pub fn skipResponseData(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return skipped;
    }

    /// Detach an established Extended CONNECT response stream from HTTP/3
    /// message parsing after final response HEADERS have been consumed.
    pub fn detachResponseStream(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
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
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
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
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        self.receiveDetachedResponseProgressInternal(
            detached_stream_id,
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.receiveDetachedResponseProgressInternal(
            detached_stream_id,
            deadline,
        );
    }

    fn receiveDetachedResponseProgressInternal(
        self: *HandshakeClient,
        detached_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
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
        try self.flushResponsePacketFeedback();
    }

    pub fn connectDatagramsNegotiated(self: HandshakeClient) bool {
        return self.control.settings.sent and
            self.control.settings.received and
            self.control.settings.local.h3_datagram and
            self.control.settings.peer.h3_datagram and
            self.established.connection.datagramsEnabled();
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

    pub fn sendConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
    ) Error!void {
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        try self.established.connection.sendDatagram(encoded);
    }

    pub fn sendConnectDatagramWithTimeout(
        self: *HandshakeClient,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        try self.validateConnectDatagramSend(stream_id, payload);
        const encoded = try self.connect_datagrams.encode(stream_id, payload);
        while (true) {
            try self.validateConnectDatagramSend(stream_id, payload);
            self.established.connection.trySendDatagramWithDeadline(
                encoded,
                deadline,
            ) catch |err| switch (err) {
                error.CongestionLimited => {
                    try self.receiveDetachedResponseProgressWithDeadline(
                        stream_id,
                        deadline,
                    );
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
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

    pub fn receiveConnectDatagram(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!OwnedConnectDatagram {
        return receiveConnectDatagramFromSession(self, stream_id, null) catch |err|
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
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveConnectDatagramFromSession(self, stream_id, .fromNow(
            self.connectionIo(),
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveConnectDatagramWithDeadline(
        self: *HandshakeClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedConnectDatagram {
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        return receiveConnectDatagramFromSession(self, stream_id, deadline);
    }

    pub fn closeConnectDatagramAssociation(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
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
        if (!self.request_lifecycle.contains(detached_stream_id)) {
            return error.UnexpectedStream;
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
                self.failReceivedResponse(
                    detached_stream_id,
                    bytes,
                    err,
                    true,
                ) catch {};
                return err;
            },
        };
        errdefer head.deinit(self.allocator);
        http3.validateResponsePushPromises(
            self.control,
            bytes[0..head.consumed],
        ) catch |err| {
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
        errdefer if (rejection_receive) |*receive| receive.deinit();
        if (rejection_receive) |*receive| {
            try receive.consume(head.consumed);
        }
        try self.qpack_decode.decoder_instructions.ensureUnusedCapacity(
            self.qpack_decode.allocator,
            11 *| head.qpack_section_acknowledgments,
        );
        const promise_checkpoint = self.push_streams.promiseCount();
        errdefer self.push_streams.rollbackPromises(promise_checkpoint);
        registerResponsePushPromises(
            &self.push_streams,
            detached_stream_id,
            bytes[0..head.consumed],
        ) catch |err| {
            self.failReceivedResponse(
                detached_stream_id,
                bytes[0..head.consumed],
                err,
                true,
            ) catch {};
            return err;
        };
        try self.established.connection.releaseReceivedCapacity(
            detached_stream_id,
            head.consumed,
        );
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
        // The head is committed now. Feedback remains queued if its socket send
        // cannot make progress; later packet/control operations retry it. A
        // transient feedback failure must not turn a successfully consumed
        // final response into an unreturnable error.
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
        if (!self.connect_datagrams.contains(detached_stream_id)) {
            return error.UnexpectedStream;
        }
        try self.processResponsePacketPreserving(
            detached_stream_id,
            packet,
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
        if (!self.request_lifecycle.contains(stream_id) or
            !self.request_lifecycle.responseDecodeOptions(stream_id)
                .extended_connect)
        {
            return error.UnexpectedStream;
        }
        try self.processResponsePacketPreserving(stream_id, packet);
    }

    /// Temporary compatibility hook for protocol adapters that detach only
    /// after constructing their higher-level session object. The stream must
    /// already be a locally opened Extended CONNECT request.
    pub fn registerPendingConnectDatagramAssociation(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
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
        };
        try visitConnectionResponsePacket(&context, packetView(packet.*));
        try self.flushResponsePacketFeedback();
    }

    fn flushResponsePacketFeedback(self: *HandshakeClient) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    fn releaseStreamingResponseCapacity(self: *HandshakeClient) Error!void {
        var index: usize = 0;
        while (self.streaming_responses.entryAt(index)) |entry| : (index += 1) {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    /// Poll one promised response without aggregating its DATA payload.
    pub fn receivePushEvent(
        self: *HandshakeClient,
    ) Error!StreamingPushEvent {
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
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.pollPushEventMatching(null);
    }

    /// Wait for an event from any promised push within one relative budget.
    pub fn receivePushEventWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingPushEvent {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(null, deadline);
    }

    fn receivePushEventMatching(
        self: *HandshakeClient,
        target_push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        while (true) {
            if (try self.pollPushEventMatching(target_push_id)) |event| {
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
                deadline,
            );
            try self.flushResponsePacketFeedback();
        }
    }

    fn pollPushEventMatching(
        self: *HandshakeClient,
        target_push_id: ?u64,
    ) Error!?StreamingPushEvent {
        var index: usize = 0;
        while (self.push_streams.entryAt(index)) |entry| : (index += 1) {
            if (PushStreamSet.entryReader(entry)) |reader| {
                try releaseStreamingReaderCapacity(
                    &self.established.connection,
                    reader,
                );
            }
        }
        try self.applyPendingPushCancellations();
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        const ready = self.push_streams.next(
            self.qpack_decode.table,
            self.options.local_settings.qpack_blocked_streams,
            target_push_id,
        ) catch |err| {
            if (self.push_streams.lastErrorStreamId()) |stream_id| {
                if (messageStreamErrorCode(err)) |code| {
                    const cancel_qpack = self.push_streams
                        .hasUnacknowledgedDynamicSection(
                        stream_id,
                        self.qpack_decode.table,
                    ) catch false;
                    if (cancel_qpack) {
                        self.qpack_decode.recordStreamCancellation(
                            stream_id,
                        ) catch {};
                    }
                    self.established.connection.sendStopSending(
                        stream_id,
                        code,
                    ) catch {};
                    self.push_streams.failStream(stream_id);
                    self.sendQpackFeedback() catch {};
                    return err;
                }
            }
            if (runtime_error.protocolClose(err) != null) {
                closeConnectionForHttp3Error(
                    &self.established.connection,
                    err,
                ) catch {};
            }
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
            self.flushResponsePacketFeedback() catch {};
        }
        if (event.value == .finished) {
            self.push_streams.removeFinished(ready.index);
        }
        return event;
    }

    fn applyPendingPushCancellations(
        self: *HandshakeClient,
    ) Error!void {
        while (self.push_streams.firstCancelledStream()) |stream_id| {
            try self.established.connection.sendStopSending(
                stream_id,
                http3.ApplicationErrorCode.request_cancelled,
            );
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
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader.?,
        );
        return entry.reader.?.readData(out);
    }

    pub fn skipPushData(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!usize {
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        const reader = if (entry.reader) |*value| value else return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            reader,
        );
        const skipped = try reader.skipData();
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            reader,
        );
        return skipped;
    }

    pub fn receivePush(
        self: *HandshakeClient,
    ) Error!PushedResponse {
        return self.receivePushWithInformational(null);
    }

    /// Aggregate one promised response within a relative budget. The partial
    /// head, body, trailers, and reader remain owned by the client on timeout.
    pub fn receivePushWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PushedResponse {
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
        return self.receivePushWithInformationalAndDeadline(null, deadline);
    }

    /// Aggregate one promised response while reporting its ordered 1xx heads.
    pub fn receivePushWithInformational(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
    ) Error!PushedResponse {
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
        return push_aggregate.receive(
            self,
            &self.push_aggregate,
            self.allocator,
            informational,
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
        if (self.request_lifecycle.isEmpty()) {
            return null;
        }
        try self.releaseStreamingResponseCapacity();
        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) {
                return error.UnexpectedStream;
            }
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(reset.stream_id);
            self.finishStreamingResponse(reset.stream_id);
            self.flushResponsePacketFeedback() catch {};
            return .{ .reset = .{
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.request_lifecycle.prepareFinish();
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        const ready_value = self.streaming_responses.nextResponse(
            &self.response_streams,
            self.qpack_decode.table,
            self.options.local_settings.qpack_blocked_streams,
        ) catch |err| {
            self.failReceivedResponse(
                self.streaming_responses.lastErrorStreamId(),
                null,
                err,
                false,
            ) catch {};
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
                self.failReceivedResponse(
                    stream_id,
                    null,
                    err,
                    false,
                ) catch {};
                return err;
            };
        }
        const owned_event = ready.event;
        self.applyStreamingResponseEvent(stream_id, owned_event) catch |err| {
            self.failReceivedResponse(stream_id, null, err, false) catch {};
            return err;
        };
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
                deadline,
            );
            try self.flushResponsePacketFeedback();
        }
    }

    pub fn sendGoAway(self: *HandshakeClient, stream_id: u64) Error!void {
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

    pub fn peerOrigins(self: HandshakeClient) []const http3.OriginKey {
        return self.control.peerOrigins();
    }

    pub fn peerOriginSetInitialized(self: HandshakeClient) bool {
        return self.control.peerOriginSetInitialized();
    }

    pub fn peerOriginKnown(
        self: HandshakeClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginKnown(origin);
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
        try self.receiveProgress();
    }

    pub fn pollControlWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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
            deadline,
        );
        try self.flushResponsePacketFeedback();
    }

    /// Client-side counterpart to `HandshakeServerSession`'s recovery drain.
    /// It preserves response, push, and detached CONNECT routing while waiting
    /// for all currently retained reliable sends to be acknowledged.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *HandshakeClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
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
        _ = try deadline_policy.usableAwake(self.connectionIo(), deadline);
        while (self.established.connection.pendingRecoveryCount() != 0) {
            try self.pollControlWithDeadline(deadline);
        }
    }

    /// Advertise the inclusive server-push ID limit.
    pub fn sendMaxPushId(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        try self.push_streams.reservePromisesThrough(push_id);
        const previous_max_push_id = self.control.local_max_push_id;
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
        sendConnectionPushControl(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .max_push_id,
            push_id,
        ) catch |err| {
            self.control.local_max_push_id = previous_max_push_id;
            return err;
        };
    }

    pub fn cancelPush(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
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
        try self.push_streams.observePeerCancellation(push_id);
        defer if (self.push_aggregate.push_id == push_id) {
            self.push_aggregate.deinit(self.allocator);
        };
        try self.applyPendingPushCancellations();
    }

    pub fn cancelRequest(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        return self.cancelRequestInternal(
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
        var cancel_qpack = decoded_dynamic_section;
        if (!cancel_qpack) {
            cancel_qpack = try self.response_streams.requiresQpackCancellation(
                stream_id,
                self.qpack_decode.table,
            );
        }
        if (!cancel_qpack) {
            cancel_qpack =
                try self.streaming_responses.hasUnacknowledgedDynamicSection(
                    stream_id,
                    self.qpack_decode.table,
                );
        }
        defer {
            self.connect_datagrams.unregister(stream_id);
            self.qpack_encode.abandonStream(stream_id);
            self.response_streams.remove(stream_id);
            self.streaming_responses.remove(stream_id);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            _ = self.outbound_bodies.finish(stream_id);
        }
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
    }

    /// Best-effort cleanup for an Extended CONNECT adapter that is abandoned
    /// after receiving its response head. Unlike `cancelRequest`, local stream
    /// state is always released so an infallible adapter destructor can return
    /// ownership of this HTTP/3 connection to its caller.
    pub fn abandonExtendedConnect(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        var cancel_qpack = self.response_streams
            .requiresQpackCancellation(
            stream_id,
            self.qpack_decode.table,
        ) catch false;
        cancel_qpack = cancel_qpack or
            (self.streaming_responses.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            ) catch false);
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
        ) catch {};
        self.connect_datagrams.unregister(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = self.request_lifecycle.finish(stream_id) catch false;
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn sendPriorityUpdate(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        // PRIORITY_UPDATE can precede the request itself, which is essential
        // for this synchronous request API: `next_stream_id` is the one request
        // stream that may be prioritized before request() opens it.
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
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

    pub fn sendPushPriorityUpdate(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        if (!self.push_streams.hasPromise(push_id)) {
            return error.UnexpectedStream;
        }
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

    fn receiveResponseProgressForSend(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
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
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.sendQpackFeedback() catch {};
        return responseResetError(code);
    }

    fn applyStreamingResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
        event: StreamingEvent,
    ) Error!void {
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
            self.sendQpackFeedback() catch {};
        }
        if (event == .finished) {
            self.finishStreamingResponse(stream_id);
        }
    }

    fn finishStreamingResponse(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        // Detached CONNECT readers are removed from `streaming_responses` and
        // retain their association until explicit close or peer FIN/reset.
        if (self.streaming_responses.find(stream_id) != null) {
            self.connect_datagrams.unregister(stream_id);
        }
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.streaming_responses.remove(stream_id);
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
};

pub const HandshakeClientPool = handshake_client_pool.Pool(@This());
pub const HandshakeClientPoolOptions =
    handshake_client_pool.Options(@This());
pub const HandshakeClientPoolConnector =
    handshake_client_pool.Connector(@This());
pub const HandshakeClientPoolDefaultConnector =
    handshake_client_pool.DefaultConnectorContext(@This());
pub const HandshakeClientPoolStats = http3.origin_pool.Stats;
pub const HandshakeClientPoolError = handshake_client_pool.Error;

pub const OwnedHandshakeRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedHandshakeRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedHandshakeResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponseEvent = union(enum) {
    response: struct {
        stream_id: u62,
        value: OwnedHandshakeResponse,
    },
    reset: struct {
        stream_id: u62,
        application_error_code: u64,
    },

    pub fn deinit(
        self: *OwnedHandshakeResponseEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .response => |*response| response.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

pub const ProtectedServer = struct {
    quic_server: quic.runtime.Server,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    protected_send: ProtectedSendState,
    request_streams: RequestStreamSet,
    streaming_requests: StreamingRequestSet,
    receive_packets: ProtectedPacketCursor = .{},
    request_lifecycle: ServerRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    push_send_scratch: PushSendScratch = .{},
    sent_push_ids: std.ArrayList(u64) = .empty,
    peer_promised_push_ids: std.ArrayList(u64) = .empty,
    next_push_stream_id: u62 = first_server_push_stream_id,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedServer {
        try validateProtectedConfig(config);
        try validateBlockedStreamLimit(
            config.local_settings,
            limits.max_concurrent_request_streams,
        );
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_server = quic_server,
            .config = config,
            .control = try .init(.{
                .max_priority_updates = config.max_priority_updates,
            }),
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
            // The peer's encoder capacity is not known until its SETTINGS
            // frame arrives. Starting at zero prevents speculative inserts
            // from exceeding an as-yet-unadvertised limit.
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                config.max_stream_buffer,
            ),
            .protected_send = .init(allocator),
            .request_streams = .init(
                allocator,
                config.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.local_settings,
                .request,
            ),
            .request_lifecycle = .init(allocator),
            .outbound_bodies = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
        };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.push_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.stream_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.outbound_bodies.deinit();
        self.sent_push_ids.deinit(self.quic_server.endpoint.allocator);
        self.peer_promised_push_ids.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.receive_packets.deinit();
        self.control.deinit(self.quic_server.endpoint.allocator);
        self.request_lifecycle.deinit();
        self.streaming_requests.deinit();
        self.request_streams.deinit();
        self.protected_send.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *ProtectedServer) Error!OwnedProtectedRequest {
        return self.receiveRequestInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Aggregate the next request within one relative application budget. A
    /// timeout preserves partial STREAM and QPACK state for a later call.
    pub fn receiveRequestWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestInternal(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Aggregate the next request before `deadline` without retiring a
    /// partially received request when the deadline expires.
    pub fn receiveRequestWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedRequest {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestInternal(deadline);
    }

    fn receiveRequestInternal(
        self: *ProtectedServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedRequest {
        if (self.streaming_requests.retainedCount() != 0) {
            return error.UnexpectedStream;
        }
        const assembled = self.receiveStreamBytesUntil(deadline) catch |err| {
            self.failReceivedRequest(
                self.request_streams.lastErrorFrom(),
                self.request_streams.lastErrorStreamId(),
                null,
                err,
                false,
            );
            return err;
        };
        errdefer self.quic_server.endpoint.allocator.free(assembled.bytes);
        if (requestEndedBeforeHeaders(assembled.bytes)) {
            self.failReceivedRequest(
                assembled.from,
                assembled.stream_id,
                assembled.bytes,
                error.RequestIncomplete,
                true,
            );
            return error.RequestIncomplete;
        }
        var request = http3.decodeRequestWithDynamicTable(
            self.quic_server.endpoint.allocator,
            assembled.bytes,
            self.config.local_settings,
            self.qpack_decode.table,
        ) catch |err| {
            self.failReceivedRequest(
                assembled.from,
                assembled.stream_id,
                assembled.bytes,
                err,
                true,
            );
            return err;
        };
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        try self.qpack_decode.prepareSectionAcknowledgments(
            request.qpack_section_acknowledgments,
        );
        try prepareServerRequestReceived(&self.request_lifecycle);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        self.request_streams.remove(assembled.stream_id);
        serverRequestReceivedAssumeCapacity(
            &self.control,
            &self.request_lifecycle,
            assembled.stream_id,
            requestPriority(request.headers),
        );
        self.sendQpackFeedback(assembled.from) catch {};
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    /// Poll the next event from any client request stream.
    ///
    /// Unlike `receiveRequest`, this never aggregates DATA payloads. Once a
    /// head identifies a stream, applications can interleave polling with
    /// `readRequestData`; STREAM ranges for every active request remain bounded
    /// by `ProtectedConfig.max_stream_buffer`.
    pub fn receiveRequestEvent(
        self: *ProtectedServer,
    ) Error!StreamingRequestEvent {
        return self.receiveRequestEventInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveRequestEventWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventInternal(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveRequestEventWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestEventInternal(deadline);
    }

    fn receiveRequestEventInternal(
        self: *ProtectedServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        while (true) {
            if (try self.pollRequestEvent()) |event| return event;
            if (deadline) |absolute| {
                try self.receiveRequestPacketWithDeadline(absolute);
            } else {
                try self.receiveRequestPacket();
            }
        }
    }

    /// Wait for one request stream without consuming events already ready on
    /// siblings. Long-lived Extended CONNECT adapters use this to coexist with
    /// ordinary HTTP requests on the same protected connection.
    pub fn receiveRequestEventFor(
        self: *ProtectedServer,
        stream_id: u62,
    ) Error!StreamingRequestEvent {
        return self.receiveRequestEventForInternal(
            stream_id,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveRequestEventForWithTimeout(
        self: *ProtectedServer,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestEventForInternal(
            stream_id,
            .fromNow(
                self.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveRequestEventForWithDeadline(
        self: *ProtectedServer,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestEventForInternal(stream_id, deadline);
    }

    fn receiveRequestEventForInternal(
        self: *ProtectedServer,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingRequestEvent {
        while (true) {
            if (try self.pollRequestEventFor(stream_id)) |event| return event;
            if (deadline) |absolute| {
                try self.receiveRequestPacketWithDeadline(absolute);
            } else {
                try self.receiveRequestPacket();
            }
        }
    }

    /// Return the next request event already buffered locally without reading
    /// UDP. Consumed DATA credit is emitted first so repeated polling and
    /// `readRequestData` calls continue to advance bounded request windows.
    pub fn pollRequestEvent(
        self: *ProtectedServer,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(null);
    }

    pub fn pollRequestEventFor(
        self: *ProtectedServer,
        stream_id: u62,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(stream_id);
    }

    fn pollRequestEventMatching(
        self: *ProtectedServer,
        target_stream_id: ?u62,
    ) Error!?StreamingRequestEvent {
        var index: usize = 0;
        while (self.streaming_requests.entryAt(index)) |entry| : (index += 1) {
            try sendProtectedReaderCapacity(
                &self.quic_server.endpoint,
                entry.from orelse return error.UnexpectedStream,
                self.config,
                &self.next_packet_number,
                &self.protected_send,
                &entry.reader,
            );
        }
        if (if (target_stream_id) |stream_id|
            self.streaming_requests.takeReset(stream_id)
        else
            self.streaming_requests.takeFirstReset()) |reset|
        {
            finishServerRequest(&self.control, &self.request_lifecycle, reset.stream_id);
            self.qpack_encode.abandonStream(reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            return .{ .reset = .{
                .from = reset.from,
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        if (self.streaming_requests.mightProduceRequestHead(
            &self.request_streams,
            target_stream_id,
        )) {
            try prepareServerRequestReceived(&self.request_lifecycle);
        }
        const ready = self.streaming_requests.nextMatchingEvent(
            &self.request_streams,
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
            target_stream_id,
            false,
        ) catch |err| {
            const stream_id = self.streaming_requests.lastErrorStreamId();
            const from = if (stream_id) |id|
                if (self.streaming_requests.find(id)) |entry| entry.from else null
            else
                null;
            self.failReceivedRequest(from, stream_id, null, err, false);
            return err;
        };
        if (ready) |value| {
            return self.applyStreamingRequestEvent(
                value.entry,
                value.event,
            ) catch |err| {
                self.failReceivedRequest(
                    value.entry.from,
                    value.entry.reader.streamId(),
                    null,
                    err,
                    false,
                );
                return err;
            };
        }
        return null;
    }

    fn failReceivedRequest(
        self: *ProtectedServer,
        from: ?net.IpAddress,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) void {
        if (stream_id) |id| {
            if (err == error.RequestIncomplete) {
                const peer = from orelse return;
                self.cancelRequestInternal(
                    peer,
                    id,
                    http3.ApplicationErrorCode.request_incomplete,
                    false,
                ) catch self.retireRequestState(id);
                return;
            }
            if (messageStreamErrorCode(err)) |code| {
                const peer = from orelse return;
                const uses_dynamic = if (assembled)
                    messageUsesDynamicQpack(
                        assembled_bytes orelse &.{},
                        self.qpack_decode.table,
                    ) catch false
                else
                    false;
                self.cancelRequestInternal(
                    peer,
                    id,
                    code,
                    uses_dynamic,
                ) catch self.retireRequestState(id);
                self.sendQpackFeedback(peer) catch {};
                return;
            }
        }
        if (runtime_error.protocolClose(err) != null) {
            if (from) |peer| {
                sendProtectedHttp3Close(
                    &self.quic_server.endpoint,
                    peer,
                    self.config,
                    &self.next_packet_number,
                    &self.protected_send,
                    err,
                );
            }
            return;
        }
    }

    pub fn readRequestData(
        self: *ProtectedServer,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            entry.from orelse return error.UnexpectedStream,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            entry.from orelse return error.UnexpectedStream,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return read;
    }

    /// Discard currently available DATA without copying it to caller storage.
    /// Receive-window updates match `readRequestData`, including the credit
    /// created by bytes consumed in a prior call.
    pub fn skipRequestData(
        self: *ProtectedServer,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        const from = entry.from orelse return error.UnexpectedStream;
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return skipped;
    }

    pub fn sendResponse(self: *ProtectedServer, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithPush(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        const push_stream_id = self.next_push_stream_id;
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try self.peer_promised_push_ids.ensureUnusedCapacity(
            self.quic_server.endpoint.allocator,
            1,
        );
        try validateNewServerPush(
            self.control,
            self.sent_push_ids.items,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
        try self.sent_push_ids.ensureUnusedCapacity(
            self.quic_server.endpoint.allocator,
            1,
        );
        const automatic_date = if (self.config.auto_date_header and
            (server_response.headerValue(response.headers, "date") == null or
                server_response.headerValue(push.response.headers, "date") == null))
            server_response.cachedDate(true, self.quic_server.endpoint.io)
        else
            null;
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_response = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            response,
            automatic_date,
            &response_headers_stack,
        );
        defer prepared_response.deinit(self.quic_server.endpoint.allocator);
        var push_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared_push_response = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            push.response,
            automatic_date,
            &push_headers_stack,
        );
        defer prepared_push_response.deinit(
            self.quic_server.endpoint.allocator,
        );
        var prepared_push = push;
        prepared_push.response = prepared_push_response.value;
        try sendProtectedPush(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.push_send_scratch,
            self.control.settings.peer,
            request_stream_id,
            prepared_response.value,
            push_stream_id,
            prepared_push,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        self.sent_push_ids.appendAssumeCapacity(push.push_id);
        self.peer_promised_push_ids.appendAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;
        finishServerRequest(&self.control, &self.request_lifecycle, request_stream_id);
        self.control.retirePushPriority(
            self.quic_server.endpoint.allocator,
            push.push_id,
        );
        return push_stream_id;
    }

    pub fn startResponse(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        self.stream_send_scratch.reset();
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.config.auto_date_header,
                self.quic_server.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(self.quic_server.endpoint.allocator);
        const streaming = try prepared.value.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.quic_server.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendProtectedStreamingHead(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
        );
        if (!streaming.body_allowed or
            streaming.expected_length == 0)
        {
            finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        }
    }

    pub fn sendResponseBody(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(stream_id, window);
        }
        try sendProtectedBodyChunk(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
        );
        if (fin) finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    pub fn sendResponseBodyPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendResponseBodyPacedChunk(to, stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendResponseBodyPacedChunk(
                to,
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    /// Send one logical response DATA sequence from borrowed slices without
    /// joining them in caller storage. Empty slices are ignored, and `fin` is
    /// attached only to the final non-empty contribution.
    pub fn sendResponseBodyPartsPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        if (non_empty == 0) {
            try self.sendResponseBodyPaced(to, stream_id, &.{}, fin);
            return;
        }
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            try self.sendResponseBodyPaced(
                to,
                stream_id,
                part,
                fin and sent == non_empty,
            );
        }
    }

    /// Send one DATA contribution per response stream in socket batches. All
    /// streams must belong to `to`; a socket-visible prefix commits exactly
    /// the corresponding HTTP/3 offsets and FIN states.
    pub fn sendResponseBodyBatchPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        chunks: []const BodyChunk,
    ) Error!void {
        try sendProtectedBodyBatchPaced(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            chunks,
            self,
            ProtectedServer.receiveBatchProgressForSend,
            ProtectedServer.finishBatchResponseStream,
        );
    }

    /// Send complete response bodies according to RFC 9218 request priority.
    /// The lightweight runtime has no congestion controller, so eligibility
    /// is derived from the configured peer stream window and packet-size
    /// bound; PRIORITY_UPDATE still takes precedence over the request field.
    pub fn sendResponseBodiesPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        responses: []const ResponseBody,
    ) Error!void {
        if (responses.len == 0) return;
        const allocator = self.quic_server.endpoint.allocator;
        var workspace: response_scheduler.Workspace(
            quic.one_rtt.max_batch_packets,
        ) = .{};
        try workspace.init(allocator, responses.len);
        defer workspace.deinit(allocator);
        const candidates = workspace.candidates();

        for (responses, 0..) |response, index| {
            if (self.outbound_bodies.find(response.stream_id) == null) {
                return error.UnexpectedStream;
            }
            if (!workspace.registerResponse(index, response.stream_id)) {
                return error.UnexpectedStream;
            }
            if (response.data.len == 0) return error.InvalidFrame;
        }

        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        const max_batch_packets = response_scheduler.batchPacketLimit(
            self.config.response_scheduler_max_batch_packets,
            quic.one_rtt.max_batch_packets,
        );
        var remaining_responses = responses.len;
        var next_stream: usize = 0;
        while (remaining_responses != 0) {
            const selection = self.refreshProtectedResponseCandidates(
                responses,
                candidates,
                chunk_limit,
            ) orelse {
                try self.receiveBatchProgressForSend();
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
                try self.receiveBatchProgressForSend();
                continue;
            }
            const sent_count = sendProtectedBodyBatchProgress(
                &self.quic_server.endpoint,
                to,
                self.config,
                &self.next_packet_number,
                &self.protected_send,
                &self.outbound_bodies,
                workspace.chunks(),
                self,
                ProtectedServer.finishBatchResponseStream,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveBatchProgressForSend();
                    continue;
                },
                else => return err,
            };
            const commit = workspace.commitSentPrefix(sent_count);
            remaining_responses -= commit.completed_responses;
            if (selection.exclusive_index == null) {
                next_stream = (commit.last_response_index.? + 1) %
                    responses.len;
            }
        }
    }

    fn refreshProtectedResponseCandidates(
        self: *ProtectedServer,
        responses: []const ResponseBody,
        candidates: []response_scheduler.Candidate,
        chunk_limit: usize,
    ) ?response_scheduler.Selection {
        std.debug.assert(responses.len == candidates.len);
        var selection: response_scheduler.SelectionAccumulator = .{};
        for (responses, candidates, 0..) |response, *candidate, index| {
            const offset = candidate.offset;
            const remaining = response.data.len - offset;
            if (remaining == 0) {
                // FIN removes the outbound body entry. Completed candidates
                // must remain in the fixed scheduler array until every peer
                // finishes, but are deliberately ineligible for selection.
                candidate.* = .{
                    .stream_id = response.stream_id,
                    .offset = offset,
                    .remaining = 0,
                    .send_capacity = 0,
                    .priority = .{},
                };
                selection.consider(candidate.*, index);
                continue;
            }
            const entry = self.outbound_bodies.find(response.stream_id).?;
            const stream_capacity = if (entry.flow_limit) |limit|
                std.math.cast(usize, limit -| entry.send.next_offset) orelse
                    std.math.maxInt(usize)
            else
                std.math.maxInt(usize);
            candidate.* = .{
                .stream_id = response.stream_id,
                .offset = offset,
                .remaining = remaining,
                .send_capacity = responseBodySendCapacity(
                    remaining,
                    std.math.maxInt(usize),
                    stream_capacity,
                    std.math.maxInt(usize),
                    self.quic_server.endpoint.limits.max_datagram_size,
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
        self: ProtectedServer,
        stream_id: u62,
    ) http3.Priority {
        return self.request_lifecycle.priority(stream_id);
    }

    fn receiveBatchProgressForSend(self: *ProtectedServer) Error!void {
        _ = try self.receiveRequestPacketTimeout(100_000);
    }

    fn finishBatchResponseStream(
        self: *ProtectedServer,
        stream_id: u62,
    ) void {
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    fn sendResponseBodyPacedChunk(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendResponseBody(to, stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    _ = try self.receiveRequestPacketTimeout(100_000);
                    continue;
                },
                else => return err,
            };
            _ = try self.receiveRequestPacketTimeout(100_000);
            return;
        }
    }

    pub fn finishResponseTrailers(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        try sendProtectedTrailers(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.stream_send_scratch,
        );
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    pub fn finishResponseTrailersPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishResponseTrailers(to, stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    _ = try self.receiveRequestPacketTimeout(100_000);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn sendResponseWithInformational(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var prepared = try server_response.prepare(
            self.quic_server.endpoint.allocator,
            response,
            server_response.automaticDate(
                self.config.auto_date_header,
                self.quic_server.endpoint.io,
                response,
            ),
            &response_headers_stack,
        );
        defer prepared.deinit(self.quic_server.endpoint.allocator);
        try sendProtectedResponseSequence(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            informational,
            prepared.value,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    pub fn sendGoAway(self: *ProtectedServer, to: net.IpAddress, stream_id: u64) Error!void {
        try validateServerGoAwayStreamId(stream_id);
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_server.endpoint, to, self.config, &self.control, &self.control_send, &self.next_packet_number, &self.protected_send, .goaway, stream_id);
    }

    pub fn sendOrigins(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        const previous_sent = self.control.local_origin_set_sent;
        errdefer self.control.local_origin_set_sent = previous_sent;
        self.protected_send.resetCriticalStreamScratch();
        try self.control.writeOrigins(
            &self.protected_send.critical_stream_payload,
            self.quic_server.endpoint.allocator,
            origins,
        );
        const previous_send = self.control_send;
        errdefer self.control_send = previous_send;
        try self.control_send.appendFrames(
            &self.protected_send.critical_stream_frames,
            self.quic_server.endpoint.allocator,
            self.protected_send.critical_stream_payload.items,
            self.config.max_stream_frame_data,
            false,
        );
        try sendProtectedFrames(
            &self.quic_server.endpoint,
            to,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            self.protected_send.critical_stream_frames.items,
            self.config.max_frames_per_packet,
            &self.protected_send,
        );
    }

    pub fn initiateShutdown(
        self: *ProtectedServer,
        to: net.IpAddress,
    ) Error!void {
        if (self.request_lifecycle.state() != .active) return;
        try self.sendGoAway(
            to,
            @as(u64, quic.varint.max_value) & ~@as(u64, 0x3),
        );
        self.request_lifecycle.markInitialGoAwaySent();
    }

    pub fn completeShutdown(
        self: *ProtectedServer,
        to: net.IpAddress,
    ) Error!void {
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (!self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAway(
            to,
            try self.request_lifecycle.finalGoAwayId(),
        );
        self.request_lifecycle.markFinalGoAwaySent();
    }

    pub fn drainComplete(self: ProtectedServer) bool {
        return self.request_lifecycle.drainComplete(
            self.request_streams.lowestStream(),
            self.streaming_requests.lowestEntryStream(),
            self.streaming_requests.lowestResetStream(),
            self.control.local_goaway_id,
        );
    }

    pub fn cancelRequest(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        return self.cancelRequestInternal(
            to,
            stream_id,
            application_error_code,
            false,
        );
    }

    fn cancelRequestInternal(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
        decoded_dynamic_section: bool,
    ) Error!void {
        const body = self.outbound_bodies.find(stream_id);
        const local_final_size = if (body) |entry| entry.send.next_offset else 0;
        const send_reset = if (body) |entry| !entry.send.fin_sent else true;
        var cancel_qpack = decoded_dynamic_section;
        if (!cancel_qpack) {
            cancel_qpack = self.request_streams.requiresQpackCancellation(
                stream_id,
                self.qpack_decode.table,
            ) catch |err| {
                self.retireRequestState(stream_id);
                return err;
            };
        }
        if (!cancel_qpack) {
            cancel_qpack =
                self.streaming_requests.hasUnacknowledgedDynamicSection(
                    stream_id,
                    self.qpack_decode.table,
                ) catch |err| {
                    self.retireRequestState(stream_id);
                    return err;
                };
        }
        // Once cancellation is chosen, retain no application/request state
        // even if the best-effort RESET/STOP or QPACK feedback cannot reach
        // the peer. A socket failure cannot make this request usable again.
        self.retireRequestState(stream_id);
        try sendProtectedRequestCancellation(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            application_error_code,
            local_final_size,
            send_reset,
            cancel_qpack,
        );
    }

    pub fn rejectRequest(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
    ) Error!void {
        try self.cancelRequest(
            to,
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
        );
    }

    /// Release request bookkeeping after a complete final response has been
    /// sent by a protocol adapter. The lightweight protected transport has no
    /// retained recovery connection, so no additional cancellation frame is
    /// emitted here.
    pub fn finishRequest(
        self: *ProtectedServer,
        stream_id: u62,
    ) Error!void {
        const exists = self.request_lifecycle.contains(stream_id) or
            self.request_streams.contains(stream_id) or
            self.streaming_requests.contains(stream_id) or
            self.outbound_bodies.find(stream_id) != null;
        if (!exists) return error.UnexpectedStream;
        self.retireRequestState(stream_id);
    }

    fn retireRequestState(
        self: *ProtectedServer,
        stream_id: u62,
    ) void {
        self.request_streams.remove(stream_id);
        self.streaming_requests.remove(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    fn receiveStreamBytesUntil(
        self: *ProtectedServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AssembledStream {
        if (try self.request_streams.copyReady(
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
        )) |ready| return ready;

        while (true) {
            var packet = if (deadline) |absolute|
                try self.receive_packets.takeWithDeadline(
                    &self.quic_server.endpoint,
                    self.config.receive_keys,
                    self.config.local_connection_id.len,
                    &self.expected_packet_number,
                    self.config.max_frames_per_packet,
                    absolute,
                )
            else
                try self.receive_packets.take(
                    &self.quic_server.endpoint,
                    self.config.receive_keys,
                    self.config.local_connection_id.len,
                    &self.expected_packet_number,
                    self.config.max_frames_per_packet,
                );
            defer packet.deinit(self.quic_server.endpoint.allocator);
            updateOutboundBodyFlowLimitsFromFrames(
                &self.outbound_bodies,
                packet.frames,
            );
            if (try applyProtectedServerRequestPacketFrames(
                self,
                packet,
                null,
            )) |reset| {
                try self.sendQpackFeedback(reset.from);
                return requestResetError(reset.application_error_code);
            }
            if (try self.request_streams.copyReady(
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                return ready;
            }
        }
    }

    fn receiveRequestPacket(self: *ProtectedServer) Error!void {
        var packet = try self.receive_packets.take(
            &self.quic_server.endpoint,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            &self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        defer packet.deinit(self.quic_server.endpoint.allocator);

        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
        _ = try applyProtectedServerRequestPacketFrames(
            self,
            packet,
            &self.streaming_requests,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
    }

    fn receiveRequestPacketWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        var packet = try self.receive_packets.takeWithDeadline(
            &self.quic_server.endpoint,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            &self.expected_packet_number,
            self.config.max_frames_per_packet,
            deadline,
        );
        defer packet.deinit(self.quic_server.endpoint.allocator);

        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
        _ = try applyProtectedServerRequestPacketFrames(
            self,
            packet,
            &self.streaming_requests,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
    }

    /// Process one protected transport packet for control-stream progress.
    pub fn pollControl(self: *ProtectedServer) Error!void {
        try self.receiveRequestPacket();
    }

    pub fn pollControlWithTimeout(
        self: *ProtectedServer,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.pollControlWithDeadline(.fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn pollControlWithDeadline(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.receiveRequestPacketWithDeadline(deadline);
    }

    fn receiveRequestPacketTimeout(
        self: *ProtectedServer,
        timeout_ns: i64,
    ) Error!bool {
        var datagram = self.quic_server.endpoint.receiveBytesTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromNanoseconds(timeout_ns),
            },
        }) catch |err| switch (err) {
            error.Timeout => return false,
            else => |other| return @errorCast(other),
        };
        defer datagram.deinit(self.quic_server.endpoint.allocator);
        var packet = try quic.one_rtt.openReceivedBytes(
            &self.quic_server.endpoint,
            datagram.from,
            datagram.bytes,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        defer packet.deinit(self.quic_server.endpoint.allocator);
        self.expected_packet_number = packet.packet.packet_number + 1;
        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
        _ = try applyProtectedServerRequestPacketFrames(
            self,
            packet,
            &self.streaming_requests,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
        return true;
    }

    fn applyStreamingRequestEvent(
        self: *ProtectedServer,
        entry: *StreamingRequestSet.Entry,
        event: StreamingEvent,
    ) Error!StreamingRequestEvent {
        const stream_id = entry.reader.streamId();
        const from = entry.from orelse unreachable;
        if (try streamingRequestSectionAcknowledgments(event)) |count| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                stream_id,
                count,
            );
            self.sendQpackFeedback(from) catch {};
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
            self.streaming_requests.remove(stream_id);
        }
        return .{ .message = .{
            .from = from,
            .stream_id = stream_id,
            .value = event,
        } };
    }

    fn sendQpackFeedback(self: *ProtectedServer, to: net.IpAddress) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
    }
};

pub const ProtectedClient = struct {
    quic_client: quic.runtime.Client,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    protected_send: ProtectedSendState,
    response_streams: ResponseStreamSet,
    streaming_responses: StreamingResponseSet,
    push_streams: PushStreamSet,
    push_aggregate: ClientPushAggregateState = .{},
    receive_packets: ProtectedPacketCursor = .{},
    request_lifecycle: ClientRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    stream_send_scratch: StreamMessageSendScratch = .{},
    next_stream_id: u62 = 0,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedClient {
        try validateProtectedConfig(config);
        try validateBlockedStreamLimit(
            config.local_settings,
            limits.max_concurrent_request_streams,
        );
        var quic_client = try quic.runtime.Client.connect(allocator, io, local_address, server, limits.quic);
        errdefer quic_client.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_client = quic_client,
            .config = config,
            .control = try .init(.{
                .max_priority_updates = config.max_priority_updates,
            }),
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                config.max_stream_buffer,
            ),
            .protected_send = .init(allocator),
            .response_streams = .init(
                allocator,
                config.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.max_informational_responses,
                config.local_settings,
                .response,
            ),
            .push_streams = .initWithInformationalLimit(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.max_informational_responses,
                config.local_settings,
            ),
            .request_lifecycle = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .outbound_bodies = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
        };
    }

    pub fn deinit(self: *ProtectedClient) void {
        self.stream_send_scratch.deinit(
            self.quic_client.endpoint.allocator,
        );
        self.outbound_bodies.deinit();
        self.receive_packets.deinit();
        self.push_aggregate.deinit(self.quic_client.endpoint.allocator);
        self.push_streams.deinit();
        self.streaming_responses.deinit();
        self.request_lifecycle.deinit();
        self.response_streams.deinit();
        self.control.deinit(self.quic_client.endpoint.allocator);
        self.protected_send.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn request(self: *ProtectedClient, request_options: http3.Request) Error!OwnedProtectedResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponse(stream_id);
    }

    pub fn requestWithTimeout(
        self: *ProtectedClient,
        request_options: http3.Request,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(request_options, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn requestWithDeadline(
        self: *ProtectedClient,
        request_options: http3.Request,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        return self.requestWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
        );
    }

    pub fn peerGoAwayId(self: ProtectedClient) ?u64 {
        return self.control.peer_goaway_id;
    }

    pub fn goAwayRetryDisposition(
        self: ProtectedClient,
        stream_id: u62,
    ) GoAwayRetryDisposition {
        return stream_lifecycle.goAwayRetryDisposition(
            self.control.peer_goaway_id,
            stream_id,
        );
    }

    /// Send a protected request and observe ordered 1xx heads before final.
    pub fn requestWithInformational(
        self: *ProtectedClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedProtectedResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponseWithInformational(stream_id, informational);
    }

    pub fn requestWithInformationalAndTimeout(
        self: *ProtectedClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn requestWithInformationalAndDeadline(
        self: *ProtectedClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            informational,
            deadline,
        );
    }

    pub fn sendRequest(
        self: *ProtectedClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;
        self.request_lifecycle.markAllocated(stream_id);

        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedMessage(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            request_options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        return stream_id;
    }

    pub fn startRequest(
        self: *ProtectedClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;
        self.request_lifecycle.markAllocated(stream_id);
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.quic_client.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendProtectedStreamingHead(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
        );
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(stream_id, window);
        }
        try sendProtectedBodyChunk(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
        );
    }

    pub fn sendRequestBodyPaced(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendRequestBodyPacedChunk(stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendRequestBodyPacedChunk(
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    /// Client counterpart to `sendResponseBodyPartsPaced`; caller slices stay
    /// borrowed only for each synchronous protected send.
    pub fn sendRequestBodyPartsPaced(
        self: *ProtectedClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        if (non_empty == 0) {
            try self.sendRequestBodyPaced(stream_id, &.{}, fin);
            return;
        }
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            try self.sendRequestBodyPaced(
                stream_id,
                part,
                fin and sent == non_empty,
            );
        }
    }

    /// Batch one DATA contribution per active request stream. The shared
    /// destination allows packet protection and the UDP send to be amortized
    /// while preserving stream state for any unsent suffix.
    pub fn sendRequestBodyBatchPaced(
        self: *ProtectedClient,
        chunks: []const BodyChunk,
    ) Error!void {
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        try sendProtectedBodyBatchPaced(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            chunks,
            self,
            ProtectedClient.receiveBatchProgressForSend,
            ProtectedClient.finishBatchRequestStream,
        );
    }

    fn receiveBatchProgressForSend(self: *ProtectedClient) Error!void {
        try self.receiveResponsePacket();
    }

    fn finishBatchRequestStream(
        self: *ProtectedClient,
        stream_id: u62,
    ) void {
        _ = self;
        _ = stream_id;
        // The request lifecycle remains open until its response is consumed.
    }

    fn sendRequestBodyPacedChunk(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendRequestBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponsePacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn finishRequestTrailers(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendProtectedTrailers(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.stream_send_scratch,
        );
    }

    pub fn finishRequestTrailersPaced(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishRequestTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponsePacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn receiveResponse(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!OwnedProtectedResponse {
        return self.receiveResponseWithInformational(stream_id, null);
    }

    pub fn receiveResponseWithTimeout(
        self: *ProtectedClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseWithDeadline(stream_id, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveResponseWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            null,
            deadline,
        );
    }

    /// Aggregate a protected response with callback-scoped 1xx observation.
    pub fn receiveResponseWithInformational(
        self: *ProtectedClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedProtectedResponse {
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
        self: *ProtectedClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseWithInformationalAndDeadline(
            stream_id,
            informational,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveResponseWithInformationalAndDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveResponseWithInformationalInternal(
            stream_id,
            informational,
            deadline,
        );
    }

    fn receiveResponseWithInformationalInternal(
        self: *ProtectedClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponse {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        const assembled = self.receiveStreamBytesUntil(
            stream_id,
            deadline,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.qpack_encode.abandonStream(stream_id);
                self.sendQpackFeedback() catch {};
                return err;
            },
            else => {
                self.failReceivedResponse(null, stream_id, null, err, false);
                return err;
            },
        };
        errdefer self.quic_client.endpoint.allocator.free(assembled.bytes);
        if (assembled.bytes.len == 0) {
            self.failReceivedResponse(
                assembled.from,
                stream_id,
                assembled.bytes,
                error.MissingStatus,
                true,
            );
            return error.MissingStatus;
        }
        http3.validateResponsePushPromises(
            self.control,
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                assembled.from,
                stream_id,
                assembled.bytes,
                err,
                true,
            );
            return err;
        };
        const section_count = responseFieldSectionCount(
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                assembled.from,
                stream_id,
                assembled.bytes,
                err,
                true,
            );
            return err;
        };
        try self.qpack_decode.prepareSectionAcknowledgments(section_count);
        try self.request_lifecycle.prepareFinish();
        const promise_checkpoint = self.push_streams.promiseCount();
        errdefer self.push_streams.rollbackPromises(promise_checkpoint);
        registerResponsePushPromises(
            &self.push_streams,
            assembled.stream_id,
            assembled.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                assembled.from,
                stream_id,
                assembled.bytes,
                err,
                true,
            );
            return err;
        };
        var response = http3.decodeResponseWithDynamicTableAndOptions(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.config.max_informational_responses;
                options.informational = informational;
                break :blk options;
            },
        ) catch |err| {
            self.failReceivedResponse(
                assembled.from,
                stream_id,
                assembled.bytes,
                err,
                true,
            );
            return err;
        };
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        self.response_streams.remove(stream_id);
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.sendQpackFeedback() catch {};
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn receiveNextResponse(
        self: *ProtectedClient,
    ) Error!OwnedProtectedResponseEvent {
        return self.receiveNextResponseWithInformational(null);
    }

    pub fn receiveNextResponseWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponseEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveNextResponseWithDeadline(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveNextResponseWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponseEvent {
        return self.receiveNextResponseWithInformationalAndDeadline(
            null,
            deadline,
        );
    }

    /// Aggregate whichever outstanding response becomes ready first and
    /// correlate every callback-scoped 1xx head with its request stream.
    pub fn receiveNextResponseWithInformational(
        self: *ProtectedClient,
        informational: ?MultiplexedInformationalObserver,
    ) Error!OwnedProtectedResponseEvent {
        return self.receiveNextResponseWithInformationalInternal(
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveNextResponseWithInformationalAndTimeout(
        self: *ProtectedClient,
        informational: ?MultiplexedInformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedProtectedResponseEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveNextResponseWithInformationalAndDeadline(
            informational,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveNextResponseWithInformationalAndDeadline(
        self: *ProtectedClient,
        informational: ?MultiplexedInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponseEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveNextResponseWithInformationalInternal(
            informational,
            deadline,
        );
    }

    fn receiveNextResponseWithInformationalInternal(
        self: *ProtectedClient,
        informational: ?MultiplexedInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedProtectedResponseEvent {
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
                    self.qpack_encode.abandonStream(reset.stream_id);
                    self.sendQpackFeedback() catch {};
                    return .{ .reset = .{
                        .stream_id = reset.stream_id,
                        .application_error_code = reset.application_error_code,
                    } };
                }
            }
            const ready_stream_id = self.response_streams.firstReadyStream(
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            ) catch |err| {
                self.failReceivedResponse(
                    self.response_streams.lastErrorFrom(),
                    self.response_streams.lastErrorStreamId(),
                    null,
                    err,
                    false,
                );
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
            if (deadline) |absolute| {
                try self.receiveResponsePacketWithDeadline(absolute);
            } else {
                try self.receiveResponsePacket();
            }
        }
    }

    pub fn receiveResponseEvent(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        return self.receiveResponseEventInternal(stream_id, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    /// Return one event already buffered for `stream_id` without reading UDP.
    /// Calling this selects incremental mode for that response, matching the
    /// blocking event APIs while remaining suitable for external event loops.
    pub fn pollResponseEvent(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id)) |active| {
            try sendProtectedReaderCapacity(
                &self.quic_client.endpoint,
                active.from orelse self.quic_client.peer,
                self.config,
                &self.next_packet_number,
                &self.protected_send,
                &active.reader,
            );
        }
        if (self.response_streams.resetFor(stream_id)) |code| {
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(stream_id);
            self.finishStreamingResponse(stream_id);
            self.sendQpackFeedback() catch {};
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
        const event = (entry.reader.next(self.qpack_decode.table) catch |err| {
            self.failReceivedResponse(
                entry.from,
                stream_id,
                null,
                err,
                false,
            );
            return err;
        }) orelse return null;
        var owned_event = event;
        errdefer owned_event.deinit(
            self.quic_client.endpoint.allocator,
        );
        self.applyStreamingResponseEvent(stream_id, owned_event) catch |err| {
            self.failReceivedResponse(
                entry.from,
                stream_id,
                null,
                err,
                false,
            );
            return err;
        };
        return owned_event;
    }

    pub fn receiveResponseEventWithTimeout(
        self: *ProtectedClient,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveResponseEventInternal(
            stream_id,
            .fromNow(
                self.quic_client.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveResponseEventWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveResponseEventInternal(stream_id, deadline);
    }

    fn receiveResponseEventInternal(
        self: *ProtectedClient,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?StreamingEvent {
        if (try self.pollResponseEvent(stream_id)) |event| return event;
        if (deadline) |absolute| {
            try self.receiveResponsePacketWithDeadline(absolute);
        } else {
            try self.receiveResponsePacket();
        }
        return self.pollResponseEvent(stream_id);
    }

    /// Poll one incremental event from any outstanding response stream.
    ///
    /// The first call selects streaming mode for all currently buffered
    /// responses. Continue using streaming APIs for those stream IDs; aggregate
    /// `receiveResponse` cannot reclaim a reader whose head/body has advanced.
    pub fn receiveNextResponseEvent(
        self: *ProtectedClient,
    ) Error!StreamingResponseEvent {
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
    /// request without reading UDP. The selected stream ID lets one
    /// dispatcher service multiple lightweight protected requests fairly.
    pub fn pollNextResponseEvent(
        self: *ProtectedClient,
    ) Error!?StreamingResponseEvent {
        if (self.request_lifecycle.isEmpty()) return null;

        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) {
                return error.UnexpectedStream;
            }
            try self.request_lifecycle.prepareFinish();
            _ = self.response_streams.takeReset(reset.stream_id);
            self.finishStreamingResponse(reset.stream_id);
            self.sendQpackFeedback() catch {};
            return .{ .reset = .{
                .stream_id = reset.stream_id,
                .application_error_code = reset.application_error_code,
            } };
        }
        try self.request_lifecycle.prepareFinish();
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        const ready_value = self.streaming_responses.nextResponse(
            &self.response_streams,
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
        ) catch |err| {
            const stream_id = self.streaming_responses.lastErrorStreamId();
            const from = if (stream_id) |id|
                if (self.streaming_responses.find(id)) |entry| entry.from else null
            else
                null;
            self.failReceivedResponse(from, stream_id, null, err, false);
            return err;
        } orelse return null;
        var ready = ready_value;
        var event_owned = true;
        errdefer if (event_owned) ready.event.deinit(
            self.quic_client.endpoint.allocator,
        );
        const stream_id: u62 = @intCast(
            ready.entry.reader.streamId(),
        );
        applyResponseReaderSemantics(
            self.request_lifecycle,
            stream_id,
            &ready.entry.reader,
        );
        // `nextResponse` decoded this head before applying request context.
        // Validate request-sensitive HEAD/CONNECT semantics before exposure.
        if (ready.event == .head and ready.event.head == .response) {
            ready.entry.reader.applyDecodedResponseHead(
                &ready.event.head.response,
            ) catch |err| {
                self.failReceivedResponse(
                    ready.entry.from,
                    stream_id,
                    null,
                    err,
                    false,
                );
                return err;
            };
        }
        const owned_event = ready.event;
        self.applyStreamingResponseEvent(stream_id, owned_event) catch |err| {
            self.failReceivedResponse(
                ready.entry.from,
                stream_id,
                null,
                err,
                false,
            );
            return err;
        };
        event_owned = false;
        return .{ .message = .{
            .stream_id = stream_id,
            .value = owned_event,
        } };
    }

    /// Wait for the next incremental event within one relative budget. A
    /// timeout leaves all active readers and partially received frames intact.
    pub fn receiveNextResponseEventWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        return self.receiveNextResponseEventInternal(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveNextResponseEventWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (self.request_lifecycle.isEmpty()) {
            return error.UnexpectedStream;
        }
        return self.receiveNextResponseEventInternal(deadline);
    }

    fn receiveNextResponseEventInternal(
        self: *ProtectedClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingResponseEvent {
        while (true) {
            if (try self.pollNextResponseEvent()) |event| return event;
            if (deadline) |absolute| {
                try self.receiveResponsePacketWithDeadline(absolute);
            } else {
                try self.receiveResponsePacket();
            }
        }
    }

    pub fn readResponseData(
        self: *ProtectedClient,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            entry.from orelse self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            entry.from orelse self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return read;
    }

    /// Discard currently available response DATA without an intermediate copy
    /// while preserving the same protected receive-window feedback as reads.
    pub fn skipResponseData(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        const from = entry.from orelse self.quic_client.peer;
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return skipped;
    }

    pub fn receivePushEvent(
        self: *ProtectedClient,
    ) Error!StreamingPushEvent {
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(null);
    }

    /// Return one promised-response event already buffered locally without
    /// reading UDP. Aggregate push state remains exclusive with this API.
    pub fn pollPushEvent(
        self: *ProtectedClient,
    ) Error!?StreamingPushEvent {
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.pollPushEventMatching(null);
    }

    pub fn receivePushEventWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingPushEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventWithDeadline(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receivePushEventWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatchingUntil(null, deadline);
    }

    fn receivePushEventMatching(
        self: *ProtectedClient,
        target_push_id: ?u64,
    ) Error!StreamingPushEvent {
        return self.receivePushEventMatchingUntil(
            target_push_id,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn receivePushEventMatchingUntil(
        self: *ProtectedClient,
        target_push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        while (true) {
            if (try self.pollPushEventMatching(target_push_id)) |event| {
                return event;
            }
            if (deadline) |absolute| {
                try self.receiveResponsePacketWithDeadline(absolute);
            } else {
                try self.receiveResponsePacket();
            }
        }
    }

    fn pollPushEventMatching(
        self: *ProtectedClient,
        target_push_id: ?u64,
    ) Error!?StreamingPushEvent {
        // Consumption may have created receive-window credit. Emit it before
        // selecting the next event so nonblocking loops do not deadlock after
        // repeatedly reading DATA without another socket receive.
        var index: usize = 0;
        while (self.push_streams.entryAt(index)) |entry| : (index += 1) {
            if (PushStreamSet.entryReader(entry)) |reader| {
                try sendProtectedReaderCapacity(
                    &self.quic_client.endpoint,
                    PushStreamSet.entryPeer(entry) orelse self.quic_client.peer,
                    self.config,
                    &self.next_packet_number,
                    &self.protected_send,
                    reader,
                );
            }
        }
        try self.applyPendingPushCancellations();
        try self.qpack_decode.prepareSectionAcknowledgments(1);
        const ready = self.push_streams.next(
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
            target_push_id,
        ) catch |err| {
            const stream_id = self.push_streams.lastErrorStreamId();
            const from = if (stream_id) |id|
                self.push_streams.peerForStream(id)
            else
                null;
            if (stream_id) |id| {
                if (messageStreamErrorCode(err)) |code| {
                    const cancel_qpack = self.push_streams
                        .hasUnacknowledgedDynamicSection(
                        id,
                        self.qpack_decode.table,
                    ) catch false;
                    if (cancel_qpack) {
                        self.qpack_decode.recordStreamCancellation(id) catch {};
                    }
                    const frames = [_]quic.Frame{.{ .stop_sending = .{
                        .stream_id = id,
                        .application_error_code = code,
                    } }};
                    sendProtectedFrames(
                        &self.quic_client.endpoint,
                        from orelse self.quic_client.peer,
                        self.config.send_keys,
                        self.config.peer_connection_id,
                        &self.next_packet_number,
                        &frames,
                        self.config.max_frames_per_packet,
                        &self.protected_send,
                    ) catch {};
                    self.push_streams.failStream(id);
                    self.sendQpackFeedback() catch {};
                    return err;
                }
            }
            if (runtime_error.protocolClose(err) != null) {
                sendProtectedHttp3Close(
                    &self.quic_client.endpoint,
                    from orelse self.quic_client.peer,
                    self.config,
                    &self.next_packet_number,
                    &self.protected_send,
                    err,
                );
            }
            return err;
        } orelse return null;
        var event = ready.event;
        errdefer event.deinit(self.quic_client.endpoint.allocator);
        if (event.value == .push_promise) return error.UnexpectedFrame;
        if (try streamingResponseSectionAcknowledgments(event.value)) |count| {
            self.qpack_decode.acknowledgeSectionsAssumeCapacity(
                event.stream_id,
                count,
            );
            self.sendQpackFeedback() catch {};
        }
        if (event.value == .finished) {
            self.push_streams.removeFinished(ready.index);
        }
        return event;
    }

    fn applyPendingPushCancellations(
        self: *ProtectedClient,
    ) Error!void {
        while (self.push_streams.firstCancelledStream()) |stream_id| {
            const frames = [_]quic.Frame{.{ .stop_sending = .{
                .stream_id = stream_id,
                .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            } }};
            try sendProtectedFrames(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config.send_keys,
                self.config.peer_connection_id,
                &self.next_packet_number,
                &frames,
                self.config.max_frames_per_packet,
                &self.protected_send,
            );
            std.debug.assert(
                self.push_streams.takeCancelledStream().? == stream_id,
            );
        }
    }

    pub fn readPushData(
        self: *ProtectedClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        return self.push_streams.readData(push_id, out);
    }

    /// Discard currently available push DATA and return its receive-window
    /// credit without allocating caller storage.
    pub fn skipPushData(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!usize {
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        const reader = if (entry.reader) |*value| value else return error.UnexpectedStream;
        const from = entry.from orelse self.quic_client.peer;
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            reader,
        );
        const skipped = try reader.skipData();
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            reader,
        );
        return skipped;
    }

    pub fn receivePush(
        self: *ProtectedClient,
    ) Error!PushedResponse {
        return self.receivePushWithInformational(null);
    }

    /// Aggregate one promised response within a relative budget. The partial
    /// head, body, trailers, and reader remain owned by the client on timeout.
    pub fn receivePushWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PushedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePushWithInformationalAndDeadline(
            null,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receivePushWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        return self.receivePushWithInformationalAndDeadline(null, deadline);
    }

    /// Aggregate one promised response while reporting its ordered 1xx heads.
    pub fn receivePushWithInformational(
        self: *ProtectedClient,
        informational: ?PushInformationalObserver,
    ) Error!PushedResponse {
        return self.receivePushWithInformationalAttempt(
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receivePushWithInformationalAndTimeout(
        self: *ProtectedClient,
        informational: ?PushInformationalObserver,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!PushedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePushWithInformationalAndDeadline(
            informational,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receivePushWithInformationalAndDeadline(
        self: *ProtectedClient,
        informational: ?PushInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receivePushWithInformationalAttempt(
            informational,
            deadline,
        );
    }

    fn receivePushWithInformationalAttempt(
        self: *ProtectedClient,
        informational: ?PushInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PushedResponse {
        return push_aggregate.receive(
            self,
            &self.push_aggregate,
            self.quic_client.endpoint.allocator,
            informational,
            deadline,
            ProtectedClient.nextPushEventForAggregate,
            ProtectedClient.readPushDataForAggregate,
            ProtectedClient.pushStreamPendingForAggregate,
        ) catch |err| switch (err) {
            // The reader and decoded values are resumable only for
            // transport-budget failures. Protocol/allocator failures end
            // this aggregate attempt and must release retained ownership.
            error.Timeout, error.ConcurrencyUnavailable => return err,
            else => {
                self.push_aggregate.deinit(
                    self.quic_client.endpoint.allocator,
                );
                return err;
            },
        };
    }

    fn nextPushEventForAggregate(
        self: *ProtectedClient,
        push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamingPushEvent {
        return self.receivePushEventMatchingUntil(push_id, deadline);
    }

    fn readPushDataForAggregate(
        self: *ProtectedClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        return self.readPushData(push_id, out);
    }

    fn pushStreamPendingForAggregate(
        self: *ProtectedClient,
        push_id: u64,
    ) bool {
        const entry = self.push_streams.findByPushId(push_id) orelse
            return false;
        return entry.reader != null and entry.reader.?.current_frame != null;
    }

    pub fn sendGoAway(self: *ProtectedClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_client.endpoint, self.quic_client.peer, self.config, &self.control, &self.control_send, &self.next_packet_number, &self.protected_send, .goaway, stream_id);
    }

    pub fn peerOrigins(self: ProtectedClient) []const http3.OriginKey {
        return self.control.peerOrigins();
    }

    pub fn peerOriginSetInitialized(self: ProtectedClient) bool {
        return self.control.peerOriginSetInitialized();
    }

    pub fn peerOriginKnown(
        self: ProtectedClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginKnown(origin);
    }

    pub fn peerOriginSetAllows(
        self: ProtectedClient,
        initial_origin: http3.Origin,
        requested_origin: http3.Origin,
    ) ?bool {
        return self.control.peerOriginSetAllows(
            initial_origin,
            requested_origin,
        );
    }

    pub fn removePeerOriginAfterMisdirected(
        self: *ProtectedClient,
        origin: http3.Origin,
    ) Error!void {
        try self.control.removePeerOrigin(
            self.quic_client.endpoint.allocator,
            origin,
        );
    }

    /// Wait for the peer's mandatory SETTINGS while retaining any response
    /// or push bytes that arrive first for their normal consumers.
    pub fn receivePeerSettings(
        self: *ProtectedClient,
    ) Error!http3.Settings {
        return self.receivePeerSettingsInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receivePeerSettingsWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!http3.Settings {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerSettingsInternal(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receivePeerSettingsWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!http3.Settings {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receivePeerSettingsInternal(deadline);
    }

    fn receivePeerSettingsInternal(
        self: *ProtectedClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!http3.Settings {
        while (!self.control.settings.received) {
            if (deadline) |absolute| {
                try self.receiveResponsePacketWithDeadline(absolute);
            } else {
                try self.receiveResponsePacket();
            }
        }
        return self.control.settings.peer;
    }

    /// Process one protected transport packet for control-stream progress.
    pub fn pollControl(self: *ProtectedClient) Error!void {
        try self.receiveResponsePacket();
    }

    pub fn pollControlWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.pollControlWithDeadline(.fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn pollControlWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveResponsePacketWithDeadline(deadline);
    }

    pub fn sendMaxPushId(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!void {
        try self.push_streams.reservePromisesThrough(push_id);
        const previous_max_push_id = self.control.local_max_push_id;
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        sendProtectedPushControl(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            .max_push_id,
            push_id,
        ) catch |err| {
            self.control.local_max_push_id = previous_max_push_id;
            return err;
        };
    }

    pub fn cancelPush(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPushControl(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            .cancel_push,
            push_id,
        );
        try self.push_streams.observePeerCancellation(push_id);
        defer if (self.push_aggregate.push_id == push_id) {
            self.push_aggregate.deinit(self.quic_client.endpoint.allocator);
        };
        try self.applyPendingPushCancellations();
    }

    pub fn cancelRequest(
        self: *ProtectedClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        return self.cancelRequestInternal(
            stream_id,
            application_error_code,
            false,
        );
    }

    fn cancelRequestInternal(
        self: *ProtectedClient,
        stream_id: u62,
        application_error_code: u64,
        decoded_dynamic_section: bool,
    ) Error!void {
        const body = self.outbound_bodies.find(stream_id);
        const local_final_size = if (body) |entry| entry.send.next_offset else 0;
        const send_reset = if (body) |entry| !entry.send.fin_sent else false;
        var cancel_qpack = decoded_dynamic_section;
        if (!cancel_qpack) {
            cancel_qpack = try self.response_streams.requiresQpackCancellation(
                stream_id,
                self.qpack_decode.table,
            );
        }
        if (!cancel_qpack) {
            cancel_qpack =
                try self.streaming_responses.hasUnacknowledgedDynamicSection(
                    stream_id,
                    self.qpack_decode.table,
                );
        }
        defer {
            self.qpack_encode.abandonStream(stream_id);
            self.response_streams.remove(stream_id);
            self.streaming_responses.remove(stream_id);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            _ = self.outbound_bodies.finish(stream_id);
        }
        try sendProtectedRequestCancellation(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            application_error_code,
            local_final_size,
            send_reset,
            cancel_qpack,
        );
    }

    pub fn sendPriorityUpdate(
        self: *ProtectedClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPriorityUpdate(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            priority,
        );
    }

    pub fn sendPushPriorityUpdate(
        self: *ProtectedClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        if (!self.push_streams.hasPromise(push_id)) {
            return error.UnexpectedStream;
        }
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPriorityUpdateRaw(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            http3.FrameType.priority_update_push,
            push_id,
            priority,
        );
    }

    fn receiveStreamBytesUntil(
        self: *ProtectedClient,
        expected_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!AssembledStream {
        if (self.response_streams.takeReset(expected_stream_id)) |code| {
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        if (try self.response_streams.copyReady(
            expected_stream_id,
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
        )) |ready| return ready;
        while (true) {
            if (deadline) |absolute| {
                try self.receiveResponsePacketWithDeadline(absolute);
            } else {
                try self.receiveResponsePacket();
            }
            if (self.response_streams.takeReset(expected_stream_id)) |code| {
                return if (code == http3.ApplicationErrorCode.request_rejected)
                    error.RequestRejected
                else
                    error.RequestCancelled;
            }
            if (try self.response_streams.copyReady(
                expected_stream_id,
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                return ready;
            }
        }
    }

    fn receiveResponsePacket(self: *ProtectedClient) Error!void {
        return self.receiveResponsePacketInternal(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn receiveResponsePacketWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.receiveResponsePacketInternal(deadline);
    }

    fn receiveResponsePacketInternal(
        self: *ProtectedClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        var packet = if (deadline) |absolute|
            try self.receive_packets.takeWithDeadline(
                &self.quic_client.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                &self.expected_packet_number,
                self.config.max_frames_per_packet,
                absolute,
            )
        else
            try self.receive_packets.take(
                &self.quic_client.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                &self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
        defer packet.deinit(self.quic_client.endpoint.allocator);
        errdefer |err| sendProtectedHttp3Close(
            &self.quic_client.endpoint,
            packet.from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            err,
        );
        var routing: response_routing.State = .{
            .allocator = self.quic_client.endpoint.allocator,
            .control = &self.control,
            .qpack_decode = &self.qpack_decode,
            .qpack_encode = &self.qpack_encode,
            .max_blocked_streams = self.config.local_settings.qpack_blocked_streams,
            .response_streams = &self.response_streams,
            .streaming_responses = &self.streaming_responses,
            .push_streams = &self.push_streams,
            .request_lifecycle = &self.request_lifecycle,
        };
        if (try response_routing.routePacket(
            &routing,
            packet.from,
            packet.frames,
        )) try self.sendQpackFeedback();
    }

    fn applyStreamingResponseEvent(
        self: *ProtectedClient,
        stream_id: u62,
        event: StreamingEvent,
    ) Error!void {
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
            // This also flushes Insert Count Increment instructions produced
            // while pumping the peer's encoder stream.
            self.sendQpackFeedback() catch {};
        }
        if (event == .finished) {
            self.finishStreamingResponse(stream_id);
        }
    }

    fn finishStreamingResponse(
        self: *ProtectedClient,
        stream_id: u62,
    ) void {
        _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.streaming_responses.remove(stream_id);
    }

    fn failReceivedResponse(
        self: *ProtectedClient,
        from: ?net.IpAddress,
        stream_id: ?u62,
        assembled_bytes: ?[]const u8,
        err: anyerror,
        assembled: bool,
    ) void {
        if (stream_id) |id| {
            if (messageStreamErrorCode(err)) |code| {
                const uses_dynamic = if (assembled)
                    messageUsesDynamicQpack(
                        assembled_bytes orelse &.{},
                        self.qpack_decode.table,
                    ) catch false
                else
                    false;
                self.cancelRequestInternal(
                    id,
                    code,
                    uses_dynamic,
                ) catch {
                    self.qpack_encode.abandonStream(id);
                    self.response_streams.remove(id);
                    self.streaming_responses.remove(id);
                    _ = self.request_lifecycle.finish(id) catch false;
                    _ = self.outbound_bodies.finish(id);
                };
                self.sendQpackFeedback() catch {};
                return;
            }
        }
        if (runtime_error.protocolClose(err) != null) {
            sendProtectedHttp3Close(
                &self.quic_client.endpoint,
                from orelse self.quic_client.peer,
                self.config,
                &self.next_packet_number,
                &self.protected_send,
                err,
            );
            return;
        }
    }

    fn sendQpackFeedback(self: *ProtectedClient) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
    }
};

fn streamingResponseSectionAcknowledgments(
    event: StreamingEvent,
) Error!?usize {
    return switch (event) {
        .head => |head| switch (head) {
            .request => error.UnexpectedFrame,
            .response => |response| response.qpack_section_acknowledgments,
        },
        .push_promise => |promise| promise.request.qpack_section_acknowledgments,
        .trailers => |trailers| trailers.qpack_section_acknowledgments,
        .data_available, .finished => null,
    };
}

fn streamingRequestSectionAcknowledgments(
    event: StreamingEvent,
) Error!?usize {
    return switch (event) {
        .head => |head| switch (head) {
            .request => |request| request.qpack_section_acknowledgments,
            .response => error.UnexpectedFrame,
        },
        .push_promise => error.UnexpectedFrame,
        .trailers => |trailers| trailers.qpack_section_acknowledgments,
        .data_available, .finished => null,
    };
}

fn registerResponsePushPromises(
    pushes: *PushStreamSet,
    request_stream_id: u62,
    bytes: []const u8,
) Error!void {
    const checkpoint = pushes.promiseCount();
    errdefer pushes.rollbackPromises(checkpoint);
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type != http3.FrameType.push_promise) continue;
        const promise = try http3.parsePushPromisePayload(frame.payload);
        try pushes.registerPromise(promise.push_id, request_stream_id);
    }
}

fn responseFieldSectionCount(bytes: []const u8) Error!usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type == http3.FrameType.headers or
            frame.frame_type == http3.FrameType.push_promise)
        {
            count = std.math.add(usize, count, 1) catch
                return error.ExcessiveLoad;
        }
    }
    return count;
}

fn releaseStreamingReaderCapacity(
    connection: *quic.one_rtt.Connection,
    reader: *StreamingMessageReader,
) Error!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    try connection.releaseReceivedCapacity(
        reader.streamId(),
        amount,
    );
    reader.markCredited(amount);
}

fn sendProtectedReaderCapacity(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    reader: *StreamingMessageReader,
) Error!void {
    const credit = try reader.pendingCredit() orelse return;
    const frames = [_]quic.Frame{.{ .max_stream_data = .{
        .stream_id = credit.stream_id,
        .maximum_stream_data = credit.maximum_stream_data,
    } }};
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        &frames,
        config.max_frames_per_packet,
        protected_send,
    );
    reader.markCredited(credit.amount);
}

fn updateOutboundBodyFlowLimitsFromFrames(
    bodies: *OutboundBodySet,
    frames: []const quic.Frame,
) void {
    for (frames) |frame| {
        if (frame != .max_stream_data) continue;
        const stream_id = std.math.cast(
            u62,
            frame.max_stream_data.stream_id,
        ) orelse continue;
        bodies.updateFlowLimit(
            stream_id,
            frame.max_stream_data.maximum_stream_data,
        );
    }
}

fn requestPriority(
    headers: []const http3.Qpack.HeaderField,
) http3.Priority {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, "priority")) {
            return http3.Priority.parse(header.value);
        }
    }
    return .{};
}

fn requestHasProtocol(
    headers: []const http3.Qpack.HeaderField,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

fn requestEndedBeforeHeaders(bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = http3.Frame.parse(bytes[offset..]) catch return false;
        if (frame.frame_type == http3.FrameType.headers) return false;
        if (frame.frame_type == http3.FrameType.data) return false;
        switch (frame.frame_type) {
            http3.FrameType.cancel_push,
            http3.FrameType.settings,
            http3.FrameType.goaway,
            http3.FrameType.max_push_id,
            http3.FrameType.priority_update_request,
            http3.FrameType.priority_update_push,
            http3.FrameType.push_promise,
            => return false,
            else => {},
        }
        offset += frame.consumed;
    }
    return true;
}

fn receivedInputComplete(
    connection: *const quic.one_rtt.Connection,
    stream_id: u62,
    available_len: usize,
) bool {
    const stats = connection.recvStreamStats(stream_id) orelse return false;
    const final_size = stats.final_size orelse return false;
    const available = std.math.cast(u64, available_len) orelse return false;
    const contiguous_end = std.math.add(
        u64,
        stats.bytes_read,
        available,
    ) catch return false;
    return contiguous_end == final_size;
}

fn responseHeadErrorAtFin(bytes: []const u8) Error {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = http3.Frame.parse(bytes[offset..]) catch
            return error.BufferTooShort;
        offset += frame.consumed;
    }
    return error.MissingStatus;
}

test "HTTP/3 detached response FIN distinguishes missing head from truncated frame" {
    try std.testing.expectEqual(
        error.MissingStatus,
        responseHeadErrorAtFin(&.{}),
    );
    try std.testing.expectEqual(
        error.BufferTooShort,
        responseHeadErrorAtFin(&.{0x01}),
    );
}

pub const OwnedProtectedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedProtectedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedProtectedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponseEvent = union(enum) {
    response: struct {
        stream_id: u62,
        value: OwnedProtectedResponse,
    },
    reset: struct {
        stream_id: u62,
        application_error_code: u64,
    },

    pub fn deinit(
        self: *OwnedProtectedResponseEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .response => |*response| response.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

fn validateBlockedStreamLimit(
    settings: http3.Settings,
    max_concurrent_streams: usize,
) Error!void {
    try settings.validateLocal();
    const runtime_limit = std.math.cast(
        u64,
        max_concurrent_streams,
    ) orelse std.math.maxInt(u64);
    if (settings.qpack_blocked_streams > runtime_limit) {
        return error.QpackDynamicTableUnsupported;
    }
}

fn validateProtectedConfig(config: ProtectedConfig) Error!void {
    if (config.max_priority_updates == 0 or
        config.max_client_bidirectional_streams > quic.max_stream_count)
    {
        return error.InvalidSetting;
    }
}

fn validateHandshakeSessionOptions(options: HandshakeSessionOptions) Error!void {
    if (options.max_priority_updates == 0) return error.InvalidSetting;
}

fn applyResponseReaderSemantics(
    lifecycle: ClientRequestLifecycle,
    stream_id: u62,
    reader: *StreamingMessageReader,
) void {
    const options = lifecycle.responseDecodeOptions(stream_id);
    reader.applyResponseSemantics(options);
}

const sendConnectionFrames = body_sender.sendConnectionFrames;

fn visitStreamingServerRequestPacket(
    session: *HandshakeServerSession,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    _ = applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        session.established.connection.endpoint.allocator,
        &session.control,
        &session.qpack_decode,
        &session.qpack_encode,
        session.options.local_settings.qpack_blocked_streams,
        &session.request_streams,
        &session.streaming_requests,
        &session.request_lifecycle,
        .{ .connection = &session.established.connection },
        session.peer_promised_push_ids.items,
        null,
        &session.connect_datagrams,
    ) catch |err| {
        try closeConnectionForHttp3Error(
            &session.established.connection,
            err,
        );
        return err;
    };
    try routeConnectDatagramsFromPacket(
        &session.connect_datagrams,
        &session.established.connection,
        packet.frames,
        packet.packet_number,
    );
}

fn visitDetachedServerRequestPacket(
    context: struct { *HandshakeServerSession, u62 },
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    const session, const detached_stream_id = context;
    _ = applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        session.established.connection.endpoint.allocator,
        &session.control,
        &session.qpack_decode,
        &session.qpack_encode,
        session.options.local_settings.qpack_blocked_streams,
        &session.request_streams,
        &session.streaming_requests,
        &session.request_lifecycle,
        .{ .connection = &session.established.connection },
        session.peer_promised_push_ids.items,
        detached_stream_id,
        &session.connect_datagrams,
    ) catch |err| {
        try closeConnectionForHttp3Error(
            &session.established.connection,
            err,
        );
        return err;
    };
    try routeConnectDatagramsFromPacket(
        &session.connect_datagrams,
        &session.established.connection,
        packet.frames,
        packet.packet_number,
    );
}

const ConnectionRequestReceiveContext = struct {
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    request_streams: *RequestStreamSet,
    request_lifecycle: *ServerRequestLifecycle,
    peer_promised_push_ids: []const u64,
    detached_streams: ?*connect_datagram.Registry = null,
    reset: ?RequestStreamReset = null,
};

fn visitConnectionRequestPacket(
    context: *ConnectionRequestReceiveContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    context.reset = applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        context.connection.endpoint.allocator,
        context.control,
        context.qpack_decode,
        context.qpack_encode,
        context.max_blocked_streams,
        context.request_streams,
        null,
        context.request_lifecycle,
        .{ .connection = context.connection },
        context.peer_promised_push_ids,
        null,
        context.detached_streams,
    ) catch |err| {
        try closeConnectionForHttp3Error(context.connection, err);
        return err;
    };
    if (context.detached_streams) |detached| {
        try routeConnectDatagramsFromPacket(
            detached,
            context.connection,
            packet.frames,
            packet.packet_number,
        );
    }
}

fn receiveConnectionRequestStreamBytes(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    request_lifecycle: *ServerRequestLifecycle,
    peer_promised_push_ids: []const u64,
) Error!AssembledStream {
    return receiveConnectionRequestStreamBytesUntil(
        connection,
        receive_packets,
        options,
        control,
        qpack_decode,
        qpack_encode,
        request_streams,
        request_lifecycle,
        peer_promised_push_ids,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveConnectionRequestStreamBytesUntil(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    request_lifecycle: *ServerRequestLifecycle,
    peer_promised_push_ids: []const u64,
    detached_streams: ?*connect_datagram.Registry,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!AssembledStream {
    if (try request_streams.copyReady(
        qpack_decode.table,
        options.local_settings.qpack_blocked_streams,
    )) |ready| return ready;

    while (true) {
        var context: ConnectionRequestReceiveContext = .{
            .connection = connection,
            .control = control,
            .qpack_decode = qpack_decode,
            .qpack_encode = qpack_encode,
            .max_blocked_streams = options.local_settings.qpack_blocked_streams,
            .request_streams = request_streams,
            .request_lifecycle = request_lifecycle,
            .peer_promised_push_ids = peer_promised_push_ids,
            .detached_streams = detached_streams,
        };
        var receive_error: ?ReceiveTimeoutError = null;
        if (deadline) |absolute| {
            receive_packets.visitWithDeadline(
                connection,
                absolute,
                &context,
                visitConnectionRequestPacket,
            ) catch |err| {
                switch (err) {
                    error.Timeout => receive_error = err,
                    else => return err,
                }
            };
        } else {
            receive_packets.visit(
                connection,
                &context,
                visitConnectionRequestPacket,
            ) catch |err| return err;
        }
        if (context.reset) |reset| {
            return requestResetError(reset.application_error_code);
        }
        if (try request_streams.copyReady(
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
        if (receive_error) |err| return err;
    }
}

fn responseResetError(application_error_code: u64) Error {
    return if (application_error_code ==
        http3.ApplicationErrorCode.request_rejected)
        error.RequestRejected
    else
        error.RequestCancelled;
}

fn applyProtectedServerRequestPacketFrames(
    server: *ProtectedServer,
    packet: quic.one_rtt.ReceivedPacket,
    streaming_requests: ?*StreamingRequestSet,
) Error!?RequestStreamReset {
    return applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        server.quic_server.endpoint.allocator,
        &server.control,
        &server.qpack_decode,
        &server.qpack_encode,
        server.config.local_settings.qpack_blocked_streams,
        &server.request_streams,
        streaming_requests,
        &server.request_lifecycle,
        .{ .static_limit = server.config.max_client_bidirectional_streams },
        server.peer_promised_push_ids.items,
        null,
        null,
    ) catch |err| {
        sendProtectedHttp3Close(
            &server.quic_server.endpoint,
            packet.from,
            server.config,
            &server.next_packet_number,
            &server.protected_send,
            err,
        );
        return err;
    };
}

fn receiveConnectionResponseStreamBytes(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    expected_stream_id: u62,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    response_streams: *ResponseStreamSet,
    streaming_responses: *StreamingResponseSet,
    push_streams: *PushStreamSet,
    request_lifecycle: *const ClientRequestLifecycle,
) Error!AssembledStream {
    return receiveConnectionResponseStreamBytesUntil(
        connection,
        receive_packets,
        expected_stream_id,
        options,
        control,
        qpack_decode,
        qpack_encode,
        response_streams,
        streaming_responses,
        push_streams,
        request_lifecycle,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveConnectionResponseStreamBytesUntil(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    expected_stream_id: u62,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    response_streams: *ResponseStreamSet,
    streaming_responses: *StreamingResponseSet,
    push_streams: *PushStreamSet,
    request_lifecycle: *const ClientRequestLifecycle,
    detached_streams: ?*connect_datagram.Registry,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!AssembledStream {
    if (response_streams.takeReset(expected_stream_id)) |code| {
        return if (code == http3.ApplicationErrorCode.request_rejected)
            error.RequestRejected
        else
            error.RequestCancelled;
    }
    if (try response_streams.copyReady(
        expected_stream_id,
        qpack_decode.table,
        options.local_settings.qpack_blocked_streams,
    )) |ready| return ready;

    while (true) {
        var receive_error: ?ReceiveTimeoutError = null;
        receiveConnectionResponsePacketUntil(
            connection,
            receive_packets,
            control,
            qpack_decode,
            qpack_encode,
            options.local_settings.qpack_blocked_streams,
            response_streams,
            streaming_responses,
            push_streams,
            request_lifecycle,
            null,
            detached_streams,
            deadline,
        ) catch |err| {
            switch (err) {
                error.Timeout => receive_error = err,
                else => return err,
            }
        };
        if (response_streams.takeReset(expected_stream_id)) |code| {
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        if (try response_streams.copyReady(
            expected_stream_id,
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
        if (receive_error) |err| return err;
    }
}

fn receiveConnectionResponsePacket(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
    detached_stream_id: ?u62,
    detached_streams: ?*connect_datagram.Registry,
) Error!void {
    return receiveConnectionResponsePacketUntil(
        connection,
        receive_packets,
        control,
        qpack_decode,
        qpack_encode,
        max_blocked_streams,
        response_streams,
        streaming_responses,
        push_streams,
        request_lifecycle,
        detached_stream_id,
        detached_streams,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn receiveConnectionResponsePacketUntil(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
    detached_stream_id: ?u62,
    detached_streams: ?*connect_datagram.Registry,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    var context: ConnectionResponseReceiveContext = .{
        .connection = connection,
        .control = control,
        .qpack_decode = qpack_decode,
        .qpack_encode = qpack_encode,
        .max_blocked_streams = max_blocked_streams,
        .response_streams = response_streams,
        .streaming_responses = streaming_responses,
        .push_streams = push_streams,
        .request_lifecycle = request_lifecycle,
        .detached_stream_id = detached_stream_id,
        .detached_streams = detached_streams,
    };
    if (deadline) |absolute| {
        try receive_packets.visitWithDeadline(
            connection,
            absolute,
            &context,
            visitConnectionResponsePacket,
        );
    } else {
        try receive_packets.visit(
            connection,
            &context,
            visitConnectionResponsePacket,
        );
    }
}

const ConnectionResponseReceiveContext = struct {
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
    detached_stream_id: ?u62,
    detached_streams: ?*connect_datagram.Registry = null,
};

fn visitConnectionResponsePacket(
    context: *ConnectionResponseReceiveContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    errdefer |err| closeConnectionForHttp3Error(
        context.connection,
        err,
    ) catch {};
    var routing: response_routing.State = .{
        .allocator = context.connection.endpoint.allocator,
        .connection = context.connection,
        .control = context.control,
        .qpack_decode = context.qpack_decode,
        .qpack_encode = context.qpack_encode,
        .max_blocked_streams = context.max_blocked_streams,
        .response_streams = context.response_streams,
        .streaming_responses = context.streaming_responses,
        .push_streams = context.push_streams,
        .request_lifecycle = context.request_lifecycle,
        .detached_stream_id = context.detached_stream_id,
        .detached_streams = context.detached_streams,
    };
    _ = try response_routing.routePacket(
        &routing,
        packet.from,
        packet.frames,
    );
    if (context.detached_streams) |registry| {
        try routeConnectDatagramsFromPacket(
            registry,
            context.connection,
            packet.frames,
            packet.packet_number,
        );
    }
}

test "HTTP/3 handshake server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe2} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
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
            var session = try server_ptr.accept();
            defer session.deinit();
            session.control.local_goaway_id = 0;
            try std.testing.expectError(error.RequestRejected, session.receiveRequest());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe3} ** 32,
        },
    });
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.critical_stream_send_scratch,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    try sendConnectionMessage(
        &client.established.connection,
        &client.stream_send_scratch,
        &client.critical_stream_send_scratch,
        0,
        .{ .method = "GET", .path = "/rejected", .authority = "localhost" },
        client.options,
        client.control.settings.peer,
        &client.qpack_encode,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xaa, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xbb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();
    server.control.local_goaway_id = 0;

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            std.testing.expectError(error.RequestRejected, shared.server.receiveRequest()) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    // Send a request without waiting for a response; the server-side receive path
    // should reject it because local GOAWAY(0) says no client request stream is
    // still acceptable.
    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{ .method = "GET", .path = "/rejected", .authority = "localhost" }).write(&encoded, allocator);
    var send_state = quic.stream_state.SendState.init(0);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send_state.appendFrames(&frames, allocator, encoded.items, encoded.items.len, true);
    try sendProtectedFrames(&client.quic_client.endpoint, client.quic_client.peer, client.config.send_keys, client.config.peer_connection_id, &client.next_packet_number, frames.items, client.config.max_frames_per_packet, &client.protected_send);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected runtime rejects server-initiated bidirectional message streams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xc2, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    const invalid = [_]quic.Frame{.{
        .stream = .{
            .stream_id = 1, // server-initiated bidirectional: invalid for HTTP/3 messages.
            .data = "not a request stream",
            .fin = true,
        },
    }};
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &invalid,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    try std.testing.expectError(error.StreamCreationError, server.receiveRequest());
}

test "HTTP/3 handshake runtime establishes QUIC and exchanges request response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        },
        .session = .{ .local_settings = .{ .h3_datagram = true }, .max_stream_frame_data = 7 },
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
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings("h3", session.established.alpn);

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3-handshake", request.request.path);
            try std.testing.expectEqualStrings("split by handshake runtime", request.request.body);
            try std.testing.expect(session.control.settings.received);
            try std.testing.expectEqual(@as(u64, 6), session.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), session.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), session.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), session.control.peer_qpack_decoder_stream_id);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "handshake pong",
            });
            try std.testing.expect(session.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        },
        .session = .{ .local_settings = .{ .webtransport_max_sessions = 6 }, .max_stream_frame_data = 7 },
    });
    defer client.deinit();
    try std.testing.expectEqualStrings("h3", client.established.alpn);

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3-handshake",
        .authority = "localhost",
        .body = "split by handshake runtime",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("handshake pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);
}

test "HTTP/3 CONNECT datagrams round trip over a detached handshake stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xc0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xc8, 0xc9, 0xca, 0xcb };
    const server_cid = [_]u8{ 0xcc, 0xcd, 0xce, 0xcf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        },
        .session = .{ .local_settings = settings },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        response_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var head_event = try session.receiveRequestEvent();
            defer head_event.deinit(self.server.allocator);
            const stream_id = head_event.message.stream_id;
            try session.startResponse(stream_id, .{
                .status = 200,
                .request_method = "CONNECT",
                .extended_connect = true,
            }, null);
            self.response_sent.set(self.server.quic_server.endpoint.io);
            try session.detachRequestStream(stream_id);
            var incoming = try session.receiveConnectDatagramWithTimeout(
                stream_id,
                .fromSeconds(2),
            );
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("client datagram", incoming.payload);
            try session.sendConnectDatagram(stream_id, "server datagram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        thread.join();
    };
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xc1} ** 32,
            .x25519_secret_key = [_]u8{0xc2} ** 32,
        },
        .session = .{ .local_settings = settings },
    });
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/capsule",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "connect-udp" }},
    }, null);
    try shared.response_sent.wait(io);
    _ = try client.receivePeerSettingsWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            const date = server_response.headerValue(head.headers, "date") orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                @as(usize, server_response.date_value_len),
                date.len,
            );
            break;
        }
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try client.detachResponseStream(stream_id);
    try std.testing.expect(client.connectDatagramsNegotiated());
    try std.testing.expect(client.maxConnectDatagramPayloadSize(stream_id).? > 0);
    try client.sendConnectDatagram(stream_id, "client datagram");
    var incoming = try client.receiveConnectDatagramWithTimeout(
        stream_id,
        .fromSeconds(2),
    );
    defer incoming.deinit(allocator);
    try std.testing.expectEqualStrings("server datagram", incoming.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head registers preceding push promise" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    const client_cid = [_]u8{ 0xb8, 0xb9, 0xba, 0xbb };
    const server_cid = [_]u8{ 0xbc, 0xbd, 0xbe, 0xbf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            if (request != .message or
                request.message.value != .head or
                request.message.value.head != .request)
            {
                return error.TestUnexpectedResult;
            }
            while (session.control.peer_max_push_id != 0) {
                try session.receiveRequestPacket();
            }
            _ = try session.sendResponseWithPush(
                request.message.stream_id,
                .{
                    .status = 200,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                },
                .{
                    .push_id = 0,
                    .request = .{
                        .method = "GET",
                        .path = "/detached-asset",
                        .authority = "localhost",
                    },
                    .response = .{ .status = 204 },
                },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(0);
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-push",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            break;
        }
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expect(client.push_streams.hasPromise(0));
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.promiseCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head reports terminal missing headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const server_cid = [_]u8{ 0xac, 0xad, 0xae, 0xaf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        saw_stop: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            const stream_id = request.message.stream_id;
            try session.established.connection.send(&.{.{ .stream = .{
                .stream_id = stream_id,
                .data = &.{},
                .fin = true,
            } }});
            while (!self.saw_stop) {
                var packet = try session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } });
                defer packet.deinit(self.server.allocator);
                for (packet.frames) |frame| switch (frame) {
                    .stop_sending => |stop| if (stop.stream_id == stream_id) {
                        try std.testing.expectEqual(
                            @as(u64, http3.ApplicationErrorCode.message_error),
                            stop.application_error_code,
                        );
                        self.saw_stop = true;
                    },
                    else => {},
                };
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-missing",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (client.established.connection.recvStreamStats(stream_id) == null or
        client.established.connection.recvStreamStats(stream_id).?.final_size ==
            null)
    {
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expectError(
        error.MissingStatus,
        client.pollDetachedResponseHead(stream_id),
    );
    try std.testing.expect(!client.request_lifecycle.contains(stream_id));
    try std.testing.expect(!client.established.connection.closing());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 detached response head closes on terminal truncated frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    const client_cid = [_]u8{ 0x98, 0x99, 0x9a, 0x9b };
    const server_cid = [_]u8{ 0x9c, 0x9d, 0x9e, 0x9f };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
    };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequestEvent();
            defer request.deinit(self.server.allocator);
            try session.established.connection.send(&.{.{
                .stream = .{
                    .stream_id = request.message.stream_id,
                    // HEADERS type without its payload-length varint.
                    .data = &.{http3.FrameType.headers},
                    .fin = true,
                },
            }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/detached-truncated",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "test" }},
    }, null);

    while (client.established.connection.recvStreamStats(stream_id) == null or
        client.established.connection.recvStreamStats(stream_id).?.final_size ==
            null)
    {
        try client.established.connection.servicePacketServicingTimersDeadline(
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        );
    }
    try std.testing.expectError(
        error.BufferTooShort,
        client.pollDetachedResponseHead(stream_id),
    );
    const close = quic.one_rtt.testing.localCloseInfo(
        &client.established.connection,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(close.application);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.frame_error),
        close.error_code,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 paced request send preserves detached CONNECT during backpressure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };
    const settings = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        detached: std.Io.Event = .unset,
        send_terminal: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.detached.set(self.server.quic_server.endpoint.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var head_event = try session.receiveRequestEvent();
            defer head_event.deinit(self.server.allocator);
            const stream_id = head_event.message.stream_id;
            try session.startResponse(stream_id, .{
                .status = 200,
                .request_method = "CONNECT",
                .extended_connect = true,
            }, null);
            try session.detachRequestStream(stream_id);
            self.detached.set(self.server.quic_server.endpoint.io);
            try self.send_terminal.wait(
                self.server.quic_server.endpoint.io,
            );
            try session.sendResponseBodyPaced(stream_id, &.{}, true);
            // Unblock the client only after peer FIN is already socket-visible.
            // Its paced send must process that detached terminal packet before
            // consuming this later credit update and retrying successfully.
            const credit = [_]quic.Frame{.{ .max_stream_data = .{
                .stream_id = stream_id,
                .maximum_stream_data = 64 * 1024,
            } }};
            try session.established.connection.send(&credit);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_terminal.set(io);
        thread.join();
    };

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/backpressure",
        .authority = "localhost",
        .headers = &.{.{
            .name = ":protocol",
            .value = "connect-udp",
        }},
    }, null);
    try shared.detached.wait(io);
    while (true) {
        if (try client.pollDetachedResponseHead(stream_id)) |head_value| {
            var head = head_value;
            defer head.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            break;
        }
        try client.established.connection
            .servicePacketServicingTimersDeadline(.fromNow(io, .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        }));
    }
    try client.detachResponseStream(stream_id);

    const blocked_at = try quic.one_rtt.testing
        .clampSendStreamLimitToUsed(
        &client.established.connection,
        stream_id,
    );
    shared.send_terminal.set(io);
    try client.sendRequestBodyPaced(stream_id, "x", false);
    try std.testing.expect(
        quic.one_rtt.testing.sendStreamLimit(
            &client.established.connection,
            stream_id,
        ).? > blocked_at,
    );
    try std.testing.expectEqual(
        connect_datagram.Terminal.peer_fin,
        (try client.connect_datagrams.terminal(stream_id)).?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 CONNECT datagram invalid QSID closes the connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const local_cid = "h3-dgram-local";
    const peer_cid = "h3-dgram-peer";
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = peer_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    // Injecting at the transport queue isolates the RFC 9297 parser/error
    // mapping from packet protection while still exercising real close state.
    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{});
    try std.testing.expectError(
        error.BufferTooShort,
        drainConnectDatagrams(&registry, &connection),
    );
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.datagram_error,
        connection.close_info.?.error_code,
    );
    try std.testing.expect(connection.close_info.?.application);
    try std.testing.expectEqualStrings(
        "invalid-http-datagram",
        connection.close_info.?.reason_phrase,
    );
    try std.testing.expectEqual(@as(usize, 0), registry.associations.items.len);
}

test "HTTP/3 CONNECT datagrams preserve terminal frame ordering" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "order-local",
        .peer_connection_id = "order-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{
        0x00, 'b', 'e', 'f', 'o', 'r', 'e',
    });
    try quic.one_rtt.testing.injectReceivedDatagram(&connection, &.{
        0x00, 'a', 'f', 't', 'e', 'r',
    });
    const frames = [_]quic.Frame{
        .{ .datagram = .{ .data = &.{
            0x00, 'b', 'e', 'f', 'o', 'r', 'e',
        }, .length_present = true } },
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            .final_size = 0,
        } },
        .{ .datagram = .{ .data = &.{
            0x00, 'a', 'f', 't', 'e', 'r',
        }, .length_present = true } },
    };
    try routeConnectDatagramsFromPacket(&registry, &connection, &frames, 0);
    var before = (try registry.poll(0)).?;
    defer before.deinit(allocator);
    try std.testing.expectEqualStrings("before", before.payload);
    try std.testing.expectEqualDeep(
        connect_datagram.Terminal{
            .peer_reset = http3.ApplicationErrorCode.request_cancelled,
        },
        (try registry.drainedTerminal(0)).?,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(4));
    try std.testing.expectEqual(@as(usize, 0), connection.datagramReceiveQueueLen());

    registry.unregister(0);
    try registry.register(0);
    try quic.one_rtt.testing.injectReceivedDatagram(
        &connection,
        &.{ 0x00, 'l', 'a', 't', 'e' },
    );
    const close_frames = [_]quic.Frame{
        .{ .application_close = .{
            .error_code = 0,
            .reason_phrase = "done",
        } },
        .{ .datagram = .{ .data = &.{ 0x00, 'l', 'a', 't', 'e' } } },
    };
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &close_frames,
        0,
    );
    try std.testing.expectEqual(@as(?OwnedConnectDatagram, null), try registry.poll(0));
    try std.testing.expectEqual(
        connect_datagram.Terminal.connection_closed,
        (try registry.drainedTerminal(0)).?,
    );

    // A terminal frame does not need to share a packet with a DATAGRAM. Mark
    // it immediately so a DATAGRAM arriving in a later packet is discarded
    // without entering the bounded application queue.
    registry.unregister(0);
    try registry.register(0);
    const fin_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = &.{},
        .fin = true,
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &fin_frames,
        1,
    );
    try std.testing.expectEqual(
        connect_datagram.Terminal.peer_fin,
        (try registry.drainedTerminal(0)).?,
    );
    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        2,
        &.{ 0x00, 'l', 'a', 't', 'e' },
    );
    const late_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 'l', 'a', 't', 'e' },
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &late_frames,
        2,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.datagramReceiveQueueLen(),
    );
}

test "HTTP/3 CONNECT datagram routing isolates GRO packet copies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "gro-local",
        .peer_connection_id = "gro-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 4,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        10,
        &.{ 0x00, 'o', 'n', 'e' },
    );
    try quic.one_rtt.testing.injectReceivedDatagramForPacket(
        &connection,
        11,
        &.{ 0x00, 't', 'w', 'o' },
    );
    const first_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 'o', 'n', 'e' },
    } }};
    const second_frames = [_]quic.Frame{.{ .datagram = .{
        .data = &.{ 0x00, 't', 'w', 'o' },
    } }};
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &first_frames,
        10,
    );
    try std.testing.expectEqual(@as(usize, 1), connection.datagramReceiveQueueLen());
    try routeConnectDatagramsFromPacket(
        &registry,
        &connection,
        &second_frames,
        11,
    );
    var first = (try registry.poll(0)).?;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.payload);
    var second = (try registry.poll(0)).?;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.payload);
    try std.testing.expectEqual(@as(usize, 0), connection.datagramReceiveQueueLen());
}

test "HTTP/3 CONNECT datagram validates transport-dropped payloads" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdb} ** quic.protection.secret_len,
    );
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "drop-local",
        .peer_connection_id = "drop-peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 0,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var registry = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = &.{} } }};
    try std.testing.expectError(
        error.BufferTooShort,
        routeConnectDatagramsFromPacket(
            &registry,
            &connection,
            &frames,
            12,
        ),
    );
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        http3.ApplicationErrorCode.datagram_error,
        connection.close_info.?.error_code,
    );
}

test "HTTP/3 handshake client requests from URI endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x01, 0x11 };
    const client_cid = [_]u8{ 0xa2, 0xb2, 0xc2, 0xd2 };
    const server_cid = [_]u8{ 0xa3, 0xb3, 0xc3, 0xd3 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa4} ** 32,
            .x25519_secret_key = [_]u8{0xa5} ** 32,
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
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/uri", request.request.path);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.authority.?[0..9]);
            try session.sendResponse(request.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var uri_buf: [64]u8 = undefined;
    const uri_text = try std.fmt.bufPrint(&uri_buf, "https://127.0.0.1:{d}/uri", .{server.address().ip4.port});
    const uri = try std.Uri.parse(uri_text);
    var response = try HandshakeClient.requestUri(allocator, io, .{ .ip4 = .loopback(0) }, uri, .{}, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xa6} ** 32,
            .x25519_secret_key = [_]u8{0xa7} ** 32,
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 URI request deadline covers the response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        deadline: std.Io.Clock.Timestamp,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            // A received request proves the handshake and request send both
            // completed inside the caller's budget. Hold the response past
            // that same absolute timestamp so only response waiting can time
            // out, independent of host load.
            try self.deadline.wait(
                session.established.connection.endpoint.io,
            );
            try std.Io.sleep(
                session.established.connection.endpoint.io,
                .fromMilliseconds(25),
                .awake,
            );
        }
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    var shared = Shared{ .server = &server, .deadline = deadline };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var uri_buf: [64]u8 = undefined;
    const uri_text = try std.fmt.bufPrint(
        &uri_buf,
        "https://127.0.0.1:{d}/deadline",
        .{server.address().getPort()},
    );
    const uri = try std.Uri.parse(uri_text);
    try std.testing.expectError(
        error.Timeout,
        HandshakeClient.requestUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{},
            .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
            .{
                .connect_timeout = .fromSeconds(1),
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .random = [_]u8{0xd3} ** 32,
                    .x25519_secret_key = [_]u8{0xd4} ** 32,
                },
            },
            deadline,
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client requests via Alt-Svc target" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const uri = try std.Uri.parse("https://origin.example/alt");

    try std.testing.expectError(error.InvalidHeader, HandshakeClient.requestUriAltSvc(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{ .alpn = "h2", .connect_host = "127.0.0.1", .origin_host = "origin.example", .port = 443 },
        .{},
        .{},
        .{ .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid } },
    ));

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
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
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/alt", request.request.path);
            try std.testing.expectEqualStrings("origin.example", request.request.authority.?);
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const server_address = server.address();
    var alt_svc_value_buf: [64]u8 = undefined;
    const alt_svc_value = try std.fmt.bufPrint(
        &alt_svc_value_buf,
        "h3=\"127.0.0.1:{d}\"; ma=60",
        .{server_address.ip4.port},
    );
    const alt_svc_headers = [_]http3.Qpack.HeaderField{
        .{ .name = "alt-svc", .value = alt_svc_value },
    };
    var response = try HandshakeClient.requestUriAltSvcHeader(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        &alt_svc_headers,
        .{},
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb6} ** 32,
            .x25519_secret_key = [_]u8{0xb7} ** 32,
        } },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake server retains interleaved request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), first.stream_id);
            try std.testing.expectEqualStrings("/first", first.request.path);
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_streams.count(),
            );

            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), second.stream_id);
            try std.testing.expectEqualStrings("/second", second.request.path);
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.count(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x61} ** 32,
                .x25519_secret_key = [_]u8{0x62} ** 32,
            },
        },
    );
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.critical_stream_send_scratch,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = 4,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try client.established.connection.send(&frames);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client cancellation reaches server" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c };
    const client_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x77} ** 32,
                .x25519_secret_key = [_]u8{0x78} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectError(
                error.RequestCancelled,
                session.receiveRequest(),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.count(),
            );
            const reset = session.established.connection.streamResetReceived(0) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                reset.application_error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x75} ** 32,
                .x25519_secret_key = [_]u8{0x76} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.cancelRequest(
        0,
        http3.ApplicationErrorCode.request_cancelled,
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake server performs two-phase graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80 };
    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x8b} ** 32,
                .x25519_secret_key = [_]u8{0x8c} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.initiateShutdown();
            try session.completeShutdown();
            try std.testing.expectEqual(
                @as(?u64, 4),
                session.control.local_goaway_id,
            );
            try std.testing.expect(!session.drainComplete());
            try session.sendResponse(request.stream_id, .{ .status = 204 });
            try std.testing.expect(session.drainComplete());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x89} ** 32,
                .x25519_secret_key = [_]u8{0x8a} ** 32,
            },
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/graceful",
        .authority = "localhost",
    });
    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 4)
    {
        try client.receiveProgress();
    }
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expectEqual(@as(?u64, 4), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-graceful",
    }));
}

test "HTTP/3 handshake client sends priority update before request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94 };
    const client_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const server_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x9f} ** 32,
                .x25519_secret_key = [_]u8{0xa0} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(1),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            // Admission consumes the one-shot control-stream hint into the
            // active request lifecycle. Validate the effective scheduler
            // priority rather than the retired compatibility view.
            const priority = session.request_lifecycle.priority(
                request.stream_id,
            );
            try std.testing.expectEqual(
                @as(u3, 2),
                priority.urgency,
            );
            try std.testing.expect(priority.incremental);
            try std.testing.expect(
                session.control.requestPriorityUpdate(request.stream_id) ==
                    null,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x9d} ** 32,
                .x25519_secret_key = [_]u8{0x9e} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.sendPriorityUpdate(0, .{
        .urgency = 2,
        .incremental = true,
    });
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/prioritized",
        .authority = "localhost",
    });
    var response = client.receiveResponseWithTimeout(
        stream_id,
        .fromSeconds(3),
    ) catch |err| {
        thread.join();
        joined = true;
        if (shared.err) |server_err| return server_err;
        return err;
    };
    defer response.deinit(allocator);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client advertises and cancels server push IDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4 };
    const client_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const server_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xdf} ** 32,
                .x25519_secret_key = [_]u8{0xe0} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            while (session.control.peer_max_push_id != 8 or
                !session.control.pushCancelled(7) or
                !session.control.pushCancelled(3))
            {
                var packet = try session.established.connection.receivePacket();
                defer packet.deinit(
                    session.established.connection.endpoint.allocator,
                );
                for (packet.frames) |frame| {
                    if (frame != .stream) continue;
                    if (try applyControlStreamFrameForRole(
                        &session.control,
                        session.established.connection.endpoint.allocator,
                        frame.stream,
                        .server,
                    )) {
                        try configureQpackEncoderFromPeerSettings(
                            session.control,
                            &session.qpack_encode,
                        );
                    }
                }
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xdd} ** 32,
                .x25519_secret_key = [_]u8{0xde} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(4);
    try client.sendMaxPushId(8);
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPush(7);
    try client.cancelPush(3);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client streams promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Observation = struct {
        push_ids: [2]u64 = undefined,
        request_stream_ids: [2]u62 = undefined,
        stream_ids: [2]u62 = undefined,
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            push_id: u64,
            request_stream_id: u62,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.push_ids[self.count] = push_id;
            self.request_stream_ids[self.count] = request_stream_id;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };
    const original_dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_cid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    const server_cid = [_]u8{ 0xed, 0xee, 0xef, 0xf0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            while (session.control.peer_max_push_id != 1) {
                try session.receiveRequestPacket();
            }
            const push_stream_id = try session.sendResponseWithPush(
                request.stream_id,
                .{ .status = 204 },
                .{
                    .push_id = 1,
                    .request = .{
                        .method = "GET",
                        .path = "/handshake.css",
                        .authority = "localhost",
                    },
                    .informational = &.{
                        .{ .status = 103 },
                        .{ .status = 102 },
                    },
                    .response = .{
                        .status = 200,
                        .body = "handshake-asset",
                    },
                },
            );
            try std.testing.expectEqual(
                first_server_push_stream_id,
                push_stream_id,
            );
            try std.testing.expect(
                session.push_send_scratch.parent.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.pushed.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.frames.capacity != 0,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var thread_joined = false;
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer client.deinit();
    defer if (!thread_joined) thread.join();
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    var observation: Observation = .{};
    var pushed = try client.receivePushWithInformational(.{
        .context = &observation,
        .on_response = Observation.observe,
    });
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(@as(u62, 15), pushed.stream_id);
    try std.testing.expectEqualStrings(
        "handshake-asset",
        pushed.response.body,
    );
    try std.testing.expectEqual(@as(usize, 2), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(@as(u64, 1), observation.push_ids[index]);
        try std.testing.expectEqual(
            request_stream_id,
            observation.request_stream_ids[index],
        );
        try std.testing.expectEqual(@as(u62, 15), observation.stream_ids[index]);
        try std.testing.expectEqual(
            if (index == 0) @as(u16, 103) else 102,
            status,
        );
    }
    thread.join();
    thread_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client sends priority update for promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            try session.peer_promised_push_ids.append(
                session.established.connection.endpoint.allocator,
                1,
            );
            while (session.control.pushPriorityUpdate(1) == null) {
                try session.receiveRequestPacket();
            }
            const priority =
                session.control.pushPriorityUpdate(1).?.priority();
            try std.testing.expectEqual(@as(u3, 4), priority.urgency);
            try std.testing.expect(priority.incremental);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(1);
    try client.push_streams.registerPromise(1, 0);
    try client.sendPushPriorityUpdate(1, .{
        .urgency = 4,
        .incremental = true,
    });
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client retains interleaved responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Observation = struct {
        stream_ids: [4]u62 = undefined,
        statuses: [4]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };

    const original_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_cid = [_]u8{ 0xa9, 0xaa, 0xab, 0xac };
    const server_cid = [_]u8{ 0xad, 0xae, 0xaf, 0xb0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponseWithInformational(
                second.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "second-response" },
            );
            try session.sendResponseWithInformational(
                first.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "first-response" },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
        },
    );
    defer client.deinit();

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    var observation: Observation = .{};
    const observer: MultiplexedInformationalObserver = .{
        .context = &observation,
        .on_response = Observation.observe,
    };
    var first_event = try client.receiveNextResponseWithInformational(observer);
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(
        second_id,
        first_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "second-response",
        first_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.request_lifecycle.count(),
    );
    var second_event = try client.receiveNextResponseWithInformational(observer);
    defer second_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        first_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "first-response",
        second_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
    try std.testing.expectEqual(@as(usize, 4), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(
            if (index < 2) second_id else first_id,
            observation.stream_ids[index],
        );
        try std.testing.expectEqual(
            if (index % 2 == 0) @as(u16, 103) else 102,
            status,
        );
    }
}

test "HTTP/3 handshake client response deadline preserves progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x43} ** 32,
            .x25519_secret_key = [_]u8{0x44} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.Io.sleep(
                session.established.connection.endpoint.io,
                .fromMilliseconds(80),
                .awake,
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "after-timeout",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x41} ** 32,
            .x25519_secret_key = [_]u8{0x42} ** 32,
        } },
    );
    defer client.deinit();
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/deadline",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseWithTimeout(
            stream_id,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(client.request_lifecycle.contains(stream_id));

    var saw_head = false;
    var saw_finished = false;
    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!saw_finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                saw_head = true;
            },
            .data_available => {
                const count = try client.readResponseData(
                    stream_id,
                    body[body_len..],
                );
                body_len += count;
            },
            .finished => saw_finished = true,
            .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expectEqualStrings("after-timeout", body[0..body_len]);
    try std.testing.expect(!client.request_lifecycle.contains(stream_id));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client next-response deadlines preserve progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x63} ** 32,
            .x25519_secret_key = [_]u8{0x64} ** 32,
        } },
    );
    defer server.deinit();

    const aggregate_body = "aggregate-next";
    const streaming_body = "streaming-next";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        aggregate_head_sent: std.Io.Event = .unset,
        aggregate_timed_out: std.Io.Event = .unset,
        streaming_head_sent: std.Io.Event = .unset,
        streaming_timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.aggregate_head_sent.set(self.io);
                self.aggregate_timed_out.set(self.io);
                self.streaming_head_sent.set(self.io);
                self.streaming_timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();

            var aggregate = try session.receiveRequest();
            defer aggregate.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                aggregate.stream_id,
                .{ .status = 200 },
                aggregate_body.len,
            );
            self.aggregate_head_sent.set(self.io);
            try self.aggregate_timed_out.wait(self.io);
            try session.sendResponseBody(
                aggregate.stream_id,
                aggregate_body,
                true,
            );

            var streaming = try session.receiveRequest();
            defer streaming.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                streaming.stream_id,
                .{ .status = 200 },
                streaming_body.len,
            );
            self.streaming_head_sent.set(self.io);
            try self.streaming_timed_out.wait(self.io);
            try session.sendResponseBody(
                streaming.stream_id,
                streaming_body,
                true,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x61} ** 32,
            .x25519_secret_key = [_]u8{0x62} ** 32,
        } },
    );
    defer client.deinit();

    const aggregate_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/aggregate-next-deadline",
        .authority = "localhost",
    });
    try shared.aggregate_head_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(aggregate_id));
    try std.testing.expect(!client.response_streams.isEmpty());
    shared.aggregate_timed_out.set(io);

    var aggregate_event = try client.receiveNextResponseWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer aggregate_event.deinit(allocator);
    try std.testing.expect(aggregate_event == .response);
    try std.testing.expectEqual(
        aggregate_id,
        aggregate_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        aggregate_body,
        aggregate_event.response.value.response.body,
    );
    try std.testing.expect(!client.request_lifecycle.contains(aggregate_id));

    const streaming_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-next-deadline",
        .authority = "localhost",
    });
    try shared.streaming_head_sent.wait(io);
    var head = try client.receiveNextResponseEventWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expectEqual(streaming_id, head.message.stream_id);
    try std.testing.expect(head.message.value == .head);

    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseEventWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(streaming_id));
    try std.testing.expect(client.streaming_responses.find(streaming_id) != null);
    shared.streaming_timed_out.set(io);

    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!finished) {
        var event = try client.receiveNextResponseEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        try std.testing.expectEqual(streaming_id, event.message.stream_id);
        switch (event.message.value) {
            .data_available => {
                body_len += try client.readResponseData(
                    streaming_id,
                    body[body_len..],
                );
            },
            .finished => finished = true,
            .head, .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings(streaming_body, body[0..body_len]);
    try std.testing.expect(!client.request_lifecycle.contains(streaming_id));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client push deadlines preserve progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        } },
    );
    defer server.deinit();

    const aggregate_body = "aggregate-push-after-timeout";
    const streaming_body = "streaming-push-after-timeout";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        aggregate_prefix_sent: std.Io.Event = .unset,
        aggregate_timed_out: std.Io.Event = .unset,
        streaming_prefix_sent: std.Io.Event = .unset,
        streaming_timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.aggregate_prefix_sent.set(self.io);
                self.aggregate_timed_out.set(self.io);
                self.streaming_prefix_sent.set(self.io);
                self.streaming_timed_out.set(self.io);
            };
        }

        fn sendSplitPush(
            self: *@This(),
            session: *HandshakeServerSession,
            request_stream_id: u62,
            push_id: u64,
            push_stream_id: u62,
            path: []const u8,
            body: []const u8,
            body_prefix_len: usize,
            prefix_sent: *std.Io.Event,
            timed_out: *std.Io.Event,
        ) !void {
            var parent: std.ArrayList(u8) = .empty;
            defer parent.deinit(allocator);
            var pushed: std.ArrayList(u8) = .empty;
            defer pushed.deinit(allocator);
            try encodePushMessages(
                allocator,
                session.control.settings.peer,
                request_stream_id,
                .{ .status = 204 },
                push_stream_id,
                .{
                    .push_id = push_id,
                    .request = .{
                        .method = "GET",
                        .path = path,
                        .authority = "localhost",
                    },
                    .response = .{
                        .status = 200,
                        .body = body,
                    },
                },
                &session.qpack_encode,
                &parent,
                &pushed,
            );
            try sendConnectionQpackEncoderInstructions(
                &session.established.connection,
                &session.critical_stream_send_scratch,
                &session.qpack_encode,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                session.options,
            );
            const split = pushed.items.len - body.len + body_prefix_len;
            const prefix_frames = [_]quic.Frame{
                .{ .stream = .{
                    .stream_id = request_stream_id,
                    .data = parent.items,
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = push_stream_id,
                    .data = pushed.items[0..split],
                    .fin = false,
                } },
            };
            try sendConnectionFrames(
                &session.established.connection,
                &prefix_frames,
                session.options.max_frames_per_packet,
            );
            prefix_sent.set(self.io);
            try timed_out.wait(self.io);
            try sendConnectionFrames(
                &session.established.connection,
                &.{.{ .stream = .{
                    .stream_id = push_stream_id,
                    .offset = split,
                    .data = pushed.items[split..],
                    .fin = true,
                } }},
                session.options.max_frames_per_packet,
            );
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(allocator);
            while (session.control.peer_max_push_id != 2) {
                try session.receiveRequestPacket();
            }
            try self.sendSplitPush(
                &session,
                first.stream_id,
                1,
                first_server_push_stream_id,
                "/aggregate-push",
                aggregate_body,
                aggregate_body.len / 2,
                &self.aggregate_prefix_sent,
                &self.aggregate_timed_out,
            );

            var second = try session.receiveRequest();
            defer second.deinit(allocator);
            try self.sendSplitPush(
                &session,
                second.stream_id,
                2,
                first_server_push_stream_id + 4,
                "/streaming-push",
                streaming_body,
                0,
                &self.streaming_prefix_sent,
                &self.streaming_timed_out,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        // Never hide a client-side assertion behind a server thread waiting
        // for the continuation gates below.
        shared.aggregate_timed_out.set(io);
        shared.streaming_timed_out.set(io);
        thread.join();
    };

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        } },
    );
    defer client.deinit();
    try client.sendMaxPushId(2);

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first-push",
        .authority = "localhost",
    });
    try shared.aggregate_prefix_sent.wait(io);
    while (true) {
        const event = try client.receiveResponseEvent(first_id);
        if (event) |value| {
            var owned = value;
            defer owned.deinit(allocator);
            if (owned == .push_promise) break;
        }
    }
    try std.testing.expectError(
        error.Timeout,
        client.receivePushWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(@as(?u64, 1), client.push_aggregate.push_id);
    try std.testing.expect(client.push_aggregate.head != null);
    try std.testing.expectEqualStrings(
        aggregate_body[0 .. aggregate_body.len / 2],
        client.push_aggregate.body.items,
    );
    shared.aggregate_timed_out.set(io);
    var aggregate = try client.receivePushWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer aggregate.deinit(allocator);
    try std.testing.expectEqualStrings(aggregate_body, aggregate.response.body);

    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second-push",
        .authority = "localhost",
    });
    try shared.streaming_prefix_sent.wait(io);
    while (true) {
        const event = try client.receiveResponseEvent(second_id);
        if (event) |value| {
            var owned = value;
            defer owned.deinit(allocator);
            if (owned == .push_promise) break;
        }
    }
    var push_head = try client.receivePushEventWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer push_head.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), push_head.push_id);
    try std.testing.expect(push_head.value == .head);
    try std.testing.expectError(
        error.Timeout,
        client.receivePushEventWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.push_streams.findByPushId(2) != null);
    shared.streaming_timed_out.set(io);

    var skipped_body_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!finished) {
        var event = try client.receivePushEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 2), event.push_id);
        switch (event.value) {
            .data_available => {
                skipped_body_len += try client.skipPushData(2);
            },
            .finished => finished = true,
            .head, .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(streaming_body.len, skipped_body_len);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client drains GRO response batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try sendConnectionSettings(
                &session.established.connection,
                &session.critical_stream_send_scratch,
                &session.control,
                &session.control_send,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                &session.qpack_decoder_send,
                &session.qpack_decoder_prefix_sent,
                session.options,
                server_control_stream_id,
            );

            var first_bytes: std.ArrayList(u8) = .empty;
            defer first_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-one",
            }).write(
                &first_bytes,
                session.established.connection.endpoint.allocator,
            );
            var second_bytes: std.ArrayList(u8) = .empty;
            defer second_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-two",
            }).write(
                &second_bytes,
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(
                first_bytes.items.len,
                second_bytes.items.len,
            );
            const second_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = second.stream_id,
                .data = second_bytes.items,
                .fin = true,
            } }};
            const first_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = first.stream_id,
                .data = first_bytes.items,
                .fin = true,
            } }};
            const packets = [_][]const quic.Frame{
                &second_frames,
                &first_frames,
            };
            try session.established.connection.sendMany(&packets);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
        },
    );
    defer client.deinit();
    if (!client.endpoint.groReceiveEnabled()) {
        thread.join();
        if (shared.err) |err| return err;
        return error.SkipZigTest;
    }

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    });
    // Force the cursor through the timer-aware GRO branch rather than the
    // no-deadline shortcut. The server's two response packets should still be
    // retained as one owning batch behind the first application event.
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    client.established.connection.ack_delay_start_ns = @intCast(now);
    client.established.connection.ack_delay_deadline_ns =
        @intCast(now + std.time.ns_per_s);
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        second_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "response-two",
        second_event.response.value.response.body,
    );
    try std.testing.expect(client.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.receive_packets.batch.?.remaining(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.response_streams.count(),
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(first_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "response-one",
        first_event.response.value.response.body,
    );
}

test "HTTP/3 handshake client batches request DATA across streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var saw_first = false;
            var saw_second = false;
            var first_stream_id: ?u62 = null;
            var second_stream_id: ?u62 = null;
            for (0..2) |_| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-first",
                )) {
                    try std.testing.expectEqualStrings(
                        "first-body",
                        request.request.body,
                    );
                    saw_first = true;
                    first_stream_id = request.stream_id;
                } else if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-second",
                )) {
                    try std.testing.expectEqualStrings(
                        "second-body",
                        request.request.body,
                    );
                    saw_second = true;
                    second_stream_id = request.stream_id;
                } else {
                    return error.TestUnexpectedResult;
                }
            }
            try std.testing.expect(saw_first);
            try std.testing.expect(saw_second);
            try session.startResponse(
                first_stream_id.?,
                .{ .status = 200 },
                "first-response".len,
            );
            try session.startResponse(
                second_stream_id.?,
                .{ .status = 200 },
                "second-response".len,
            );
            try session.sendResponseBodyBatchPaced(&.{
                .{
                    .stream_id = first_stream_id.?,
                    .data = "first-response",
                    .fin = true,
                },
                .{
                    .stream_id = second_stream_id.?,
                    .data = "second-response",
                    .fin = true,
                },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer client.deinit();

    const first = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-first",
        .authority = "localhost",
    }, "first-body".len);
    const second = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-second",
        .authority = "localhost",
    }, "second-body".len);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendRequestBodyBatchPaced(&.{
            .{ .stream_id = first, .data = "first-body", .fin = true },
            .{ .stream_id = first, .data = "first-body", .fin = true },
        }),
    );
    try client.sendRequestBodyBatchPaced(&.{
        .{ .stream_id = first, .data = "first-body", .fin = true },
        .{ .stream_id = second, .data = "second-body", .fin = true },
    });
    for (0..2) |_| {
        var event = try client.receiveNextResponse();
        defer event.deinit(allocator);
        try std.testing.expect(event == .response);
        try std.testing.expectEqual(@as(u16, 200), event.response.value.response.status);
        if (event.response.stream_id == first) {
            try std.testing.expectEqualStrings(
                "first-response",
                event.response.value.response.body,
            );
        } else if (event.response.stream_id == second) {
            try std.testing.expectEqualStrings(
                "second-response",
                event.response.value.response.body,
            );
        } else {
            return error.TestUnexpectedResult;
        }
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 detached progress timeout validates budget before state" {
    var server: HandshakeServerSession = undefined;
    try std.testing.expectError(
        error.Timeout,
        server.receiveDetachedRequestProgressWithTimeout(0, .zero),
    );

    var client: HandshakeClient = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveDetachedResponseProgressWithTimeout(0, .zero),
    );
}

test "HTTP/3 handshake runtime streams request and response DATA chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "handshake-request",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200 },
                "handshake-response".len,
            );
            try session.sendResponseBody(
                request.stream_id,
                "handshake-",
                false,
            );
            try session.sendResponseBody(
                request.stream_id,
                "response",
                false,
            );
            try session.finishResponseTrailers(
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/streaming",
            .authority = "localhost",
        },
        "handshake-request".len,
    );
    try client.sendRequestBody(stream_id, "handshake-", false);
    try client.sendRequestBody(stream_id, "request", false);
    try client.finishRequestTrailers(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings(
        "handshake-response",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );
}

test "HTTP/3 handshake server streams large request through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var saw_head = false;
            var saw_trailers = false;
            var body_read: usize = 0;
            var checksum: u64 = 0;
            var stream_id: ?u62 = null;
            var read_buf: [113]u8 = undefined;
            while (session.streaming_requests.retainedCount() != 0 or
                !saw_head)
            {
                var event = try session.receiveRequestEvent();
                defer event.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expect(event == .message);
                const message = &event.message;
                if (stream_id) |expected| {
                    try std.testing.expectEqual(expected, message.stream_id);
                } else {
                    stream_id = message.stream_id;
                }
                switch (message.value) {
                    .head => |head| {
                        try std.testing.expect(head == .request);
                        try std.testing.expectEqual(
                            @as(?usize, body_len),
                            head.request.content_length,
                        );
                        saw_head = true;
                    },
                    .push_promise => return error.TestUnexpectedResult,
                    .data_available => {
                        while (true) {
                            const active = session.streaming_requests.find(
                                message.stream_id,
                            ).?;
                            if (!active.reader.hasPendingFrame()) break;
                            const read = try session.readRequestData(
                                message.stream_id,
                                &read_buf,
                            );
                            if (read == 0) break;
                            for (read_buf[0..read]) |byte| checksum +%= byte;
                            body_read += read;
                        }
                        const active = session.streaming_requests.find(
                            message.stream_id,
                        ).?;
                        try std.testing.expect(
                            active.reader.bufferedBytes() <= 512,
                        );
                    },
                    .trailers => |trailers| {
                        try std.testing.expectEqualStrings(
                            "yes",
                            trailers.fields[0].value,
                        );
                        saw_trailers = true;
                    },
                    .finished => {},
                }
            }
            try std.testing.expect(saw_head);
            try std.testing.expect(saw_trailers);
            try std.testing.expectEqual(body_len, body_read);

            var chunk: [400]u8 = undefined;
            var chunk_sum: u64 = 0;
            for (&chunk, 0..) |*byte, index| {
                byte.* = @truncate(index);
                chunk_sum += byte.*;
            }
            var expected = chunk_sum * (body_len / chunk.len);
            for (chunk[0 .. body_len % chunk.len]) |byte| expected += byte;
            try std.testing.expectEqual(expected, checksum);
            try session.sendResponse(stream_id.?, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/large-handshake-request",
            .authority = "localhost",
        },
        body_len,
    );
    var chunk: [400]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
    var remaining = body_len;
    while (remaining != 0) {
        const count = @min(chunk.len, remaining);
        try client.sendRequestBodyPaced(
            stream_id,
            chunk[0..count],
            false,
        );
        remaining -= count;
    }
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-request-finished",
        .value = "yes",
    }});
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client streams dynamic response through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 1024 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_frame_data = 480,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/large-handshake-stream",
                    request.request.path,
                );
                if (exchange != 0) {
                    // The first response inserts both repeated fields. Reading
                    // the next request pumps the client's Insert Count
                    // Increment, allowing later response sections to reference
                    // those entries without blocking.
                    try std.testing.expect(
                        session.qpack_encode.known_received_count >= 2,
                    );
                }
                const response: http3.Response = .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-stream-kind",
                        .value = "bounded-handshake",
                    }},
                    .trailers = &.{.{
                        .name = "x-stream-finished",
                        .value = "yes",
                    }},
                };
                if (exchange < 2) {
                    var warmup = response;
                    warmup.body = "warmup";
                    try session.sendResponse(request.stream_id, warmup);
                    continue;
                }
                try session.startResponse(
                    request.stream_id,
                    .{
                        .status = response.status,
                        .headers = response.headers,
                    },
                    body_len,
                );
                var chunk: [400]u8 = undefined;
                for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
                var remaining = body_len;
                while (remaining != 0) {
                    const count = @min(chunk.len, remaining);
                    try session.sendResponseBodyPaced(
                        request.stream_id,
                        chunk[0..count],
                        false,
                    );
                    remaining -= count;
                }
                try session.finishResponseTrailersPaced(
                    request.stream_id,
                    response.trailers,
                );
                return;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    for (0..2) |exchange| {
        var warmup = try client.request(.{
            .method = "GET",
            .path = "/large-handshake-stream",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqualStrings("warmup", warmup.response.body);
        if (exchange == 1) {
            try std.testing.expect(
                warmup.response.qpack_section_acknowledgments != 0,
            );
        }
    }

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/large-handshake-stream",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_trailers = false;
    var body_read: usize = 0;
    var checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (client.request_lifecycle.contains(stream_id)) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expectEqual(
                    @as(u16, 200),
                    head.response.status,
                );
                try std.testing.expectEqual(
                    @as(?usize, body_len),
                    head.response.content_length,
                );
                try std.testing.expect(
                    head.response.qpack_section_acknowledgments != 0,
                );
                saw_head = true;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = client.streaming_responses.find(
                        stream_id,
                    ).?;
                    if (!active.reader.hasPendingFrame()) break;
                    const read = try client.readResponseData(
                        stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    for (read_buf[0..read]) |byte| checksum +%= byte;
                    body_read += read;
                }
                const active = client.streaming_responses.find(stream_id).?;
                try std.testing.expect(
                    active.reader.bufferedBytes() <= 512,
                );
            },
            .trailers => |trailers| {
                try std.testing.expectEqualStrings(
                    "yes",
                    trailers.fields[0].value,
                );
                try std.testing.expect(
                    trailers.qpack_section_acknowledgments != 0,
                );
                saw_trailers = true;
            },
            .finished => {},
        }
    }
    thread.join();
    if (shared.err) |err| return err;

    var chunk: [400]u8 = undefined;
    var chunk_checksum: u64 = 0;
    for (&chunk, 0..) |*byte, index| {
        byte.* = @truncate(index);
        chunk_checksum += byte.*;
    }
    var expected_checksum =
        chunk_checksum * (body_len / chunk.len);
    for (chunk[0 .. body_len % chunk.len]) |byte| {
        expected_checksum += byte;
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
    try std.testing.expectEqual(body_len, body_read);
    try std.testing.expectEqual(expected_checksum, checksum);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entryCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.count(),
    );
}

test "HTTP/3 handshake runtime reuses acknowledged dynamic QPACK entries" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const server_cid = [_]u8{ 0xac, 0xad, 0xae, 0xaf };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
            },
        },
    );
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
            var session = try server_ptr.accept();
            defer session.deinit();
            var encoded_capacity: usize = 0;
            var frame_capacity: usize = 0;
            var encoded_ptr: [*]u8 = undefined;
            var frame_ptr: [*]quic.Frame = undefined;
            var critical_capacity: usize = 0;
            var critical_frames_capacity: usize = 0;
            var critical_ptr: [*]u8 = undefined;
            var critical_frames_ptr: [*]quic.Frame = undefined;

            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/handshake-dynamic",
                    request.request.path,
                );
                var repeated_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-handshake-request")) {
                        repeated_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "repeated-request-value",
                    repeated_value orelse return error.TestUnexpectedResult,
                );

                if (exchange == 1) {
                    // The second request carries inserts but remains literal
                    // under SETTINGS_QPACK_BLOCKED_STREAMS=0. Waiting for it
                    // also consumes feedback that unlocks response reuse.
                    try std.testing.expectEqual(
                        @as(usize, 0),
                        request.request.qpack_section_acknowledgments,
                    );
                    try std.testing.expect(
                        session.qpack_decode.table.insert_count != 0,
                    );
                    try std.testing.expect(
                        session.qpack_encode.known_received_count != 0,
                    );
                } else if (exchange == 2) {
                    try std.testing.expect(
                        request.request.qpack_section_acknowledgments != 0,
                    );
                }

                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-handshake-response",
                        .value = "repeated-response-value",
                    }},
                    .body = "ok",
                });
                if (exchange == 0) {
                    encoded_capacity =
                        session.stream_send_scratch.encoded.capacity;
                    frame_capacity =
                        session.stream_send_scratch.frames.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    try std.testing.expect(frame_capacity != 0);
                    encoded_ptr = session.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                    frame_ptr = session.stream_send_scratch.frames
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        session.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        frame_capacity,
                        session.stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        session.stream_send_scratch.encoded
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        frame_ptr,
                        session.stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
                // The second exchange can carry the first dynamic inserts and
                // therefore establishes the steady-state high-water mark.
                if (exchange == 1) {
                    critical_capacity = session
                        .critical_stream_send_scratch.payload.capacity;
                    critical_frames_capacity = session
                        .critical_stream_send_scratch.frames.capacity;
                    try std.testing.expect(critical_capacity != 0);
                    try std.testing.expect(critical_frames_capacity != 0);
                    critical_ptr = session.critical_stream_send_scratch.payload
                        .allocatedSlice().ptr;
                    critical_frames_ptr = session
                        .critical_stream_send_scratch.frames.allocatedSlice().ptr;
                } else if (exchange == 2) {
                    try std.testing.expectEqual(
                        critical_capacity,
                        session.critical_stream_send_scratch.payload.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_frames_capacity,
                        session.critical_stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_ptr,
                        session.critical_stream_send_scratch.payload
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        critical_frames_ptr,
                        session.critical_stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
                if (exchange != 0) {
                    try std.testing.expect(
                        session.qpack_encode.pending_sections.items.len != 0,
                    );
                }
            }
            try std.testing.expect(
                session.qpack_encoder_send.next_offset > 1,
            );
            try std.testing.expect(
                session.qpack_decoder_send.next_offset > 1,
            );
            try std.testing.expectEqual(
                @as(?usize, 512),
                session.qpack_encode.peer_max_capacity,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer client.deinit();

    var encoded_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var encoded_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    var critical_capacity: usize = 0;
    var critical_frames_capacity: usize = 0;
    var critical_ptr: [*]u8 = undefined;
    var critical_frames_ptr: [*]quic.Frame = undefined;
    for (0..3) |exchange| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/handshake-dynamic",
            .authority = "example.test",
            .headers = &.{.{
                .name = "x-handshake-request",
                .value = "repeated-request-value",
            }},
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        var repeated_value: ?[]const u8 = null;
        for (response.response.headers) |header| {
            if (std.mem.eql(u8, header.name, "x-handshake-response")) {
                repeated_value = header.value;
            }
        }
        try std.testing.expectEqualStrings(
            "repeated-response-value",
            repeated_value orelse return error.TestUnexpectedResult,
        );
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            frame_capacity = client.stream_send_scratch.frames.capacity;
            try std.testing.expect(encoded_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            frame_ptr = client.stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                client.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                client.stream_send_scratch.frames.allocatedSlice().ptr,
            );
        }
        if (exchange == 1) {
            critical_capacity =
                client.critical_stream_send_scratch.payload.capacity;
            critical_frames_capacity =
                client.critical_stream_send_scratch.frames.capacity;
            try std.testing.expect(critical_capacity != 0);
            try std.testing.expect(critical_frames_capacity != 0);
            critical_ptr = client.critical_stream_send_scratch.payload
                .allocatedSlice().ptr;
            critical_frames_ptr = client.critical_stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else if (exchange == 2) {
            try std.testing.expectEqual(
                critical_capacity,
                client.critical_stream_send_scratch.payload.capacity,
            );
            try std.testing.expectEqual(
                critical_frames_capacity,
                client.critical_stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                critical_ptr,
                client.critical_stream_send_scratch.payload
                    .allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                critical_frames_ptr,
                client.critical_stream_send_scratch.frames
                    .allocatedSlice().ptr,
            );
        }
    }

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(client.qpack_encode.known_received_count != 0);
    try std.testing.expect(client.qpack_decode.table.insert_count != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(client.qpack_encoder_send.next_offset > 1);
    try std.testing.expect(client.qpack_decoder_send.next_offset > 1);
    try std.testing.expectEqual(
        @as(?usize, 512),
        client.qpack_encode.peer_max_capacity,
    );
}

test "HTTP/3 handshake runtime decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const client_cid = [_]u8{ 0xf8, 0xf9, 0xfa, 0xfb };
    const server_cid = [_]u8{ 0xfc, 0xfd, 0xfe, 0xff };
    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
        .session = .{
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
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
            var session = try server_ptr.accept();
            defer session.deinit();
            // Advertise capacity before accepting any dependent encoder
            // instruction or field section.
            try sendConnectionSettings(
                &session.established.connection,
                &session.critical_stream_send_scratch,
                &session.control,
                &session.control_send,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                &session.qpack_decoder_send,
                &session.qpack_decoder_prefix_sent,
                session.options,
                server_control_stream_id,
            );
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/handshake-qpack", request.request.path);
            var value: ?[]const u8 = null;
            for (request.request.headers) |header| {
                if (std.mem.eql(u8, header.name, "x-handshake")) {
                    value = header.value;
                }
            }
            try std.testing.expectEqualStrings("dynamic", value orelse
                return error.TestUnexpectedResult);
            try std.testing.expectEqual(
                @as(u64, 1),
                session.qpack_decode.table.insert_count,
            );
            try std.testing.expectEqual(
                @as(u64, 1),
                session.options.local_settings.qpack_blocked_streams,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        },
        .session = .{
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    });
    defer client.deinit();

    // Process the server SETTINGS and critical-stream prefixes before using
    // its advertised QPACK capacity.
    var settings_packet = try client.established.connection.receivePacket();
    defer settings_packet.deinit(allocator);
    for (settings_packet.frames) |frame| {
        if (frame != .stream) continue;
        if ((frame.stream.stream_id & 0x02) != 0 and
            frame.stream.stream_id == server_qpack_encoder_stream_id)
        {
            try client.qpack_decode.applyEncoderStreamFrame(
                &client.control,
                frame.stream,
            );
            continue;
        }
        _ = try applyControlStreamFrameForRole(
            &client.control,
            allocator,
            frame.stream,
            .client,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 256),
        client.control.settings.peer.qpack_max_table_capacity,
    );

    try sendConnectionSettings(
        &client.established.connection,
        &client.critical_stream_send_scratch,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-handshake", "dynamic");
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/handshake-qpack" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-handshake", .value = "dynamic" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&message, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        message.items,
        message.items.len,
        true,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    // Deliver the dependent message first, then unblock it with split encoder
    // instructions on the persistent stream.
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-handshake",
            .value = "dynamic",
        } },
    );
    frames.clearRetainingCapacity();
    try client.qpack_encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 runtime exchanges request and response over QUIC UDP frame endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
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
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3", request.request.path);
            try std.testing.expectEqualStrings("ping split by dev sender", request.request.body);
            try std.testing.expect(request.extra_datagrams.len != 0);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong split by dev sender",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3",
        .authority = "localhost",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping split by dev sender",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("pong split by dev sender", response.response.body);
}

test "HTTP/3 dev request deadline validates and resumes a partial STREAM" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
    );
    defer server.deinit();
    var client = try quic.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        },
    );
    defer client.deinit();

    // Validation happens before socket progress or request-state mutation.
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.zero),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const body = "retained after the bounded receive expires";
    try (http3.Request{
        .method = "POST",
        .path = "/dev-request-deadline",
        .authority = "localhost",
        .body = body,
    }).write(&encoded, allocator);
    const split = encoded.items.len - body.len + body.len / 2;
    try client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items[0..split],
    } }});

    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.request_streams.count(),
    );

    try client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded.items[split..],
        .fin = true,
    } }});
    var request = try server.receiveRequestWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), request.stream_id);
    try std.testing.expectEqualStrings(
        "/dev-request-deadline",
        request.request.path,
    );
    try std.testing.expectEqualStrings(body, request.request.body);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
}

test "HTTP/3 dev runtime assembles split STREAM request and response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
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
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/split", request.request.path);
            try std.testing.expectEqualStrings("split request body", request.request.body);
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expect(request.extra_datagrams.len != 0);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "split response body",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            const first = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }};
            const second = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }};
            try server_ptr.quic_server.sendFrames(request.from, &first);
            try server_ptr.quic_server.sendFrames(request.from, &second);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var encoded_request: std.ArrayList(u8) = .empty;
    defer encoded_request.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/split",
        .authority = "localhost",
        .body = "split request body",
    }).write(&encoded_request, allocator);
    const split = encoded_request.items.len / 2;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = encoded_request.items[0..split],
        .fin = false,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded_request.items[split..],
        .fin = true,
    } }};
    try client.quic_client.sendFrames(&first);
    try client.quic_client.sendFrames(&second);

    var assembled = try receiveRuntimeStreamBytes(
        &client.quic_client.endpoint,
        server.address(),
        0,
        client.limits.max_stream_buffer,
    );
    defer assembled.deinit(allocator);
    try std.testing.expect(assembled.datagrams.len > 1);
    var response = try http3.decodeResponse(allocator, assembled.bytes);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("split response body", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client assembles split STREAM response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
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
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("/split-response", request.request.path);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .body = "client public API assembled this split response",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }});
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "GET",
        .path = "/split-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("client public API assembled this split response", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client deadline validation does not send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/must-not-send",
        .authority = "localhost",
    };
    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(request_options, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndTimeout(
            request_options,
            null,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.request_unusable);
    client.next_stream_id = std.math.maxInt(u62) - 3;
    try std.testing.expectError(
        error.StreamCreationError,
        client.request(request_options),
    );
    try std.testing.expectEqual(
        @as(u62, std.math.maxInt(u62) - 3),
        client.next_stream_id,
    );
    try std.testing.expect(!client.request_unusable);
    client.next_stream_id = 0;
    client.limits.max_stream_frame_data = 0;
    try std.testing.expectError(
        error.InvalidStreamRange,
        client.request(request_options),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.request_unusable);

    // Neither deadline validation nor local frame preflight emitted stream
    // zero, and the latter did not poison the client.
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );
}

test "HTTP/3 dev client bounded requests deliver informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
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
            {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/bounded-timeout",
                    request.request.path,
                );
                try self.server.sendResponse(
                    request.from,
                    request.stream_id,
                    .{ .status = 204 },
                );
            }
            {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/bounded-informational",
                    request.request.path,
                );
                try self.server.sendResponseWithInformational(
                    request.from,
                    request.stream_id,
                    &.{.{
                        .status = 103,
                        .headers = &.{.{
                            .name = "link",
                            .value = "</dev.css>",
                        }},
                    }},
                    .{
                        .status = 200,
                        .headers = &.{.{
                            .name = "date",
                            .value = "Sun, 06 Nov 1994 08:49:37 GMT",
                        }},
                        .body = "bounded final",
                    },
                );
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();
    var unrelated = try quic.runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer unrelated.deinit();
    var spoofed: std.ArrayList(u8) = .empty;
    defer spoofed.deinit(allocator);
    try (http3.Response{
        .status = 500,
        .body = "wrong peer",
    }).write(&spoofed, allocator);
    try unrelated.sendFrames(client.address(), &.{.{ .stream = .{
        .stream_id = 0,
        .data = spoofed.items,
        .fin = true,
    } }});
    // Consume the queued spoof deterministically before the real server can
    // reply. The bounded request path must discard it and continue waiting.
    std.Io.sleep(io, .fromMilliseconds(5), .awake) catch {};
    var no_content = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/bounded-timeout",
        .authority = "localhost",
    }, .fromSeconds(1));
    defer no_content.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), no_content.response.status);
    const automatic_date = server_response.headerValue(
        no_content.response.headers,
        "date",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(usize, server_response.date_value_len),
        automatic_date.len,
    );

    const Observation = struct {
        count: usize = 0,
        status: u16 = 0,
        header_valid: bool = false,
        saw_date: bool = false,

        fn observe(
            context: *anyopaque,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
            self.status = response.status;
            for (response.headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "date")) {
                    self.saw_date = true;
                }
                if (std.mem.eql(u8, header.name, "link") and
                    std.mem.eql(u8, header.value, "</dev.css>"))
                {
                    self.header_valid = true;
                }
            }
        }
    };
    var observation: Observation = .{};
    var response = try client.requestWithInformationalAndDeadline(
        .{
            .method = "GET",
            .path = "/bounded-informational",
            .authority = "localhost",
        },
        .{
            .context = &observation,
            .on_response = Observation.observe,
        },
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observation.count);
    try std.testing.expectEqual(@as(u16, 103), observation.status);
    try std.testing.expect(observation.header_valid);
    try std.testing.expect(!observation.saw_date);
    try std.testing.expectEqualStrings(
        "bounded final",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        server_response.headerValue(response.response.headers, "date") orelse
            return error.TestUnexpectedResult,
    );
    var date_count: usize = 0;
    for (response.response.headers) |header| {
        date_count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, "date"));
    }
    try std.testing.expectEqual(@as(usize, 1), date_count);
    try std.testing.expect(!client.request_unusable);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client fails closed after partial response timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "response deliberately left incomplete",
    }).write(&encoded, allocator);
    const split = encoded.items.len / 2;
    // Queue an incomplete stream-zero response before the request. This keeps
    // the test deterministic while exercising the client's actual socket and
    // call-local STREAM assembly.
    try server.quic_server.sendFrames(client.address(), &.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items[0..split],
    } }});

    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(.{
            .method = "GET",
            .path = "/partial-response",
            .authority = "localhost",
        }, .fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_unusable);
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);

    // The first request did reach the server; a retry is rejected locally and
    // cannot allocate or emit stream four.
    var request = try server.receiveRequestWithTimeout(.fromSeconds(1));
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/partial-response",
        request.request.path,
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = "GET",
            .path = "/must-fail-closed",
            .authority = "localhost",
        }),
    );
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestWithTimeout(.fromMilliseconds(20)),
    );
}

test "HTTP/3 dev runtime enforces stream reassembly limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer receiver.deinit();
    var sender = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, receiver.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer sender.deinit();

    try sender.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 32,
        .data = "too-far",
        .fin = true,
    } }});
    try std.testing.expectError(
        error.StreamBufferTooLarge,
        receiveRuntimeStreamBytes(&receiver, sender.address(), 0, 16),
    );
}

test "HTTP/3 dev runtime receives requests with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        batch: ?OwnedRequestBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.server.receiveRequestsConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_b.deinit();

    const req_a = http3.Request{ .method = "POST", .path = "/batch-a", .authority = "localhost", .body = "a" };
    const req_b = http3.Request{ .method = "POST", .path = "/batch-b", .authority = "localhost", .body = "b" };
    var encoded_a: std.ArrayList(u8) = .empty;
    defer encoded_a.deinit(allocator);
    var encoded_b: std.ArrayList(u8) = .empty;
    defer encoded_b.deinit(allocator);
    try req_a.write(&encoded_a, allocator);
    try req_b.write(&encoded_b, allocator);
    const frame_a = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_a.items, .fin = true } }};
    const frame_b = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_b.items, .fin = true } }};
    try client_a.quic_client.sendFrames(&frame_a);
    try client_b.quic_client.sendFrames(&frame_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.requests) |maybe_request| {
        const request = maybe_request.?;
        if (std.mem.eql(u8, request.request.path, "/batch-a")) saw_a = true;
        if (std.mem.eql(u8, request.request.path, "/batch-b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test {
    _ = @import("runtime/development/tests/message.zig");
    _ = @import("runtime/development/tests/send.zig");
    _ = @import("runtime/datagram/tests/routing.zig");
    _ = handshake_client_pool;
    _ = connect_datagram;
    _ = @import("runtime/qpack/state_tests.zig");
    _ = @import("runtime/qpack/tests/writer.zig");
    _ = @import("runtime/qpack/tests/integration.zig");
    _ = @import("runtime/qpack/tests/request_transport.zig");
    _ = @import("runtime/qpack/tests/response_transport.zig");
    _ = @import("runtime/control/receive_tests.zig");
    _ = @import("runtime/control/tests/integration.zig");
    _ = @import("runtime/control/send_tests.zig");
    _ = @import("runtime/receive/routing/tests/request.zig");
    _ = @import("runtime/receive/routing/tests/response.zig");
    _ = @import("runtime/receive/tests/connection_error.zig");
    _ = @import("runtime/receive/tests/runtime_close.zig");
    _ = @import("runtime/send/tests/body.zig");
    _ = @import("runtime/send/tests/message.zig");
    _ = @import("runtime/send/tests/partial_send.zig");
    _ = @import("runtime/stream/reader_tests.zig");
    _ = @import("runtime/stream/set_tests.zig");
    _ = @import("runtime/stream/push/state_tests.zig");
    _ = @import("runtime/stream/push/tests/control.zig");
    _ = @import("runtime/stream/push/tests/events.zig");
    _ = @import("runtime/stream/push/tests/aggregate.zig");
    _ = @import("runtime/stream/push/tests/aggregate_state.zig");
    _ = @import("runtime/stream/push/tests/send.zig");
    _ = @import("runtime/server/tests/protected.zig");
    _ = @import("runtime/server/tests/gro.zig");
    _ = @import("runtime/server/tests/limits.zig");
    _ = @import("runtime/server/tests/lifecycle.zig");
    _ = @import("runtime/server/tests/streaming.zig");
    _ = @import("runtime/server/tests/receive.zig");
    _ = @import("runtime/client/tests/protected.zig");
    _ = @import("runtime/client/tests/deadline.zig");
    _ = @import("runtime/client/tests/streaming.zig");
    _ = @import("runtime/handshake_client_pool_tests.zig");
    _ = @import("runtime/development_streaming_tests.zig");
    _ = @import("runtime/development_server_tests.zig");
    _ = @import("runtime/development/server_peer/state_tests.zig");
    _ = @import("runtime/endpoint_dispatcher_tests.zig");
    _ = @import("runtime/endpoint_server_tests.zig");
    _ = @import("runtime/handshake_server_serve_tests.zig");
    _ = @import("runtime/cancellation_tests.zig");
    _ = @import("runtime/informational_tests.zig");
    _ = @import("runtime/response_scheduler/tests/integration.zig");
    _ = @import("runtime/response_scheduler/tests/protected.zig");
}
