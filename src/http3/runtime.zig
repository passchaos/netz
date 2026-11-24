const std = @import("std");
const content_digest = @import("../http/digest.zig");
const RuntimeModule = @This();
const round_robin = @import("../internal/round_robin.zig");
pub const deadline_policy = @import("../internal/deadline.zig");
pub const address_resolver = @import("../internal/address_resolver.zig");
pub const happy_eyeballs = @import("../internal/happy_eyeballs.zig");
const http_method = @import("../internal/http_method.zig");
const http3 = @import("mod.zig");
pub const quic = @import("../quic/mod.zig");
const body_batch = @import("runtime/body_batch.zig");
const client_uri = @import("runtime/client/uri.zig");
pub const connect_datagram = @import("runtime/datagram.zig");
const connect_datagram_routing = @import("runtime/datagram/routing.zig");
pub const connect_datagram_send = @import("runtime/datagram/send.zig");
pub const connect_datagram_progress = @import("runtime/datagram/progress.zig");
const connect_udp_dispatcher_relay =
    @import("runtime/connect_udp_dispatcher_relay.zig");
const connect_ip_session = @import("runtime/connect_ip_session.zig");
const development_datagram_queue =
    @import("runtime/development/datagram_queue.zig");
const development_send = @import("runtime/development/send.zig");
const development_receive = @import("runtime/development/receive.zig");
const development_message = @import("runtime/development/message.zig");
const development_data_error = @import("runtime/development/data_error.zig");
const development_request_buffer =
    @import("runtime/development/request_buffer.zig");
const development_server_peer =
    @import("runtime/development/server_peer/state.zig");
pub const handshake_client_pool = @import("runtime/handshake_client_pool.zig");
const endpoint_handler_supervisor =
    @import("runtime/endpoint_handler_supervisor.zig");
pub const ticket_receiver = @import("runtime/ticket_receiver.zig");
pub const runtime_error = @import("runtime/error.zig");
pub const uri_redirect = @import("../http1/runtime/redirect.zig");
pub const server_response = @import("runtime/server/response.zig");
pub const complete_response = @import("runtime/server/complete_response.zig");
pub const paced_body = @import("runtime/send/paced_body.zig");
const body_sender = @import("runtime/send/body.zig");
pub const body_fragment = @import("runtime/send/body_fragment.zig");
const message_sender = @import("runtime/send/message.zig");
pub const complete_request = @import("runtime/client/complete_request.zig");
const send_packetizer = @import("runtime/send/packetizer.zig");
const protected_send_module = @import("runtime/send/protected.zig");
const send_scratch = @import("runtime/send/scratch.zig");
const receive_cursor = @import("runtime/receive/cursor.zig");
const receive_policy = @import("runtime/receive/policy.zig");
const receive_connection_error =
    @import("runtime/receive/connection_error.zig");
const request_routing = @import("runtime/receive/routing/request.zig");
pub const response_routing = @import("runtime/receive/routing/response.zig");
pub const response_scheduler = @import("runtime/response_scheduler/core.zig");
pub const concurrent = @import("runtime/concurrent.zig");
const control_receive = @import("runtime/control/receive.zig");
const control_sender = @import("runtime/control/send.zig");
pub const stream_lifecycle = @import("runtime/stream/lifecycle.zig");
const buffered_common = @import("runtime/stream/buffered/common.zig");
const buffered_request = @import("runtime/stream/buffered/request.zig");
const buffered_response = @import("runtime/stream/buffered/response.zig");
const outbound_body = @import("runtime/stream/outbound_body.zig");
const stream_reader = @import("runtime/stream/reader.zig");
const streaming_set = @import("runtime/stream/set.zig");
const stream_events = @import("runtime/stream/events.zig");
const push_state = @import("runtime/stream/push/state.zig");
pub const push_aggregate = @import("runtime/stream/push/aggregate.zig");
pub const push_read_failure = @import("runtime/stream/push/read_failure.zig");

const net = std.Io.net;
const server_runtime = @import("runtime/server.zig");
const client_runtime = @import("runtime/client.zig");

// The cleartext runtime intentionally has no HTTP/3 control stream. Its
// historical aggregate codec accepts Extended CONNECT, so its incremental
// parser must model that same capability instead of the default disabled
// SETTINGS value. Dynamic QPACK remains disabled by the zero-capacity state.
pub const development_settings: http3.Settings = .{
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

/// High-level handlers return one final response. Convert an accidental 1xx
/// into a terminal 500 while preserving the explicit informational APIs.
pub fn normalizeHandlerResponse(
    response: *http3.Response,
    request_method: []const u8,
    extended_connect: bool,
) bool {
    const invalid_final = response.status >= 100 and response.status < 200;
    if (invalid_final) response.* = .{ .status = 500 };
    if (response.request_method == null) response.request_method = request_method;
    response.extended_connect = extended_connect;
    return invalid_final;
}

fn serveConnectionShutdownError(err: anyerror) Error {
    return switch (err) {
        error.Timeout => error.RecoveryDrainTimeout,
        error.ConcurrencyUnavailable => error.RecoveryDrainUnavailable,
        else => |other| @errorCast(other),
    };
}

pub fn finishServedConnectionWithDeadline(
    session: *HandshakeServerSession,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    session.initiateShutdownWithDeadline(deadline) catch |err|
        return serveConnectionShutdownError(err);
    session.completeShutdownWithDeadline(deadline) catch |err|
        return serveConnectionShutdownError(err);
    session.waitForRecoveryIdleWithDeadline(deadline) catch |err|
        return serveConnectionShutdownError(err);
}

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

pub const MultiplexedInformationalContext = struct {
    observer: MultiplexedInformationalObserver,
    stream_id: u62,

    pub fn notify(
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

pub const InformationalCallbackGuard = struct {
    observer: http3.InformationalObserver,
    callback_reader_active: *bool,

    pub fn notify(
        context: *anyopaque,
        response: InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        std.debug.assert(!self.callback_reader_active.*);
        self.callback_reader_active.* = true;
        defer self.callback_reader_active.* = false;
        self.observer.on_response(self.observer.context, response);
    }
};

pub const PushInformationalCallbackGuard = struct {
    observer: PushInformationalObserver,
    callback_reader_active: *bool,

    pub fn notify(
        context: *anyopaque,
        push_id: u64,
        request_stream_id: u62,
        stream_id: u62,
        response: InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        std.debug.assert(!self.callback_reader_active.*);
        self.callback_reader_active.* = true;
        defer self.callback_reader_active.* = false;
        self.observer.on_response(
            self.observer.context,
            push_id,
            request_stream_id,
            stream_id,
            response,
        );
    }
};

pub const Error = runtime_error.Error;
pub const HandshakeWorkerError = runtime_error.HandshakeWorkerError;
pub const HandshakeAdmissionError = runtime_error.HandshakeAdmissionError;
pub const ReceiveTimeoutError = runtime_error.ReceiveTimeoutError;
pub const RedirectError = runtime_error.Error || uri_redirect.Error;
pub const RedirectTimeoutError = runtime_error.ReceiveTimeoutError ||
    uri_redirect.Error;
pub const OwnedConnectDatagram = connect_datagram.Owned;
pub const EarlyConnectDatagramLimits = connect_datagram.EarlyLimits;
pub const ShutdownState = stream_lifecycle.ShutdownState;
pub const GoAwayRetryDisposition = stream_lifecycle.GoAwayRetryDisposition;

pub const ClientRequestLifecycle = stream_lifecycle.Client;
pub const ServerRequestLifecycle = stream_lifecycle.Server;
pub const RequestStreamSet = buffered_request.Set;
pub const ResponseStreamSet = buffered_response.Set;
pub const PreparedRequest = buffered_request.PreparedReady;
pub const PreparedResponse = buffered_response.PreparedReady;
pub const OutboundBodySet = outbound_body.Set;
const AssembledStream = buffered_common.AssembledStream;
pub const StreamingHead = stream_reader.Head;
pub const StreamingEvent = stream_reader.Event;
pub const StreamingMessageReader = stream_reader.Reader;
pub const StreamingRequestEvent = stream_events.Request;
pub const request_failure = @import("runtime/receive/request_failure.zig");
pub const RequestFailure = request_failure.Failure;
pub const RequestEventResult = request_failure.Result;
pub const message_data = @import("runtime/receive/message_data.zig");
pub const releaseStreamingReaderCapacity = message_data.releaseCapacity;
pub const releaseStreamingReaderCapacityOnce = message_data.releaseCapacityOnce;
pub const response_failure = @import("runtime/receive/response_failure.zig");
pub const ResponseFailure = response_failure.Failure;
pub const ResponseEventResult = response_failure.Result;

pub const StreamingResponseEvent = stream_events.Response;
pub const StreamCallbackSink =
    @import("runtime/shared_handshake_client_pool/stream_command.zig").CallbackSink;
pub const PeerResponseCancellation = stream_events.PeerResponseCancellation;
pub const SessionTicketStats = ticket_receiver.Stats;
const StreamingMessageSet = streaming_set.Set;
pub const StreamingRequestSet = streaming_set.Set;
pub const StreamingResponseSet = streaming_set.Set;
pub const PushStreamSet = push_state.Set;
const ControlStreamRole = control_receive.ControlStreamRole;
const ServerRequestIdValidator = control_receive.ServerRequestIdValidator;
pub const ServerPushIdSet = control_receive.ServerPushIdSet;
const PromisedPushIds = control_receive.PromisedPushIds;
const MessageStreamDisposition = control_receive.MessageStreamDisposition;
pub const validateServerGoAwayStreamId = control_receive.validateServerGoAwayStreamId;
pub const validateClientGoAwayPushId = control_receive.validateClientGoAwayPushId;
pub const validateNewServerPush = control_receive.validateNewServerPush;
const rejectByLocalGoAway = control_receive.rejectByLocalGoAway;
pub const configureQpackEncoderFromPeerSettings =
    control_receive.configureQpackEncoderFromPeerSettings;
pub const applyControlStreamFrameForRole =
    control_receive.applyControlStreamFrameForRole;
pub const applyControlStreamFrameForRoleWithPushes =
    control_receive.applyControlStreamFrameForRoleWithPushes;
const peekUniStreamType = control_receive.peekUniStreamType;
const applyControlStreamFrame = control_receive.applyControlStreamFrame;
const applyControlStreamFrameValidated =
    control_receive.applyControlStreamFrameValidated;
const isRegisteredCriticalStream = control_receive.isRegisteredCriticalStream;
const rejectCriticalStreamClosureFrame =
    control_receive.rejectCriticalStreamClosureFrame;
const rejectClosedCriticalStream = control_receive.rejectClosedCriticalStream;
pub const messageStreamDisposition = control_receive.messageStreamDisposition;
const ControlFrameKind = control_sender.ControlFrameKind;
const PushControlFrameKind = control_sender.PushControlFrameKind;
const controlFramesInto = control_sender.controlFramesInto;
pub const sendConnectionControlFrame = control_sender.sendConnectionControlFrame;
pub const sendConnectionControlFrameWithDeadline =
    control_sender.sendConnectionControlFrameWithDeadline;
pub const trySendConnectionControlFrame =
    control_sender.trySendConnectionControlFrame;
pub const sendConnectionPushControl = control_sender.sendConnectionPushControl;
pub const sendConnectionPushControlWithDeadline =
    control_sender.sendConnectionPushControlWithDeadline;
pub const trySendConnectionPushControl =
    control_sender.trySendConnectionPushControl;
pub const sendConnectionPriorityUpdate = control_sender.sendConnectionPriorityUpdate;
pub const sendConnectionPriorityUpdateRaw =
    control_sender.sendConnectionPriorityUpdateRaw;
pub const sendConnectionPriorityUpdateRawWithDeadline =
    control_sender.sendConnectionPriorityUpdateRawWithDeadline;
pub const trySendConnectionPriorityUpdateRaw =
    control_sender.trySendConnectionPriorityUpdateRaw;
pub const sendProtectedControlFrame = control_sender.sendProtectedControlFrame;
pub const sendProtectedControlFrameWithDeadline =
    control_sender.sendProtectedControlFrameWithDeadline;
pub const sendProtectedPushControl = control_sender.sendProtectedPushControl;
pub const sendProtectedPushControlWithDeadline =
    control_sender.sendProtectedPushControlWithDeadline;
pub const sendProtectedPriorityUpdate = control_sender.sendProtectedPriorityUpdate;
pub const sendProtectedPriorityUpdateRaw =
    control_sender.sendProtectedPriorityUpdateRaw;
pub const sendProtectedPriorityUpdateRawWithDeadline =
    control_sender.sendProtectedPriorityUpdateRawWithDeadline;
pub const sendConnectionSettings = control_sender.sendConnectionSettings;
pub const sendConnectionSettingsWithDeadline =
    control_sender.sendConnectionSettingsWithDeadline;
pub const trySendConnectionSettings = control_sender.trySendConnectionSettings;
pub const sendConnectionQpackEncoderInstructions =
    control_sender.sendConnectionQpackEncoderInstructions;
pub const sendConnectionQpackFeedback = control_sender.sendConnectionQpackFeedback;
pub const sendConnectionQpackFeedbackWithDeadline =
    control_sender.sendConnectionQpackFeedbackWithDeadline;
pub const trySendConnectionQpackFeedback =
    control_sender.trySendConnectionQpackFeedback;
pub const cancelConnectionRequest = control_sender.cancelConnectionRequest;
pub const sendProtectedSettings = control_sender.sendProtectedSettings;
pub const sendProtectedSettingsWithDeadline =
    control_sender.sendProtectedSettingsWithDeadline;
const sendProtectedQpackEncoderInstructions =
    control_sender.sendProtectedQpackEncoderInstructions;
pub const sendProtectedQpackFeedback = control_sender.sendProtectedQpackFeedback;
pub const sendProtectedQpackFeedbackWithDeadline =
    control_sender.sendProtectedQpackFeedbackWithDeadline;
pub const sendProtectedRequestCancellation =
    control_sender.sendProtectedRequestCancellation;
const writeDataFrame = body_sender.writeDataFrame;
const BodyPartCursor = body_sender.BodyPartCursor;
const max_paced_body_part_descriptors =
    body_sender.max_paced_body_part_descriptors;
pub const default_paced_request_body_chunk_bytes =
    body_sender.default_paced_request_body_chunk_bytes;
pub const default_paced_response_body_chunk_bytes =
    body_sender.default_paced_response_body_chunk_bytes;
pub const pacedBodyChunkLimit = body_sender.pacedBodyChunkLimit;
pub const responseBodySendCapacity = body_sender.responseBodySendCapacity;
pub const pacedProtectedBodyChunkLimit = body_sender.pacedProtectedBodyChunkLimit;
pub const sendConnectionBodyChunk = body_sender.sendConnectionBodyChunk;
pub const sendConnectionBodyChunkWithDeadline =
    body_sender.sendConnectionBodyChunkWithDeadline;
const sendConnectionBodyParts = body_sender.sendConnectionBodyParts;
pub const trySendConnectionBodyParts = body_sender.trySendConnectionBodyParts;
pub const trySendConnectionBodyChunk = body_sender.trySendConnectionBodyChunk;
pub const sendConnectionBodyBatchPaced = body_sender.sendConnectionBodyBatchPaced;
pub const sendConnectionBodyBatchPacedWithDeadline =
    body_sender.sendConnectionBodyBatchPacedWithDeadline;
pub const sendConnectionBodyBatchPacedProgress =
    body_sender.sendConnectionBodyBatchPacedProgress;
pub const sendProtectedBodyBatchPaced = body_sender.sendProtectedBodyBatchPaced;
pub const sendProtectedBodyBatchPacedWithDeadline =
    body_sender.sendProtectedBodyBatchPacedWithDeadline;
pub const sendProtectedBodyBatchProgress =
    body_sender.sendProtectedBodyBatchProgress;
pub const sendProtectedBodyChunk = body_sender.sendProtectedBodyChunk;
pub const sendProtectedBodyChunkWithDeadline =
    body_sender.sendProtectedBodyChunkWithDeadline;
pub const sendConnectionMessage = message_sender.sendConnectionMessage;
const sendConnectionMessageWithDeadline =
    message_sender.sendConnectionMessageWithDeadline;
pub const prepareConnectionMessage = message_sender.prepareConnectionMessage;
pub const trySendConnectionRequestLiteral =
    message_sender.trySendConnectionRequestLiteral;
pub const trySendConnectionStreamingRequestHeadLiteral =
    message_sender.trySendConnectionStreamingRequestHeadLiteral;
pub const trySendConnectionResponseLiteral =
    message_sender.trySendConnectionResponseLiteral;
pub const ResponseLiteralOptions = message_sender.ResponseLiteralOptions;
pub const trySendConnectionResponseLiteralWithOptions =
    message_sender.trySendConnectionResponseLiteralWithOptions;
pub const trySendConnectionStreamingResponseHeadLiteral =
    message_sender.trySendConnectionStreamingResponseHeadLiteral;
const sendProtectedMessage = message_sender.sendProtectedMessage;
const sendProtectedMessageWithDeadline =
    message_sender.sendProtectedMessageWithDeadline;
pub const sendPreparedProtectedMessageUntil =
    message_sender.sendPreparedProtectedMessageUntil;
pub const sendProtectedResponseSequence =
    message_sender.sendProtectedResponseSequence;
pub const sendProtectedResponseSequenceWithDeadline =
    message_sender.sendProtectedResponseSequenceWithDeadline;
pub const encodePushMessages = message_sender.encodePushMessages;
pub const sendConnectionPush = message_sender.sendConnectionPush;
pub const sendConnectionPushWithDeadline =
    message_sender.sendConnectionPushWithDeadline;
pub const sendConnectionPushStreamingHeads =
    message_sender.sendConnectionPushStreamingHeads;
pub const sendConnectionPushStreamingHeadsWithDeadline =
    message_sender.sendConnectionPushStreamingHeadsWithDeadline;
pub const sendProtectedPush = message_sender.sendProtectedPush;
pub const sendProtectedPushWithDeadline =
    message_sender.sendProtectedPushWithDeadline;
pub const sendProtectedPushStreamingHeads =
    message_sender.sendProtectedPushStreamingHeads;
pub const sendProtectedPushStreamingHeadsWithDeadline =
    message_sender.sendProtectedPushStreamingHeadsWithDeadline;
pub const sendConnectionStreamingHead = message_sender.sendConnectionStreamingHead;
pub const sendConnectionStreamingHeadWithDeadline =
    message_sender.sendConnectionStreamingHeadWithDeadline;
pub const sendConnectionStreamingHeadProgress = message_sender.sendConnectionStreamingHeadProgress;
pub const sendProtectedStreamingHead = message_sender.sendProtectedStreamingHead;
pub const sendProtectedStreamingHeadWithDeadline =
    message_sender.sendProtectedStreamingHeadWithDeadline;
pub const sendConnectionTrailers = message_sender.sendConnectionTrailers;
pub const sendConnectionTrailersWithDeadline =
    message_sender.sendConnectionTrailersWithDeadline;
pub const trySendConnectionTrailersLiteral =
    message_sender.trySendConnectionTrailersLiteral;
pub const sendProtectedTrailers = message_sender.sendProtectedTrailers;
pub const sendProtectedTrailersWithDeadline =
    message_sender.sendProtectedTrailersWithDeadline;
pub const RequestStreamReset = request_routing.RequestStreamReset;
pub const requestResetError = request_routing.requestResetError;
const serverRequestReceived = request_routing.serverRequestReceived;
pub const prepareServerRequestReceived =
    request_routing.prepareServerRequestReceived;
pub const serverRequestReceivedAssumeCapacity =
    request_routing.serverRequestReceivedAssumeCapacity;
pub const finishServerRequest = request_routing.finishServerRequest;
const reconcileServerRequestPriorities =
    request_routing.reconcileServerRequestPriorities;
pub const applyServerRequestPacketFrames =
    request_routing.applyServerRequestPacketFrames;
pub const closeConnectionForHttp3Error =
    receive_connection_error.closeConnection;
pub const sendProtectedHttp3Close =
    receive_connection_error.sendProtectedClose;
pub const messageStreamErrorCode = runtime_error.messageStreamErrorCode;
pub const messageUsesDynamicQpack = buffered_common.messageUsesDynamicQpack;

/// Close a stateful QUIC connection using the canonical RFC 9114/9204 mapping
/// for a peer-originated HTTP/3 protocol failure. Local implementation and
/// transport errors are deliberately ignored by the mapper.
pub fn closeConnectionForProtocolError(
    connection: *quic.one_rtt.Connection,
    err: anyerror,
) Error!void {
    return closeConnectionForHttp3Error(connection, err);
}

pub fn sendProtectedFrames(
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

pub const ensureConnectDatagramsNegotiated =
    connect_datagram_routing.ensureNegotiated;

pub const NoConnectProgress = struct {
    pub const ErrorSet = error{};
    pub fn maintain(_: @This(), _: ?std.Io.Clock.Timestamp) ErrorSet!void {}
};

const connect_datagram_receive = @import("runtime/datagram/receive.zig");
pub const receiveConnectDatagramFromSession = connect_datagram_receive.owned;
pub const receiveConnectDatagramIntoFromSession = connect_datagram_receive.into;
pub const receiveConnectDatagramsIntoFromSession = connect_datagram_receive.many;

pub const observeConnectDatagramTerminal = connect_datagram_routing.observeTerminal;
pub const ensureConnectDatagramSendSideOpen =
    connect_datagram_routing.ensureSendSideOpen;
pub const connectDatagramTerminalError = connect_datagram_routing.terminalError;
pub const pollConnectDatagramRegistry = connect_datagram_routing.poll;
pub const pollConnectDatagramRegistryInto = connect_datagram_routing.pollInto;
pub const drainConnectDatagrams = connect_datagram_routing.drain;

/// Replay HTTP DATAGRAM frames in their authenticated QUIC packet order. The
/// transport queue itself is intentionally connection-wide and does not retain
/// ordering metadata relative to RESET_STREAM/FIN, so adapters must mark the
/// affected association as soon as a terminal stream frame is crossed. A later
/// DATAGRAM in that same packet is then dropped by `Registry.route`, while a
/// preceding one remains queued for delivery.
pub const routeConnectDatagramsFromPacket = connect_datagram_routing.routePacket;
const routeConnectDatagramsFromPacketInto =
    connect_datagram_routing.routePacketInto;

pub const client_control_stream_id: u62 = 2;
pub const client_qpack_encoder_stream_id: u62 = 6;
pub const client_qpack_decoder_stream_id: u62 = 10;
pub const first_client_extension_uni_stream_id: u62 = 14;
pub const server_control_stream_id: u62 = 3;
pub const server_qpack_encoder_stream_id: u62 = 7;
pub const server_qpack_decoder_stream_id: u62 = 11;
pub const first_server_push_stream_id: u62 = 15;

pub const StreamMessageSendScratch = send_scratch.Message;
pub const PushSendScratch = send_scratch.Push;
pub const CriticalStreamSendScratch = send_scratch.Critical;
const sendRuntimeStreamMessage = development_send.streamMessage;
const retainDevelopmentDatagramFrames = development_send.retainDatagramFrames;
const sendRuntimeStreamingHead = development_send.streamingHead;
const sendRuntimeStreamingHeadAtOffset = development_send.streamingHeadAtOffset;
const sendRuntimeResponsePrefix = development_send.responsePrefix;
const sendRuntimeRequestCancellation = development_send.requestCancellation;
const sendRuntimeBodyChunk = development_send.bodyChunk;
const sendRuntimeBodyChunkWithDeadline = development_send.bodyChunkWithDeadline;
const appendRuntimeStreamMessageFrames =
    development_send.appendStreamMessageFrames;
pub const receiveRuntimeStreamBytes = development_receive.streamBytes;
const receiveRuntimeStreamBytesUntil = development_receive.streamBytesUntil;

pub const UriEndpoint = client_uri.Endpoint;
pub const UriRequestOptions = client_uri.RequestOptions;
pub const RedirectPolicy = uri_redirect.Policy;
pub const RedirectOptions = struct {
    policy: RedirectPolicy = .{},
};

pub fn redirectH3Location(
    headers: []const http3.Qpack.HeaderField,
) RedirectError!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

pub fn redirectH3Headers(
    allocator: std.mem.Allocator,
    source: []const http3.Qpack.HeaderField,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http3.Qpack.HeaderField,
) std.mem.Allocator.Error![]const http3.Qpack.HeaderField {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectH3Header(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(
        http3.Qpack.HeaderField,
        retained_count,
    );
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectH3Header(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectH3Header(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}
pub const uriEndpoint = client_uri.parseEndpoint;
pub const uriRequestTargetAlloc = client_uri.requestTargetAlloc;

pub const connectDeadline = client_uri.connectDeadline;
pub const cappedConnectDeadline = client_uri.cappedConnectDeadline;
pub const resolveEndpointBefore = client_uri.resolveEndpointBefore;
pub const resolveHostPortAddressesBefore =
    client_uri.resolveHostPortAddressesBefore;
pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = happy_eyeballs.Policy;
pub const HappyEyeballsOptions = happy_eyeballs.Options;

/// Compose one address-specific handshake budget with the caller/connection
/// deadline. The phase timeout restarts for each address but can never extend
/// the total URI connection budget.
pub fn addressAttemptDeadline(
    io: std.Io,
    total: ?std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) Error!?std.Io.Clock.Timestamp {
    return deadline_policy.earlier(
        total,
        try connectDeadline(io, timeout),
    );
}

/// Resolve one URI endpoint through the application resolver when configured.
/// Literal IPs deliberately retain the parser-owned bypass so URI authority
/// and TLS identity never become coupled to the returned transport address.
pub fn resolveEndpointWithResolverBefore(
    endpoint: client_uri.Endpoint,
    allocator: std.mem.Allocator,
    io: std.Io,
    resolver: ?AddressResolver,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    switch (endpoint.target) {
        .ip => return resolveEndpointBefore(endpoint, allocator, io, deadline),
        .host => {},
    }
    const configured = resolver orelse
        return resolveEndpointBefore(endpoint, allocator, io, deadline);
    return configured.resolve(
        configured.context,
        allocator,
        io,
        endpoint.tls_host,
        endpoint.port,
        deadline,
    ) catch |err| switch (err) {
        error.Timeout => error.HandshakeTimeout,
        else => |other| other,
    };
}

/// Resolve an alternative-service transport route without changing the
/// authenticated origin. Literal route addresses bypass the resolver.
pub fn resolveHostPortWithResolverBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    resolver: ?AddressResolver,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    if (net.IpAddress.parse(host, port)) |_| {
        return resolveHostPortAddressesBefore(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    } else |_| {}
    const configured = resolver orelse
        return resolveHostPortAddressesBefore(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    return configured.resolve(
        configured.context,
        allocator,
        io,
        host,
        port,
        deadline,
    ) catch |err| switch (err) {
        error.Timeout => error.HandshakeTimeout,
        else => |other| other,
    };
}
pub const handshakeRecoveryBefore = client_uri.handshakeRecoveryBefore;

pub const ProtectedSendState = protected_send_module.State;
pub const ConnectionPacketCursor = receive_cursor.Connection;
pub const ProtectedPacketCursor = receive_cursor.Protected;
pub const packetView = receive_cursor.packetView;

pub const Limits = struct {
    /// Keep the integrated HTTP/3 endpoint on the proven 4 KiB receive shape.
    /// Generic QUIC endpoints retain their 65,535-byte physical receive
    /// capacity, while this bounded default lets zio batch sixteen ordinary
    /// UDP datagrams.
    quic: quic.runtime.Limits = .{
        .max_datagram_size = receive_policy.default_endpoint_max_datagram_size,
    },
    /// Add a current IMF-fixdate `date` field to cleartext-development server
    /// final responses that do not already contain one.
    auto_date_header: bool = true,
    /// Maximum bytes buffered while reassembling one HTTP/3 request/response
    /// stream in the cleartext development runtime.  Protected/handshake
    /// runtimes already expose this via their session options; keeping the
    /// cleartext path explicit prevents large STREAM offsets from turning the
    /// UDP frame endpoint into an unbounded message buffer.
    max_stream_buffer: usize = 64 * 1024,
    /// Cumulative request-body budget enforced by streaming request readers,
    /// matching HTTP/1 and HTTP/2 `max_body_bytes`. A declared Content-Length
    /// is checked as well; DATA accumulation is bounded for streams without
    /// one.
    max_body_bytes: usize = 16 * 1024 * 1024,
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
pub const push_failure = @import("runtime/stream/push/failure.zig");
pub const PushFailure = push_failure.Failure;
pub const PushEventResult = push_failure.Result;

pub const PushedResponse = push_aggregate.Response;
pub const ClientPushAggregateState = push_aggregate.State;

pub const ServerPush = message_sender.ServerPush;

const qpack_state = @import("runtime/qpack/state.zig");

pub const QpackDecodeState = qpack_state.QpackDecodeState;
pub const QpackEncodeState = qpack_state.QpackEncodeState;

pub const Server = server_runtime.Server;

pub const Client = client_runtime.Client;
pub const ProtectedConfig = client_runtime.ProtectedConfig;
pub const HandshakeSessionOptions = client_runtime.HandshakeSessionOptions;
pub const EarlyRequestReplayPolicy = client_runtime.EarlyRequestReplayPolicy;
pub const PreparedEarlyRequestOptions = client_runtime.PreparedEarlyRequestOptions;
pub const PreparedEarlyRequest = client_runtime.PreparedEarlyRequest;
pub const BodyChunk = client_runtime.BodyChunk;
pub const BodyWriteProgress = client_runtime.BodyWriteProgress;
pub const DevelopmentBodyWriteProgress = client_runtime.DevelopmentBodyWriteProgress;
pub const EarlyRequestDisposition = client_runtime.EarlyRequestDisposition;
pub const EarlyDataRequestResult = client_runtime.EarlyDataRequestResult;
pub const EarlyHandshakeClient = client_runtime.EarlyHandshakeClient;
pub const ResponseBody = client_runtime.ResponseBody;
pub const BodyWriteState = client_runtime.BodyWriteState;
pub const BodyBatchProgress = client_runtime.BodyBatchProgress;
pub const EarlyDataRetryReason = client_runtime.EarlyDataRetryReason;
pub const testing = client_runtime.testing;
pub const validateBodyWrite = client_runtime.validateBodyWrite;
pub const bodyPartsLength = client_runtime.bodyPartsLength;

pub const HandshakeServerOptions = struct {
    /// Native QUIC/TLS options. `handshake.alpn_protocol` must be an HTTP/3
    /// identifier (`h3` or `h3-NN`); `HandshakeServer.bind` rejects other
    /// values with `error.InvalidAlpn` before binding.
    handshake: quic.handshake.ServerOptions,
    session: HandshakeSessionOptions = .{},
    /// Maximum time `serveConnection` keeps the sole connection pump alive
    /// after the final response. One absolute budget covers both GOAWAY phases
    /// and the wait for reliable QUIC recovery to become empty. This protects
    /// short-lived convenience servers from losing a dropped tail DATA/FIN
    /// packet without allowing graceful shutdown itself to block forever.
    serve_connection_recovery_drain_timeout: std.Io.Duration =
        .fromSeconds(5),

    /// Native QUIC/TLS handshake options. Flat accessor for `handshake`.
    pub fn nativeHandshake(
        self: *HandshakeServerOptions,
    ) *quic.handshake.ServerOptions {
        return &self.handshake;
    }

    /// HTTP/3 session and 1-RTT limits. Flat accessor for `session`.
    pub fn sessionOptions(
        self: *HandshakeServerOptions,
    ) *HandshakeSessionOptions {
        return &self.session;
    }
};

pub const HandshakeAdmissionOptions = struct {
    /// Closing slots also reserve one slot for each live handshake. Closing
    /// routes remain until three current PTOs expire; full storage rejects new admission.
    closing_handshake_capacity: usize = 1024,
    /// Bound how long a timed socket wait can hide a completed worker.
    handshake_poll_interval: std.Io.Duration = .fromMilliseconds(5),
    max_pending_handshakes: usize = 128,
    /// Aggregate pending plus established connection budget for the endpoint.
    /// Zero inherits `max_pending_handshakes` for compatibility.
    max_connections: usize = 0,
    inbox_capacity: usize = 16,
    /// Absolute lifetime for one pending TLS/QUIC handshake. Zero derives the
    /// existing bounded PTO budget from `ServerOptions.handshake_recovery`.
    handshake_timeout_ms: u32 = 0,
};

pub const EndpointHandlerServeOptions = endpoint_handler_supervisor.Options;
pub const EndpointHandlerErrorStage = endpoint_handler_supervisor.ErrorStage;
pub const EndpointHandlerErrorPolicy = endpoint_handler_supervisor.ErrorPolicy;
pub const EndpointHandlerErrorEvent = endpoint_handler_supervisor.ErrorEvent;
pub const EndpointHandlerErrorObserver = endpoint_handler_supervisor.ErrorObserver;
pub const ReplayRiskDecision = endpoint_handler_supervisor.ReplayRiskDecision;
pub const ReplayRiskRequest = endpoint_handler_supervisor.ReplayRiskRequest;
pub const ReplayRiskInspector = endpoint_handler_supervisor.ReplayRiskInspector;
pub const ReplayRiskPolicy = endpoint_handler_supervisor.ReplayRiskPolicy;
pub const OwnedEndpointRequest = endpoint_handler_supervisor.OwnedRequest;

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
    closing_packet: ?@import("../quic/handshake/closing.zig").Packet = null,
    closing_lifetime_ns: u64,
    retain_closing: bool = false,

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
        if (self.retain_closing and self.dispatcher.closePendingHandshake(self.handle, self.closing_packet, self.closing_lifetime_ns)) {
            self.registered = false;
            return;
        }
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
            .failure => |err| self.admission.retain_closing = self.admission.closing_packet != null or err == error.ConnectionClosed,
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
        if (options.closing_handshake_capacity == 0 or options.handshake_poll_interval.nanoseconds <= 0) return error.InvalidHandshakeRecovery;
        dispatcher.closing_handshake_capacity = options.closing_handshake_capacity;
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

    /// Wait for an event under the caller's absolute deadline.
    /// Handshake expiry and QUIC transport timers may be serviced first, but
    /// neither can renew the outer endpoint-loop budget.
    pub fn receiveWithDeadline(
        self: *HandshakeSupervisor,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) HandshakeAdmissionError!HandshakeSupervisorEvent {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        while (true) {
            const poll_deadline = if (self.active_workers.load(.acquire) != 0)
                deadline_policy.earlier(absolute, .fromNow(self.io, .{ .raw = self.admission_options.handshake_poll_interval, .clock = .awake })).?
            else
                absolute;
            return self.receiveOnceUntil(supported_versions, .{ .deadline = poll_deadline }) catch |err| switch (err) {
                error.Timeout => {
                    if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
                    continue;
                },
                else => return err,
            };
        }
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
        // From this point the endpoint dispatcher is the sole UDP receive
        // owner. Blocking session helpers must not race it for sibling
        // datagrams; callback code uses the explicit one-attempt APIs.
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
                // A worker delayed until after its admission deadline observes
                // the generic preflight Timeout, while a worker already inside
                // the QUIC handshake reports HandshakeTimeout. Supervisor
                // completions expose one stable handshake-lifetime error
                // independent of scheduler timing.
                break :blk .{ .failure = if (err == error.Timeout)
                    error.HandshakeTimeout
                else
                    err };
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

    /// Advance the shared transport once before polling buffered request
    /// events. Endpoint adapters use this after a ready request cannot return
    /// receive credit or cancellation because pacing/flow control must first
    /// progress; it preserves the single UDP receive owner without spinning
    /// on the same application event.
    pub fn receiveTransportProgressOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!?EndpointServerEvent {
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
                try self.processSessionPacket(
                    packet.connection_handle,
                    target,
                    &packet.packet,
                );
            },
            .unrouted => {
                const unrouted = event.unrouted;
                event = .{ .connected = 0 };
                return .{ .unrouted = unrouted };
            },
        }
        return self.pollRequestAcrossSessions();
    }

    fn processSessionPacket(
        self: *EndpointServer,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        promoted: *PromotedHandshakeSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) HandshakeAdmissionError!void {
        promoted.session.processRequestPacket(packet) catch |err| {
            // HTTP/3 parsing can queue RESET_STREAM, STOP_SENDING, QPACK
            // feedback, or CONNECTION_CLOSE before surfacing an error. The
            // dispatcher refreshed before handing out this packet, so mirror
            // the post-parser state even on failure.
            try self.refreshTimerIfOwned(handle);
            return err;
        };
        // A successful parser pass can likewise emit ACK/QPACK/flow-control
        // work. Refresh this exact connection before a ready sibling request
        // can make round-robin polling return early.
        try self.refreshTimerIfOwned(handle);
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

    /// Run bounded application handlers for complete owned requests while
    /// retaining sole QUIC/QPACK ownership on this endpoint task. Handler
    /// results are copied into an owned completion before request storage is
    /// released, then submitted nonblockingly as transport credit permits.
    ///
    /// `context` may be entered concurrently by up to
    /// `options.max_handler_tasks` workers and must synchronize mutable state.
    /// The request pointer is callback-borrowed and must not be retained.
    /// Response slices must remain valid through the handler return boundary;
    /// the supervisor then copies them with the configured thread-safe
    /// allocator, so they must not refer to handler stack locals. Borrowing the
    /// request is safe because it remains retained through response delivery.
    /// Streaming requests and Extended CONNECT protocols should continue to
    /// use `serveUntil`, whose callbacks retain direct session access.
    pub fn serveHandlersUntil(
        self: *EndpointServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *const OwnedEndpointRequest,
        ) Error!http3.Response,
        options: EndpointHandlerServeOptions,
    ) anyerror!void {
        return endpoint_handler_supervisor.serveUntil(
            RuntimeModule,
            self,
            HandlerContext,
            context,
            handler,
            options,
        );
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
        var event = promoted.session.pollRequestEventOnce() catch |err| {
            // Protocol errors can queue RESET_STREAM, STOP_SENDING, QPACK
            // feedback, or CONNECTION_CLOSE before they are surfaced. Do not
            // strand that recovery work outside the endpoint timer heap.
            try promoted.dispatcher.refreshConnectionTimer(promoted.handle);
            return err;
        };
        errdefer if (event) |*owned| owned.deinit(promoted.allocator);
        // Polling can return receive credit, emit QPACK feedback, retire a
        // completed request stream, or arm a retry after an automatic credit
        // send fails. The dispatcher last refreshed when it delivered the
        // inbound packet, so mirror the resulting connection deadline before
        // the endpoint waits on its shared UDP socket again.
        try promoted.dispatcher.refreshConnectionTimer(promoted.handle);
        return event;
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

        /// Exercise the production promoted-session poll adapter, including
        /// its dispatcher timer refresh, without constructing the endpoint's
        /// handshake-admission maps in focused transport tests.
        pub fn pollSessionRequestEntry(
            promoted: *PromotedHandshakeSession,
        ) HandshakeAdmissionError!?StreamingRequestEvent {
            return EndpointServer.pollSessionRequestEntry(
                {},
                promoted.handle,
                promoted,
            );
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

    /// Perform one bounded caller-buffer receive iteration. Established QUIC
    /// packets are parsed and applied to their HTTP/3 sessions while `storage`
    /// is borrowed; only stable lifecycle, request, and unrouted events escape
    /// this call. A zero result means the poll interval elapsed without one.
    pub fn receiveManyOnce(
        self: *EndpointServer,
        supported_versions: []const u32,
        storage: []u8,
        output: []EndpointServerEvent,
        poll_interval: std.Io.Clock.Duration,
    ) HandshakeAdmissionError!usize {
        if (output.len == 0 or
            output.len > quic.runtime.max_receive_batch_messages)
        {
            return error.BufferTooShort;
        }
        if (poll_interval.raw.nanoseconds <= 0) {
            return error.InvalidHandshakeRecovery;
        }
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.server.quic_server.endpoint.io,
            poll_interval,
        );
        return self.receiveManyUntil(
            supported_versions,
            storage,
            output,
            deadline,
        ) catch |err| switch (err) {
            error.Timeout => 0,
            else => |other| return other,
        };
    }

    fn receiveManyUntil(
        self: *EndpointServer,
        supported_versions: []const u32,
        storage: []u8,
        output: []EndpointServerEvent,
        deadline: std.Io.Clock.Timestamp,
    ) HandshakeAdmissionError!usize {
        while (true) {
            var count: usize = 0;
            errdefer for (output[0..count]) |*event| {
                event.deinit(self.allocator);
            };
            if (try self.pollRequestAcrossSessions()) |request| {
                output[0] = request;
                return 1;
            }

            if (self.handshakes.pollCompleted()) |completion_value| {
                var completion = completion_value;
                const event = try self.finishTransportCompletion(&completion);
                output[0] = switch (event) {
                    .connected => |handle| .{ .connected = handle },
                    .handshake_failed => |failure| .{
                        .handshake_failed = failure,
                    },
                    .closed, .packet, .unrouted => unreachable,
                };
                return 1;
            }

            const now = std.Io.Clock.awake.now(
                self.server.quic_server.endpoint.io,
            ).nanoseconds;
            _ = self.handshakes.expireAt(if (now <= 0)
                0
            else
                std.math.cast(u64, now) orelse std.math.maxInt(u64));

            const Adapter = struct {
                server: *EndpointServer,

                fn visit(
                    adapter: *@This(),
                    packet: quic.endpoint_dispatcher.RoutedPacketView,
                ) HandshakeAdmissionError!void {
                    const promoted = adapter.server.sessions.getPtr(
                        packet.connection_handle,
                    ) orelse return error.UnknownConnectionHandle;
                    try promoted.session.processRequestPacketView(
                        packet.packet,
                    );
                }
            };
            var adapter = Adapter{ .server = self };
            var transport_events: [
                quic.runtime.max_receive_batch_messages
            ]quic.endpoint_dispatcher.VisitEvent = undefined;
            const transport_count = try self.dispatcher
                .receiveManyVisitingTimeout(
                supported_versions,
                storage,
                transport_events[0..output.len],
                .{ .deadline = deadline },
                &adapter,
                Adapter.visit,
            );
            defer for (transport_events[0..transport_count]) |*event| {
                event.deinit(self.allocator);
            };

            for (transport_events[0..transport_count]) |*event| {
                switch (event.*) {
                    .new_initial => {
                        var owned = takeEndpointVisitEvent(event);
                        defer owned.deinit(self.allocator);
                        _ = self.handshakes.admit(&owned) catch |err|
                            switch (err) {
                                error.PendingHandshakeLimitReached => {
                                    const rejected = owned;
                                    owned = .consumed;
                                    output[count] = .{ .unrouted = rejected };
                                    count += 1;
                                },
                                else => |other| return other,
                            };
                    },
                    .packet => |packet| {
                        const promoted = self.sessions.getPtr(
                            packet.connection_handle,
                        ) orelse return error.UnknownConnectionHandle;
                        const request = (try pollSessionRequestEntry(
                            {},
                            packet.connection_handle,
                            promoted,
                        )) orelse continue;
                        if (requestEventAlreadyReturned(
                            output[0..count],
                            packet.connection_handle,
                            request,
                        )) {
                            var duplicate = request;
                            duplicate.deinit(self.allocator);
                            continue;
                        }
                        output[count] = .{ .request = .{
                            .connection_handle = packet.connection_handle,
                            .request = request,
                        } };
                        count += 1;
                    },
                    .timer => |timer| {
                        const promoted = self.sessions.getPtr(
                            timer.connection_handle,
                        ) orelse return error.UnknownConnectionHandle;
                        if (!promoted.session.established.connection.closed()) {
                            continue;
                        }
                        output[count] = .{ .closed = .{
                            .handle = timer.connection_handle,
                            .timer = timer.timer,
                        } };
                        count += 1;
                        if (!self.removeConnection(timer.connection_handle)) {
                            return error.UnknownConnectionHandle;
                        }
                    },
                    .unrouted => {
                        const owned = takeEndpointVisitEvent(event);
                        output[count] = .{ .unrouted = owned };
                        count += 1;
                    },
                    .pending_handshake,
                    .discarded_long_header,
                    .consumed,
                    => {},
                }
            }
            if (count != 0) return count;
        }
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

fn takeEndpointVisitEvent(
    event: *quic.endpoint_dispatcher.VisitEvent,
) quic.endpoint_dispatcher.Event {
    return switch (event.*) {
        .new_initial => |initial| blk: {
            event.* = .consumed;
            break :blk .{ .new_initial = initial };
        },
        .unrouted => |unrouted| blk: {
            event.* = .consumed;
            break :blk .{ .unrouted = unrouted };
        },
        else => unreachable,
    };
}

fn requestEventAlreadyReturned(
    events: []const EndpointServerEvent,
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    request: StreamingRequestEvent,
) bool {
    const stream_id = switch (request) {
        .reset => return false,
        .message => |message| switch (message.value) {
            .data_available => message.stream_id,
            .head, .push_promise, .trailers, .finished => return false,
        },
    };
    for (events) |event| switch (event) {
        .request => |previous| {
            if (previous.connection_handle != handle) continue;
            switch (previous.request) {
                .reset => {},
                .message => |message| if (message.stream_id == stream_id and
                    message.value == .data_available) return true,
            }
        },
        else => {},
    };
    return false;
}

pub const HandshakeClientOptions = struct {
    /// Native QUIC/TLS handshake options. URI-level facades (unified HTTP,
    /// WebSocket over H3, WebTransport `EndpointClient`) install platform
    /// roots when no trust material is set; the low-level
    /// `HandshakeClient.connectUri*`/`requestUri*` helpers, direct-address
    /// connects and session helpers require explicit configuration. An
    /// established ALPN that is not HTTP/3 is rejected after the handshake.
    handshake: quic.handshake.ClientOptions,
    session: HandshakeSessionOptions = .{},
    /// Absolute budget for the complete QUIC/TLS connection. URI entry points
    /// include hostname resolution and every address fallback in this same
    /// budget; direct-address and caller-owned-endpoint entry points begin it
    /// immediately before the handshake.
    connect_timeout: ?std.Io.Duration = null,
    /// Optional per-resolved-address QUIC/TLS handshake budget. Each fallback
    /// address receives a fresh phase budget, capped by the total
    /// `connect_timeout` or caller deadline. Null preserves the existing
    /// handshake-recovery policy.
    address_attempt_timeout: ?std.Io.Duration = null,
    /// Resolver-address scheduling for owning and ordinary-pool URI connects.
    /// Ordered preserves resolver order. Happy Eyeballs stable-interleaves
    /// families and overlaps independent QUIC handshakes after a delay.
    address_connect_policy: AddressConnectPolicy = .ordered,
    /// Optional bind address for the family opposite the entry point's
    /// `local_address`. It makes dual-family URI racing explicit instead of
    /// silently discarding DNS results that the primary UDP socket cannot
    /// reach. The two bind addresses must use different families.
    alternate_local_address: ?net.IpAddress = null,
    /// Optional application resolver shared by direct URI connections,
    /// redirects, Alt-Svc routes, and pools. Literal IP route hosts bypass it;
    /// QUIC/TLS authentication remains bound to the URI origin.
    address_resolver: ?AddressResolver = null,

    /// Native QUIC/TLS handshake options. Flat accessor for `handshake`.
    pub fn nativeHandshake(
        self: *HandshakeClientOptions,
    ) *quic.handshake.ClientOptions {
        return &self.handshake;
    }

    /// HTTP/3 session and 1-RTT limits. Flat accessor for `session`.
    pub fn sessionOptions(
        self: *HandshakeClientOptions,
    ) *HandshakeSessionOptions {
        return &self.session;
    }
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
        // The server speaks HTTP/3 framing on this ALPN. Reject a configured
        // protocol the client-side check would also refuse after negotiation.
        if (!http3.isHttp3Alpn(options.handshake.alpn_protocol)) {
            return error.InvalidAlpn;
        }
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
        var session = try HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
        errdefer session.deinit();
        // Publish the server control stream before the request loop starts.
        // Event-driven clients (extended CONNECT adapters in particular) wait
        // for peer SETTINGS before opening their first request stream, so a
        // lazy send here would deadlock both sides until their deadlines.
        try session.ensureSettingsSent();
        return session;
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
            .closing_lifetime_ns = @import("../quic/handshake/closing.zig").lifetimeNs(self.handshake_options.handshake_recovery.initial_pto_ms),
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
        options.failed_close_out = &admission.closing_packet;
        options.failed_close_lifetime_out = &admission.closing_lifetime_ns;
        var established = try quic.handshake
            .acceptFromInitialSourceWithDeadline(
            &self.quic_server.endpoint,
            admission.datagramSource(),
            admission.takeInitial(),
            options,
            admission.deadline(),
        );
        var session = HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        ) catch |err| {
            established.deinit();
            return err;
        };
        errdefer session.deinit();
        // Complete critical-stream setup in the isolated handshake worker.
        // Once promoted, the endpoint loop is the sole owner and application
        // callbacks must not sleep while emitting their first response.
        try session.ensureSettingsSent();
        return session;
    }

    pub fn promoteAdmission(
        self: *HandshakeServer,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        admission: *HandshakeAdmission,
        connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
        session: *HandshakeServerSession,
    ) HandshakeAdmissionError!void {
        _ = self;
        try session.bindDispatcher();
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
    /// the lower-level request-event APIs. After the final response, one
    /// absolute recovery-drain deadline covers both GOAWAY phases and the
    /// reliable-send drain.
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
        const served = try session.serveRequests(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
        if (served != 0) {
            const deadline = std.Io.Clock.Timestamp.fromNow(
                session.connectionIo(),
                .{
                    .raw = self.serve_connection_recovery_drain_timeout,
                    .clock = .awake,
                },
            );
            try finishServedConnectionWithDeadline(&session, deadline);
        }
        return served;
    }
};

/// Deadline-bound cancellation pump shared by the authenticated HTTP/3
/// client and server. Each turn repeats the same one-attempt RESET_STREAM
/// plus STOP_SENDING submission dispatcher owners use; transport backpressure
/// services only this connection's receive/timer owner under one absolute
/// awake-clock deadline. A timeout before socket submission leaves both QUIC
/// stream halves and all HTTP/3 request ownership untouched and retryable.
pub fn cancelHandshakeRequestWithDeadline(
    owner: anytype,
    stream_id: u62,
    application_error_code: u64,
    deadline: std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    const connection = &owner.established.connection;
    while (true) {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
        owner.cancelRequestInternalOnce(
            stream_id,
            application_error_code,
            false,
        ) catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {
                try connection.servicePacketServicingTimersDeadline(deadline);
                continue;
            },
            else => |other| return other,
        };
        return;
    }
}

pub const HandshakeServerSession = @import("runtime/handshake_server_session.zig").HandshakeServerSession;

const HandshakeConcurrentAdapter = struct {
    pub fn peerSettings(session: *HandshakeServerSession) http3.Settings {
        return session.control.settings.peer;
    }
    pub fn sendInformational(session: *HandshakeServerSession, from: net.IpAddress, stream_id: u62, response: http3.InformationalResponse, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
        _ = from;
        if (deadline) |until| return session.sendInformationalResponseWithDeadline(stream_id, response, until);
        return session.sendInformationalResponse(stream_id, response);
    }
    pub fn maxStreams(session: *HandshakeServerSession) usize {
        return session.options.max_concurrent_request_streams;
    }
    pub fn maxBodyBuffer(session: *HandshakeServerSession) usize {
        return session.options.max_stream_buffer;
    }
    pub fn receive(
        session: *HandshakeServerSession,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!StreamingRequestEvent {
        return if (deadline) |value|
            session.receiveRequestEventWithDeadline(value)
        else
            session.receiveRequestEvent();
    }
    pub fn availableBody(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!usize {
        _ = from;
        return session.availableRequestData(stream_id);
    }
    pub fn readBody(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        _ = from;
        return session.readRequestData(stream_id, out);
    }
    pub fn startResponse(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        _ = from;
        return session.startResponse(stream_id, response, body_length);
    }
    pub fn sendBody(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        _ = from;
        return session.sendResponseBodyPaced(stream_id, data, fin);
    }
    /// Emit a complete buffered response (head, body and FIN) in one QUIC
    /// packet. Used by the concurrent engine when the handler supplies the
    /// whole body up front.
    pub fn sendCompleteResponse(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        data: []const u8,
        request_method: ?[]const u8,
    ) Error!void {
        _ = from;
        var headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField = undefined;
        var length_buffer: [20]u8 = undefined;
        var prepared = try @import("runtime/concurrent/response.zig").prepare(
            session.established.connection.endpoint.allocator,
            response,
            body_length,
            data,
            request_method,
            &headers_stack,
            &length_buffer,
        );
        defer prepared.deinit(session.established.connection.endpoint.allocator);
        return session.trySendResponseLiteral(stream_id, prepared.value);
    }

    pub fn sendCompleteResponseWithInformational(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        body_length: ?usize,
        data: []const u8,
        request_method: ?[]const u8,
    ) Error!void {
        _ = from;
        var headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField = undefined;
        var length_buffer: [20]u8 = undefined;
        var prepared = try @import("runtime/concurrent/response.zig").prepare(
            session.established.connection.endpoint.allocator,
            response,
            body_length,
            data,
            request_method,
            &headers_stack,
            &length_buffer,
        );
        defer prepared.deinit(session.established.connection.endpoint.allocator);
        return session.sendResponseWithInformational(stream_id, informational, prepared.value);
    }

    pub fn finishTrailers(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        _ = from;
        return session.finishResponseTrailersPaced(stream_id, trailers);
    }
    pub fn cancel(
        session: *HandshakeServerSession,
        from: net.IpAddress,
        stream_id: u62,
        code: u64,
    ) Error!void {
        _ = from;
        return session.cancelRequest(stream_id, code);
    }
    pub fn goaway(
        session: *HandshakeServerSession,
        last_stream_id: u64,
    ) Error!void {
        return session.sendGoAway(last_stream_id);
    }
};

pub const HandshakeConcurrentEngine = concurrent.Engine(HandshakeServerSession, HandshakeConcurrentAdapter);

pub fn sleepResponseSchedulerDelayUntil(
    io: std.Io,
    delay_ns: i64,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    const delay = std.Io.Duration.fromNanoseconds(delay_ns);
    if (deadline) |absolute| {
        const remaining = (try deadline_policy.usableAwake(io, absolute))
            .durationFromNow(io).raw;
        if (delay.nanoseconds >= remaining.nanoseconds) {
            try std.Io.sleep(io, remaining, .awake);
            return error.Timeout;
        }
    }
    try std.Io.sleep(io, delay, .awake);
}

pub const HandshakeClient = @import("runtime/handshake_client.zig").HandshakeClient;

pub const HandshakeClientPool = handshake_client_pool.Pool(@This());
pub const HandshakeClientPoolOptions =
    handshake_client_pool.Options(@This());
pub const HandshakeClientPoolConnector =
    handshake_client_pool.Connector(@This());
pub const HandshakeClientPoolRedirectConnectContext =
    handshake_client_pool.RedirectConnectContext;
pub const HandshakeClientPoolDefaultConnector =
    handshake_client_pool.DefaultConnectorContext(@This());
pub const HandshakeClientPoolTransportConnector =
    handshake_client_pool.TransportConnector(@This());
pub const HandshakeClientPoolStats = http3.origin_pool.Stats;
pub const HandshakeClientPoolError = handshake_client_pool.Error;
pub const HandshakeClientPoolUriBatchRequest =
    HandshakeClientPool.UriBatchRequest;
pub const HandshakeClientPoolSharedDispatcher =
    @import("runtime/handshake_client_pool/shared.zig").Dispatcher(
        HandshakeClientPool,
        @This(),
    );
pub const HandshakeClientPoolSharedSender =
    HandshakeClientPoolSharedDispatcher.Sender;
pub const HandshakeClientPoolSharedOptions =
    @import("runtime/handshake_client_pool/shared.zig").Options;
pub const HandshakeClientPoolSharedStats =
    @import("runtime/handshake_client_pool/shared.zig").Stats;
pub const HandshakeClientPoolSharedError =
    @import("runtime/handshake_client_pool/shared.zig").Error;
pub const HandshakeClientPoolSharedRequestError =
    HandshakeClientPoolSharedDispatcher.RequestError;
pub const SharedHandshakeClientPool =
    @import("runtime/shared_handshake_client_pool.zig").Pool(@This());
pub const ConnectUdpClientSession = http3.connect_udp.Session(HandshakeClient);
pub const ConnectUdpServerSession = http3.connect_udp.Session(
    HandshakeServerSession,
);
pub const ConnectUdpDispatcherRelay = connect_udp_dispatcher_relay.Server(
    RuntimeModule,
);
pub const ConnectIpClientSession = connect_ip_session.Session(
    http3,
    http3.connect_ip,
    HandshakeClient,
    BodyWriteProgress,
    .client,
);
pub const ConnectIpServerSession = connect_ip_session.Session(
    http3,
    http3.connect_ip,
    HandshakeServerSession,
    BodyWriteProgress,
    .server,
);
pub const SharedHandshakeClientPoolOptions =
    @import("runtime/shared_handshake_client_pool.zig").Options(@This());
pub const SharedHandshakeClientPoolAddressResolver =
    AddressResolver;
pub const SharedHandshakeClientPoolError =
    @import("runtime/shared_handshake_client_pool.zig").Error;
pub const SharedHandshakeClientPoolRequestDispatcher =
    SharedHandshakeClientPool.RequestDispatcher;
pub const SharedHandshakeClientPoolRequestSender =
    SharedHandshakeClientPoolRequestDispatcher.Sender;
pub const SharedHandshakeClientPoolRequestDispatcherOptions =
    @import("runtime/shared_handshake_client_pool/dispatcher.zig").Options;
pub const SharedHandshakeClientPoolRequestDispatcherStats =
    @import("runtime/shared_handshake_client_pool/dispatcher.zig").Stats;
pub const SharedHandshakeClientPoolRequestDispatcherError =
    @import("runtime/shared_handshake_client_pool/dispatcher.zig").Error;
pub const SharedHandshakeClientPoolRequestError =
    SharedHandshakeClientPoolRequestDispatcher.RequestError;

pub const OwnedHandshakeRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    /// True only when accepted TLS 0-RTT STREAM data contributed to this
    /// request. Handlers can reject replay-sensitive work with status 425.
    was_early_data: bool = false,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    /// Whether this request carries replay risk from the current QUIC 0-RTT
    /// hop or an earlier gateway hop marked with RFC 8470 Early-Data.
    pub fn mightHaveBeenEarly(self: OwnedHandshakeRequest) bool {
        return self.was_early_data or self.request.mightHaveBeenEarly();
    }

    pub fn deinit(self: *OwnedHandshakeRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn verifyContentDigest(self: OwnedHandshakeResponse, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return self.response.verifyContentDigest(policy);
    }

    pub fn deinit(self: *OwnedHandshakeResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

/// One terminal result from an independently-deadlined HTTP/3 request batch.
/// Successful response ownership transfers to the observer. A stream-local
/// error affects only its request; a connection error is reported to every
/// unfinished member before the batch call returns it.
pub const BatchOwnedHandshakeResponseResult = union(enum) {
    response: OwnedHandshakeResponse,
    err: anyerror,
};

pub const BatchOwnedHandshakeResponseObserver = struct {
    context: *anyopaque,
    on_result: *const fn (
        context: *anyopaque,
        request_index: usize,
        result: BatchOwnedHandshakeResponseResult,
    ) void,
};

/// Cross-task cancellation source for an independently-deadlined HTTP/3
/// request batch. The sole connection reader consumes cancellation bits, then
/// calls `acknowledge` to reset `event` only after accounting for racing
/// producer updates.
pub const BatchHandshakeCancellationObserver = struct {
    event: *std.Io.Event,
    context: *anyopaque,
    take_canceled: *const fn (
        context: *anyopaque,
        request_index: usize,
    ) bool,
    acknowledge: *const fn (context: *anyopaque) void,
};

pub const RedirectedHandshakeResponse = struct {
    allocator: std.mem.Allocator,
    response: OwnedHandshakeResponse,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectedHandshakeResponse) void {
        const allocator = self.allocator;
        self.response.deinit(allocator);
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn takeResponse(
        self: *RedirectedHandshakeResponse,
    ) OwnedHandshakeResponse {
        const response = self.response;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return response;
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

pub const ProtectedServer = @import("runtime/protected.zig").ProtectedServer;
pub const ProtectedClient = @import("runtime/protected.zig").ProtectedClient;

pub fn streamingResponseSectionAcknowledgments(
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

pub fn streamingRequestSectionAcknowledgments(
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

pub fn registerResponsePushPromises(
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

pub fn responseFieldSectionCount(bytes: []const u8) Error!usize {
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

pub fn sendProtectedReaderCapacity(
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

pub fn updateOutboundBodyFlowLimitsFromFrames(
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

pub fn requestPriority(
    headers: []const http3.Qpack.HeaderField,
) http3.Priority {
    return http3.Priority.parseFields(headers);
}

pub fn requestHasProtocol(
    headers: []const http3.Qpack.HeaderField,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

pub fn requestEndedBeforeHeaders(bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = http3.Frame.parse(bytes[offset..]) catch return false;
        if (frame.frame_type == http3.FrameType.headers) return false;
        if (frame.frame_type == http3.FrameType.data) return false;
        if (frame.frame_type == http3.FrameType.push_promise or
            http3.messageStreamForbiddenFrame(frame.frame_type))
        {
            return false;
        }
        offset += frame.consumed;
    }
    return true;
}

pub fn receivedInputComplete(
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

pub fn responseHeadErrorAtFin(bytes: []const u8) Error {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = http3.Frame.parse(bytes[offset..]) catch
            return error.BufferTooShort;
        offset += frame.consumed;
    }
    return error.MissingStatus;
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

pub fn validateBlockedStreamLimit(
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

pub fn validateProtectedConfig(config: ProtectedConfig) Error!void {
    if (config.max_priority_updates == 0 or
        config.max_client_bidirectional_streams > quic.max_stream_count)
    {
        return error.InvalidSetting;
    }
}

pub fn validateHandshakeSessionOptions(options: HandshakeSessionOptions) Error!void {
    if (options.max_priority_updates == 0 or
        options.max_post_handshake_crypto_bytes < 4)
    {
        return error.InvalidSetting;
    }
    try validateBlockedStreamLimit(
        options.local_settings,
        options.max_concurrent_request_streams,
    );
    try receive_policy.validateMaxDatagrams(
        options.max_receive_batch_datagrams,
    );
}

pub fn resolvePacedBodyChunkBytes(
    options: HandshakeSessionOptions,
    default_chunk_bytes: usize,
) HandshakeSessionOptions {
    var resolved = options;
    if (resolved.paced_body_chunk_bytes == 0) {
        resolved.paced_body_chunk_bytes = default_chunk_bytes;
    }
    return resolved;
}

pub fn applyResponseReaderSemantics(
    lifecycle: ClientRequestLifecycle,
    stream_id: u62,
    reader: *StreamingMessageReader,
) void {
    const options = lifecycle.responseDecodeOptions(stream_id);
    reader.applyResponseSemantics(options);
}

pub const sendConnectionFrames = body_sender.sendConnectionFrames;
pub const sendConnectionFramesWithDeadline =
    body_sender.sendConnectionFramesWithDeadline;

pub fn visitStreamingServerRequestPacket(
    session: *HandshakeServerSession,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    session.flushResponseCancellations();
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
        .{ .set = &session.promised_push_ids },
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

pub const DetachedServerRequestContext = struct {
    session: *HandshakeServerSession,
    detached_stream_id: u62,
    datagram_target: ?*connect_datagram.ReceiveIntoTarget = null,
};

pub fn visitDetachedServerRequestPacket(
    context: DetachedServerRequestContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    const session = context.session;
    const detached_stream_id = context.detached_stream_id;
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
        .{ .set = &session.promised_push_ids },
        detached_stream_id,
        &session.connect_datagrams,
    ) catch |err| {
        try closeConnectionForHttp3Error(
            &session.established.connection,
            err,
        );
        return err;
    };
    try routeConnectDatagramsFromPacketInto(
        &session.connect_datagrams,
        &session.established.connection,
        packet.frames,
        packet.packet_number,
        context.datagram_target,
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
    peer_promised_push_ids: PromisedPushIds,
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
    peer_promised_push_ids: PromisedPushIds,
) Error!PreparedRequest {
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
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Sends the interim `100 Continue` for an aggregate request. The callback
/// runs only when a complete, QPACK-unblocked request head asked for it.
pub const ContinueSink = struct {
    context: *anyopaque,
    send: *const fn (
        context: *anyopaque,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void,
};

/// Parse the RFC 9110 `Expect` field as a comma-separated case-insensitive
/// list. Unknown expectations are ignored; only `100-continue` changes
/// server behavior.
pub fn requestHeadersExpectContinue(
    headers: []const http3.Qpack.HeaderField,
) bool {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "expect")) continue;
        var rest = header.value;
        while (rest.len != 0) {
            const comma = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
            const token = std.mem.trim(u8, rest[0..comma], " \t");
            if (std.ascii.eqlIgnoreCase(token, "100-continue")) {
                return true;
            }
            rest = if (comma == rest.len) "" else rest[comma + 1 ..];
        }
    }
    return false;
}

fn sendAggregateContinues(
    connection: *quic.one_rtt.Connection,
    request_streams: *RequestStreamSet,
    table: http3.Qpack.DynamicTable,
    options: HandshakeSessionOptions,
    sink: ContinueSink,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!void {
    while (try request_streams.previewHead(
        table,
        options.local_settings,
    )) |preview| {
        var head = preview.head;
        if (!preview.request_finished and
            requestHeadersExpectContinue(head.headers))
        {
            sink.send(
                sink.context,
                preview.stream_id,
                deadline,
            ) catch |err| {
                head.deinit(connection.endpoint.allocator);
                return err;
            };
        }
        head.deinit(connection.endpoint.allocator);
        request_streams.markContinueChecked(preview.stream_id);
    }
}

pub fn receiveConnectionRequestStreamBytesUntil(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    request_lifecycle: *ServerRequestLifecycle,
    peer_promised_push_ids: PromisedPushIds,
    detached_streams: ?*connect_datagram.Registry,
    deadline: ?std.Io.Clock.Timestamp,
    continue_sink: ?ContinueSink,
) ReceiveTimeoutError!PreparedRequest {
    if (try request_streams.prepareReady(
        qpack_decode.table,
        options.local_settings.qpack_blocked_streams,
    )) |ready| return ready;

    while (true) {
        if (continue_sink) |sink| {
            try sendAggregateContinues(
                connection,
                request_streams,
                qpack_decode.table,
                options,
                sink,
                deadline,
            );
        }
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
        if (try request_streams.prepareReady(
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
        if (receive_error) |err| return err;
    }
}

pub fn responseResetError(application_error_code: u64) Error {
    return if (application_error_code ==
        http3.ApplicationErrorCode.request_rejected)
        error.RequestRejected
    else
        error.RequestCancelled;
}

pub fn applyProtectedServerRequestPacketFrames(
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
        .{ .set = &server.promised_push_ids },
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
) Error!PreparedResponse {
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
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn receiveConnectionResponseStreamBytesUntil(
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
    ticket_receiver_value: ?*ticket_receiver.Receiver,
    established: ?*quic.handshake.EstablishedConnection,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!PreparedResponse {
    if (response_streams.takeReset(expected_stream_id)) |code| {
        return if (code == http3.ApplicationErrorCode.request_rejected)
            error.RequestRejected
        else
            error.RequestCancelled;
    }
    if (try response_streams.prepareReady(
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
            ticket_receiver_value,
            established,
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
        if (try response_streams.prepareReady(
            expected_stream_id,
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
        if (receive_error) |err| return err;
    }
}

pub fn receiveConnectionResponsePacket(
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
    ticket_receiver_value: ?*ticket_receiver.Receiver,
    established: ?*quic.handshake.EstablishedConnection,
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
        ticket_receiver_value,
        established,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn receiveConnectionResponsePacketUntil(
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
    ticket_receiver_value: ?*ticket_receiver.Receiver,
    established: ?*quic.handshake.EstablishedConnection,
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
        .ticket_receiver = ticket_receiver_value,
        .established = established,
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
    if (push_streams) |pushes| {
        while (pushes.firstCancelledStream()) |stream_id| {
            if (deadline) |absolute| {
                try connection.sendStopSendingWithDeadline(
                    stream_id,
                    http3.ApplicationErrorCode.request_cancelled,
                    absolute,
                );
            } else {
                try connection.sendStopSending(
                    stream_id,
                    http3.ApplicationErrorCode.request_cancelled,
                );
            }
            std.debug.assert(
                pushes.takeCancelledStream().? == stream_id,
            );
        }
    }
}

pub const ConnectionResponseReceiveContext = struct {
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
    datagram_target: ?*connect_datagram.ReceiveIntoTarget = null,
    ticket_receiver: ?*ticket_receiver.Receiver = null,
    established: ?*quic.handshake.EstablishedConnection = null,
};

pub fn visitConnectionResponsePacket(
    context: *ConnectionResponseReceiveContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    errdefer |err| closeConnectionForHttp3Error(
        context.connection,
        err,
    ) catch {};
    if (context.ticket_receiver) |receiver| {
        receiver.ingest(
            context.established orelse return error.Unexpected,
            packet.frames,
        ) catch |err| {
            context.connection.failClosedApplication(
                http3.ApplicationErrorCode.internal_error,
                "invalid-post-handshake-ticket",
            );
            return @errorCast(err);
        };
    }
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
        try routeConnectDatagramsFromPacketInto(
            registry,
            context.connection,
            packet.frames,
            packet.packet_number,
            context.datagram_target,
        );
    }
}

test {
    _ = @import("runtime/interface_adoption_tests.zig");
    _ = @import("runtime/tests.zig");
}
