const std = @import("std");
const content_digest = @import("../http/digest.zig");
const RuntimeModule = @This();
const round_robin = @import("../internal/round_robin.zig");
pub const deadline_policy = @import("../internal/deadline.zig");
pub const address_resolver = @import("../internal/address_resolver.zig");
pub const happy_eyeballs = @import("../internal/happy_eyeballs.zig");
const http_method = @import("../internal/http_method.zig");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");
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
const handshake_client_pool = @import("runtime/handshake_client_pool.zig");
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

fn finishServedConnectionWithDeadline(
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
test {
    _ = @import("runtime/concurrent_tests.zig");
    _ = @import("runtime/request/cancel_deadline_tests.zig");
    _ = @import("runtime/request/finish_rejected_deadline_tests.zig");
    _ = @import("runtime/receive/request_failure_retry_tests.zig");
    _ = @import("runtime/receive/field_value_tests.zig");
    _ = @import("runtime/receive/priority_metadata_tests.zig");
    _ = @import("runtime/receive/response_failure_retry_tests.zig");
    _ = @import("runtime/receive/message_data_tests.zig");
    _ = @import("runtime/receive/failure_ownership_tests.zig");
    _ = @import("runtime/stream/push/failure_tests.zig");
}

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
const configureQpackEncoderFromPeerSettings =
    control_receive.configureQpackEncoderFromPeerSettings;
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
const sendConnectionQpackEncoderInstructions =
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
const sendConnectionMessage = message_sender.sendConnectionMessage;
const sendConnectionMessageWithDeadline =
    message_sender.sendConnectionMessageWithDeadline;
pub const prepareConnectionMessage = message_sender.prepareConnectionMessage;
pub const trySendConnectionRequestLiteral =
    message_sender.trySendConnectionRequestLiteral;
pub const trySendConnectionStreamingRequestHeadLiteral =
    message_sender.trySendConnectionStreamingRequestHeadLiteral;
pub const trySendConnectionResponseLiteral =
    message_sender.trySendConnectionResponseLiteral;
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
const encodePushMessages = message_sender.encodePushMessages;
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

pub fn receiveConnectDatagramFromSession(
    session: anytype,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
    progress: anytype,
) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!OwnedConnectDatagram {
    while (true) {
        if (@hasDecl(@TypeOf(progress), "inspect")) try progress.inspect(deadline);
        if (try session.pollConnectDatagram(stream_id)) |datagram| {
            return datagram;
        }
        try progress.maintain(deadline);
        // Protocol maintenance may receive while waiting for outbound grants.
        // Deliver its queued input before beginning another socket wait.
        if (try session.pollConnectDatagram(stream_id)) |datagram| return datagram;
        if (deadline) |absolute| {
            if (@TypeOf(session) == *HandshakeServerSession) {
                if (session.connect_datagrams.streamDetached(stream_id))
                    try session.receiveDetachedRequestProgressWithDeadline(
                        stream_id,
                        absolute,
                    )
                else
                    try session.receiveAttachedConnectDatagramProgress(
                        absolute,
                    );
            } else {
                if (session.connect_datagrams.streamDetached(stream_id))
                    try session.receiveDetachedResponseProgressWithDeadline(
                        stream_id,
                        absolute,
                    )
                else
                    try session.receiveAttachedConnectDatagramProgress(
                        absolute,
                    );
            }
        } else {
            if (@TypeOf(session) == *HandshakeServerSession) {
                if (session.connect_datagrams.streamDetached(stream_id))
                    try session.receiveDetachedRequestProgress(stream_id)
                else
                    try session.receiveAttachedConnectDatagramProgress(null);
            } else {
                if (session.connect_datagrams.streamDetached(stream_id))
                    try session.receiveDetachedResponseProgress(stream_id)
                else
                    try session.receiveAttachedConnectDatagramProgress(null);
            }
        }
    }
}

pub fn receiveConnectDatagramIntoFromSession(
    session: anytype,
    stream_id: u62,
    output: []u8,
    deadline: ?std.Io.Clock.Timestamp,
    progress: anytype,
) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)![]u8 {
    while (true) {
        if (@hasDecl(@TypeOf(progress), "inspect")) try progress.inspect(deadline);
        if (try session.pollConnectDatagramInto(stream_id, output)) |payload| {
            return payload;
        }
        try progress.maintain(deadline);
        if (try session.pollConnectDatagramInto(stream_id, output)) |payload| return payload;
        var target = connect_datagram.ReceiveIntoTarget.init(
            stream_id,
            output,
        );
        if (@TypeOf(session) == *HandshakeServerSession and
            session.connect_datagrams.streamDetached(stream_id))
        {
            try session.receiveDetachedRequestProgressInto(
                stream_id,
                deadline,
                &target,
            );
        } else if (@TypeOf(session) != *HandshakeServerSession and
            session.connect_datagrams.streamDetached(stream_id))
        {
            try session.receiveDetachedResponseProgressInto(
                stream_id,
                deadline,
                &target,
            );
        } else {
            try session.receiveAttachedConnectDatagramProgress(deadline);
        }
        if (try target.finish()) |payload| {
            if (@hasDecl(@TypeOf(progress), "inspect")) try progress.inspect(deadline);
            return payload;
        }
    }
}

pub fn receiveConnectDatagramsIntoFromSession(
    session: anytype,
    stream_id: u62,
    outputs: [][]u8,
    received_count: *usize,
    deadline: ?std.Io.Clock.Timestamp,
    progress: anytype,
) (@TypeOf(progress).ErrorSet || ReceiveTimeoutError)!void {
    received_count.* = 0;
    for (outputs) |*output| {
        output.* = try receiveConnectDatagramIntoFromSession(
            session,
            stream_id,
            output.*,
            deadline,
            progress,
        );
        received_count.* += 1;
    }
}

pub const observeConnectDatagramTerminal = connect_datagram_routing.observeTerminal;
pub const ensureConnectDatagramSendSideOpen =
    connect_datagram_routing.ensureSendSideOpen;
pub const connectDatagramTerminalError = connect_datagram_routing.terminalError;
pub const pollConnectDatagramRegistry = connect_datagram_routing.poll;
pub const pollConnectDatagramRegistryInto = connect_datagram_routing.pollInto;
const drainConnectDatagrams = connect_datagram_routing.drain;

/// Replay HTTP DATAGRAM frames in their authenticated QUIC packet order. The
/// transport queue itself is intentionally connection-wide and does not retain
/// ordering metadata relative to RESET_STREAM/FIN, so adapters must mark the
/// affected association as soon as a terminal stream frame is crossed. A later
/// DATAGRAM in that same packet is then dropped by `Registry.route`, while a
/// preceding one remains queued for delivery.
const routeConnectDatagramsFromPacket = connect_datagram_routing.routePacket;
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
const receiveRuntimeStreamBytes = development_receive.streamBytes;
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
    handshake: quic.handshake.ServerOptions,
    session: HandshakeSessionOptions = .{},
    /// Maximum time `serveConnection` keeps the sole connection pump alive
    /// after the final response. One absolute budget covers both GOAWAY phases
    /// and the wait for reliable QUIC recovery to become empty. This protects
    /// short-lived convenience servers from losing a dropped tail DATA/FIN
    /// packet without allowing graceful shutdown itself to block forever.
    serve_connection_recovery_drain_timeout: std.Io.Duration =
        .fromSeconds(5),
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
        var value = response;
        value.body = data;
        value.request_method = request_method;
        var headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var length_buffer: [20]u8 = undefined;
        if (body_length) |length| {
            if (server_response.headerValue(value.headers, "content-length") == null) {
                if (value.headers.len == headers_stack.len) return error.InvalidHeader;
                @memcpy(headers_stack[0..value.headers.len], value.headers);
                headers_stack[value.headers.len] = .{
                    .name = "content-length",
                    .value = std.fmt.bufPrint(
                        &length_buffer,
                        "{d}",
                        .{length},
                    ) catch return error.InvalidHeader,
                };
                value.headers = headers_stack[0 .. value.headers.len + 1];
            }
        }
        return session.trySendResponseLiteral(stream_id, value);
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
        var value = response;
        value.body = data;
        value.request_method = request_method;
        var headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var length_buffer: [20]u8 = undefined;
        if (body_length) |length| {
            if (server_response.headerValue(value.headers, "content-length") == null) {
                if (value.headers.len == headers_stack.len) return error.InvalidHeader;
                @memcpy(headers_stack[0..value.headers.len], value.headers);
                headers_stack[value.headers.len] = .{
                    .name = "content-length",
                    .value = std.fmt.bufPrint(
                        &length_buffer,
                        "{d}",
                        .{length},
                    ) catch return error.InvalidHeader,
                };
                value.headers = headers_stack[0 .. value.headers.len + 1];
            }
        }
        return session.sendResponseWithInformational(
            stream_id,
            informational,
            value,
        );
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

test "HTTP/3 response scheduler delay respects caller deadline" {
    const FixedIo = struct {
        now_ns: i96 = 1_000_000,
        sleep_calls: usize = 0,
        slept_ns: i96 = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            timeout: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            const target = switch (timeout) {
                .none => return error.Canceled,
                .duration => |duration| self.now_ns + duration.raw.nanoseconds,
                .deadline => |deadline| deadline.raw.nanoseconds,
            };
            self.slept_ns += target - self.now_ns;
            self.now_ns = target;
        }
    };
    var fixed: FixedIo = .{};
    var vtable = std.Io.Threaded.init(std.testing.allocator, .{});
    defer vtable.deinit();
    var io_vtable = vtable.io().vtable.*;
    io_vtable.now = FixedIo.now;
    io_vtable.sleep = FixedIo.sleep;
    const io = std.Io{ .userdata = &fixed, .vtable = &io_vtable };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(10),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        sleepResponseSchedulerDelayUntil(io, std.time.ns_per_s, deadline),
    );
    try std.testing.expectEqual(@as(usize, 1), fixed.sleep_calls);
    try std.testing.expectEqual(@as(i96, 10 * std.time.ns_per_ms), fixed.slept_ns);
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

test "HTTP/3 handshake sessions resolve direction-aware paced body defaults" {
    try std.testing.expectEqual(
        default_paced_request_body_chunk_bytes,
        resolvePacedBodyChunkBytes(
            .{},
            default_paced_request_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
    try std.testing.expectEqual(
        default_paced_response_body_chunk_bytes,
        resolvePacedBodyChunkBytes(
            .{},
            default_paced_response_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 4096),
        resolvePacedBodyChunkBytes(
            .{ .paced_body_chunk_bytes = 4096 },
            default_paced_response_body_chunk_bytes,
        ).paced_body_chunk_bytes,
    );
}

pub fn applyResponseReaderSemantics(
    lifecycle: ClientRequestLifecycle,
    stream_id: u62,
    reader: *StreamingMessageReader,
) void {
    const options = lifecycle.responseDecodeOptions(stream_id);
    reader.applyResponseSemantics(options);
}

test "HTTP/3 handshake options reject invalid SETTINGS before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const unreachable_server = net.IpAddress{ .ip4 = .loopback(443) };
    const invalid_settings = http3.Settings{
        .qpack_max_table_capacity = @as(u64, quic.varint.max_value) + 1,
    };

    try std.testing.expectError(
        error.InvalidSetting,
        validateHandshakeSessionOptions(.{
            .max_post_handshake_crypto_bytes = 3,
        }),
    );

    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeServer.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{},
            .{
                .handshake = .{ .local_connection_id = "server" },
                .session = .{ .local_settings = invalid_settings },
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeClient.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            unreachable_server,
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = "12345678",
                    .local_connection_id = "client",
                    .server_name = "localhost",
                },
                .session = .{ .local_settings = invalid_settings },
            },
        ),
    );
    try std.testing.expectError(
        error.QpackDynamicTableUnsupported,
        validateHandshakeSessionOptions(.{
            .local_settings = .{ .qpack_blocked_streams = 2 },
            .max_concurrent_request_streams = 1,
        }),
    );
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
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
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
) ReceiveTimeoutError!PreparedRequest {
    if (try request_streams.prepareReady(
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

test "HTTP/3 protected request zero-progress failures preserve retry state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa3, 0x21, 0x22, 0x23 };
    const server_cid = [_]u8{ 0xa4, 0x21, 0x22, 0x23 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa6} ** quic.protection.secret_len,
    );
    const settings: http3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    };
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = settings,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        client_address: net.IpAddress,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const expected_ids = [_]u62{ 0, 4 };
            for (expected_ids) |expected_id| {
                var request = try self.server.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    self.server.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqual(expected_id, request.stream_id);
                try self.server.sendResponse(
                    self.client_address,
                    request.stream_id,
                    .{ .status = 204 },
                );
            }
        }
    };

    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();
    var shared = Shared{
        .server = &server,
        .client_address = client.quic_client.address(),
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(error.InvalidHeader, client.sendRequest(.{
        .method = "GET",
        .path = "/invalid-before-send",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "invalid" }},
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.control.settings.sent);

    // Seed the peer limits without marking SETTINGS received: the protected
    // server will send its real control stream with the first response.
    client.control.settings.peer = settings;
    try client.qpack_encode.configurePeerLimits(
        settings.qpack_max_table_capacity,
        settings.qpack_blocked_streams,
    );
    _ = try client.qpack_encode.insertField(
        "x-protected-transaction",
        "reused-value",
    );
    const inserted_before_request = client.qpack_encode.table.insert_count;

    const FailOnCall = struct {
        delegate: std.Io,
        fail_on_call: usize,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == self.fail_on_call) {
                return .{ error.NetworkDown, 0 };
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var failed = FailOnCall{
        .delegate = client.quic_client.endpoint.io,
        .fail_on_call = 3,
    };
    var failed_vtable = failed.delegate.vtable.*;
    failed_vtable.netSend = FailOnCall.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &failed,
        .vtable = &failed_vtable,
    };
    defer client.quic_client.endpoint.io = failed.delegate;

    const request: http3.Request = .{
        .method = "GET",
        .path = "/protected-transaction",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-protected-transaction",
            .value = "reused-value",
        }},
    };
    try std.testing.expectError(error.NetworkDown, client.sendRequest(request));
    try std.testing.expectEqual(@as(usize, 3), failed.calls);
    try std.testing.expect(client.protected_send.isUsable());
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pendingEncoderInstructions().len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(
        client.qpack_encode.table.insert_count > inserted_before_request,
    );

    client.quic_client.endpoint.io = failed.delegate;
    const aggregate_id = try client.sendRequest(request);
    try std.testing.expectEqual(@as(u62, 0), aggregate_id);
    var aggregate_response = try client.receiveResponseWithTimeout(
        aggregate_id,
        .fromSeconds(2),
    );
    defer aggregate_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), aggregate_response.response.status);

    failed.calls = 0;
    failed.fail_on_call = 1;
    client.quic_client.endpoint.io = .{
        .userdata = &failed,
        .vtable = &failed_vtable,
    };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expect(client.protected_send.isUsable());
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(client.outbound_bodies.find(4) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );

    client.quic_client.endpoint.io = failed.delegate;
    const streaming_id = try client.startRequest(request, 0);
    try std.testing.expectEqual(@as(u62, 4), streaming_id);
    var streaming_response = try client.receiveResponseWithTimeout(
        streaming_id,
        .fromSeconds(2),
    );
    defer streaming_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), streaming_response.response.status);

    thread.join();
    joined = true;
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
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            const pending_sections =
                session.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseWithDeadline(
                    request.stream_id,
                    .{ .status = 204 },
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expectEqual(
                pending_sections,
                session.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            try session.sendResponseWithTimeout(
                request.stream_id,
                .{
                    .status = 200,
                    .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                    .body = "handshake pong",
                },
                .fromSeconds(2),
            );
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

test "HTTP/3 aggregate deadlines bound request and response head sends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const DeadlineSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
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
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .pacing_max_burst_packets = 1,
            },
            .random = [_]u8{0x51} ** 32,
            .x25519_secret_key = [_]u8{0x52} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        body_done: std.Io.Event = .unset,
        response_timeout: bool = false,
        body_timeout: bool = false,
        zero_send_calls: bool = false,
        zero_sleep_calls: bool = false,
        lifecycle_retained: bool = false,
        connection_open: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.body_done.set(self.io);
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
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings("/after-timeout", request.request.path);

            const before_invalid_deadline =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponsePacedWithDeadline(
                    request.stream_id,
                    .{ .status = 204 },
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                before_invalid_deadline,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
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
            var fixed = DeadlineSendIo{
                .delegate = session.established.connection.endpoint.io,
            };
            var vtable = fixed.delegate.vtable.*;
            vtable.now = DeadlineSendIo.now;
            vtable.sleep = DeadlineSendIo.sleep;
            vtable.netSend = DeadlineSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(fixed.now_ns),
            );
            const packet_number =
                session.established.connection.next_packet_number;
            if (session.sendResponsePacedWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.now_ns + 1),
                },
            )) |_| {
                return error.TestUnexpectedResult;
            } else |err| {
                if (err != error.Timeout) return err;
                self.response_timeout = true;
            }
            self.zero_send_calls = fixed.send_calls == 0;
            self.zero_sleep_calls = fixed.sleep_calls == 0;
            self.lifecycle_retained =
                session.request_lifecycle.count() == 1;
            self.connection_open =
                !session.established.connection.closed();
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            session.established.connection.endpoint.io = fixed.delegate;
            try session.sendResponsePacedWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );

            var body_request = try session.receiveRequest();
            defer body_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), body_request.stream_id);
            try std.testing.expectEqualStrings(
                "/body-timeout",
                body_request.request.path,
            );
            const now = std.Io.Clock.awake.now(
                session.established.connection.endpoint.io,
            ).nanoseconds;
            fixed = .{
                .delegate = session.established.connection.endpoint.io,
                .now_ns = now,
            };
            vtable = fixed.delegate.vtable.*;
            vtable.now = DeadlineSendIo.now;
            vtable.sleep = DeadlineSendIo.sleep;
            vtable.netSend = DeadlineSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(fixed.now_ns),
            );
            fixed.now_ns += std.time.ns_per_s;
            var body: [4096]u8 = .{0xa5} ** 4096;
            if (session.sendResponsePacedWithDeadline(
                body_request.stream_id,
                .{ .status = 200, .body = &body },
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(fixed.now_ns + 1),
                },
            )) |_| {
                return error.TestUnexpectedResult;
            } else |err| {
                if (err != error.Timeout) return err;
                self.body_timeout = true;
            }
            try std.testing.expect(fixed.send_calls >= 1);
            try std.testing.expect(!session.established.connection.closed());
            try std.testing.expect(!session.request_lifecycle.contains(body_request.stream_id));
            session.established.connection.endpoint.io = fixed.delegate;
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
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .pacing_max_burst_packets = 1,
            },
            .random = [_]u8{0x53} ** 32,
            .x25519_secret_key = [_]u8{0x54} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(
            .{
                .method = "GET",
                .path = "/wrong-clock",
                .authority = "localhost",
            },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

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
    var fixed = DeadlineSendIo{ .delegate = client.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = DeadlineSendIo.now;
    vtable.sleep = DeadlineSendIo.sleep;
    vtable.netSend = DeadlineSendIo.netSend;
    client.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed.now_ns),
    );
    const packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndDeadline(
            .{
                .method = "GET",
                .path = "/must-not-send",
                .authority = "localhost",
            },
            null,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expectEqual(packet_number, client.established.connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    try std.testing.expect(client.request_lifecycle.contains(0));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expect(!client.established.connection.closed());
    client.endpoint.io = fixed.delegate;

    var response = try client.requestWithDeadline(
        .{
            .method = "GET",
            .path = "/after-timeout",
            .authority = "localhost",
        },
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    _ = try client.sendRequest(.{
        .method = "GET",
        .path = "/body-timeout",
        .authority = "localhost",
    });
    try shared.body_done.wait(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.response_timeout);
    try std.testing.expect(shared.body_timeout);
    try std.testing.expect(shared.zero_send_calls);
    try std.testing.expect(shared.zero_sleep_calls);
    try std.testing.expect(shared.lifecycle_retained);
    try std.testing.expect(shared.connection_open);
}

test "HTTP/3 streaming head deadlines validate before state mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c };
    const client_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
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
            .random = [_]u8{0x65} ** 32,
            .x25519_secret_key = [_]u8{0x66} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        checked: bool = false,
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
            const packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.startResponseWithDeadline(
                    request.stream_id,
                    .{ .status = 200 },
                    4,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            try session.startResponseWithDeadline(
                request.stream_id,
                .{ .status = 204 },
                0,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            self.checked = true;
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
            .random = [_]u8{0x67} ** 32,
            .x25519_secret_key = [_]u8{0x68} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.startRequestWithDeadline(
            .{
                .method = "POST",
                .path = "/wrong-clock",
                .authority = "localhost",
            },
            4,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

    const request_id = try client.startRequestWithDeadline(.{
        .method = "GET",
        .path = "/server-check",
        .authority = "localhost",
    }, 0, .fromNow(
        client.connectionIo(),
        .{ .raw = .fromSeconds(2), .clock = .awake },
    ));
    try std.testing.expectEqual(@as(u62, 0), request_id);
    var response = try client.receiveResponse(request_id);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.checked);
}

test "HTTP/3 request deadline bounds bidirectional stream admission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_streams_bidi = 0;
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
            .local_transport_parameters = server_transport,
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            std.Io.sleep(
                session.connectionIo(),
                .fromMilliseconds(100),
                .awake,
            ) catch |err| {
                self.err = err;
            };
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
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(
            .{
                .method = "GET",
                .path = "/stream-credit-timeout",
                .authority = "localhost",
            },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.established.connection.closed());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
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
            try std.testing.expectError(
                error.InvalidStatus,
                session.acceptConnectResponse(stream_id, .{
                    .status = 404,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidStatus,
                session.tryAcceptConnectResponse(stream_id, .{
                    .status = 404,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidHeader,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                }),
            );
            try std.testing.expectError(
                error.InvalidStatus,
                session.acceptConnectResponse(stream_id, .{
                    .status = 204,
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                    .body = "not a head-only admission",
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                session.acceptConnectResponse(stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "0",
                    }},
                    .request_method = "CONNECT",
                    .extended_connect = true,
                }),
            );
            try std.testing.expect(
                session.maxConnectDatagramPayloadSize(stream_id) == null,
            );
            try session.acceptConnectResponse(stream_id, .{
                .status = 200,
                .request_method = "CONNECT",
                .extended_connect = true,
            });
            self.response_sent.set(self.server.quic_server.endpoint.io);
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

test "HTTP/3 handshake server ORIGIN deadline is transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
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
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb1} ** 32,
            .x25519_secret_key = [_]u8{0xb2} ** 32,
        } },
    );
    defer server.deinit();

    const origin = "https://alt.example";
    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        sent: std.Io.Event = .unset,
        observed: std.Io.Event = .unset,
        checked: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.sent.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            try std.testing.expect(!session.control.local_origin_set_sent);
            try std.testing.expectError(
                error.Timeout,
                session.sendOriginsWithDeadline(
                    &.{origin},
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expect(!session.control.local_origin_set_sent);
            try session.sendOriginsWithTimeout(
                &.{origin},
                .fromSeconds(2),
            );
            try std.testing.expect(session.control.local_origin_set_sent);
            self.checked = true;
            self.sent.set(self.io);
            try self.observed.wait(self.io);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.observed.set(io);
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
            .random = [_]u8{0xb3} ** 32,
            .x25519_secret_key = [_]u8{0xb4} ** 32,
        } },
    );
    defer client.deinit();

    try shared.sent.wait(io);
    if (shared.err) |err| return err;
    while (!client.peerOriginSetInitialized()) {
        try client.pollControlWithTimeout(.fromSeconds(2));
    }
    try std.testing.expect(client.peerOriginKnown(
        try http3.originFromSerialized(origin),
    ));
    shared.observed.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.checked);
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
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            try std.testing.expectError(
                error.Timeout,
                session.initiateShutdownWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expectEqual(
                stream_lifecycle.ShutdownState.active,
                session.request_lifecycle.state(),
            );
            try session.initiateShutdownWithTimeout(.fromSeconds(2));
            try session.completeShutdownWithTimeout(.fromSeconds(2));
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

test "HTTP/3 serveConnection shutdown deadline covers GOAWAY send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var session = try HandshakeServerSession.initPreconfigured(
        &endpoint,
        peer_endpoint.address(),
        .{},
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "shutdown-server",
            .peer_connection_id = "shutdown-client",
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer session.deinit();
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

    const FixedIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var fixed = FixedIo{ .delegate = endpoint.io };
    var fixed_vtable = fixed.delegate.vtable.*;
    fixed_vtable.now = FixedIo.now;
    fixed_vtable.sleep = FixedIo.sleep;
    fixed_vtable.netSend = FixedIo.netSend;
    endpoint.io = .{ .userdata = &fixed, .vtable = &fixed_vtable };
    defer endpoint.io = fixed.delegate;

    quic.one_rtt.testing.exhaustPacingAt(
        &session.established.connection,
        @intCast(fixed.now_ns),
    );
    const packet_number = session.established.connection.next_packet_number;
    const control_offset = session.control_send.next_offset;
    try std.testing.expectError(
        error.RecoveryDrainTimeout,
        finishServedConnectionWithDeadline(&session, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        session.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, session.control_send.next_offset);
    try std.testing.expectEqual(@as(?u64, null), session.control.local_goaway_id);
    try std.testing.expectEqual(
        ShutdownState.active,
        session.request_lifecycle.state(),
    );
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

    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendPriorityUpdateWithDeadline(
            0,
            .{ .urgency = 1 },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try client.sendPriorityUpdateWithTimeout(0, .{
        .urgency = 2,
        .incremental = true,
    }, .fromSeconds(2));
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
                    if (try applyControlStreamFrameForRoleWithPushes(
                        &session.control,
                        session.established.connection.endpoint.allocator,
                        frame.stream,
                        .server,
                        .{ .slice = &.{ 7, 3 } },
                        null,
                        null,
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

    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendMaxPushIdWithDeadline(
            4,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try std.testing.expectEqual(@as(?u64, null), client.control.local_max_push_id);
    try client.sendMaxPushIdWithTimeout(4, .fromSeconds(2));
    try client.sendMaxPushIdWithTimeout(8, .fromSeconds(2));
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPushWithTimeout(7, .fromSeconds(2));
    try client.cancelPushWithTimeout(3, .fromSeconds(2));
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
            const push = ServerPush{
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
            };
            const packet_number =
                session.established.connection.next_packet_number;
            const control_offset = session.control_send.next_offset;
            const next_push_stream_id = session.next_push_stream_id;
            const pending_sections =
                session.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseWithPushAndDeadline(
                    request.stream_id,
                    .{ .status = 204 },
                    push,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                session.control_send.next_offset,
            );
            try std.testing.expectEqual(
                next_push_stream_id,
                session.next_push_stream_id,
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                session.promised_push_ids.rangeCount(),
            );
            try std.testing.expectEqual(
                pending_sections,
                session.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_lifecycle.count(),
            );
            const push_stream_id = try session.sendResponseWithPushAndTimeout(
                request.stream_id,
                .{ .status = 204 },
                push,
                .fromSeconds(2),
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
            while (!session.established.connection
                .localStreamClosed(push_stream_id))
            {
                try session.pollControlWithTimeout(.fromSeconds(2));
            }
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
    try std.testing.expect(client.established.connection
        .peerStreamClosed(pushed.stream_id));
    try std.testing.expect(client.push_streams.hasPromise(pushed.push_id));
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
            try session.promised_push_ids.prepareInsertValue(
                session.established.connection.endpoint.allocator,
                1,
            );
            session.promised_push_ids.insertAssumeCapacity(1);
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
    const packet_number = client.established.connection.next_packet_number;
    const control_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.sendPushPriorityUpdateWithDeadline(
            1,
            .{ .urgency = 2 },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try client.sendPushPriorityUpdateWithTimeout(1, .{
        .urgency = 4,
        .incremental = true,
    }, .fromSeconds(2));
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
                    .enable_pacing = true,
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
            const chunks = [_]BodyChunk{
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
            };
            var committed: usize = 99;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyBatchPacedWithTimeout(
                    &chunks,
                    &committed,
                    .zero,
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), committed);
            committed = 99;
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyBatchPacedWithDeadline(
                    &chunks,
                    &committed,
                    .fromNow(
                        session.connectionIo(),
                        .{ .raw = .fromSeconds(1), .clock = .real },
                    ),
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), committed);
            try session.sendResponseBodyBatchPacedWithDeadline(
                &chunks,
                &committed,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            try std.testing.expectEqual(@as(usize, 2), committed);
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
                    .enable_pacing = true,
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
    const chunks = [_]BodyChunk{
        .{ .stream_id = first, .data = "first-body", .fin = true },
        .{ .stream_id = second, .data = "second-body", .fin = true },
    };
    const first_offset = client.outbound_bodies.find(first).?.send.next_offset;
    const second_offset = client.outbound_bodies.find(second).?.send.next_offset;
    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithTimeout(
            &chunks,
            &committed,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(
        first_offset,
        client.outbound_bodies.find(first).?.send.next_offset,
    );
    try std.testing.expectEqual(
        second_offset,
        client.outbound_bodies.find(second).?.send.next_offset,
    );
    committed = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendRequestBodyBatchPaced(&.{
            .{ .stream_id = first, .data = "first-body", .fin = true },
            .{ .stream_id = first, .data = "first-body", .fin = true },
        }),
    );
    const FixedPacingIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            return error.Canceled;
        }
    };
    var fixed_io = FixedPacingIo{
        .delegate = client.endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = client.endpoint.io.vtable.*;
    fixed_vtable.now = FixedPacingIo.now;
    fixed_vtable.sleep = FixedPacingIo.sleep;
    client.endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns),
    );
    committed = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(
                client.connectionIo(),
                .{ .raw = .fromNanoseconds(1), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    const pacing = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        quic.one_rtt.TimerDeadlineKind.pacing,
        pacing.kind,
    );
    fixed_io.now_ns = @intCast(pacing.deadline_ns);
    _ = (try client.established.connection.serviceNextTimerAt(
        pacing.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    client.endpoint.io = fixed_io.delegate;
    const PartialBatchSend = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.calls += 1;
            const prefix_len = @min(@as(usize, 1), messages.len);
            if (prefix_len != 0) {
                const send_error, const sent_count = self.delegate.vtable.netSend(
                    self.delegate.userdata,
                    socket_handle,
                    messages[0..prefix_len],
                    flags,
                );
                if (send_error != null or sent_count != prefix_len) {
                    return .{ send_error, sent_count };
                }
            }
            return .{ error.NetworkDown, prefix_len };
        }
    };
    var partial = PartialBatchSend{ .delegate = client.endpoint.io };
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = PartialBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial.delegate;
    committed = 99;
    try std.testing.expectError(
        error.NetworkDown,
        client.sendRequestBodyBatchPacedWithDeadline(
            &chunks,
            &committed,
            .fromNow(
                client.connectionIo(),
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expect(client.outbound_bodies.find(first) == null);
    try std.testing.expectEqual(
        second_offset,
        client.outbound_bodies.find(second).?.send.next_offset,
    );
    client.endpoint.io = partial.delegate;
    committed = 99;
    try client.sendRequestBodyBatchPacedWithDeadline(
        chunks[1..],
        &committed,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
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
    var committed_chunks: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodyBatchPacedWithTimeout(
            &.{},
            &committed_chunks,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed_chunks);
    var committed_bytes: [0]usize = .{};
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodiesPacedWithTimeout(
            &.{},
            &committed_bytes,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveDetachedRequestProgressWithTimeout(0, .zero),
    );

    var client: HandshakeClient = undefined;
    committed_chunks = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyBatchPacedWithTimeout(
            &.{},
            &committed_chunks,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed_chunks);
    try std.testing.expectError(
        error.Timeout,
        client.receiveDetachedResponseProgressWithTimeout(0, .zero),
    );
}

test "HTTP/3 handshake body parts deadline resumes exact slice prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            const send_error, const sent_count = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (sent_count != 0) self.now_ns += std.time.ns_per_s;
            return .{ send_error, sent_count };
        }
    };

    const original_dcid =
        [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    const server_cid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90 };
    const session_options: HandshakeSessionOptions = .{
        .max_frames_per_packet = 8,
        .max_stream_frame_data = 32,
        .paced_body_chunk_bytes = 3,
        .enable_data_prefix_fast_path = true,
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
            },
            .session = session_options,
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
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "abcdefghi",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200 },
                "jklmnopqr".len,
            );
            const response_before =
                session.outbound_bodies.find(request.stream_id).?.*;
            var progress: BodyWriteProgress = .{
                .committed_bytes = 99,
                .fin_committed = true,
            };
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "jk", "lmno", "pqr" },
                    true,
                    &progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            const response_after =
                session.outbound_bodies.find(request.stream_id).?.*;
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(
                response_before.written,
                response_after.written,
            );
            try std.testing.expectEqual(
                response_before.send.next_offset,
                response_after.send.next_offset,
            );
            const response_packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.InvalidContentLength,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "too-", "many-bytes" },
                    true,
                    &progress,
                    .fromNow(
                        session.connectionIo(),
                        .{ .raw = .fromSeconds(2), .clock = .awake },
                    ),
                ),
            );
            try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
            try std.testing.expectEqual(
                response_packet_number,
                session.established.connection.next_packet_number,
            );

            var timed = DeadlineAfterSendIo{
                .delegate = session.established.connection.endpoint.io,
                .now_ns = std.Io.Clock.awake.now(
                    session.established.connection.endpoint.io,
                ).nanoseconds,
            };
            var timed_vtable = timed.delegate.vtable.*;
            timed_vtable.now = DeadlineAfterSendIo.now;
            timed_vtable.netSend = DeadlineAfterSendIo.netSend;
            session.established.connection.endpoint.io = .{
                .userdata = &timed,
                .vtable = &timed_vtable,
            };
            defer session.established.connection.endpoint.io = timed.delegate;

            try std.testing.expectError(
                error.Timeout,
                session.sendResponseBodyPartsPacedWithDeadline(
                    request.stream_id,
                    &.{ "jk", "lmno", "pqr" },
                    true,
                    &progress,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed.now_ns + 1),
                    },
                ),
            );
            try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

            session.established.connection.endpoint.io = timed.delegate;
            try session.sendResponseBodyPartsPacedWithDeadline(
                request.stream_id,
                &.{ "mno", "pqr" },
                false,
                &progress,
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
            );
            try std.testing.expectEqual(@as(usize, 6), progress.committed_bytes);
            try std.testing.expect(!progress.fin_committed);

            const trailer_packet_number =
                session.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                session.finishResponseTrailersPacedWithDeadline(
                    request.stream_id,
                    &.{.{ .name = "x-response-finish", .value = "ok" }},
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                trailer_packet_number,
                session.established.connection.next_packet_number,
            );
            const trailer_now = std.Io.Clock.awake.now(
                session.connectionIo(),
            ).nanoseconds;
            quic.one_rtt.testing.exhaustPacingAt(
                &session.established.connection,
                @intCast(trailer_now),
            );
            try std.testing.expectError(
                error.Timeout,
                session.finishResponseTrailersPacedWithDeadline(
                    request.stream_id,
                    &.{.{ .name = "x-response-finish", .value = "ok" }},
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(trailer_now + 1),
                    },
                ),
            );
            try std.testing.expectEqual(
                trailer_packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expect(
                session.outbound_bodies.find(request.stream_id) != null,
            );
            quic.one_rtt.testing.setPacingBudgetAt(
                &session.established.connection,
                session.established.connection.currentSendDatagramSize(),
                @intCast(trailer_now),
            );
            try session.finishResponseTrailersPacedWithDeadline(
                request.stream_id,
                &.{.{ .name = "x-response-finish", .value = "ok" }},
                .fromNow(
                    session.connectionIo(),
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                ),
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = true,
                },
                .random = [_]u8{0x93} ** 32,
                .x25519_secret_key = [_]u8{0x94} ** 32,
            },
            .session = session_options,
        },
    );
    defer client.deinit();
    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/parts-deadline",
            .authority = "localhost",
        },
        "abcdefghi".len,
    );
    const before = client.outbound_bodies.find(stream_id).?.*;
    var progress: BodyWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithTimeout(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const after = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(before.written, after.written);
    try std.testing.expectEqual(before.send.next_offset, after.send.next_offset);
    const request_packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "too-", "many-bytes" },
            true,
            &progress,
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectEqual(
        request_packet_number,
        client.established.connection.next_packet_number,
    );

    var timed = DeadlineAfterSendIo{
        .delegate = client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(client.endpoint.io).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.endpoint.io = .{ .userdata = &timed, .vtable = &timed_vtable };
    defer client.endpoint.io = timed.delegate;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "ab", &.{}, "cdef", "ghi" },
            true,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

    client.endpoint.io = timed.delegate;
    try client.sendRequestBodyPartsPacedWithDeadline(
        stream_id,
        &.{ "def", "ghi" },
        false,
        &progress,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 6), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);

    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithTimeout(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .zero,
        ),
    );
    const trailer_packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithDeadline(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        trailer_packet_number,
        client.established.connection.next_packet_number,
    );
    const trailer_now = std.Io.Clock.awake.now(io).nanoseconds;
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(trailer_now),
    );
    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithDeadline(
            stream_id,
            &.{.{ .name = "x-request-finish", .value = "ok" }},
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(trailer_now + 1),
            },
        ),
    );
    try std.testing.expectEqual(
        trailer_packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expect(client.outbound_bodies.find(stream_id) != null);
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.established.connection,
        client.established.connection.currentSendDatagramSize(),
        @intCast(trailer_now),
    );
    try client.finishRequestTrailersPacedWithDeadline(
        stream_id,
        &.{.{ .name = "x-request-finish", .value = "ok" }},
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );

    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("jklmnopqr", response.response.body);
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
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
            var encoded_ptr: [*]u8 = undefined;
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
                try std.testing.expectEqual(@as(usize, 0), session.stream_send_scratch.frames.capacity);
                if (exchange == 0) {
                    encoded_capacity =
                        session.stream_send_scratch.encoded.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    encoded_ptr = session.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        session.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        session.stream_send_scratch.encoded
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
    var encoded_ptr: [*]u8 = undefined;
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
        // Complete HEADERS now submit borrowed fragments directly, retaining
        // only encoded field-section storage between these dynamic exchanges.
        try std.testing.expectEqual(@as(usize, 0), client.stream_send_scratch.frames.capacity);
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            try std.testing.expect(encoded_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
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

test "HTTP/3 handshake request failures keep stream cursors and QPACK transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
    const settings: http3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
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
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x41} ** 32,
                .x25519_secret_key = [_]u8{0x42} ** 32,
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
            const expected_ids = [_]u62{ 0, 4 };
            for (expected_ids) |expected_id| {
                var request = try session.receiveRequestWithTimeout(
                    .fromSeconds(2),
                );
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqual(expected_id, request.stream_id);
                var header_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(
                        u8,
                        header.name,
                        "x-request-transaction",
                    )) {
                        header_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "reused-value",
                    header_value orelse return error.TestUnexpectedResult,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 204,
                });
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
                .initial_one_rtt_config = .{ .enable_pacing = false },
                .random = [_]u8{0x43} ** 32,
                .x25519_secret_key = [_]u8{0x44} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 256 },
            },
        },
    );
    defer client.deinit();

    _ = try client.receivePeerSettingsWithTimeout(.fromSeconds(2));
    try std.testing.expectError(error.InvalidHeader, client.sendRequest(.{
        .method = "GET",
        .path = "/invalid-before-reserve",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "invalid" }},
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(!client.control.settings.sent);
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
    try std.testing.expect(client.qpack_encoder_prefix_sent);
    const qpack_offset = client.qpack_encoder_send.next_offset;
    _ = try client.qpack_encode.insertField(
        "x-request-transaction",
        "reused-value",
    );
    try std.testing.expect(
        client.qpack_encode.pendingEncoderInstructions().len != 0,
    );
    const inserted_before_request = client.qpack_encode.table.insert_count;

    const FailSendIo = struct {
        delegate: std.Io,
        fail_on_call: usize,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == self.fail_on_call) {
                return .{ error.NetworkDown, 0 };
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var failed = FailSendIo{
        .delegate = client.endpoint.io,
        .fail_on_call = 2,
    };
    var failed_vtable = failed.delegate.vtable.*;
    failed_vtable.netSend = FailSendIo.netSend;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    defer client.endpoint.io = failed.delegate;

    const request: http3.Request = .{
        .method = "GET",
        .path = "/request-transaction",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-request-transaction",
            .value = "reused-value",
        }},
    };
    try std.testing.expectError(error.NetworkDown, client.sendRequest(request));
    try std.testing.expectEqual(@as(usize, 2), failed.calls);
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 4),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(client.request_lifecycle.contains(0));
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    const aggregate_failed_stream = client.established.connection
        .sendStreamStats(0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 0),
        aggregate_failed_stream.highest_sent_offset,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        aggregate_failed_stream.final_size,
    );
    try std.testing.expect(
        client.qpack_encoder_send.next_offset > qpack_offset,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pendingEncoderInstructions().len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(
        client.qpack_encode.table.insert_count > inserted_before_request,
    );
    try std.testing.expect(!client.established.connection.closed());

    client.endpoint.io = failed.delegate;
    const aggregate_id = try client.trySendRequest(request);
    try std.testing.expectEqual(@as(u62, 0), aggregate_id);
    var aggregate_response = try client.receiveResponseWithTimeout(
        aggregate_id,
        .fromSeconds(2),
    );
    defer aggregate_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), aggregate_response.response.status);
    try std.testing.expectEqual(@as(usize, 0), client.qpack_encode.pendingEncoderInstructions().len);

    failed.calls = 0;
    failed.fail_on_call = 1;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 8),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(client.request_lifecycle.contains(4));
    try std.testing.expectEqual(@as(usize, 1), client.request_lifecycle.count());
    if (client.established.connection.sendStreamStats(4)) |failed_stream| {
        try std.testing.expectEqual(
            @as(u64, 0),
            failed_stream.highest_sent_offset,
        );
        try std.testing.expectEqual(
            @as(?u64, null),
            failed_stream.final_size,
        );
    }
    try std.testing.expect(client.outbound_bodies.find(4) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(!client.established.connection.closed());

    client.endpoint.io = failed.delegate;
    const streaming_id = try client.tryStartRequest(request, 0);
    try std.testing.expectEqual(@as(u62, 4), streaming_id);
    var streaming_response = try client.receiveResponseWithTimeout(
        streaming_id,
        .fromSeconds(2),
    );
    defer streaming_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), streaming_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;

    failed.calls = 0;
    client.endpoint.io = .{ .userdata = &failed, .vtable = &failed_vtable };
    try std.testing.expectError(
        error.NetworkDown,
        client.startRequest(request, 0),
    );
    try std.testing.expectEqual(@as(u62, 8), client.next_stream_id);
    try std.testing.expect(client.request_lifecycle.contains(8));
    failed.calls = 0;
    try std.testing.expectError(
        error.NetworkDown,
        client.cancelRequest(
            8,
            http3.ApplicationErrorCode.request_cancelled,
        ),
    );
    try std.testing.expect(client.established.connection.closed());
    try std.testing.expectEqual(@as(u62, 12), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
}

test "HTTP/3 established client rejects untyped early bidirectional stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x45} ** quic.protection.secret_len,
    );
    var established = try quic.handshake.establishPreconfigured(
        &client_endpoint,
        server_endpoint.address(),
        .client,
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "early-client",
            .peer_connection_id = "early-server",
        },
    );
    defer established.deinit();
    try established.connection.importSentEarlyData(0, &.{.{ .stream = .{
        .stream_id = 0,
        .data = "early request",
        .fin = true,
    } }});
    try std.testing.expectEqual(
        @as(u64, 4),
        established.connection.nextLocalBidirectionalStreamId(),
    );

    try std.testing.expectError(
        error.UnexpectedEarlyData,
        HandshakeClient.initEstablished(
            &client_endpoint,
            server_endpoint.address(),
            established,
            .{},
        ),
    );
}

test "HTTP/3 established client rejects unknown early unidirectional streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x46} ** quic.protection.secret_len,
    );
    var established = try quic.handshake.establishPreconfigured(
        &client_endpoint,
        server_endpoint.address(),
        .client,
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "early-uni-client",
            .peer_connection_id = "early-uni-server",
        },
    );
    defer established.deinit();
    try established.connection.importSentEarlyData(0, &.{.{ .stream = .{
        .stream_id = 2,
        .data = "unknown early unidirectional bytes",
    } }});
    try std.testing.expectEqual(
        @as(u64, 6),
        established.connection.nextLocalUnidirectionalStreamId(),
    );
    try std.testing.expectError(
        error.StreamCreationError,
        HandshakeClient.initEstablished(
            &client_endpoint,
            server_endpoint.address(),
            established,
            .{},
        ),
    );
}

test "HTTP/3 handshake adopts accepted typed early request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-early-request-ticket";
    const psk = [_]u8{0x47} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 17,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "HEAD",
        .path = "/early-request",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
    const client_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    const server_cid = [_]u8{ 0x54, 0x55, 0x56, 0x57 };
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
            .random = [_]u8{0x58} ** 32,
            .x25519_secret_key = [_]u8{0x59} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 17,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-1",
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 20,
                .max_retries = 3,
                .should_drop = struct {
                    fn first(attempt: u8) bool {
                        return attempt == 0;
                    }
                }.first,
            },
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
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.accepted,
                session.established.early_data_status,
            );
            var early_request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer early_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), early_request.stream_id);
            try std.testing.expect(early_request.was_early_data);
            try std.testing.expect(
                session.established.connection
                    .recvStreamReceivedEarlyData(early_request.stream_id),
            );
            try std.testing.expectEqualStrings(
                "/early-request",
                early_request.request.path,
            );
            try session.sendResponse(early_request.stream_id, .{
                .status = 200,
                .request_method = "HEAD",
                .body = "suppressed-head-body",
            });

            var next_request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer next_request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), next_request.stream_id);
            try std.testing.expect(!next_request.was_early_data);
            try std.testing.expect(
                !session.established.connection
                    .recvStreamReceivedEarlyData(next_request.stream_id),
            );
            try session.sendResponse(next_request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
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
            .random = [_]u8{0x5a} ** 32,
            .x25519_secret_key = [_]u8{0x5b} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .handshake_recovery = .{
                .initial_pto_ms = 5,
                .max_pto_ms = 10,
                .max_retries = 5,
            },
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.accepted,
        connected.disposition,
    );
    try std.testing.expect(client.established.connection.next_packet_number > 1);
    var early_response = try client.receiveResponseWithTimeout(
        early.stream_id,
        .fromSeconds(2),
    );
    defer early_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), early_response.response.status);
    try std.testing.expectEqualStrings("", early_response.response.body);
    const next_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/after-early",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 4), next_id);
    var next_response = try client.receiveResponseWithTimeout(
        next_id,
        .fromSeconds(2),
    );
    defer next_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), next_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 rejected typed early request remains explicit and replayable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-rejected-early-request-ticket";
    const psk = [_]u8{0x5c} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 23,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/replayed-after-rejection",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    const client_cid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };
    const server_cid = [_]u8{ 0x6c, 0x6d, 0x6e, 0x6f };
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
            .random = [_]u8{0x70} ** 32,
            .x25519_secret_key = [_]u8{0x71} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 23,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .cipher_suites = &.{.chacha20_poly1305_sha256},
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-rejected",
            },
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
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.rejected,
                session.established.early_data_status,
            );
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings(
                "/replayed-after-rejection",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
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
            .random = [_]u8{0x72} ** 32,
            .x25519_secret_key = [_]u8{0x73} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.rejected,
        connected.disposition,
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

    var response = try client.requestWithTimeout(
        request_options,
        .fromSeconds(2),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 typed early request remains replayable after Version Negotiation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-vn-early-request-ticket";
    const psk = [_]u8{0x76} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 29,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    const request_options: http3.Request = .{
        .method = "GET",
        .path = "/replayed-after-vn",
        .authority = "localhost",
    };
    var early = try PreparedEarlyRequest.init(
        allocator,
        request_options,
        .{},
        .{},
    );
    defer early.deinit();

    const original_dcid = [_]u8{ 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e };
    const client_cid = [_]u8{ 0x7f, 0x80, 0x81, 0x82 };
    const server_cid = [_]u8{ 0x83, 0x84, 0x85, 0x86 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .version = .version_2,
            .available_versions = &.{.version_2},
            .local_connection_id = &server_cid,
            .random = [_]u8{0x87} ** 32,
            .x25519_secret_key = [_]u8{0x88} ** 32,
            .key_exchange_groups = &.{.x25519},
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 29,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
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
            const endpoint = &self.server.quic_server.endpoint;
            var first_initial = try endpoint.receiveBytes();
            defer first_initial.deinit(endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                first_header.version,
            );
            try std.testing.expectEqual(
                quic.PacketType.initial,
                first_header.packet_type,
            );
            var first_early = try endpoint.receiveBytes();
            defer first_early.deinit(endpoint.allocator);
            const early_info = try quic.protection
                .peekProtectedLongPacketInfo(first_early.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                early_info.version,
            );
            try std.testing.expectEqual(
                quic.protection.ProtectedLongPacketType.zero_rtt,
                early_info.packet_type,
            );
            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(endpoint.allocator);
            try quic.writeVersionNegotiationPacket(
                &vn,
                endpoint.allocator,
                .{
                    .destination_connection_id = first_header.source_connection_id,
                    .source_connection_id = first_header.destination_connection_id,
                    .versions = &.{quic.Version.version_2.wireValue()},
                },
            );
            try endpoint.sendBytes(first_initial.from, vn.items);

            var session = try self.server.accept();
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                session.established.early_data_status,
            );
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expectEqualStrings(
                "/replayed-after-vn",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .version = .version_1,
            .available_versions = &.{ .version_2, .version_1 },
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x89} ** 32,
            .x25519_secret_key = [_]u8{0x8a} ** 32,
            .key_exchange_groups = &.{.x25519},
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.rejected,
        connected.disposition,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        client.earlyDataStatus(),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.established.connection.next_packet_number);

    var response = try client.requestWithTimeout(
        request_options,
        .fromSeconds(2),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(.consumed, lease.state);
}

test "HTTP/3 typed early request rejects mismatched local settings before connect" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = "settings-mismatch-ticket",
        .psk = [_]u8{0x74} ** 32,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 29,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var early = try PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/settings-mismatch",
            .authority = "localhost",
        },
        .{ .h3_datagram = true },
        .{},
    );
    defer early.deinit();

    try std.testing.expectError(
        error.InvalidSetting,
        HandshakeClient.connectWithEarlyRequest(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = "12345678",
                .local_connection_id = "client",
                .server_name = "localhost",
                .resumption_now_ms = 1500,
                .resumption_server_id = "localhost:443",
            } },
            &early,
            &cache,
            &lease,
        ),
    );
    try std.testing.expectEqual(.active, lease.state);
    try std.testing.expect(cache.ownsActiveLease(lease));
    try std.testing.expectError(
        error.ExcessiveLoad,
        HandshakeClient.connectWithEarlyRequest(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = "12345678",
                    .local_connection_id = "client",
                    .server_name = "localhost",
                    .resumption_now_ms = 1500,
                    .resumption_server_id = "localhost:443",
                },
                .session = .{ .max_concurrent_request_streams = 0 },
            },
            &early,
            &cache,
            &lease,
        ),
    );
    try std.testing.expectEqual(.active, lease.state);
    try std.testing.expect(cache.ownsActiveLease(lease));

    var tiny_limits = quic.practical_transport_parameters;
    tiny_limits.initial_max_streams_uni = 2;
    var limited_lease = lease;
    limited_lease.session.transport_parameters =
        .fromTransportParameters(tiny_limits);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        early.validateTransportLimits(.{}, .{ .handshake = .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
        } }, &limited_lease),
    );
}

test "HTTP/3 accepted early request rejects reduced peer settings" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var remembered_transport = quic.practical_transport_parameters;
    remembered_transport.max_datagram_frame_size = 1200;
    const remembered_settings: http3.Settings = .{ .h3_datagram = true };
    const ticket = "h3-reduced-settings-ticket";
    const psk = [_]u8{0x75} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 31,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            remembered_transport,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var early = try PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/reduced-settings",
            .authority = "localhost",
        },
        .{},
        remembered_settings,
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{ 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d };
    const client_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const server_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.max_datagram_frame_size = 1200;
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
            .local_transport_parameters = server_transport,
            .random = [_]u8{0x86} ** 32,
            .x25519_secret_key = [_]u8{0x87} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 31,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "typed-request-settings-reduced",
            },
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
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try HandshakeClient.connectWithEarlyRequest(
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
            .local_transport_parameters = remembered_transport,
            .random = [_]u8{0x88} ** 32,
            .x25519_secret_key = [_]u8{0x89} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        EarlyRequestDisposition.accepted,
        connected.disposition,
    );
    try std.testing.expectError(
        error.InvalidSetting,
        client.receiveResponseWithTimeout(
            early.stream_id,
            .fromSeconds(2),
        ),
    );
    try std.testing.expect(
        client.established.connection.closing() or
            client.established.connection.closed(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
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

test "HTTP/3 development body deadline distinguishes retry from fail close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 96 } },
    );
    defer server.deinit();
    var client = try Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .quic = .{ .max_datagram_size = 96 },
            .max_stream_frame_data = 32,
        },
    );
    defer client.deinit();
    const body = [_]u8{0xa5} ** 256;
    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/bounded-body",
        .authority = "localhost",
    }, body.len);
    const before = client.outbound_bodies.find(stream_id).?.*;
    var progress: DevelopmentBodyWriteProgress = .{
        .send_attempted = true,
        .completed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyWithDeadline(
            stream_id,
            &body,
            true,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const after_invalid = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expect(!progress.send_attempted);
    try std.testing.expect(!progress.completed);
    try std.testing.expectEqual(before.written, after_invalid.written);
    try std.testing.expectEqual(
        before.send.next_offset,
        after_invalid.send.next_offset,
    );
    try std.testing.expect(!client.request_unusable);

    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };
    var timed = DeadlineAfterSendIo{
        .delegate = client.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    defer client.quic_client.endpoint.io = timed.delegate;
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyWithDeadline(
            stream_id,
            &body,
            true,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(progress.send_attempted);
    try std.testing.expect(!progress.completed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    try std.testing.expect(client.request_unusable);
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.sendRequestBody(stream_id, "must-not-replay", false),
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
        client: *Client,
        count: usize = 0,
        status: u16 = 0,
        header_valid: bool = false,
        saw_date: bool = false,
        error_seen: ?anyerror = null,
        stream_error_seen: ?anyerror = null,
        unexpectedly_read: bool = false,

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
            var datagram = self.client.receiveDatagramWithTimeout(
                .fromMilliseconds(1),
            ) catch |err| {
                self.error_seen = err;
                self.probeDevelopmentStream();
                return;
            };
            defer datagram.deinit(self.client.quic_client.endpoint.allocator);
            self.unexpectedly_read = true;
            self.probeDevelopmentStream();
        }

        fn probeDevelopmentStream(self: *@This()) void {
            var stream = self.client.pollDevelopmentStream(.{
                .session_id = 0,
                .local_role = .client,
            }) catch |err| {
                self.stream_error_seen = err;
                return;
            } orelse return;
            defer stream.deinit();
            self.unexpectedly_read = true;
        }
    };
    var observation = Observation{ .client = &client };
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
    try std.testing.expect(!observation.unexpectedly_read);
    switch (observation.error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConcurrentRead => {},
        else => return error.TestUnexpectedResult,
    }
    switch (observation.stream_error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConcurrentRead => {},
        else => return error.TestUnexpectedResult,
    }
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

test "HTTP/3 development server aggregate response fails closed after send attempt" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .quic = .{ .max_datagram_size = 4096 },
            .max_stream_frame_data = 4,
        },
    );
    defer server.deinit();

    const PartialSend = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == 2) return .{ error.NetworkDown, 0 };
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    var partial = PartialSend{ .delegate = server.quic_server.endpoint.io };
    var vtable = partial.delegate.vtable.*;
    vtable.netSend = PartialSend.netSend;
    server.quic_server.endpoint.io = .{
        .userdata = &partial,
        .vtable = &vtable,
    };
    defer server.quic_server.endpoint.io = partial.delegate;

    const valid_frame_size = server.limits.max_stream_frame_data;
    server.limits.max_stream_frame_data = 0;
    try std.testing.expectError(
        error.InvalidStreamRange,
        server.sendResponse(receiver.address(), 0, .{
            .status = 200,
            .body = "preflight failure",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expect(
        !server.aggregate_response_unusable.load(.acquire),
    );
    server.limits.max_stream_frame_data = valid_frame_size;

    try std.testing.expectError(
        error.NetworkDown,
        server.sendResponse(receiver.address(), 0, .{
            .status = 200,
            .body = "response split across several datagrams",
        }),
    );
    try std.testing.expect(partial.calls >= 2);
    try std.testing.expect(
        server.aggregate_response_unusable.load(.acquire),
    );

    const calls = partial.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        server.sendResponse(receiver.address(), 4, .{ .status = 204 }),
    );
    try std.testing.expectEqual(calls, partial.calls);
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
    _ = @import("runtime/send/tests/paced_body.zig");
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
    _ = @import("runtime/server/complete_response_tests.zig");
    _ = @import("runtime/client/tests/protected.zig");
    _ = @import("runtime/client/tests/deadline.zig");
    _ = @import("runtime/client/resolver_tests.zig");
    _ = @import("runtime/client/happy_eyeballs_tests.zig");
    _ = @import("runtime/client/owned_head_tests.zig");
    _ = @import("runtime/client/complete_request.zig");
    _ = @import("runtime/qpack/tests/cancellation.zig");
    _ = @import("runtime/qpack/tests/decoder_progress.zig");
    _ = @import("runtime/connect_udp_tests.zig");
    _ = @import("runtime/connect_udp_dispatcher_relay_tests.zig");
    _ = @import("runtime/connect_ip_tests.zig");
    _ = @import("runtime/connect_ip_dispatcher_tests.zig");
    _ = @import("runtime/client/batch_tests.zig");
    _ = @import("runtime/redirect_tests.zig");
    _ = @import("runtime/client/tests/streaming.zig");
    _ = @import("runtime/handshake_client_pool_tests.zig");
    _ = @import("runtime/handshake_client_pool/admission_tests.zig");
    _ = @import("runtime/handshake_client_pool/retirement_tests.zig");
    _ = @import("runtime/handshake_client_pool/return_tests.zig");
    _ = @import("runtime/handshake_client_pool/batch_tests.zig");
    _ = @import("runtime/handshake_client_pool/shared_tests.zig");
    _ = @import("runtime/handshake_client_pool/shared_route_tests.zig");
    _ = @import("runtime/handshake_client_pool/shared_authority_tests.zig");
    _ = @import("runtime/handshake_client_pool_redirect_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_socks5_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_happy_eyeballs_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_request_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_stream_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_stream_dispatcher_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_dispatcher_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_handshake_progress_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_concurrent_handshake_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool/alt_svc_tests.zig");
    _ = @import("runtime/shared_handshake_client_pool_redirect_tests.zig");
    _ = @import("runtime/development_streaming_tests.zig");
    _ = @import("runtime/development_server_tests.zig");
    _ = @import("runtime/development/server_peer/state_tests.zig");
    _ = @import("runtime/endpoint_dispatcher_tests.zig");
    _ = @import("runtime/endpoint_server_tests.zig");
    _ = @import("runtime/endpoint_handler_supervisor_tests.zig");
    _ = @import("runtime/handshake_server_serve_tests.zig");
    _ = @import("runtime/cancellation_tests.zig");
    _ = @import("runtime/early_data_tests.zig");
    _ = @import("runtime/informational_tests.zig");
    _ = @import("runtime/recovery_tests.zig");
    _ = @import("runtime/response_scheduler/tests/integration.zig");
    _ = @import("runtime/response_scheduler/tests/protected.zig");
}
