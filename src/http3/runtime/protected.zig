//! HTTP/3 protected request/response endpoints over QUIC.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const BodyChunk = runtime.BodyChunk;
const BodyWriteProgress = runtime.BodyWriteProgress;
const Client = runtime.Client;
const ClientPushAggregateState = runtime.ClientPushAggregateState;
const ClientRequestLifecycle = runtime.ClientRequestLifecycle;
const Error = runtime.Error;
const GoAwayRetryDisposition = runtime.GoAwayRetryDisposition;
const HandshakeClient = runtime.HandshakeClient;
const InformationalCallbackGuard = runtime.InformationalCallbackGuard;
const InformationalObserver = runtime.InformationalObserver;
const Limits = runtime.Limits;
const MultiplexedInformationalContext = runtime.MultiplexedInformationalContext;
const MultiplexedInformationalObserver = runtime.MultiplexedInformationalObserver;
const OutboundBodySet = runtime.OutboundBodySet;
const OwnedProtectedRequest = runtime.OwnedProtectedRequest;
const OwnedProtectedResponse = runtime.OwnedProtectedResponse;
const OwnedProtectedResponseEvent = runtime.OwnedProtectedResponseEvent;
const PreparedRequest = runtime.PreparedRequest;
const PreparedResponse = runtime.PreparedResponse;
const ProtectedConfig = runtime.ProtectedConfig;
const ProtectedPacketCursor = runtime.ProtectedPacketCursor;
const ProtectedSendState = runtime.ProtectedSendState;
const PushInformationalCallbackGuard = runtime.PushInformationalCallbackGuard;
const PushInformationalObserver = runtime.PushInformationalObserver;
const PushSendScratch = runtime.PushSendScratch;
const PushStreamSet = runtime.PushStreamSet;
const PushedResponse = runtime.PushedResponse;
const QpackDecodeState = runtime.QpackDecodeState;
const QpackEncodeState = runtime.QpackEncodeState;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const RequestStreamSet = runtime.RequestStreamSet;
const ResponseBody = runtime.ResponseBody;
const ResponseStreamSet = runtime.ResponseStreamSet;
const Server = runtime.Server;
const ServerPush = runtime.ServerPush;
const ServerPushIdSet = runtime.ServerPushIdSet;
const ServerRequestLifecycle = runtime.ServerRequestLifecycle;
const StreamMessageSendScratch = runtime.StreamMessageSendScratch;
const StreamingEvent = runtime.StreamingEvent;
const StreamingPushEvent = runtime.StreamingPushEvent;
const StreamingRequestEvent = runtime.StreamingRequestEvent;
const StreamingRequestSet = runtime.StreamingRequestSet;
const StreamingResponseEvent = runtime.StreamingResponseEvent;
const StreamingResponseSet = runtime.StreamingResponseSet;
const applyProtectedServerRequestPacketFrames = runtime.applyProtectedServerRequestPacketFrames;
const applyResponseReaderSemantics = runtime.applyResponseReaderSemantics;
const bodyPartsLength = runtime.bodyPartsLength;
const client_control_stream_id = runtime.client_control_stream_id;
const client_qpack_decoder_stream_id = runtime.client_qpack_decoder_stream_id;
const client_qpack_encoder_stream_id = runtime.client_qpack_encoder_stream_id;
const deadline_policy = runtime.deadline_policy;
const finishServerRequest = runtime.finishServerRequest;
const first_server_push_stream_id = runtime.first_server_push_stream_id;
const messageStreamErrorCode = runtime.messageStreamErrorCode;
const messageUsesDynamicQpack = runtime.messageUsesDynamicQpack;
const pacedProtectedBodyChunkLimit = runtime.pacedProtectedBodyChunkLimit;
const prepareConnectionMessage = runtime.prepareConnectionMessage;
const prepareServerRequestReceived = runtime.prepareServerRequestReceived;
const push_aggregate = runtime.push_aggregate;
const push_read_failure = runtime.push_read_failure;
const registerResponsePushPromises = runtime.registerResponsePushPromises;
const requestEndedBeforeHeaders = runtime.requestEndedBeforeHeaders;
const requestHasProtocol = runtime.requestHasProtocol;
const requestPriority = runtime.requestPriority;
const requestResetError = runtime.requestResetError;
const responseBodySendCapacity = runtime.responseBodySendCapacity;
const responseFieldSectionCount = runtime.responseFieldSectionCount;
const response_routing = runtime.response_routing;
const response_scheduler = runtime.response_scheduler;
const runtime_error = runtime.runtime_error;
const sendPreparedProtectedMessageUntil = runtime.sendPreparedProtectedMessageUntil;
const sendProtectedBodyBatchPaced = runtime.sendProtectedBodyBatchPaced;
const sendProtectedBodyBatchPacedWithDeadline = runtime.sendProtectedBodyBatchPacedWithDeadline;
const sendProtectedBodyBatchProgress = runtime.sendProtectedBodyBatchProgress;
const sendProtectedBodyChunk = runtime.sendProtectedBodyChunk;
const sendProtectedBodyChunkWithDeadline = runtime.sendProtectedBodyChunkWithDeadline;
const sendProtectedControlFrame = runtime.sendProtectedControlFrame;
const sendProtectedControlFrameWithDeadline = runtime.sendProtectedControlFrameWithDeadline;
const sendProtectedFrames = runtime.sendProtectedFrames;
const sendProtectedHttp3Close = runtime.sendProtectedHttp3Close;
const sendProtectedPriorityUpdate = runtime.sendProtectedPriorityUpdate;
const sendProtectedPriorityUpdateRaw = runtime.sendProtectedPriorityUpdateRaw;
const sendProtectedPriorityUpdateRawWithDeadline = runtime.sendProtectedPriorityUpdateRawWithDeadline;
const sendProtectedPush = runtime.sendProtectedPush;
const sendProtectedPushControl = runtime.sendProtectedPushControl;
const sendProtectedPushControlWithDeadline = runtime.sendProtectedPushControlWithDeadline;
const sendProtectedPushStreamingHeads = runtime.sendProtectedPushStreamingHeads;
const sendProtectedPushStreamingHeadsWithDeadline = runtime.sendProtectedPushStreamingHeadsWithDeadline;
const sendProtectedPushWithDeadline = runtime.sendProtectedPushWithDeadline;
const sendProtectedQpackFeedback = runtime.sendProtectedQpackFeedback;
const sendProtectedQpackFeedbackWithDeadline = runtime.sendProtectedQpackFeedbackWithDeadline;
const sendProtectedReaderCapacity = runtime.sendProtectedReaderCapacity;
const sendProtectedRequestCancellation = runtime.sendProtectedRequestCancellation;
const sendProtectedResponseSequence = runtime.sendProtectedResponseSequence;
const sendProtectedResponseSequenceWithDeadline = runtime.sendProtectedResponseSequenceWithDeadline;
const sendProtectedSettings = runtime.sendProtectedSettings;
const sendProtectedSettingsWithDeadline = runtime.sendProtectedSettingsWithDeadline;
const sendProtectedStreamingHead = runtime.sendProtectedStreamingHead;
const sendProtectedStreamingHeadWithDeadline = runtime.sendProtectedStreamingHeadWithDeadline;
const sendProtectedTrailers = runtime.sendProtectedTrailers;
const sendProtectedTrailersWithDeadline = runtime.sendProtectedTrailersWithDeadline;
const serverRequestReceivedAssumeCapacity = runtime.serverRequestReceivedAssumeCapacity;
const server_control_stream_id = runtime.server_control_stream_id;
const server_qpack_decoder_stream_id = runtime.server_qpack_decoder_stream_id;
const server_qpack_encoder_stream_id = runtime.server_qpack_encoder_stream_id;
const server_response = runtime.server_response;
const stream_lifecycle = runtime.stream_lifecycle;
const streamingRequestSectionAcknowledgments = runtime.streamingRequestSectionAcknowledgments;
const streamingResponseSectionAcknowledgments = runtime.streamingResponseSectionAcknowledgments;
const updateOutboundBodyFlowLimitsFromFrames = runtime.updateOutboundBodyFlowLimitsFromFrames;
const validateBlockedStreamLimit = runtime.validateBlockedStreamLimit;
const validateBodyWrite = runtime.validateBodyWrite;
const validateClientGoAwayPushId = runtime.validateClientGoAwayPushId;
const validateNewServerPush = runtime.validateNewServerPush;
const validateProtectedConfig = runtime.validateProtectedConfig;
const validateServerGoAwayStreamId = runtime.validateServerGoAwayStreamId;

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
    promised_push_ids: ServerPushIdSet = .{},
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
        var server: ProtectedServer = .{
            .quic_server = quic_server,
            .config = config,
            .control = try .init(.{
                .max_priority_updates = config.max_priority_updates,
                .max_priority_update_payload_size = config.max_priority_update_payload_size,
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
        server.streaming_requests.setMaxBodyBytes(limits.max_body_bytes);
        return server;
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.push_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.stream_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.outbound_bodies.deinit();
        self.promised_push_ids.deinit(
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
        var prepared = self.receiveStreamBytesUntil(deadline) catch |err| {
            self.failReceivedRequest(
                self.request_streams.lastErrorFrom(),
                self.request_streams.lastErrorStreamId(),
                null,
                err,
                false,
            );
            return err;
        };
        defer prepared.deinit(self.quic_server.endpoint.allocator);
        if (requestEndedBeforeHeaders(prepared.bytes)) {
            self.failReceivedRequest(
                prepared.from,
                prepared.stream_id,
                prepared.bytes,
                error.RequestIncomplete,
                true,
            );
            return error.RequestIncomplete;
        }
        var request = http3.decodeRequestWithDynamicTable(
            self.quic_server.endpoint.allocator,
            prepared.bytes,
            self.config.local_settings,
            self.qpack_decode.table,
        ) catch |err| {
            self.failReceivedRequest(
                prepared.from,
                prepared.stream_id,
                prepared.bytes,
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
        const read = entry.reader.readData(out) catch |err| {
            if (runtime_error.dataReadPeerError(err)) self.failReceivedRequest(entry.from, stream_id, null, err, false);
            return err;
        };
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
        const skipped = entry.reader.skipData() catch |err| {
            if (runtime_error.dataReadPeerError(err)) self.failReceivedRequest(from, stream_id, null, err, false);
            return err;
        };
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

    pub fn sendResponseWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithDeadline(
            to,
            stream_id,
            response,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendResponseWithInformationalAndDeadline(
            to,
            stream_id,
            &.{},
            response,
            deadline,
        );
    }

    pub fn sendResponseWithPush(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        return self.sendResponseWithPushUntil(
            to,
            request_stream_id,
            response,
            push,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Flow-control-aware aggregate push for the lightweight protected
    /// runtime. The parent and push heads are submitted first, then both
    /// response bodies advance in bounded DATA contributions.
    pub fn sendResponseWithPushPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        return self.sendResponseWithPushPacedUntil(
            to,
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
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithPushPacedAndDeadline(
            to,
            request_stream_id,
            response,
            push,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithPushPacedAndDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendResponseWithPushPacedUntil(
            to,
            request_stream_id,
            response,
            push,
            deadline,
        );
    }

    fn sendResponseWithPushPacedUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.quic_server.endpoint.io,
                absolute,
            );
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
            self.quic_server.endpoint.allocator,
            push.push_id,
        );
        const push_stream_id = self.next_push_stream_id;
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
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

        var heads_committed = false;
        var push_scoped = false;
        var parent_scoped = false;
        errdefer if (heads_committed and !push_scoped and !parent_scoped) {
            self.protected_send.failClosed();
        };
        if (deadline) |absolute| {
            try sendProtectedPushStreamingHeadsWithDeadline(
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
                &self.outbound_bodies,
                absolute,
            );
        } else {
            try sendProtectedPushStreamingHeads(
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
                &self.outbound_bodies,
            );
        }
        heads_committed = true;
        self.promised_push_ids.insertAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;

        var push_cancelled = false;
        var push_timeout: ?ReceiveTimeoutError = null;
        push_cancelled = self.sendProtectedPushBodyAndTrailersUntil(
            to,
            push_stream_id,
            prepared_push.response,
            push.push_id,
            deadline,
        ) catch |err| blk: {
            if (err == error.Timeout and self.tryResetProtectedStream(
                to,
                push_stream_id,
                http3.ApplicationErrorCode.request_cancelled,
            )) {
                push_scoped = true;
                push_timeout = err;
                break :blk true;
            }
            return err;
        };
        if (push_cancelled) push_scoped = true;
        _ = self.sendProtectedPushBodyAndTrailersUntil(
            to,
            request_stream_id,
            prepared_response.value,
            null,
            deadline,
        ) catch |err| {
            if (err == error.Timeout and self.tryResetProtectedStream(
                to,
                request_stream_id,
                http3.ApplicationErrorCode.internal_error,
            )) {
                finishServerRequest(
                    &self.control,
                    &self.request_lifecycle,
                    request_stream_id,
                );
                parent_scoped = true;
                return err;
            }
            return err;
        };
        self.control.retirePushPriority(
            self.quic_server.endpoint.allocator,
            push.push_id,
        );
        if (push_timeout) |err| return err;
        if (push_cancelled) return error.RequestCancelled;
        return push_stream_id;
    }

    fn tryResetProtectedStream(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) bool {
        const entry = self.outbound_bodies.find(stream_id) orelse return true;
        const frame = quic.Frame{ .reset_stream = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = entry.send.next_offset,
        } };
        const result = self.protected_send.trySendFrames(
            &self.quic_server.endpoint,
            to,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            &.{frame},
        ) catch return false;
        if (result.sent_count == 0 or result.send_error != null) return false;
        _ = self.outbound_bodies.finish(stream_id);
        return true;
    }

    fn sendProtectedPushBodyAndTrailersUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        push_id: ?u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!bool {
        if (self.outbound_bodies.find(stream_id) == null) {
            if (push_id == null) {
                finishServerRequest(
                    &self.control,
                    &self.request_lifecycle,
                    stream_id,
                );
            }
            return false;
        }
        if (push_id) |id| {
            return self.sendProtectedPacedPushBodyAndTrailersUntil(
                to,
                id,
                stream_id,
                response,
                deadline,
            );
        }
        if (response.body.len != 0) {
            if (deadline) |absolute| {
                var progress: BodyWriteProgress = .{};
                try self.sendResponseBodyPacedWithDeadline(
                    to,
                    stream_id,
                    response.body,
                    response.trailers.len == 0,
                    &progress,
                    absolute,
                );
            } else {
                try self.sendResponseBodyPaced(
                    to,
                    stream_id,
                    response.body,
                    response.trailers.len == 0,
                );
            }
        }
        if (response.trailers.len != 0) {
            if (deadline) |absolute| {
                try self.finishResponseTrailersPacedWithDeadline(
                    to,
                    stream_id,
                    response.trailers,
                    absolute,
                );
            } else {
                try self.finishResponseTrailersPaced(
                    to,
                    stream_id,
                    response.trailers,
                );
            }
        }
        return false;
    }

    fn sendProtectedPacedPushBodyAndTrailersUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        push_id: u64,
        push_stream_id: u62,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!bool {
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(push_stream_id, window);
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        var offset: usize = 0;
        while (offset < response.body.len) {
            const end = @min(response.body.len, offset + chunk_limit);
            while (true) {
                if (self.control.pushCancelled(push_id)) {
                    try self.finishProtectedCancelledPacedPush(
                        to,
                        push_id,
                        push_stream_id,
                        deadline,
                    );
                    return true;
                }
                if (deadline) |absolute| {
                    sendProtectedBodyChunkWithDeadline(
                        &self.quic_server.endpoint,
                        to,
                        self.config,
                        &self.next_packet_number,
                        &self.protected_send,
                        &self.outbound_bodies,
                        push_stream_id,
                        response.body[offset..end],
                        response.trailers.len == 0 and end == response.body.len,
                        absolute,
                    ) catch |err| switch (err) {
                        error.FlowControlBlocked, error.CongestionLimited => {
                            try self.receiveRequestPacketWithDeadline(absolute);
                            continue;
                        },
                        else => |other| return @errorCast(other),
                    };
                } else {
                    sendProtectedBodyChunk(
                        &self.quic_server.endpoint,
                        to,
                        self.config,
                        &self.next_packet_number,
                        &self.protected_send,
                        &self.outbound_bodies,
                        push_stream_id,
                        response.body[offset..end],
                        response.trailers.len == 0 and end == response.body.len,
                    ) catch |err| switch (err) {
                        error.FlowControlBlocked, error.CongestionLimited => {
                            _ = try self.receiveRequestPacketTimeout(100_000);
                            continue;
                        },
                        else => |other| return @errorCast(other),
                    };
                }
                break;
            }
            offset = end;
        }
        if (response.trailers.len == 0) return false;
        while (true) {
            if (self.control.pushCancelled(push_id)) {
                try self.finishProtectedCancelledPacedPush(
                    to,
                    push_id,
                    push_stream_id,
                    deadline,
                );
                return true;
            }
            if (deadline) |absolute| {
                sendProtectedTrailersWithDeadline(
                    &self.quic_server.endpoint,
                    to,
                    self.config,
                    &self.next_packet_number,
                    &self.protected_send,
                    &self.outbound_bodies,
                    push_stream_id,
                    response.trailers,
                    self.control.settings.peer,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.stream_send_scratch,
                    absolute,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        try self.receiveRequestPacketWithDeadline(absolute);
                        continue;
                    },
                    else => |other| return @errorCast(other),
                };
            } else {
                sendProtectedTrailers(
                    &self.quic_server.endpoint,
                    to,
                    self.config,
                    &self.next_packet_number,
                    &self.protected_send,
                    &self.outbound_bodies,
                    push_stream_id,
                    response.trailers,
                    self.control.settings.peer,
                    &self.qpack_encode,
                    &self.qpack_encoder_send,
                    &self.qpack_encoder_prefix_sent,
                    &self.stream_send_scratch,
                ) catch |err| switch (err) {
                    error.FlowControlBlocked, error.CongestionLimited => {
                        _ = try self.receiveRequestPacketTimeout(100_000);
                        continue;
                    },
                    else => |other| return @errorCast(other),
                };
            }
            return false;
        }
    }

    fn finishProtectedCancelledPacedPush(
        self: *ProtectedServer,
        to: net.IpAddress,
        push_id: u64,
        push_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        const entry = self.outbound_bodies.find(push_stream_id);
        const final_size = if (entry) |body| body.send.next_offset else 0;
        const frames = [_]quic.Frame{.{ .reset_stream = .{
            .stream_id = push_stream_id,
            .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            .final_size = final_size,
        } }};
        if (deadline) |absolute| {
            try self.protected_send.sendFramesWithDeadline(
                &self.quic_server.endpoint,
                to,
                self.config.send_keys,
                self.config.peer_connection_id,
                &self.next_packet_number,
                &frames,
                self.config.max_frames_per_packet,
                absolute,
            );
        } else {
            try sendProtectedFrames(
                &self.quic_server.endpoint,
                to,
                self.config.send_keys,
                self.config.peer_connection_id,
                &self.next_packet_number,
                &frames,
                self.config.max_frames_per_packet,
                &self.protected_send,
            );
        }
        _ = self.outbound_bodies.finish(push_stream_id);
        self.control.retirePushPriority(
            self.quic_server.endpoint.allocator,
            push_id,
        );
    }

    pub fn sendResponseWithPushAndTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithPushAndDeadline(
            to,
            request_stream_id,
            response,
            push,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithPushAndDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendResponseWithPushUntil(
            to,
            request_stream_id,
            response,
            push,
            deadline,
        );
    }

    fn sendResponseWithPushUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        const push_stream_id = self.next_push_stream_id;
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
            self.quic_server.endpoint.allocator,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
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
        if (deadline) |absolute| {
            try sendProtectedPushWithDeadline(
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
                absolute,
            );
        } else {
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
        }
        self.promised_push_ids.insertAssumeCapacity(push.push_id);
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
        return self.startResponseUntil(
            to,
            stream_id,
            response,
            body_length,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn startResponseWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(
            to,
            stream_id,
            response,
            body_length,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn startResponseWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.startResponseUntil(
            to,
            stream_id,
            response,
            body_length,
            deadline,
        );
    }

    fn startResponseUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
        }
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
        const qpack_checkpoint = self.qpack_encode.checkpoint();
        const streaming = try prepared.value.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.quic_server.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.rollbackAfter(qpack_checkpoint);
        if (deadline) |absolute| {
            try sendProtectedStreamingHeadWithDeadline(
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
                absolute,
            );
        } else {
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
        }
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

    pub fn sendResponseBodyPacedWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyPacedWithDeadline(
            to,
            stream_id,
            data,
            fin,
            progress,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseBodyPacedWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(stream_id, window);
        }
        try validateBodyWrite(&self.outbound_bodies, stream_id, data.len, fin);
        if (data.len == 0) {
            var committed_chunks: usize = 0;
            self.sendResponseBodyBatchPacedWithDeadline(
                to,
                &.{.{ .stream_id = stream_id, .data = data, .fin = fin }},
                &committed_chunks,
                deadline,
            ) catch |err| {
                progress.fin_committed = committed_chunks == 1 and fin;
                return err;
            };
            progress.fin_committed = fin;
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        while (progress.committed_bytes < data.len) {
            const end = @min(
                data.len,
                progress.committed_bytes + chunk_limit,
            );
            const last = end == data.len;
            var committed_chunks: usize = 0;
            self.sendResponseBodyBatchPacedWithDeadline(
                to,
                &.{.{
                    .stream_id = stream_id,
                    .data = data[progress.committed_bytes..end],
                    .fin = fin and last,
                }},
                &committed_chunks,
                deadline,
            ) catch |err| {
                if (committed_chunks == 1) {
                    progress.committed_bytes = end;
                    progress.fin_committed = fin and last;
                }
                return err;
            };
            std.debug.assert(committed_chunks == 1);
            progress.committed_bytes = end;
            progress.fin_committed = fin and last;
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

    pub fn sendResponseBodyPartsPacedWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyPartsPacedWithDeadline(
            to,
            stream_id,
            parts,
            fin,
            progress,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseBodyPartsPacedWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        const total_len = try bodyPartsLength(parts);
        try validateBodyWrite(&self.outbound_bodies, stream_id, total_len, fin);
        if (total_len == 0) {
            return self.sendResponseBodyPacedWithDeadline(
                to,
                stream_id,
                &.{},
                fin,
                progress,
                deadline,
            );
        }
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            var part_progress: BodyWriteProgress = .{};
            self.sendResponseBodyPacedWithDeadline(
                to,
                stream_id,
                part,
                fin and sent == non_empty,
                &part_progress,
                deadline,
            ) catch |err| {
                progress.committed_bytes += part_progress.committed_bytes;
                progress.fin_committed = part_progress.fin_committed;
                return err;
            };
            progress.committed_bytes += part_progress.committed_bytes;
            progress.fin_committed = part_progress.fin_committed;
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

    pub fn sendResponseBodyBatchPacedWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_chunks.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyBatchPacedWithDeadline(
            to,
            chunks,
            committed_chunks,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseBodyBatchPacedWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return sendProtectedBodyBatchPacedWithDeadline(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            chunks,
            self,
            ProtectedServer.receiveBatchProgressForSendUntil,
            ProtectedServer.finishBatchResponseStream,
            committed_chunks,
            deadline,
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
        return self.sendResponseBodiesPacedUntil(
            to,
            responses,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendResponseBodiesPacedWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        responses: []const ResponseBody,
        committed_bytes: []usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (committed_bytes.len < responses.len) return error.BufferTooShort;
        @memset(committed_bytes[0..responses.len], 0);
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodiesPacedWithDeadline(
            to,
            responses,
            committed_bytes,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Priority-schedule protected response bodies under one absolute
    /// deadline. Each count advances only for DATA accepted by the socket, so
    /// callers can retry the exact unsent suffix of every unfinished stream.
    pub fn sendResponseBodiesPacedWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        responses: []const ResponseBody,
        committed_bytes: []usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (committed_bytes.len < responses.len) return error.BufferTooShort;
        @memset(committed_bytes[0..responses.len], 0);
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendResponseBodiesPacedUntil(
            to,
            responses,
            committed_bytes,
            deadline,
        );
    }

    fn sendResponseBodiesPacedUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        responses: []const ResponseBody,
        committed_bytes: ?[]usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (responses.len == 0) return;
        const allocator = self.quic_server.endpoint.allocator;
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
            if (deadline) |absolute| {
                _ = try deadline_policy.usableAwake(
                    self.quic_server.endpoint.io,
                    absolute,
                );
            }
            const selection = self.refreshProtectedResponseCandidates(
                responses,
                candidates,
                chunk_limit,
            ) orelse {
                if (deadline) |absolute| {
                    try self.receiveBatchProgressForSendUntil(absolute);
                } else {
                    try self.receiveBatchProgressForSend();
                }
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
                if (deadline) |absolute| {
                    try self.receiveBatchProgressForSendUntil(absolute);
                } else {
                    try self.receiveBatchProgressForSend();
                }
                continue;
            }
            var sent_count: usize = 0;
            if (deadline) |absolute| {
                self.sendResponseBodyBatchPacedWithDeadline(
                    to,
                    workspace.chunks(),
                    &sent_count,
                    absolute,
                ) catch |err| {
                    if (committed_bytes) |counts| {
                        for (workspace.chunks()[0..sent_count], 0..) |chunk, batch_index| {
                            const response_index =
                                workspace.responseIndex(batch_index);
                            counts[response_index] += chunk.data.len;
                        }
                    }
                    if (sent_count != 0) {
                        _ = workspace.commitSentPrefix(sent_count);
                    }
                    return err;
                };
            } else {
                sent_count = sendProtectedBodyBatchProgress(
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
            }
            if (committed_bytes) |counts| {
                for (workspace.chunks()[0..sent_count], 0..) |chunk, batch_index| {
                    const response_index = workspace.responseIndex(batch_index);
                    counts[response_index] += chunk.data.len;
                }
            }
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

    fn receiveBatchProgressForSendUntil(
        self: *ProtectedServer,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.receiveRequestPacketWithDeadline(deadline);
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

    pub fn finishResponseTrailersPacedWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseTrailersPacedWithDeadline(
            to,
            stream_id,
            trailers,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Finish a protected streaming response with trailers under one
    /// absolute deadline. A timeout before a packet is socket-visible leaves
    /// the body and QPACK section retryable; a visible prefix follows the
    /// protected packetizer's fail-closed rule.
    pub fn finishResponseTrailersPacedWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        while (true) {
            sendProtectedTrailersWithDeadline(
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
                deadline,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacketWithDeadline(deadline);
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
    }

    pub fn sendResponseWithInformational(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        return self.sendResponseWithInformationalUntil(
            to,
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
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseWithInformationalAndDeadline(
            to,
            stream_id,
            informational,
            response,
            .fromNow(self.quic_server.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendResponseWithInformationalAndDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendResponseWithInformationalUntil(
            to,
            stream_id,
            informational,
            response,
            deadline,
        );
    }

    fn sendResponseWithInformationalUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
        }
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
        if (deadline) |absolute| {
            try sendProtectedResponseSequenceWithDeadline(
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
                absolute,
            );
        } else {
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
        }
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
    }

    pub fn sendGoAway(self: *ProtectedServer, to: net.IpAddress, stream_id: u64) Error!void {
        return self.sendGoAwayUntil(to, stream_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendGoAwayWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendGoAwayWithDeadline(to, stream_id, .fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendGoAwayWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendGoAwayUntil(to, stream_id, deadline);
    }

    fn sendGoAwayUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try validateServerGoAwayStreamId(stream_id);
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedControlFrameWithDeadline(
                &self.quic_server.endpoint,
                to,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .goaway,
                stream_id,
                absolute,
            );
        } else {
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
            try sendProtectedControlFrame(
                &self.quic_server.endpoint,
                to,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .goaway,
                stream_id,
            );
        }
    }

    pub fn sendOrigins(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
    ) Error!void {
        return self.sendOriginsUntil(to, origins, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendOriginsWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendOriginsWithDeadline(to, origins, .fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendOriginsWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendOriginsUntil(to, origins, deadline);
    }

    fn sendOriginsUntil(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
        }
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
        if (deadline) |absolute| {
            try self.protected_send.sendFramesWithDeadline(
                &self.quic_server.endpoint,
                to,
                self.config.send_keys,
                self.config.peer_connection_id,
                &self.next_packet_number,
                self.protected_send.critical_stream_frames.items,
                self.config.max_frames_per_packet,
                absolute,
            );
        } else {
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

    pub fn initiateShutdownWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.initiateShutdownWithDeadline(to, .fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn initiateShutdownWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        if (self.request_lifecycle.state() != .active) return;
        try self.sendGoAwayWithDeadline(
            to,
            @as(u64, quic.varint.max_value) & ~@as(u64, 0x3),
            deadline,
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

    pub fn completeShutdownWithTimeout(
        self: *ProtectedServer,
        to: net.IpAddress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.completeShutdownWithDeadline(to, .fromNow(
            self.quic_server.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn completeShutdownWithDeadline(
        self: *ProtectedServer,
        to: net.IpAddress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        if (self.request_lifecycle.state() != .initial_goaway) return;
        if (!self.request_streams.isEmpty() or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAwayWithDeadline(
            to,
            try self.request_lifecycle.finalGoAwayId(),
            deadline,
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
        const cancel_qpack = decoded_dynamic_section or self.qpack_decode.table.max_capacity != 0;
        // Once cancellation is chosen, retain no application/request state
        // even if the best-effort RESET/STOP or QPACK feedback cannot reach
        // the peer. A socket failure cannot make this request usable again.
        self.retireRequestState(stream_id);
        sendProtectedRequestCancellation(
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
        ) catch |err| {
            self.protected_send.failClosed();
            return err;
        };
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
        finishServerRequest(&self.control, &self.request_lifecycle, stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    fn receiveStreamBytesUntil(
        self: *ProtectedServer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PreparedRequest {
        if (try self.request_streams.prepareReady(
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
            if (try self.request_streams.prepareReady(
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
    /// Mirrors HandshakeClient's callback-scoped single receive owner.
    callback_reader_active: bool = false,

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
        var client: ProtectedClient = .{
            .quic_client = quic_client,
            .config = config,
            .control = try .init(.{
                .max_priority_updates = config.max_priority_updates,
                .max_priority_update_payload_size = config.max_priority_update_payload_size,
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
        client.streaming_responses.setMaxBodyBytes(limits.max_body_bytes);
        client.push_streams.setMaxBodyBytes(limits.max_body_bytes);
        return client;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        const stream_id = try self.sendRequestWithDeadline(
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
        self: *ProtectedClient,
        request_options: http3.Request,
    ) Error!u62 {
        return self.sendRequestUntil(request_options, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendRequestWithTimeout(
        self: *ProtectedClient,
        request_options: http3.Request,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestWithDeadline(request_options, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendRequestWithDeadline(
        self: *ProtectedClient,
        request_options: http3.Request,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendRequestUntil(request_options, deadline);
    }

    fn sendRequestUntil(
        self: *ProtectedClient,
        request_options: http3.Request,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (!self.protected_send.isUsable()) return error.ConnectionUnusable;
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        const qpack_checkpoint = self.qpack_encode.checkpoint();
        var message_sent = false;
        errdefer {
            if (!message_sent) self.qpack_encode.rollbackAfter(qpack_checkpoint);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            if (!self.protected_send.isUsable()) {
                self.next_stream_id = next_stream_id;
                self.request_lifecycle.markAllocated(stream_id);
            }
        }
        try prepareConnectionMessage(
            self.quic_client.endpoint.allocator,
            &self.stream_send_scratch,
            stream_id,
            request_options,
            self.config,
            self.control.settings.peer,
            &self.qpack_encode,
        );

        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
        }
        try sendPreparedProtectedMessageUntil(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.stream_send_scratch,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            deadline,
        );
        message_sent = true;
        self.next_stream_id = next_stream_id;
        self.request_lifecycle.markAllocated(stream_id);
        return stream_id;
    }

    pub fn startRequest(
        self: *ProtectedClient,
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
        self: *ProtectedClient,
        request_options: http3.Request,
        body_length: ?usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startRequestWithDeadline(
            request_options,
            body_length,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn startRequestWithDeadline(
        self: *ProtectedClient,
        request_options: http3.Request,
        body_length: ?usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.startRequestUntil(
            request_options,
            body_length,
            deadline,
        );
    }

    fn startRequestUntil(
        self: *ProtectedClient,
        request_options: http3.Request,
        body_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (!self.protected_send.isUsable()) return error.ConnectionUnusable;
        const stream_id = self.next_stream_id;
        const next_stream_id = std.math.add(u62, stream_id, 4) catch
            return error.StreamCreationError;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        const qpack_checkpoint = self.qpack_encode.checkpoint();
        var head_sent = false;
        errdefer {
            if (!head_sent) self.qpack_encode.rollbackAfter(qpack_checkpoint);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            _ = self.outbound_bodies.finish(stream_id);
            if (!self.protected_send.isUsable()) {
                self.next_stream_id = next_stream_id;
                self.request_lifecycle.markAllocated(stream_id);
            }
        }
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.quic_client.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
        } else {
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
        }
        if (deadline) |absolute| {
            try sendProtectedStreamingHeadWithDeadline(
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
                absolute,
            );
        } else {
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
        }
        head_sent = true;
        self.next_stream_id = next_stream_id;
        self.request_lifecycle.markAllocated(stream_id);
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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

    pub fn sendRequestBodyPacedWithTimeout(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyPacedWithDeadline(
            stream_id,
            data,
            fin,
            progress,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendRequestBodyPacedWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try validateBodyWrite(&self.outbound_bodies, stream_id, data.len, fin);
        if (data.len == 0) {
            var committed_chunks: usize = 0;
            self.sendRequestBodyBatchPacedWithDeadline(
                &.{.{ .stream_id = stream_id, .data = data, .fin = fin }},
                &committed_chunks,
                deadline,
            ) catch |err| {
                progress.fin_committed = committed_chunks == 1 and fin;
                return err;
            };
            progress.fin_committed = fin;
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        while (progress.committed_bytes < data.len) {
            const end = @min(
                data.len,
                progress.committed_bytes + chunk_limit,
            );
            const last = end == data.len;
            var committed_chunks: usize = 0;
            self.sendRequestBodyBatchPacedWithDeadline(
                &.{.{
                    .stream_id = stream_id,
                    .data = data[progress.committed_bytes..end],
                    .fin = fin and last,
                }},
                &committed_chunks,
                deadline,
            ) catch |err| {
                if (committed_chunks == 1) {
                    progress.committed_bytes = end;
                    progress.fin_committed = fin and last;
                }
                return err;
            };
            std.debug.assert(committed_chunks == 1);
            progress.committed_bytes = end;
            progress.fin_committed = fin and last;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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

    pub fn sendRequestBodyPartsPacedWithTimeout(
        self: *ProtectedClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            parts,
            fin,
            progress,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendRequestBodyPartsPacedWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        const total_len = try bodyPartsLength(parts);
        try validateBodyWrite(&self.outbound_bodies, stream_id, total_len, fin);
        if (total_len == 0) {
            return self.sendRequestBodyPacedWithDeadline(
                stream_id,
                &.{},
                fin,
                progress,
                deadline,
            );
        }
        var non_empty: usize = 0;
        for (parts) |part| non_empty += @intFromBool(part.len != 0);
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            sent += 1;
            var part_progress: BodyWriteProgress = .{};
            self.sendRequestBodyPacedWithDeadline(
                stream_id,
                part,
                fin and sent == non_empty,
                &part_progress,
                deadline,
            ) catch |err| {
                progress.committed_bytes += part_progress.committed_bytes;
                progress.fin_committed = part_progress.fin_committed;
                return err;
            };
            progress.committed_bytes += part_progress.committed_bytes;
            progress.fin_committed = part_progress.fin_committed;
        }
    }

    /// Batch one DATA contribution per active request stream. The shared
    /// destination allows packet protection and the UDP send to be amortized
    /// while preserving stream state for any unsent suffix.
    pub fn sendRequestBodyBatchPaced(
        self: *ProtectedClient,
        chunks: []const BodyChunk,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
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

    pub fn sendRequestBodyBatchPacedWithTimeout(
        self: *ProtectedClient,
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
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendRequestBodyBatchPacedWithDeadline(
        self: *ProtectedClient,
        chunks: []const BodyChunk,
        committed_chunks: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        committed_chunks.* = 0;
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        return sendProtectedBodyBatchPacedWithDeadline(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            chunks,
            self,
            ProtectedClient.receiveBatchProgressForSendUntil,
            ProtectedClient.finishBatchRequestStream,
            committed_chunks,
            deadline,
        );
    }

    fn receiveBatchProgressForSend(self: *ProtectedClient) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.receiveResponsePacket();
    }

    fn receiveBatchProgressForSendUntil(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        try self.receiveResponsePacketWithDeadline(deadline);
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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

    pub fn finishRequestTrailersPacedWithTimeout(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestTrailersPacedWithDeadline(
            stream_id,
            trailers,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn finishRequestTrailersPacedWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        while (true) {
            sendProtectedTrailersWithDeadline(
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
                deadline,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponsePacketWithDeadline(deadline);
                    continue;
                },
                else => |other| return other,
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
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        var prepared = self.receiveStreamBytesUntil(
            stream_id,
            deadline,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.sendQpackFeedback() catch {};
                return err;
            },
            else => {
                self.failReceivedResponse(null, stream_id, null, err, false);
                return err;
            },
        };
        defer prepared.deinit(self.quic_client.endpoint.allocator);
        if (prepared.bytes.len == 0) {
            self.failReceivedResponse(
                prepared.from,
                stream_id,
                prepared.bytes,
                error.MissingStatus,
                true,
            );
            return error.MissingStatus;
        }
        http3.validateResponsePushPromises(
            self.control,
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                prepared.from,
                stream_id,
                prepared.bytes,
                err,
                true,
            );
            return err;
        };
        const section_count = responseFieldSectionCount(
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                prepared.from,
                stream_id,
                prepared.bytes,
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
            prepared.stream_id,
            prepared.bytes,
        ) catch |err| {
            self.failReceivedResponse(
                prepared.from,
                stream_id,
                prepared.bytes,
                err,
                true,
            );
            return err;
        };
        var guarded_informational: ?InformationalCallbackGuard =
            if (informational) |observer| .{
                .observer = observer,
                .callback_reader_active = &self.callback_reader_active,
            } else null;
        var response = http3.decodeResponseWithDynamicTableAndOptions(
            self.quic_client.endpoint.allocator,
            prepared.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.config.max_informational_responses;
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
                prepared.from,
                stream_id,
                prepared.bytes,
                err,
                true,
            );
            return err;
        };
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        self.qpack_decode.acknowledgeSectionsAssumeCapacity(
            prepared.stream_id,
            response.qpack_section_acknowledgments,
        );
        const assembled = self.response_streams.commitPreparedReady(
            &prepared,
        );
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        const read = entry.reader.readData(out) catch |err| {
            if (runtime_error.dataReadPeerError(err)) self.failReceivedResponse(entry.from, stream_id, null, err, false);
            return err;
        };
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        const skipped = entry.reader.skipData() catch |err| {
            if (runtime_error.dataReadPeerError(err)) self.failReceivedResponse(from, stream_id, null, err, false);
            return err;
        };
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
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.receivePushEventMatching(null);
    }

    /// Return one promised-response event already buffered locally without
    /// reading UDP. Aggregate push state remains exclusive with this API.
    pub fn pollPushEvent(
        self: *ProtectedClient,
    ) Error!?StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.push_aggregate.active()) return error.UnexpectedStream;
        return self.pollPushEventMatching(null);
    }

    pub fn receivePushEventWithTimeout(
        self: *ProtectedClient,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamingPushEvent {
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
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
            push_read_failure.protected(self, stream_id, from, err);
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
        return self.applyPendingPushCancellationsUntil(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    fn applyPendingPushCancellationsWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.applyPendingPushCancellationsUntil(deadline);
    }

    fn applyPendingPushCancellationsUntil(
        self: *ProtectedClient,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        while (self.push_streams.firstCancelledStream()) |stream_id| {
            const cancel_qpack =
                self.control.settings.local.qpack_max_table_capacity != 0;
            if (cancel_qpack) try self.qpack_decode.prepareStreamCancellation();
            const frames = [_]quic.Frame{.{ .stop_sending = .{
                .stream_id = stream_id,
                .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            } }};
            if (deadline) |absolute| {
                try self.protected_send.sendFramesWithDeadline(
                    &self.quic_client.endpoint,
                    self.quic_client.peer,
                    self.config.send_keys,
                    self.config.peer_connection_id,
                    &self.next_packet_number,
                    &frames,
                    self.config.max_frames_per_packet,
                    absolute,
                );
            } else {
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
        self: *ProtectedClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        const reader = if (entry.reader) |*value| value else return error.UnexpectedStream;
        const stream_id = reader.streamId();
        const from = entry.from;
        return reader.readData(out) catch |err| {
            if (runtime_error.dataReadPeerError(err)) {
                push_read_failure.protected(self, stream_id, from, err);
            }
            return err;
        };
    }

    /// Discard currently available push DATA and return its receive-window
    /// credit without allocating caller storage.
    pub fn skipPushData(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        const reader = if (entry.reader) |*value| value else return error.UnexpectedStream;
        const stream_id = reader.streamId();
        const from = entry.from orelse self.quic_client.peer;
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            from,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            reader,
        );
        const skipped = reader.skipData() catch |err| {
            if (runtime_error.dataReadPeerError(err)) {
                push_read_failure.protected(self, stream_id, from, err);
            }
            return err;
        };
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
        if (self.callback_reader_active) return error.ConcurrentRead;
        var guarded_informational: ?PushInformationalCallbackGuard =
            if (informational) |observer| .{
                .observer = observer,
                .callback_reader_active = &self.callback_reader_active,
            } else null;
        return push_aggregate.receive(
            self,
            &self.push_aggregate,
            self.quic_client.endpoint.allocator,
            if (guarded_informational) |*guard| .{
                .context = guard,
                .on_response = PushInformationalCallbackGuard.notify,
            } else null,
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
        return self.sendGoAwayUntil(stream_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendGoAwayWithTimeout(
        self: *ProtectedClient,
        stream_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendGoAwayWithDeadline(stream_id, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendGoAwayWithDeadline(
        self: *ProtectedClient,
        stream_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendGoAwayUntil(stream_id, deadline);
    }

    fn sendGoAwayUntil(
        self: *ProtectedClient,
        stream_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try validateClientGoAwayPushId(stream_id);
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedControlFrameWithDeadline(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .goaway,
                stream_id,
                absolute,
            );
        } else {
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
            try sendProtectedControlFrame(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .goaway,
                stream_id,
            );
        }
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        return self.sendMaxPushIdUntil(push_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendMaxPushIdWithTimeout(
        self: *ProtectedClient,
        push_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendMaxPushIdWithDeadline(push_id, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendMaxPushIdWithDeadline(
        self: *ProtectedClient,
        push_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendMaxPushIdUntil(push_id, deadline);
    }

    fn sendMaxPushIdUntil(
        self: *ProtectedClient,
        push_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.push_streams.reservePromisesThrough(push_id);
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedPushControlWithDeadline(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .max_push_id,
                push_id,
                absolute,
            );
        } else {
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
                .max_push_id,
                push_id,
            );
        }
    }

    pub fn cancelPush(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!void {
        return self.cancelPushUntil(push_id, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn cancelPushWithTimeout(
        self: *ProtectedClient,
        push_id: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelPushWithDeadline(push_id, .fromNow(
            self.quic_client.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn cancelPushWithDeadline(
        self: *ProtectedClient,
        push_id: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.cancelPushUntil(push_id, deadline);
    }

    fn cancelPushUntil(
        self: *ProtectedClient,
        push_id: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
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
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedPushControlWithDeadline(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                .cancel_push,
                push_id,
                absolute,
            );
        } else {
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
        }
        if (push_stream_id) |stream_id| {
            self.qpack_decode.discardPeerUniStream(stream_id);
        }
        self.push_streams.observePeerCancellation(push_id) catch unreachable;
        defer if (self.push_aggregate.push_id == push_id) {
            self.push_aggregate.deinit(self.quic_client.endpoint.allocator);
        };
        if (deadline) |absolute| {
            try self.applyPendingPushCancellationsWithDeadline(absolute);
        } else {
            try self.applyPendingPushCancellations();
        }
        if (deadline) |absolute| {
            try self.sendQpackFeedbackWithDeadline(absolute);
        } else {
            try self.sendQpackFeedback();
        }
    }

    pub fn cancelRequest(
        self: *ProtectedClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        const cancel_qpack = decoded_dynamic_section or self.qpack_decode.table.max_capacity != 0;
        defer {
            self.response_streams.remove(stream_id);
            self.streaming_responses.remove(stream_id);
            _ = self.request_lifecycle.finish(stream_id) catch false;
            _ = self.outbound_bodies.finish(stream_id);
        }
        sendProtectedRequestCancellation(
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
        ) catch |err| {
            self.protected_send.failClosed();
            return err;
        };
    }

    pub fn sendPriorityUpdate(
        self: *ProtectedClient,
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
        self: *ProtectedClient,
        stream_id: u62,
        priority: http3.Priority,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPriorityUpdateWithDeadline(
            stream_id,
            priority,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPriorityUpdateWithDeadline(
        self: *ProtectedClient,
        stream_id: u62,
        priority: http3.Priority,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendPriorityUpdateUntil(stream_id, priority, deadline);
    }

    fn sendPriorityUpdateUntil(
        self: *ProtectedClient,
        stream_id: u62,
        priority: http3.Priority,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedPriorityUpdateRawWithDeadline(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                http3.FrameType.priority_update_request,
                stream_id,
                priority,
                absolute,
            );
        } else {
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
    }

    pub fn sendPushPriorityUpdate(
        self: *ProtectedClient,
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
        self: *ProtectedClient,
        push_id: u64,
        priority: http3.Priority,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPushPriorityUpdateWithDeadline(
            push_id,
            priority,
            .fromNow(self.quic_client.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPushPriorityUpdateWithDeadline(
        self: *ProtectedClient,
        push_id: u64,
        priority: http3.Priority,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendPushPriorityUpdateUntil(
            push_id,
            priority,
            deadline,
        );
    }

    fn sendPushPriorityUpdateUntil(
        self: *ProtectedClient,
        push_id: u64,
        priority: http3.Priority,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (!self.push_streams.hasPromise(push_id)) {
            return error.UnexpectedStream;
        }
        if (deadline) |absolute| {
            try sendProtectedSettingsWithDeadline(
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
                absolute,
            );
            try sendProtectedPriorityUpdateRawWithDeadline(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config,
                &self.control_send,
                &self.next_packet_number,
                &self.protected_send,
                http3.FrameType.priority_update_push,
                push_id,
                priority,
                absolute,
            );
        } else {
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
    }

    fn receiveStreamBytesUntil(
        self: *ProtectedClient,
        expected_stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!PreparedResponse {
        if (self.callback_reader_active) return error.ConcurrentRead;
        if (self.response_streams.takeReset(expected_stream_id)) |code| {
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        if (try self.response_streams.prepareReady(
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
            if (try self.response_streams.prepareReady(
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (deadline) |absolute| {
            try self.applyPendingPushCancellationsWithDeadline(absolute);
        } else {
            try self.applyPendingPushCancellations();
        }
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

    fn sendQpackFeedbackWithDeadline(
        self: *ProtectedClient,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try sendProtectedQpackFeedbackWithDeadline(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            deadline,
        );
    }
};
