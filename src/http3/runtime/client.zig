//! HTTP/3 client request/response streams over a QUIC connection.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const Error = runtime.Error;
const Limits = runtime.Limits;
const Response = http3.Response;
const Qpack = http3.Qpack;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const StreamingEvent = runtime.StreamingEvent;
const http_method = @import("../../internal/http_method.zig");
const body_batch = @import("body_batch.zig");
const body_sender = @import("send/body.zig");
const body_fragment = @import("send/body_fragment.zig");
const receive_policy = @import("receive/policy.zig");
const buffered_response = @import("stream/buffered/response.zig");
const outbound_body = @import("stream/outbound_body.zig");
const streaming_set = @import("stream/set.zig");
const StreamingResponseSet = streaming_set.Set;
const EarlyConnectDatagramLimits = runtime.EarlyConnectDatagramLimits;
const requestHasProtocol = runtime.requestHasProtocol;
const client_control_stream_id = runtime.client_control_stream_id;
const development_streams = @import("development/streams.zig");
const DevelopmentStreamSet = development_streams.ReceiveSet;
const DevelopmentStreamSendSet = development_streams.SendSet;
const stream_lifecycle = @import("stream/lifecycle.zig");
const ClientRequestLifecycle = stream_lifecycle.Client;
const QpackDecodeState = runtime.QpackDecodeState;
const QpackEncodeState = runtime.QpackEncodeState;
const send_scratch = @import("send/scratch.zig");
const StreamMessageSendScratch = send_scratch.Message;
const CriticalStreamSendScratch = send_scratch.Critical;
const deadline_policy = @import("../../internal/deadline.zig");
const development_send = @import("development/send.zig");
const sendRuntimeBodyChunk = development_send.bodyChunk;
const sendRuntimeBodyChunkWithDeadline = development_send.bodyChunkWithDeadline;
const sendRuntimeStreamingHead = development_send.streamingHead;
const appendRuntimeStreamMessageFrames = development_send.appendStreamMessageFrames;
const sendRuntimeRequestCancellation = development_send.requestCancellation;
const send_packetizer = @import("send/packetizer.zig");
const runtime_error = @import("error.zig");
const messageStreamDisposition = runtime.messageStreamDisposition;
const applyResponseReaderSemantics = runtime.applyResponseReaderSemantics;
const development_receive = @import("development/receive.zig");
const receiveRuntimeStreamBytesUntil = development_receive.streamBytesUntil;
const development_data_error = @import("development/data_error.zig");
const retainDevelopmentDatagramFrames = development_send.retainDatagramFrames;
const InformationalCallbackGuard = runtime.InformationalCallbackGuard;
const development_settings = runtime.development_settings;
const DevelopmentStream = runtime.DevelopmentStream;
const DevelopmentStreamDirection = runtime.DevelopmentStreamDirection;
const DevelopmentStreamMatch = runtime.DevelopmentStreamMatch;
const DevelopmentStreamDebugCounts = runtime.DevelopmentStreamDebugCounts;
const OwnedResponse = runtime.OwnedResponse;
const client_qpack_decoder_stream_id = runtime.client_qpack_decoder_stream_id;
const client_qpack_encoder_stream_id = runtime.client_qpack_encoder_stream_id;
const ResponseStreamSet = buffered_response.Set;
const OutboundBodySet = outbound_body.Set;
const development_datagram_queue = @import("development/datagram_queue.zig");
const client_uri = @import("client/uri.zig");
const handshakeRecoveryBefore = client_uri.handshakeRecoveryBefore;
const HandshakeClient = runtime.HandshakeClient;
const HandshakeClientOptions = runtime.HandshakeClientOptions;
const HandshakeServerSession = runtime.HandshakeServerSession;
const OwnedHandshakeResponse = runtime.OwnedHandshakeResponse;

pub const Client = struct {
    quic_client: quic.runtime.Client,
    limits: Limits = .{},
    next_stream_id: u62 = 0,
    response_receive_mutex: std.Io.Mutex = .init,
    /// Aggregate 1xx callbacks run while this client owns its receive mutex.
    /// Reject same-client recursive reads before they can self-deadlock.
    callback_reader_active: bool = false,
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
        var client: Client = .{
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
        client.streaming_responses.setMaxBodyBytes(limits.max_body_bytes);
        return client;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        var guarded_informational: ?InformationalCallbackGuard =
            if (informational) |observer| .{
                .observer = observer,
                .callback_reader_active = &self.callback_reader_active,
            } else null;
        var response = try http3.decodeResponseWithOptions(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            .{
                .max_informational_responses = self.limits.max_informational_responses,
                .informational = if (guarded_informational) |*guard| .{
                    .context = guard,
                    .on_response = InformationalCallbackGuard.notify,
                } else null,
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
        const qpack_checkpoint = self.qpack_encode.checkpoint();
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
                self.qpack_encode.rollbackAfter(qpack_checkpoint);
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

    pub fn sendRequestBodyWithTimeout(
        self: *Client,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendRequestBodyWithDeadline(
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

    /// Deadline-bounded development request DATA with fail-close semantics
    /// after the first UDP submission attempt. Zero-progress timeout leaves
    /// the body offset and request direction retryable.
    pub fn sendRequestBodyWithDeadline(
        self: *Client,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        if (self.request_unusable) return error.ConnectionUnusable;
        const entry = self.outbound_bodies.find(stream_id) orelse
            return error.UnexpectedStream;
        if (entry.send.fin_sent) return error.UnexpectedStream;
        var send_attempted = false;
        sendRuntimeBodyChunkWithDeadline(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.limits.max_stream_frame_data,
            &send_attempted,
            deadline,
        ) catch |err| {
            progress.send_attempted = send_attempted;
            if (send_attempted) self.request_unusable = true;
            return err;
        };
        progress.send_attempted = send_attempted;
        progress.completed = true;
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
        return self.sendDevelopmentStreamUntil(
            session_id,
            stream_id,
            data,
            fin,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendDevelopmentStreamWithTimeout(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDevelopmentStreamWithDeadline(
            session_id,
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

    pub fn sendDevelopmentStreamWithDeadline(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        return self.sendDevelopmentStreamUntil(
            session_id,
            stream_id,
            data,
            fin,
            progress,
            deadline,
        );
    }

    fn sendDevelopmentStreamUntil(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: ?*DevelopmentBodyWriteProgress,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (self.request_unusable) return error.ConnectionUnusable;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.quic_client.endpoint.io,
                absolute,
            );
        }
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
        send_packetizer.sendEndpointUntil(
            self.quic_client.endpoint.allocator,
            &self.quic_client.endpoint,
            self.quic_client.peer,
            frames.items,
            1,
            &send_attempted,
            deadline,
        ) catch |err| {
            if (progress) |value| value.send_attempted = send_attempted;
            if (send_attempted) entry.unusable = true;
            return err;
        };
        if (progress) |value| value.* = .{
            .send_attempted = send_attempted,
            .completed = true,
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
        return self.sendDevelopmentStreamPartsUntil(
            session_id,
            stream_id,
            prefix,
            payload,
            fin,
            send_attempted,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendDevelopmentStreamPartsWithDeadline(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_client.endpoint.io,
            deadline,
        );
        var send_attempted = false;
        self.sendDevelopmentStreamPartsUntil(
            session_id,
            stream_id,
            prefix,
            payload,
            fin,
            &send_attempted,
            deadline,
        ) catch |err| {
            progress.send_attempted = send_attempted;
            return err;
        };
        progress.* = .{
            .send_attempted = send_attempted,
            .completed = true,
        };
    }

    fn sendDevelopmentStreamPartsUntil(
        self: *Client,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        send_attempted: *bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.quic_client.endpoint.io,
                absolute,
            );
        }
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
        send_packetizer.sendEndpointUntil(
            self.quic_client.endpoint.allocator,
            &self.quic_client.endpoint,
            self.quic_client.peer,
            frames.items,
            1,
            send_attempted,
            deadline,
        ) catch |err| {
            if (send_attempted.*) entry.unusable = true;
            return err;
        };
    }

    pub fn pollDevelopmentStream(
        self: *Client,
        match: DevelopmentStreamMatch,
    ) Error!?DevelopmentStream {
        if (self.callback_reader_active) return error.ConcurrentRead;
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        if (self.request_unusable) return error.ConnectionUnusable;
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
        if (self.callback_reader_active) {
            self.development_streams.removeMatching(
                self.quic_client.peer,
                match,
            );
            self.development_stream_sends.removeSession(match.session_id);
            return;
        }
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
        if (self.callback_reader_active) {
            self.development_streams.clear();
            self.development_stream_sends.clear();
            return;
        }
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.request_unusable) return error.ConnectionUnusable;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.request_unusable) return error.ConnectionUnusable;
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try self.request_lifecycle.prepareFinish();
        if (self.response_streams.takeReset(stream_id)) |code| {
            _ = try self.request_lifecycle.finish(stream_id);
            _ = self.outbound_bodies.finish(stream_id);
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
        const event = (entry.reader.next(self.qpack_decode.table) catch |err| {
            self.handleDevelopmentDataError(stream_id, err);
            return err;
        }) orelse
            return null;
        if (event == .finished) {
            _ = self.request_lifecycle.finishAssumeCapacity(stream_id);
            _ = self.outbound_bodies.finish(stream_id);
            self.streaming_responses.remove(stream_id);
        }
        return event;
    }

    /// Return one retained raw QUIC datagram without reading UDP.
    pub fn pollDatagram(self: *Client) ?quic.runtime.OwnedDatagram {
        if (self.callback_reader_active or
            !self.response_receive_mutex.tryLock()) return null;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
        if (self.request_unusable) return error.ConnectionUnusable;
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
        if (self.callback_reader_active) return error.ConcurrentRead;
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        if (self.request_unusable) return error.ConnectionUnusable;
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.readData(out) catch |err| {
            self.handleDevelopmentDataError(stream_id, err);
            return err;
        };
    }

    pub fn skipResponseData(self: *Client, stream_id: u62) Error!usize {
        if (self.callback_reader_active) return error.ConcurrentRead;
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        if (self.request_unusable) return error.ConnectionUnusable;
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.skipData() catch |err| {
            self.handleDevelopmentDataError(stream_id, err);
            return err;
        };
    }

    fn handleDevelopmentDataError(
        self: *Client,
        stream_id: u62,
        err: anyerror,
    ) void {
        if (!runtime_error.dataReadPeerError(err)) return;
        if (err == error.InvalidContentLength) {
            self.cancelRequestUnlocked(
                stream_id,
                http3.ApplicationErrorCode.message_error,
            ) catch {};
            return;
        }
        development_data_error.clearClient(self);
        development_data_error.close(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            err,
        );
    }

    pub fn cancelRequest(
        self: *Client,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.callback_reader_active) return error.ConcurrentRead;
        self.response_receive_mutex.lockUncancelable(
            self.quic_client.endpoint.io,
        );
        defer self.response_receive_mutex.unlock(
            self.quic_client.endpoint.io,
        );
        return self.cancelRequestUnlocked(stream_id, application_error_code);
    }

    fn cancelRequestUnlocked(
        self: *Client,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        const body = self.outbound_bodies.find(stream_id);
        if (body == null and !self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        const local_final_size = if (body) |entry| entry.send.next_offset else 0;
        const send_reset = if (body) |entry| !entry.send.fin_sent else false;
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
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
        if (self.callback_reader_active) return error.ConcurrentRead;
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
                else => |other| return other,
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
    /// Maximum peer PRIORITY_UPDATE payload bytes retained per entry.
    max_priority_update_payload_size: usize =
        http3.default_max_priority_update_payload_size,
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
    /// Cumulative request-body budget for streaming request readers.
    max_body_bytes: usize = 16 * 1024 * 1024,
    /// Maximum absolute 1-RTT CRYPTO offset retained while opportunistically
    /// reassembling post-handshake NewSessionTicket messages.
    max_post_handshake_crypto_bytes: usize = 256 * 1024,
    max_concurrent_request_streams: usize = 128,
    /// Maximum independent UDP datagrams retained by one zio/std.Io receive
    /// turn. One disables batching without changing the receive state machine.
    max_receive_batch_datagrams: usize =
        receive_policy.max_raw_datagram_batch,
    /// Per-CONNECT receive queue bound for unreliable HTTP Datagrams.
    max_queued_connect_datagrams: usize = 16,
    /// Per-CONNECT byte bound shared by its queued application payloads.
    max_queued_connect_datagram_bytes: usize = 64 * 1024,
    /// Opt-in connection-wide retention before CONNECT registration. The
    /// default drops unknown associations; WebTransport enables this policy.
    early_connect_datagrams: EarlyConnectDatagramLimits = .{},
    max_stream_frame_data: usize = 1200,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    /// Add a current IMF-fixdate `date` field to final server responses that
    /// do not already contain one. Informational responses are unchanged.
    auto_date_header: bool = true,
    /// Maximum distinct RFC 9218 request/push priorities retained for this
    /// connection. Replacements do not consume another slot.
    max_priority_updates: usize = http3.default_max_priority_updates,
    /// Maximum peer PRIORITY_UPDATE payload bytes retained per entry.
    max_priority_update_payload_size: usize =
        http3.default_max_priority_update_payload_size,
    /// Maximum HTTP/3 DATA bytes one paced helper attempt may hand to QUIC.
    ///
    /// Zero selects the direction-aware default: 5,000 bytes for client
    /// request bodies and 8,000 bytes for server response and push bodies.
    /// Congestion, flow-control, STREAM-frame, and actual datagram limits still
    /// cap every packet. A non-zero value overrides the role-specific default.
    paced_body_chunk_bytes: usize = 0,
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

/// One complete HTTP/3 request prepared for a QUIC 0-RTT ClientOffer.
///
/// The field section intentionally uses literal/static QPACK only: dynamic
/// table state is connection-local and does not exist before the new HTTP/3
/// session is constructed. The encoded bytes and frame slice are owned by
/// this value and must outlive the QUIC handshake that borrows `offer.frames`.
pub const EarlyRequestReplayPolicy = enum {
    /// RFC 8470 default: only methods with registered safe semantics may be
    /// sent before handshake authentication completes.
    safe_methods_only,
    /// The application explicitly accepts replay risk for this exact request.
    allow_unsafe_replay,
};

pub const PreparedEarlyRequestOptions = struct {
    replay_policy: EarlyRequestReplayPolicy = .safe_methods_only,
};

pub const PreparedEarlyRequest = struct {
    allocator: std.mem.Allocator,
    stream_id: u62,
    method: []u8,
    extended_connect: bool,
    local_settings: http3.Settings,
    remembered_peer_settings: http3.Settings,
    control_bytes: []u8,
    encoder_prefix: []u8,
    decoder_prefix: []u8,
    request_bytes: []u8,
    frames: [4]quic.Frame,

    pub fn init(
        allocator: std.mem.Allocator,
        request: http3.Request,
        local_settings: http3.Settings,
        remembered_peer_settings: http3.Settings,
    ) Error!PreparedEarlyRequest {
        return initWithOptions(
            allocator,
            request,
            local_settings,
            remembered_peer_settings,
            .{},
        );
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        request: http3.Request,
        local_settings: http3.Settings,
        remembered_peer_settings: http3.Settings,
        options: PreparedEarlyRequestOptions,
    ) Error!PreparedEarlyRequest {
        if (options.replay_policy == .safe_methods_only and
            !http_method.isSafe(request.method))
        {
            return error.UnsafeEarlyDataMethod;
        }
        const stream_id: u62 = 0;
        var control_bytes: std.ArrayList(u8) = .empty;
        defer control_bytes.deinit(allocator);
        try http3.writeControlStreamPrefix(&control_bytes, allocator);
        try http3.writeSettingsFrame(
            &control_bytes,
            allocator,
            local_settings,
        );
        var encoder_prefix: std.ArrayList(u8) = .empty;
        defer encoder_prefix.deinit(allocator);
        try http3.writeQpackEncoderStreamPrefix(&encoder_prefix, allocator);
        var decoder_prefix: std.ArrayList(u8) = .empty;
        defer decoder_prefix.deinit(allocator);
        try http3.writeQpackDecoderStreamPrefix(&decoder_prefix, allocator);
        var request_bytes: std.ArrayList(u8) = .empty;
        defer request_bytes.deinit(allocator);
        try request.writeWithSettings(
            &request_bytes,
            allocator,
            remembered_peer_settings,
        );
        const owned_control = try control_bytes.toOwnedSlice(allocator);
        errdefer allocator.free(owned_control);
        const owned_encoder = try encoder_prefix.toOwnedSlice(allocator);
        errdefer allocator.free(owned_encoder);
        const owned_decoder = try decoder_prefix.toOwnedSlice(allocator);
        errdefer allocator.free(owned_decoder);
        const owned_request = try request_bytes.toOwnedSlice(allocator);
        errdefer allocator.free(owned_request);
        const method = try allocator.dupe(u8, request.method);
        errdefer allocator.free(method);
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .method = method,
            .extended_connect = requestHasProtocol(request.headers),
            .local_settings = local_settings,
            .remembered_peer_settings = remembered_peer_settings,
            .control_bytes = owned_control,
            .encoder_prefix = owned_encoder,
            .decoder_prefix = owned_decoder,
            .request_bytes = owned_request,
            .frames = .{
                .{ .stream = .{
                    .stream_id = client_control_stream_id,
                    .data = owned_control,
                } },
                .{ .stream = .{
                    .stream_id = client_qpack_encoder_stream_id,
                    .data = owned_encoder,
                } },
                .{ .stream = .{
                    .stream_id = client_qpack_decoder_stream_id,
                    .data = owned_decoder,
                } },
                .{ .stream = .{
                    .stream_id = stream_id,
                    .data = owned_request,
                    .fin = true,
                } },
            },
        };
    }

    pub fn deinit(self: *PreparedEarlyRequest) void {
        self.allocator.free(self.method);
        self.allocator.free(self.request_bytes);
        self.allocator.free(self.decoder_prefix);
        self.allocator.free(self.encoder_prefix);
        self.allocator.free(self.control_bytes);
        self.* = undefined;
    }

    pub fn offer(
        self: *const PreparedEarlyRequest,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
    ) quic.zero_rtt.handshake.ClientOffer {
        return .{
            .cache = cache,
            .lease = lease,
            .frames = &self.frames,
        };
    }

    pub fn validateTransportLimits(
        self: PreparedEarlyRequest,
        limits: Limits,
        options: HandshakeClientOptions,
        lease: *const quic.resumption.EarlyDataLease,
    ) Error!void {
        const remembered = lease.session.transport_parameters;
        if (remembered.initial_max_streams_bidi < 1 or
            remembered.initial_max_streams_uni < 3)
        {
            return error.StreamLimitExceeded;
        }
        const request_len = std.math.cast(
            u64,
            self.request_bytes.len,
        ) orelse return error.InvalidStreamRange;
        if (request_len > remembered.initial_max_stream_data_bidi_remote) {
            return error.FlowControlBlocked;
        }
        const uni_limit = remembered.initial_max_stream_data_uni;
        if (self.control_bytes.len > uni_limit or
            self.encoder_prefix.len > uni_limit or
            self.decoder_prefix.len > uni_limit)
        {
            return error.FlowControlBlocked;
        }
        var stream_bytes = request_len;
        stream_bytes = std.math.add(
            u64,
            stream_bytes,
            self.control_bytes.len,
        ) catch return error.InvalidStreamRange;
        stream_bytes = std.math.add(
            u64,
            stream_bytes,
            self.encoder_prefix.len,
        ) catch return error.InvalidStreamRange;
        stream_bytes = std.math.add(
            u64,
            stream_bytes,
            self.decoder_prefix.len,
        ) catch return error.InvalidStreamRange;
        if (stream_bytes > remembered.initial_max_data) {
            return error.FlowControlBlocked;
        }
        var payload_len: usize = 0;
        for (self.frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        const packet_len = try quic.protection.protectedLongPacketCapacity(
            options.handshake.original_destination_connection_id.len,
            options.handshake.local_connection_id.len,
            0,
            false,
            4,
            payload_len,
        );
        if (packet_len > limits.quic.max_datagram_size) {
            return error.DatagramTooLarge;
        }
    }
};

test "HTTP/3 typed early requests require safe methods by default" {
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    inline for (.{ "POST", "PUT", "CONNECT", "PURGE", "get" }) |method| {
        try std.testing.expectError(
            error.UnsafeEarlyDataMethod,
            PreparedEarlyRequest.init(
                no_alloc.allocator(),
                .{
                    .method = method,
                    .path = "/early",
                    .authority = "example.com",
                },
                .{},
                .{},
            ),
        );
    }

    var replayable = try PreparedEarlyRequest.initWithOptions(
        std.testing.allocator,
        .{
            .method = "POST",
            .path = "/application-approved",
            .authority = "example.com",
            .body = "replayable",
        },
        .{},
        .{},
        .{ .replay_policy = .allow_unsafe_replay },
    );
    defer replayable.deinit();
    try std.testing.expectEqualStrings("POST", replayable.method);
    try std.testing.expect(replayable.request_bytes.len != 0);

    inline for (.{ "GET", "HEAD", "OPTIONS", "TRACE", "QUERY" }) |method| {
        var safe = try PreparedEarlyRequest.init(
            std.testing.allocator,
            .{
                .method = method,
                .path = "/safe",
                .authority = "example.com",
            },
            .{},
            .{},
        );
        safe.deinit();
    }
}

pub const EarlyRequestDisposition = enum { accepted, rejected };

pub const EarlyDataRetryReason = enum {
    none,
    early_data_rejected,
    too_early,
};

/// Final response from one RFC 8470 early-data request transaction.
///
/// `retry_reason != .none` means the original request was sent once more over
/// 1-RTT, either because QUIC/TLS rejected early data or because the accepted
/// early request received 425. A 425 from that 1-RTT retry is returned as the
/// final response rather than creating an unbounded retry loop.
pub const EarlyDataRequestResult = struct {
    response: OwnedHandshakeResponse,
    disposition: EarlyRequestDisposition,
    retry_reason: EarlyDataRetryReason,

    pub fn deinit(
        self: *EarlyDataRequestResult,
        allocator: std.mem.Allocator,
    ) void {
        self.response.deinit(allocator);
        self.* = undefined;
    }

    pub fn takeResponse(
        self: *EarlyDataRequestResult,
    ) OwnedHandshakeResponse {
        const response = self.response;
        self.* = undefined;
        return response;
    }
};

pub const EarlyHandshakeClient = struct {
    client: HandshakeClient,
    disposition: EarlyRequestDisposition,
};

pub const BodyChunk = body_batch.Chunk;
pub const ResponseBody = body_batch.ResponseBody;
pub const BodyBatchProgress = body_sender.ConnectionBodyBatchProgress;
pub const BodyWriteProgress = struct {
    /// Application DATA bytes committed at the UDP socket boundary.
    committed_bytes: usize = 0,
    /// True only when the requested FIN was socket-visible.
    fin_committed: bool = false,
};
pub const BodyWriteState = body_fragment.State;

pub const DevelopmentBodyWriteProgress = struct {
    /// True once at least one UDP submission was attempted. Development QUIC
    /// has no packet-number/recovery state to determine the visible prefix, so
    /// an error after this point fail-closes the corresponding send direction.
    send_attempted: bool = false,
    /// True only when the complete DATA contribution was sent successfully.
    completed: bool = false,
};

pub fn bodyPartsLength(parts: []const []const u8) Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.InvalidContentLength;
    }
    return total;
}

pub fn validateBodyWrite(
    bodies: *OutboundBodySet,
    stream_id: u62,
    data_len: usize,
    fin: bool,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    var staged = entry.*;
    try bodies.prepareChunkForEntry(&staged, data_len, fin);
}

fn bodyPartChunkLength(parts: []const []const u8) usize {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    return total;
}

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

    pub fn clientRequestCount(client: *const HandshakeClient) usize {
        return client.request_lifecycle.count();
    }

    pub fn clientPendingQpackSectionCount(
        client: *const HandshakeClient,
    ) usize {
        return client.qpack_encode.pending_sections.items.len;
    }

    pub fn clientControlSendOffset(
        client: *const HandshakeClient,
    ) u64 {
        return client.control_send.next_offset;
    }

    pub fn clientLocalGoAwayId(
        client: *const HandshakeClient,
    ) ?u64 {
        return client.control.local_goaway_id;
    }

    pub fn clientLocalMaxPushId(
        client: *const HandshakeClient,
    ) ?u64 {
        return client.control.local_max_push_id;
    }

    pub fn clientHasPushPromise(
        client: *const HandshakeClient,
        push_id: u64,
    ) bool {
        return client.push_streams.hasPromise(push_id);
    }

    pub fn clientPushPromiseCount(
        client: *const HandshakeClient,
    ) usize {
        return client.push_streams.promiseCount();
    }

    pub fn serverControlSendOffset(
        server: *const HandshakeServerSession,
    ) u64 {
        return server.control_send.next_offset;
    }

    pub fn serverHasSentOriginSet(
        server: *const HandshakeServerSession,
    ) bool {
        return server.control.hasSentOriginSet();
    }
};
