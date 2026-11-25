//! HTTP/3 server session and request-stream handling.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const Error = runtime.Error;
const Limits = runtime.Limits;
const Response = http3.Response;
const Qpack = http3.Qpack;
const concurrent = @import("concurrent.zig");
const concurrent_body_writer = @import("concurrent/body_write.zig");
const development_message = @import("development/message.zig");
const development_request_buffer = @import("development/request_buffer.zig");
const DevelopmentRequestStreamSet = development_request_buffer.Set;
const development_server_peer = @import("development/server_peer/state.zig");
const DevelopmentServerPeerSet = development_server_peer.Set;
const development_streams = @import("development/streams.zig");
const DevelopmentStreamSet = development_streams.ReceiveSet;
const DevelopmentPeerStreamSendSet = development_streams.PeerSendSet;
const DevelopmentStreamSendSet = development_streams.SendSet;
const developmentStreamMayBelongTo = development_streams.mayBelongTo;
const webtransport_bidi_stream_type = development_streams.webtransport_bidi_stream_type;
const RuntimeAssembledStream = development_request_buffer.AssembledStream;
const development_datagram_queue = @import("development/datagram_queue.zig");
const DevelopmentRetainedDatagramQueue = development_datagram_queue.Queue;
const DevelopmentBodyWriteProgress = runtime.DevelopmentBodyWriteProgress;
const DevelopmentStream = runtime.DevelopmentStream;
const DevelopmentStreamDirection = runtime.DevelopmentStreamDirection;
const DevelopmentStreamMatch = runtime.DevelopmentStreamMatch;
const DevelopmentStreamDebugCounts = runtime.DevelopmentStreamDebugCounts;
const requestHasProtocol = runtime.requestHasProtocol;
const normalizeHandlerResponse = runtime.normalizeHandlerResponse;
const OwnedRequest = runtime.OwnedRequest;
const StreamingRequestEvent = runtime.StreamingRequestEvent;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const runtime_error = @import("error.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const development_data_error = @import("development/data_error.zig");
const server_response = @import("server/response.zig");
const bounded_response = @import("server/development_response.zig");
const OwnedRequestBatch = runtime.OwnedRequestBatch;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const messageStreamDisposition = runtime.messageStreamDisposition;
const development_settings = runtime.development_settings;
const send_packetizer = @import("send/packetizer.zig");
const development_send = @import("development/send.zig");
const retainDevelopmentDatagramFrames = development_send.retainDatagramFrames;
const sendRuntimeStreamMessage = development_send.streamMessage;
const sendRuntimeResponsePrefix = development_send.responsePrefix;
const sendRuntimeStreamingHeadAtOffset = development_send.streamingHeadAtOffset;
const sendRuntimeBodyChunk = development_send.bodyChunk;
const sendRuntimeBodyChunkWithDeadline = development_send.bodyChunkWithDeadline;
const sendRuntimeRequestCancellation = development_send.requestCancellation;

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
    /// Aggregate development responses do not retain per-stream send cursors.
    /// After any UDP submission attempt fails, replaying from offset zero could
    /// corrupt a response already visible to the peer, so retire this API.
    aggregate_response_unusable: std.atomic.Value(bool) = .init(false),

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        var quic_server = try quic.runtime.Server.bind(
            allocator,
            io,
            bind_address,
            limits.quic,
        );
        errdefer quic_server.deinit();
        var server: Server = .{
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
        server.streaming_peers.setMaxBodyBytes(limits.max_body_bytes);
        return server;
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
                break :blk self.pollDevelopmentRequestEvent(null, null, true);
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
                break :blk self.pollDevelopmentRequestEvent(
                    from,
                    stream_id,
                    false,
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
                break :blk self.pollDevelopmentRequestEvent(null, null, false);
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
        return self.pollDevelopmentRequestEvent(null, null, false);
    }

    /// The caller owns `peer_state_mutex`; untargeted polling obtains the
    /// actual failed peer/stream from the multiplexed parser before cleanup.
    fn pollDevelopmentRequestEvent(
        self: *Server,
        from: ?net.IpAddress,
        stream_id: ?u62,
        head_only: bool,
    ) Error!?StreamingRequestEvent {
        const ready = if (head_only)
            self.streaming_peers.pollRequestHead()
        else if (from != null and stream_id != null)
            self.streaming_peers.pollRequestEventFor(from.?, stream_id.?)
        else
            self.streaming_peers.pollRequestEvent();
        return ready catch |err| {
            if (self.streaming_peers.lastError()) |failed| {
                self.handleDevelopmentDataError(failed.from, failed.stream_id, err);
            }
            return err;
        };
    }

    fn handleDevelopmentDataError(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
        err: anyerror,
    ) void {
        if (!runtime_error.dataReadPeerError(err)) return;
        if (err == error.InvalidContentLength) {
            self.cancelRequestUnlocked(
                from,
                stream_id,
                http3.ApplicationErrorCode.message_error,
            ) catch {};
            return;
        }
        self.streaming_peers.removePeer(from);
        self.development_streams.removePeer(from);
        self.development_stream_sends.removePeer(from);
        self.runtime_datagrams.removePeer(from);
        development_data_error.close(&self.quic_server.endpoint, from, err);
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

    /// DATA bytes currently readable from one development request without
    /// receiving another packet.
    pub fn availableRequestData(
        self: *Server,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!usize {
        self.peer_state_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.peer_state_mutex.unlock(
            self.quic_server.endpoint.io,
        );
        return self.streaming_peers.availableRequestData(from, stream_id);
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
        return self.streaming_peers.readRequestData(from, stream_id, out) catch |err| {
            self.handleDevelopmentDataError(from, stream_id, err);
            return err;
        };
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
        return self.streaming_peers.skipRequestData(from, stream_id) catch |err| {
            self.handleDevelopmentDataError(from, stream_id, err);
            return err;
        };
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
        return self.sendDevelopmentStreamSlices(
            to,
            session_id,
            stream_id,
            &.{data},
            fin,
        );
    }

    /// Atomically submit borrowed payload slices as one stream send. The
    /// slices are encoded into frames without joining them.
    pub fn sendDevelopmentStreamSlices(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        return self.sendDevelopmentStreamSlicesUntil(
            to,
            session_id,
            stream_id,
            parts,
            fin,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendDevelopmentStreamWithTimeout(
        self: *Server,
        to: net.IpAddress,
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
            to,
            session_id,
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

    pub fn sendDevelopmentStreamWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendDevelopmentStreamSlicesWithDeadline(
            to,
            session_id,
            stream_id,
            &.{data},
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendDevelopmentStreamSlicesWithTimeout(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDevelopmentStreamSlicesWithDeadline(
            to,
            session_id,
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

    pub fn sendDevelopmentStreamSlicesWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        return self.sendDevelopmentStreamSlicesUntil(
            to,
            session_id,
            stream_id,
            parts,
            fin,
            progress,
            deadline,
        );
    }

    fn sendDevelopmentStreamSlicesUntil(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        progress: ?*DevelopmentBodyWriteProgress,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline != null) {
            if (!self.peer_state_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
        }
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.quic_server.endpoint.io,
                absolute,
            );
        }
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
        for (parts, 0..) |part, index| {
            state.appendFrames(
                &frames,
                self.quic_server.endpoint.allocator,
                part,
                self.limits.max_stream_frame_data,
                fin and index + 1 == parts.len,
            ) catch |err| return err;
        }
        if (parts.len == 0 and fin) {
            state.appendFrames(
                &frames,
                self.quic_server.endpoint.allocator,
                "",
                self.limits.max_stream_frame_data,
                true,
            ) catch |err| return err;
        }
        send_packetizer.sendEndpointUntil(
            self.quic_server.endpoint.allocator,
            &self.quic_server.endpoint,
            to,
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
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        send_attempted: *bool,
    ) Error!void {
        return self.sendDevelopmentStreamPartsSlices(
            to,
            session_id,
            stream_id,
            prefix,
            &.{payload},
            fin,
            send_attempted,
        );
    }

    /// Atomically submit a stream prefix plus borrowed payload slices. The
    /// slices are encoded into frames without joining them.
    pub fn sendDevelopmentStreamPartsSlices(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        parts: []const []const u8,
        fin: bool,
        send_attempted: *bool,
    ) Error!void {
        return self.sendDevelopmentStreamPartsSlicesUntil(
            to,
            session_id,
            stream_id,
            prefix,
            parts,
            fin,
            send_attempted,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendDevelopmentStreamPartsWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        payload: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendDevelopmentStreamPartsSlicesWithDeadline(
            to,
            session_id,
            stream_id,
            prefix,
            &.{payload},
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendDevelopmentStreamPartsSlicesWithDeadline(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        parts: []const []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        var send_attempted = false;
        self.sendDevelopmentStreamPartsSlicesUntil(
            to,
            session_id,
            stream_id,
            prefix,
            parts,
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

    fn sendDevelopmentStreamPartsSlicesUntil(
        self: *Server,
        to: net.IpAddress,
        session_id: u62,
        stream_id: u62,
        prefix: []const u8,
        parts: []const []const u8,
        fin: bool,
        send_attempted: *bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (deadline != null) {
            if (!self.peer_state_mutex.tryLock()) {
                return error.ConcurrencyUnavailable;
            }
        } else {
            self.peer_state_mutex.lockUncancelable(
                self.quic_server.endpoint.io,
            );
        }
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.quic_server.endpoint.io,
                absolute,
            );
        }
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
        for (parts, 0..) |part, index| {
            try state.appendFrames(
                &frames,
                self.quic_server.endpoint.allocator,
                part,
                self.limits.max_stream_frame_data,
                fin and index + 1 == parts.len,
            );
        }
        if (parts.len == 0 and fin) {
            try state.appendFrames(
                &frames,
                self.quic_server.endpoint.allocator,
                "",
                self.limits.max_stream_frame_data,
                true,
            );
        }
        send_packetizer.sendEndpointUntil(
            self.quic_server.endpoint.allocator,
            &self.quic_server.endpoint,
            to,
            frames.items,
            1,
            send_attempted,
            deadline,
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
    /// deinitialize it or retain slices after the result is deinitialized. A
    /// handler-returned 1xx is replaced with a final 500 and its result slot is
    /// set to InvalidStatus after the response is sent.
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
        if (self.aggregate_response_unusable.load(.acquire)) {
            return error.ConnectionUnusable;
        }
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
        if (self.aggregate_response_unusable.load(.acquire)) {
            return error.ConnectionUnusable;
        }
        var send_attempted = false;
        sendRuntimeStreamMessage(
            &self.quic_server.endpoint,
            to,
            stream_id,
            encoded.items,
            self.limits.max_stream_frame_data,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) {
                self.aggregate_response_unusable.store(true, .release);
            }
            return err;
        };
    }

    /// Emit one informational response on an admitted streaming request. The
    /// next final response continues at the recorded stream offset.
    pub fn sendInformationalResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.InformationalResponse) Error!void {
        return self.sendInformationalResponseUntil(to, stream_id, response, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn sendInformationalResponseWithDeadline(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.InformationalResponse, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        return self.sendInformationalResponseUntil(to, stream_id, response, deadline);
    }

    fn sendInformationalResponseUntil(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.InformationalResponse, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        const io = self.quic_server.endpoint.io;
        if (deadline) |until| {
            _ = try deadline_policy.usableAwake(io, until);
            if (!self.peer_state_mutex.tryLock()) return error.ConcurrencyUnavailable;
        } else self.peer_state_mutex.lockUncancelable(io);
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const response_context = try peer.prepareInformational(
            stream_id,
            self.streaming_mode,
        );
        if (deadline) |until| {
            _ = try deadline_policy.usableAwake(io, until);
            if (!self.response_send_mutex.tryLock()) return error.ConcurrencyUnavailable;
        } else self.response_send_mutex.lockUncancelable(io);
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        try response.writeDynamic(
            &response_context.scratch.encoded,
            self.quic_server.endpoint.allocator,
            development_settings,
            stream_id,
            response_context.qpack_encode,
        );
        var send_attempted = false;
        development_send.responsePrefixUntil(
            &self.quic_server.endpoint,
            to,
            response_context.scratch,
            stream_id,
            self.limits.max_stream_frame_data,
            response_context.response_send_offsets,
            false,
            deadline,
            &send_attempted,
        ) catch |err| {
            if (send_attempted) peer.markSendFailed();
            return err;
        };
    }

    pub fn startResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response, body_length: ?usize) Error!void {
        return bounded_response.start(self, to, stream_id, response, body_length, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn startResponseWithDeadline(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response, body_length: ?usize, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        return bounded_response.start(self, to, stream_id, response, body_length, deadline) catch |err| return @errorCast(err);
    }

    pub fn startResponseWithTimeout(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response, body_length: ?usize, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(to, stream_id, response, body_length, .fromNow(self.quic_server.endpoint.io, .{ .clock = .awake, .raw = timeout }));
    }

    pub fn sendResponseBody(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        var progress: DevelopmentBodyWriteProgress = .{};
        return self.sendResponseBodyWithProgress(to, stream_id, data, fin, &progress);
    }

    /// Retain the submission/completion distinction on unbounded DATA errors.
    pub fn sendResponseBodyWithProgress(self: *Server, to: net.IpAddress, stream_id: u62, data: []const u8, fin: bool, progress: *DevelopmentBodyWriteProgress) Error!void {
        progress.* = .{};
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
        sendRuntimeBodyChunk(
            &self.quic_server.endpoint,
            to,
            outbound_bodies,
            stream_id,
            data,
            fin,
            self.limits.max_stream_frame_data,
            &progress.send_attempted,
        ) catch |err| {
            if (progress.send_attempted) peer.markSendFailed();
            return err;
        };
        peer.commitResponseBody(stream_id, fin);
        progress.completed = true;
    }

    pub fn sendResponseBodyWithTimeout(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResponseBodyWithDeadline(
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

    /// Deadline-bounded development response DATA. A timeout before the first
    /// UDP submission rolls back stream state. Once any packet submission is
    /// attempted, a later failure marks the peer send direction unusable
    /// because this transport cannot recover an exact socket-visible prefix.
    pub fn sendResponseBodyWithDeadline(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *DevelopmentBodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        if (!self.peer_state_mutex.tryLock()) {
            return error.ConcurrencyUnavailable;
        }
        defer self.peer_state_mutex.unlock(self.quic_server.endpoint.io);
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        const peer = self.streaming_peers.find(to) orelse
            return error.UnexpectedStream;
        const outbound_bodies = try peer.prepareResponseBody(stream_id);
        if (!self.response_send_mutex.tryLock()) {
            return error.ConcurrencyUnavailable;
        }
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
        _ = try deadline_policy.usableAwake(
            self.quic_server.endpoint.io,
            deadline,
        );
        var send_attempted = false;
        sendRuntimeBodyChunkWithDeadline(
            &self.quic_server.endpoint,
            to,
            outbound_bodies,
            stream_id,
            data,
            fin,
            self.limits.max_stream_frame_data,
            &send_attempted,
            deadline,
        ) catch |err| {
            progress.send_attempted = send_attempted;
            if (send_attempted) peer.markSendFailed();
            return err;
        };
        progress.send_attempted = send_attempted;
        progress.completed = true;
        peer.commitResponseBody(stream_id, fin);
    }

    /// Emit response trailers on an admitted streaming request and finish the
    /// response. The next stream offset continues after all DATA contributions.
    pub fn finishResponseTrailers(self: *Server, to: net.IpAddress, stream_id: u62, trailers: []const http3.Qpack.HeaderField) Error!void {
        return bounded_response.trailers(self, to, stream_id, trailers, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn finishResponseTrailersWithDeadline(self: *Server, to: net.IpAddress, stream_id: u62, trailers: []const http3.Qpack.HeaderField, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        return bounded_response.trailers(self, to, stream_id, trailers, deadline) catch |err| return @errorCast(err);
    }

    pub fn finishResponseTrailersWithTimeout(self: *Server, to: net.IpAddress, stream_id: u62, trailers: []const http3.Qpack.HeaderField, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseTrailersWithDeadline(to, stream_id, trailers, .fromNow(self.quic_server.endpoint.io, .{ .clock = .awake, .raw = timeout }));
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
        return self.cancelRequestUnlocked(to, stream_id, application_error_code);
    }

    pub fn cancelRequestWithDeadline(self: *Server, to: net.IpAddress, stream_id: u62, application_error_code: u64, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        return bounded_response.cancel(self, to, stream_id, application_error_code, deadline, retireDevelopmentPeerIfInactive) catch |err| return @errorCast(err);
    }

    pub fn cancelRequestWithTimeout(self: *Server, to: net.IpAddress, stream_id: u62, application_error_code: u64, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelRequestWithDeadline(to, stream_id, application_error_code, .fromNow(self.quic_server.endpoint.io, .{ .clock = .awake, .raw = timeout }));
    }

    fn cancelRequestUnlocked(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
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

    pub const ConcurrentStream = DevelopmentConcurrentEngine.Stream;

    /// Continuously accept request streams, run one handler task per stream,
    /// and serialize all session mutations through this owner. The call returns
    /// on `options.shutdown`, the overall deadline, idle timeout, or a
    /// connection error. See `runtime/concurrent.zig` for the contract.
    pub fn serveConcurrentStreams(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *ConcurrentStream,
        ) anyerror!void,
        options: concurrent.Options,
    ) anyerror!concurrent.Summary {
        var engine = DevelopmentConcurrentEngine.init(
            self,
            self.quic_server.endpoint.allocator,
            self.quic_server.endpoint.io,
            options,
        );
        defer engine.deinit();
        return engine.serve(HandlerContext, context, handler);
    }
};

const DevelopmentConcurrentAdapter = struct {
    pub fn peerSettings(_: *Server) http3.Settings {
        return development_settings;
    }
    pub fn sendInformational(session: *Server, from: net.IpAddress, stream_id: u62, response: http3.InformationalResponse, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
        if (deadline) |until| return session.sendInformationalResponseWithDeadline(from, stream_id, response, until);
        return session.sendInformationalResponse(from, stream_id, response);
    }
    pub fn maxStreams(session: *Server) usize {
        return session.limits.max_concurrent_request_streams;
    }
    pub fn maxBodyBuffer(session: *Server) usize {
        return session.limits.max_stream_buffer;
    }
    pub fn receive(
        session: *Server,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!StreamingRequestEvent {
        return if (deadline) |value|
            session.receiveRequestEventWithDeadline(value)
        else
            session.receiveRequestEvent();
    }
    pub fn availableBody(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!usize {
        return session.availableRequestData(from, stream_id);
    }
    pub fn readBody(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        return session.readRequestData(from, stream_id, out);
    }
    pub fn startResponse(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        if (deadline) |until| return session.startResponseWithDeadline(from, stream_id, response, body_length, until);
        return session.startResponse(from, stream_id, response, body_length);
    }
    pub fn sendBody(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
        progress: *concurrent_body_writer.Progress,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        var development_progress: DevelopmentBodyWriteProgress = .{};
        defer {
            if (development_progress.completed) {
                progress.committed_bytes = data.len;
                progress.fin_committed = fin;
            }
            progress.retryable = development_progress.completed or !development_progress.send_attempted;
        }
        if (deadline) |until| return session.sendResponseBodyWithDeadline(from, stream_id, data, fin, &development_progress, until);
        return session.sendResponseBodyWithProgress(from, stream_id, data, fin, &development_progress);
    }
    /// The cleartext development runtime keeps the two-step path.
    pub fn sendCompleteResponse(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
        data: []const u8,
        request_method: ?[]const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        var value = response;
        value.request_method = request_method;
        if (deadline) |until| {
            try session.startResponseWithDeadline(from, stream_id, value, body_length, until);
            var progress: DevelopmentBodyWriteProgress = .{};
            return session.sendResponseBodyWithDeadline(from, stream_id, data, true, &progress, until);
        }
        try session.startResponse(from, stream_id, value, body_length);
        return session.sendResponseBody(from, stream_id, data, true);
    }
    pub fn sendCompleteResponseWithInformational(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
        body_length: ?usize,
        data: []const u8,
        request_method: ?[]const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        var value = response;
        value.body = data;
        value.request_method = request_method;
        if (deadline) |until| {
            for (informational) |info| try session.sendInformationalResponseWithDeadline(from, stream_id, info, until);
            try session.startResponseWithDeadline(from, stream_id, value, body_length, until);
            var progress: DevelopmentBodyWriteProgress = .{};
            return session.sendResponseBodyWithDeadline(from, stream_id, data, true, &progress, until);
        }
        return session.sendResponseWithInformational(
            from,
            stream_id,
            informational,
            value,
        );
    }
    pub fn finishTrailers(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        if (deadline) |until| return session.finishResponseTrailersWithDeadline(from, stream_id, trailers, until);
        return session.finishResponseTrailers(from, stream_id, trailers);
    }
    pub fn cancel(
        session: *Server,
        from: net.IpAddress,
        stream_id: u62,
        code: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) anyerror!void {
        if (deadline) |until| return session.cancelRequestWithDeadline(from, stream_id, code, until);
        return session.cancelRequest(from, stream_id, code);
    }
    pub fn goaway(
        session: *Server,
        last_stream_id: u64,
    ) Error!void {
        _ = session;
        _ = last_stream_id;
    }
};

const DevelopmentConcurrentEngine = concurrent.Engine(Server, DevelopmentConcurrentAdapter);

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
            const invalid_final = normalizeHandlerResponse(
                &response,
                request.request.method,
                requestHasProtocol(request.request.headers),
            );
            task.server.sendResponse(
                request.from,
                request.stream_id,
                response,
            ) catch |err| {
                task.err.* = err;
                return;
            };
            task.err.* = if (invalid_final) error.InvalidStatus else null;
        }
    };
}
