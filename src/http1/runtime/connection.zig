//! HTTP/1 server connection and request/response exchange.

const std = @import("std");
const http1 = @import("../mod.zig");
const net = std.Io.net;
const socket_address = @import("../../internal/socket_address.zig");
const runtime = @import("../runtime.zig");

const AcceptedConnectIp = runtime.AcceptedConnectIp;
const AcceptedConnectUdp = runtime.AcceptedConnectUdp;
const ConnectIpSession = runtime.ConnectIpSession;
const ConnectUdpSession = runtime.ConnectUdpSession;
const ConnectUdpTunnel = runtime.ConnectUdpTunnel;
const Error = runtime.Error;
const Limits = runtime.Limits;
const OwnedRequest = runtime.OwnedRequest;
const RequestBodyReader = runtime.RequestBodyReader;
const RequestReadStage = runtime.RequestReadStage;
const ResponseOptions = runtime.ResponseOptions;
const ResponseWriter = runtime.ResponseWriter;
const RuntimeTransport = runtime.RuntimeTransport;
const Server = runtime.Server;
const StreamingBodyReader = runtime.StreamingBodyReader;
const StreamingBodyWriter = runtime.StreamingBodyWriter;
const StreamingRequest = runtime.StreamingRequest;
const StreamingResponseOptions = runtime.StreamingResponseOptions;
const Tunnel = runtime.Tunnel;
const WriteScratch = runtime.WriteScratch;
const adjustResponseForServeLoop = runtime.adjustResponseForServeLoop;
const body_writer = runtime.body_writer;
const connect_udp_runtime = runtime.connect_udp_runtime;
const connectionMaybeWriteContinue = runtime.connectionMaybeWriteContinue;
const connectionReadHeadSome = runtime.connectionReadHeadSome;
const connectionReadSome = runtime.connectionReadSome;
const connectionWriteSlices = runtime.connectionWriteSlices;
const deadline_policy = runtime.deadline_policy;
const discardPrefix = runtime.discardPrefix;
const findHttpHeadEndWithinLimit = runtime.findHttpHeadEndWithinLimit;
const headReadDeadline = runtime.headReadDeadline;
const http3 = runtime.http3;
const http_date = runtime.http_date;
const ignoreStreamingRequestHead = runtime.ignoreStreamingRequestHead;
const max_error_drain_bytes = runtime.max_error_drain_bytes;
const message_continue = runtime.message_continue;
const message_framing = runtime.message_framing;
const prepareResponsesCoalesced = runtime.prepareResponsesCoalesced;
const readRequestFromTransportBufferedWithStage = runtime.readRequestFromTransportBufferedWithStage;
const rejectUpgradeManagedHeaders = runtime.rejectUpgradeManagedHeaders;
const request_batch = runtime.request_batch;
const responseBatchBodyBytes = runtime.responseBatchBodyBytes;
const responseBatchWriteStrategy = runtime.responseBatchWriteStrategy;
const responseOptionsKeepAlive = runtime.responseOptionsKeepAlive;
const runtime_write = runtime.runtime_write;
const streamingRequestFromReader = runtime.streamingRequestFromReader;
const tls_stream = runtime.tls_stream;
const validateUpgradeProtocol = runtime.validateUpgradeProtocol;
const wire = runtime.wire;
const writeMessagePartsWithStrategy = runtime.writeMessagePartsWithStrategy;
const writeSlicesWithStrategy = runtime.writeSlicesWithStrategy;

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    write_scratch: WriteScratch = .{},
    writer_state: body_writer.State = .{},
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    request_head_deadline: ?std.Io.Clock.Timestamp = null,
    /// Once requested, graceful shutdown permits the active exchange to
    /// finish but prevents this connection from accepting another request.
    /// The flag is monotonic because HTTP/1 has no protocol-level mechanism
    /// for retracting a Connection: close decision already exposed to a peer.
    graceful_shutdown_requested: bool = false,
    /// A committed interim response survives retries of the current request.
    /// Cleared when that request is decoded or consumed by a batch reader.
    request_continue: message_continue.State = .{},
    /// Reused bump arena for the synchronous bodyless request path. The copied
    /// head bytes and header array are released together when the next
    /// bodyless request starts, so the hot path skips two heap allocations.
    /// Heap-owned because `Connection` may move between construction and
    /// first use.
    bodyless_arena: ?*std.heap.ArenaAllocator = null,

    pub fn transport(self: *Connection) RuntimeTransport {
        if (self.tls_server_conn) |connection| {
            return .{ .tls_server = connection };
        }
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    /// Remote IP peer recorded by accept. Unix streams return null.
    pub fn peerAddress(self: *const Connection) ?net.IpAddress {
        return socket_address.accepted(self.stream);
    }

    /// Return the authenticated client certificate chain for TLS server
    /// connections. Cleartext and anonymous TLS connections return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        const tls_connection = self.tls_server_conn orelse return null;
        return tls_connection.peerCertificates();
    }

    /// Return authenticated TLS negotiation metadata for HTTPS server
    /// connections. Cleartext connections return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedCipherSuite();
    }

    /// Return the ALPN token selected by the TLS handshake. Cleartext
    /// connections and legacy peers without ALPN return null.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedAlpn();
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedProtocol();
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        const connection = self.tls_server_conn orelse return null;
        return connection.wasResumed();
    }

    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedTranscriptHash();
    }

    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        const connection = self.tls_server_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try connection.exportKeyingMaterial(label, context, out);
    }

    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        const connection = self.tls_server_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try self.writer_state.ensureAvailable();
        connection.updateTrafficKeys(request_peer_update) catch |err| {
            switch (err) {
                error.WriteInProgress, error.KeyUpdateRequestPending => {},
                else => self.writer_state.phase = .unusable,
            }
            return err;
        };
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        const connection = self.tls_server_conn orelse return null;
        return connection.keyUpdateCounts();
    }

    pub fn close(self: *Connection) void {
        self.releaseBuffers();
        if (self.tls_server_conn) |connection| {
            connection.deinit();
        } else {
            self.stream.close(self.io);
        }
        self.* = undefined;
    }

    /// Release connection-owned buffers without touching the transport.
    ///
    /// Used when the socket moves to another owner, such as a WebSocket
    /// upgrade. The connection must not be used afterwards; `close` remains
    /// the normal retirement path.
    pub fn releaseBuffers(self: *Connection) void {
        self.inbuf.deinit(self.allocator);
        self.inbuf = .empty;
        self.write_scratch.deinit(self.allocator);
        self.write_scratch = .{};
        if (self.bodyless_arena) |arena| {
            arena.deinit();
            self.allocator.destroy(arena);
            self.bodyless_arena = null;
        }
    }

    /// Write one final response and retire the connection, even after the
    /// request read failed.
    ///
    /// A request that fails during reading (an over-limit head, an over-long
    /// target, an oversized body) marks the exchange unusable, so
    /// `writeResponse` refuses with `error.ConnectionUnusable`. The peer is
    /// still owed a 4xx response, so this method writes it, forces
    /// `Connection: close`, half-closes, drains pending input and closes.
    /// Do not use the connection afterwards.
    pub fn respondAndClose(
        self: *Connection,
        response: ResponseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.writer_state.phase == .writing or
            self.writer_state.phase == .awaiting_peer)
        {
            return error.ConnectionBusy;
        }
        // `drainAndClose` invalidates `self`, so keep the allocator locally.
        const allocator = self.allocator;
        var value = response;
        var owned: ?[]http1.Header = null;
        defer if (owned) |headers| allocator.free(headers);
        var has_connection = false;
        for (response.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
                has_connection = true;
                break;
            }
        }
        if (!has_connection) {
            const headers = try allocator.alloc(
                http1.Header,
                response.headers.len + 1,
            );
            @memcpy(headers[0..response.headers.len], response.headers);
            headers[response.headers.len] = .{
                .name = "Connection",
                .value = "close",
            };
            owned = headers;
            value.headers = headers;
        }
        try self.writeResponseFailClosed(value, self.defaultResponseDate());
        self.drainAndClose(deadline);
    }

    /// Close after an error response without destroying that response.
    ///
    /// Closing a socket while the peer's request bytes are still unread makes
    /// Linux send RST, so a client can lose the 400/408/413/414/431 response it
    /// was meant to see. This half-closes the write side first (so the response
    /// is flushed and the peer sees EOF), then reads and discards pending input
    /// until EOF or `deadline`, and finally closes. The drain is best effort:
    /// failures and an expired deadline still close the connection.
    pub fn drainAndClose(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) void {
        const drain_transport = self.transport();
        // The response is already committed; a half-close failure only means
        // the peer closed first, which is harmless here.
        drain_transport.closeWrite() catch {};
        var scratch: [4096]u8 = undefined;
        var drained: usize = 0;
        while (drained < max_error_drain_bytes) {
            if (std.Io.Clock.awake.now(self.io).nanoseconds >=
                deadline.raw.nanoseconds)
            {
                break;
            }
            const count = drain_transport.readWithDeadline(
                &scratch,
                deadline,
            ) catch break;
            if (count == 0) break;
            drained += count;
        }
        self.close();
    }

    /// Stop accepting new HTTP/1 exchanges without interrupting one that is
    /// already being served. `serve` observes this before its next read, while
    /// a handler that requests shutdown causes its active response to carry
    /// `Connection: close`. The connection-owning task must call this method;
    /// it is not an asynchronous cancellation mechanism for a blocked read.
    pub fn gracefulShutdown(self: *Connection) void {
        self.graceful_shutdown_requested = true;
    }

    pub fn readRequest(self: *Connection, options: http1.ParseOptions) Error!OwnedRequest {
        return self.readRequestInternal(options, null);
    }

    fn readRequestInternal(
        self: *Connection,
        options: http1.ParseOptions,
        failure_stage: ?*RequestReadStage,
    ) Error!OwnedRequest {
        try self.writer_state.ensureReadable();
        try self.beginRequestHeadDeadline();
        defer self.request_head_deadline = null;
        var stage: RequestReadStage = .head;
        var owned = readRequestFromTransportBufferedWithStage(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            self.request_head_deadline,
            &stage,
            &self.request_continue,
        ) catch |read_err| {
            if (failure_stage) |out| out.* = stage;
            if (read_err == error.Timeout or stage == .continue_write) {
                self.writer_state.phase = .unusable;
            }
            return read_err;
        };
        owned.request.from = self.peerAddress();
        return owned;
    }

    /// Read one request with a relative deadline for the request head. The
    /// body remains governed by the ordinary body-size and transport policy.
    /// Unlike the configured Slowloris protection, a caller-owned timeout is
    /// resumable: partial head bytes remain in `inbuf` for a later call.
    pub fn readRequestWithTimeout(
        self: *Connection,
        options: http1.ParseOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestWithDeadline(
            options,
            try self.transport().deadlineFromNow(timeout),
        );
    }

    /// Read one request using a caller-owned absolute request-head deadline.
    /// A timeout does not poison the persistent connection, allowing the same
    /// owner to resume the partially buffered head with a later deadline.
    /// Allocation failures also retain input and decoded message bytes for
    /// retry without allowing a later pipelined request to overtake them.
    /// An automatic 100 Continue already committed for this request is not
    /// sent again when its body or metadata allocation is retried.
    pub fn readRequestWithDeadline(
        self: *Connection,
        options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.writer_state.ensureReadable();
        var stage: RequestReadStage = .head;
        var owned = readRequestFromTransportBufferedWithStage(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            deadline,
            &stage,
            &self.request_continue,
        ) catch |err| {
            if (stage == .continue_write) {
                self.writer_state.phase = .unusable;
            }
            return err;
        };
        owned.request.from = self.peerAddress();
        return owned;
    }

    /// Read and validate the RFC 9298 HTTP/1.1 Upgrade request. The returned
    /// request remains owned by the caller so authentication and target policy
    /// can run before the connection is switched to the Capsule Protocol.
    pub fn readConnectUdpRequest(self: *Connection) Error!OwnedRequest {
        var request = try self.readRequest(.{});
        errdefer request.deinit(self.allocator);
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_udp.protocol,
            if (self.tls_server_conn == null) "http" else "https",
            request.request,
        );
        return request;
    }

    pub fn readConnectUdpRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readConnectUdpRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readConnectUdpRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedRequest {
        var request = try self.readRequestWithDeadline(.{}, deadline);
        errdefer request.deinit(self.allocator);
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_udp.protocol,
            if (self.tls_server_conn == null) "http" else "https",
            request.request,
        );
        return request;
    }

    pub fn acceptConnectUdpDefault(
        self: *Connection,
        request: http1.Request,
        target_host_storage: []u8,
    ) Error!AcceptedConnectUdp {
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_udp.protocol,
            if (self.tls_server_conn == null) "http" else "https",
            request,
        );
        const target = try http3.connect_udp.parseDefaultPath(
            try connect_udp_runtime.requestPath(request.target),
            target_host_storage,
        );
        return .{
            .target = target,
            .session = try self.acceptConnectUdpForTarget(request, target),
        };
    }

    /// Accept a request after application-specific URI-template routing has
    /// selected and authorized its target. General Level-3 templates are not
    /// assumed to be reversibly decodable by the transport layer.
    pub fn acceptConnectUdpForTarget(
        self: *Connection,
        request: http1.Request,
        target: http3.connect_udp.Target,
    ) Error!ConnectUdpSession {
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_udp.protocol,
            if (self.tls_server_conn == null) "http" else "https",
            request,
        );
        try target.validate();
        const response_headers = [_]http1.Header{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        const tunnel = try self.acceptUpgrade(
            request,
            http3.connect_udp.protocol,
            &response_headers,
        );
        return ConnectUdpSession.init(
            self.allocator,
            self.io,
            ConnectUdpTunnel.init(self.allocator, tunnel),
            .{},
        );
    }

    pub fn readConnectIpRequest(self: *Connection) Error!OwnedRequest {
        if (self.tls_server_conn == null) return error.EncryptionRequired;
        var request = try self.readRequest(.{});
        errdefer request.deinit(self.allocator);
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_ip.protocol,
            "https",
            request.request,
        );
        return request;
    }

    pub fn readConnectIpRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readConnectIpRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readConnectIpRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedRequest {
        if (self.tls_server_conn == null) return error.EncryptionRequired;
        var request = try self.readRequestWithDeadline(.{}, deadline);
        errdefer request.deinit(self.allocator);
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_ip.protocol,
            "https",
            request.request,
        );
        return request;
    }

    pub fn acceptConnectIpDefault(
        self: *Connection,
        request: http1.Request,
        target_storage: []u8,
    ) Error!AcceptedConnectIp {
        if (self.tls_server_conn == null) return error.EncryptionRequired;
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_ip.protocol,
            "https",
            request,
        );
        const scope = try http3.connect_ip.parseDefaultPath(
            try connect_udp_runtime.requestPath(request.target),
            target_storage,
        );
        return .{
            .scope = scope,
            .session = try self.acceptConnectIpForScope(request, scope),
        };
    }

    pub fn acceptConnectIpForScope(
        self: *Connection,
        request: http1.Request,
        scope: http3.connect_ip.Scope,
    ) Error!ConnectIpSession {
        if (self.tls_server_conn == null) return error.EncryptionRequired;
        try connect_udp_runtime.validateRequest(
            http3.capsule,
            http3.connect_ip.protocol,
            "https",
            request,
        );
        try scope.validate();
        const response_headers = [_]http1.Header{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        const tunnel = try self.acceptUpgrade(
            request,
            http3.connect_ip.protocol,
            &response_headers,
        );
        return ConnectIpSession.init(
            self.allocator,
            self.io,
            ConnectUdpTunnel.init(self.allocator, tunnel),
            .{},
        );
    }

    /// Start a pull-style request body reader. The returned reader owns a
    /// background producer that drives the existing push parser; callers use
    /// `head`, `next`, and `takeRequest`. Consume each `next` slice before the
    /// following call. `deinit` before completion cancels the producer and
    /// closes the connection because an unread body cannot preserve keep-alive.
    pub fn readRequestBody(self: *Connection, options: http1.ParseOptions) !*RequestBodyReader {
        return self.readRequestBodyWithBuffer(options, 64 * 1024);
    }

    pub fn readRequestBodyWithBuffer(self: *Connection, options: http1.ParseOptions, max_buffered_bytes: usize) !*RequestBodyReader {
        if (try self.completeBodylessRequest(options)) |reader| return reader;
        return RequestBodyReader.init(self.allocator, self, options, max_buffered_bytes);
    }

    /// Complete a request with no body without spawning the background
    /// producer. The head is read and parsed on the calling task, the owned
    /// request is built directly, and the returned reader reports completion
    /// immediately. Requests with a body (or an `Expect` field) fall back to
    /// the regular producer path with the buffered head untouched.
    fn completeBodylessRequest(
        self: *Connection,
        options: http1.ParseOptions,
    ) !?*RequestBodyReader {
        // Obs-fold parsing needs the owned-head path in the streaming reader.
        if (options.allow_obs_fold) return null;
        var headers_stack: [128]http1.Header = undefined;
        if (options.max_headers > headers_stack.len) return null;

        try self.writer_state.beginRead();
        var succeeded = false;
        defer if (!succeeded) self.writer_state.failRead();

        self.beginRequestHeadDeadline() catch |err| return err;
        defer self.request_head_deadline = null;

        const headers = headers_stack[0..options.max_headers];
        var head: http1.RequestHead = undefined;
        while (true) {
            head = http1.parseRequestHead(
                self.inbuf.items,
                headers,
                options,
            ) catch |err| switch (err) {
                error.BufferTooShort => {
                    _ = findHttpHeadEndWithinLimit(
                        self.inbuf.items,
                        self.limits.max_head_bytes,
                    ) catch |limit_err| return limit_err;
                    if (self.inbuf.items.len >= self.limits.max_head_bytes) {
                        return error.HeadersTooLarge;
                    }
                    var read_buffer: [16 * 1024]u8 = undefined;
                    const remaining =
                        self.limits.max_head_bytes - self.inbuf.items.len;
                    const destination =
                        read_buffer[0..@min(remaining, read_buffer.len)];
                    const count = connectionReadHeadSome(
                        self,
                        destination,
                    ) catch |read_err| {
                        if (read_err == error.Timeout) {
                            self.writer_state.phase = .unusable;
                        }
                        return read_err;
                    };
                    if (count == 0) return error.ConnectionClosed;
                    try self.inbuf.appendSlice(
                        self.allocator,
                        read_buffer[0..count],
                    );
                    continue;
                },
                else => |parse_err| return parse_err,
            };
            break;
        }

        // Only a request that cannot carry a body is completed here. An
        // Expect field is left to the producer so 100-continue handling stays
        // in one place. Falling back must release the read phase without
        // poisoning the connection; the producer starts a fresh read.
        const bodyless = head.body_framing == .none or
            (head.body_framing == .content_length and
                (head.content_length orelse 0) == 0);
        if (!bodyless or head.header("expect") != null) {
            succeeded = true;
            self.writer_state.finishRead();
            return null;
        }

        // The bodyless path owns the copied head and header array only until
        // the caller finishes the request. Bump-allocate both from a
        // connection-owned arena and release them together on the next
        // bodyless request, so steady-state requests skip two heap
        // allocations. The reader itself stays heap-allocated because callers
        // may deinit it after the connection has closed.
        const arena = try self.bodylessAllocator();
        const head_bytes = try arena.dupe(
            u8,
            self.inbuf.items[0..head.head_len],
        );
        errdefer arena.free(head_bytes);
        const owned_headers = try arena.dupe(
            http1.Header,
            head.headers,
        );
        errdefer arena.free(owned_headers);

        // Rebase the parsed slices into the copied head instead of parsing the
        // copy again. `inbuf` is not modified between the parse and the copy.
        const inbuf_base = @intFromPtr(self.inbuf.items.ptr);
        const head_base = @intFromPtr(head_bytes.ptr);
        const rebase = struct {
            fn slice(base: usize, target: usize, source: []const u8) []const u8 {
                const offset = @intFromPtr(source.ptr) - base;
                return @as(
                    [*]const u8,
                    @ptrFromInt(target + offset),
                )[0..source.len];
            }
        }.slice;
        const target = rebase(inbuf_base, head_base, head.target);
        for (head.headers, owned_headers) |field, *copy| {
            copy.* = .{
                .name = rebase(inbuf_base, head_base, field.name),
                .value = rebase(inbuf_base, head_base, field.value),
            };
        }
        self.consumeRequestBatch(head.head_len) catch |err| return err;
        self.request_continue.reset();

        var request = StreamingRequest{
            .head_bytes = head_bytes,
            .method = head.method,
            .target = target,
            .version = head.version,
            .headers = owned_headers,
            .body_framing = head.body_framing,
            .body_bytes = 0,
            .must_close = head.must_close,
            .owned = false,
        };
        errdefer request.deinit(arena);
        // The head view borrows the request's owned bytes and header array;
        // the reader keeps both alive until `takeRequest`/`deinit`.
        const head_value = RequestBodyReader.Head.borrow(
            self.allocator,
            &request,
            head.content_length,
        );

        succeeded = true;
        self.writer_state.finishRead();
        return RequestBodyReader.initCompleted(
            self.allocator,
            self,
            options,
            head_value,
            request,
        );
    }

    /// Reset and return the connection-owned arena used by the synchronous
    /// bodyless path. The previous reader must already be deinit'd; the
    /// connection processes one request at a time and `beginRead` rejects a
    /// second in-flight read.
    fn bodylessAllocator(self: *Connection) !std.mem.Allocator {
        const arena = self.bodyless_arena orelse blk: {
            const created = try self.allocator.create(std.heap.ArenaAllocator);
            created.* = .init(self.allocator);
            self.bodyless_arena = created;
            break :blk created;
        };
        _ = arena.reset(.retain_capacity);
        return arena.allocator();
    }

    /// Read a request while delivering body bytes without aggregation.
    pub fn readRequestStreaming(
        self: *Connection,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithOptionsAndHead(
            .{},
            context,
            ignoreStreamingRequestHead,
            consume,
        );
    }

    pub fn readRequestStreamingWithOptions(
        self: *Connection,
        options: http1.ParseOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithOptionsAndHead(
            options,
            context,
            ignoreStreamingRequestHead,
            consume,
        );
    }

    pub fn readRequestStreamingWithHead(
        self: *Connection,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithOptionsAndHead(
            .{},
            context,
            begin,
            consume,
        );
    }

    pub fn readRequestStreamingWithOptionsAndHead(
        self: *Connection,
        options: http1.ParseOptions,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        try self.writer_state.beginRead();
        self.beginRequestHeadDeadline() catch |err| {
            self.writer_state.finishRead();
            return err;
        };
        defer self.request_head_deadline = null;
        var reader = StreamingBodyReader{
            .allocator = self.allocator,
            .context = self,
            .read_some = connectionReadSome,
            .read_head_some = connectionReadHeadSome,
            .before_request_head = connectionMaybeWriteContinue,
            .inbuf = &self.inbuf,
            .limits = .{
                .max_head_bytes = self.limits.max_head_bytes,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_informational_responses = self.limits.max_informational_responses,
            },
            .options = options,
            .peer_address = self.peerAddress(),
        };
        const result = reader.readRequest(
            context,
            begin,
            consume,
        ) catch |err| {
            self.writer_state.failRead();
            return err;
        };
        self.request_continue.reset();
        self.writer_state.finishRead();
        return streamingRequestFromReader(result);
    }

    fn beginRequestHeadDeadline(self: *Connection) Error!void {
        std.debug.assert(self.request_head_deadline == null);
        // Parsing a head already carried in the previous read must not fail
        // merely because a configured timeout is zero or has no backend.
        // The protection starts only when this request needs socket input.
        if (try findHttpHeadEndWithinLimit(
            self.inbuf.items,
            self.limits.max_head_bytes,
        ) != null) return;
        const timeout = self.limits.request_head_timeout orelse return;
        self.request_head_deadline = try headReadDeadline(
            self.transport(),
            timeout,
        );
    }

    /// Read and parse an exact batch of pipelined requests without per-request
    /// allocation. Chunk framing is removed in place after the complete batch
    /// validates; trailer fields are validated but are not exposed by this
    /// borrowed API.
    ///
    /// `heads`, every head's header slice, and `bodies` borrow `self.inbuf`.
    /// They remain valid only until the next read or `consumeRequestBatch`.
    pub fn readRequestBatchInto(
        self: *Connection,
        heads: []http1.RequestHead,
        header_storage: []http1.Header,
        bodies: [][]const u8,
        options: http1.ParseOptions,
    ) Error!usize {
        try self.writer_state.ensureReadable();
        defer self.request_head_deadline = null;
        if (heads.len == 0 or heads.len != bodies.len) {
            return error.InvalidResponse;
        }
        const required_header_slots = std.math.mul(
            usize,
            heads.len,
            options.max_headers,
        ) catch return error.TooManyHeaders;
        if (options.max_headers == 0 or
            header_storage.len < required_header_slots)
        {
            return error.TooManyHeaders;
        }
        const max_batch_head_bytes = std.math.mul(
            usize,
            heads.len,
            self.limits.max_head_bytes,
        ) catch return error.BodyTooLarge;
        const max_batch_body_bytes = std.math.mul(
            usize,
            heads.len,
            self.limits.max_body_bytes,
        ) catch return error.BodyTooLarge;
        _ = std.math.add(
            usize,
            max_batch_head_bytes,
            max_batch_body_bytes,
        ) catch return error.BodyTooLarge;
        var timed_head_index: ?usize = null;

        while (true) {
            var offset: usize = 0;
            var complete = true;
            var has_chunked = false;
            var read_limit: ?usize = null;
            for (heads, bodies, 0..) |*head, *body, index| {
                const headers = header_storage[index * options.max_headers ..][0..options.max_headers];
                head.* = http1.parseRequestHead(
                    self.inbuf.items[offset..],
                    headers,
                    options,
                ) catch |err| switch (err) {
                    error.BufferTooShort => {
                        if (self.limits.request_head_timeout != null and
                            timed_head_index != index)
                        {
                            self.request_head_deadline =
                                try headReadDeadline(
                                    self.transport(),
                                    self.limits.request_head_timeout.?,
                                );
                            timed_head_index = index;
                        }
                        // A missing terminator must still respect the limit of
                        // this request head, rather than consuming the aggregate
                        // allowance of all later pipeline entries.
                        _ = try findHttpHeadEndWithinLimit(
                            self.inbuf.items[offset..],
                            self.limits.max_head_bytes,
                        );
                        read_limit = std.math.add(
                            usize,
                            offset,
                            self.limits.max_head_bytes,
                        ) catch return error.BodyTooLarge;
                        complete = false;
                        break;
                    },
                    else => return err,
                };
                head.from = self.peerAddress();
                // Header completion ends this request's budget even when its
                // body is incomplete. A later pipelined head receives a fresh
                // budget when parsing first needs more transport bytes.
                if (timed_head_index == index) {
                    self.request_head_deadline = null;
                    timed_head_index = null;
                }
                if (head.head_len > self.limits.max_head_bytes) {
                    return error.HeadersTooLarge;
                }
                if (head.must_close and index + 1 != heads.len) {
                    // A TE+CL request is parseable only so an application can
                    // answer it before retiring the connection. Never treat a
                    // following wire prefix as another request in this batch.
                    return error.InvalidResponse;
                }
                const message_len = if (head.body_framing == .chunked) blk: {
                    has_chunked = true;
                    const layout = message_framing.chunkedBodyLayout(
                        self.inbuf.items[offset + head.head_len ..],
                        self.limits.max_head_bytes,
                        self.limits.max_body_bytes,
                    ) catch |err| switch (err) {
                        error.BufferTooShort => {
                            const max_chunk_wire_bytes =
                                message_framing.maxChunkedWireBytes(
                                    self.limits.max_head_bytes,
                                    self.limits.max_body_bytes,
                                );
                            read_limit = std.math.add(
                                usize,
                                offset + head.head_len,
                                max_chunk_wire_bytes,
                            ) catch return error.BodyTooLarge;
                            complete = false;
                            break;
                        },
                        else => |e| return e,
                    };
                    const body_start = offset + head.head_len;
                    try http1.validateTrailerFields(
                        self.inbuf.items[body_start + layout.trailer_start .. body_start + layout.trailer_start + layout.trailer_fields_len],
                        options,
                    );
                    break :blk std.math.add(
                        usize,
                        head.head_len,
                        layout.wire_len,
                    ) catch return error.BodyTooLarge;
                } else blk: {
                    const known_len = (try head.messageLength()) orelse
                        return error.InvalidResponse;
                    if (known_len < head.head_len) {
                        return error.InvalidResponse;
                    }
                    if (known_len - head.head_len >
                        self.limits.max_body_bytes)
                    {
                        return error.BodyTooLarge;
                    }
                    break :blk known_len;
                };
                const next_offset = std.math.add(
                    usize,
                    offset,
                    message_len,
                ) catch return error.BodyTooLarge;
                if (next_offset > self.inbuf.items.len) {
                    read_limit = next_offset;
                    complete = false;
                    break;
                }
                body.* = self.inbuf.items[offset + head.head_len .. next_offset];
                offset = next_offset;
            }
            if (complete) {
                self.request_head_deadline = null;
                if (!has_chunked) return offset;
                return request_batch.compactValidatedRequests(
                    &self.inbuf,
                    heads,
                    header_storage,
                    bodies,
                    options,
                    offset,
                    self.limits.max_head_bytes,
                    self.limits.max_body_bytes,
                );
            }

            // Bound only the currently incomplete member. Complete batches may
            // coexist with an arbitrarily large already-buffered suffix.
            const current_read_limit = read_limit orelse unreachable;
            if (self.inbuf.items.len >= current_read_limit) {
                return error.BodyTooLarge;
            }
            var read_buffer: [16 * 1024]u8 = undefined;
            const remaining = current_read_limit - self.inbuf.items.len;
            const destination =
                read_buffer[0..@min(remaining, read_buffer.len)];
            const count = connectionReadHeadSome(self, destination) catch |read_err|
                {
                    if (read_err == error.Timeout) {
                        self.writer_state.phase = .unusable;
                    }
                    return read_err;
                };
            if (count == 0) return error.ConnectionClosed;
            try self.inbuf.appendSlice(
                self.allocator,
                read_buffer[0..count],
            );
        }
    }

    pub fn consumeRequestBatch(
        self: *Connection,
        consumed: usize,
    ) Error!void {
        if (consumed > self.inbuf.items.len) return error.InvalidResponse;
        discardPrefix(&self.inbuf, consumed);
        if (consumed != 0) self.request_continue.reset();
    }

    pub fn writeResponse(self: *Connection, response: ResponseOptions) Error!void {
        try self.writer_state.ensureAvailable();
        try self.writeResponseFailClosed(
            response,
            self.defaultResponseDate(),
        );
    }

    pub fn writeResponseWithDeadline(self: *Connection, response: ResponseOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try runtime.deadline_policy.usableAwake(self.io, deadline);
        try self.writer_state.ensureAvailable();
        return self.writeResponseFailClosedUntil(response, self.defaultResponseDate(), deadline);
    }

    pub fn writeResponseWithTimeout(self: *Connection, response: ResponseOptions, timeout: std.Io.Duration) Error!void {
        return self.writeResponseWithDeadline(response, (try runtime.deadline_policy.fromTimeout(self.io, timeout)).?);
    }

    /// Keep deterministic validation/allocation failures retryable, but retire
    /// the connection after any transport write error because an unknown wire
    /// prefix may already be visible to the peer.
    fn writeResponseFailClosed(
        self: *Connection,
        response: ResponseOptions,
        default_date: ?[]const u8,
    ) Error!void {
        return self.writeResponseFailClosedUntil(response, default_date, null);
    }

    fn writeResponseFailClosedUntil(self: *Connection, response: ResponseOptions, default_date: ?[]const u8, deadline: ?std.Io.Clock.Timestamp) Error!void {
        const parts = try runtime_write.prepareServerResponse(
            self.allocator,
            response,
            default_date,
            &self.write_scratch,
        );
        var transport_started = false;
        var committed: usize = 0;
        const output = if (deadline) |absolute|
            @import("writer_output.zig").connection(self, &.{ parts.header, parts.body }, &committed, &transport_started, absolute)
        else
            writeMessagePartsWithStrategy(self.allocator, self.transport(), self.limits.write_strategy, parts, &self.write_scratch, &transport_started);
        output catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
    }

    /// Start a response whose body is supplied incrementally.
    ///
    /// Body-forbidden responses finish at the head. Ordinary responses retain
    /// the connection slot until `finish` or `finishTrailers`.
    pub fn startResponse(
        self: *Connection,
        options: StreamingResponseOptions,
    ) Error!ResponseWriter {
        return self.startResponseUntil(options, null);
    }

    pub fn startResponseWithDeadline(self: *Connection, options: StreamingResponseOptions, deadline: std.Io.Clock.Timestamp) Error!ResponseWriter {
        _ = try runtime.deadline_policy.usableAwake(self.io, deadline);
        return self.startResponseUntil(options, deadline);
    }

    pub fn startResponseWithTimeout(self: *Connection, options: StreamingResponseOptions, timeout: std.Io.Duration) Error!ResponseWriter {
        return self.startResponseWithDeadline(options, (try runtime.deadline_policy.fromTimeout(self.io, timeout)).?);
    }

    fn startResponseUntil(self: *Connection, options: StreamingResponseOptions, deadline: ?std.Io.Clock.Timestamp) Error!ResponseWriter {
        const generation = try self.writer_state.begin();
        errdefer if (self.writer_state.phase == .writing) {
            self.writer_state.phase = .idle;
        };

        const prepared = try runtime_write.streaming.prepareServerResponse(
            self.allocator,
            options,
            self.defaultResponseDate(),
            &self.write_scratch,
        );
        const announced_trailers = self.write_scratch.trailerHeaders();
        const active_transport = self.transport();
        var committed: usize = 0;
        const output = if (deadline) |absolute|
            active_transport.writeAllWithDeadline(prepared.head, &committed, absolute)
        else
            active_transport.writeAll(prepared.head);
        output catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return .{
            .body = StreamingBodyWriter.initWithDeadline(
                self.allocator,
                &self.writer_state,
                generation,
                self,
                connectionWriteSlices,
                &self.write_scratch,
                prepared,
                announced_trailers,
                true,
                self.io,
                @import("writer_output.zig").connection,
            ),
        };
    }

    /// Validate and flush several pipelined responses as one transport write.
    ///
    /// Like Hyper's `pipeline_flush`, this avoids delayed-ACK/Nagle stalls
    /// caused by one tiny write per response. The whole batch is encoded before
    /// the socket call, so a later invalid response cannot leave an already
    /// visible prefix. Storage is retained on the connection for steady-state
    /// allocation-free reuse.
    pub fn writeResponses(
        self: *Connection,
        responses: []const ResponseOptions,
    ) Error!void {
        try self.writer_state.ensureAvailable();
        const default_date = self.defaultResponseDate();
        const strategy = responseBatchWriteStrategy(
            self.limits.write_strategy,
            responseBatchBodyBytes(responses),
        );
        if (strategy == .flatten) {
            const bytes = try prepareResponsesCoalesced(
                self.allocator,
                responses,
                default_date,
                &self.write_scratch,
            );
            self.transport().writeAll(bytes) catch |err| {
                self.writer_state.phase = .unusable;
                return err;
            };
            return;
        }
        const parts = try runtime_write.prepareServerResponseParts(
            self.allocator,
            responses,
            default_date,
            &self.write_scratch,
        );
        var transport_started = false;
        writeSlicesWithStrategy(
            self.allocator,
            self.transport(),
            strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
    }

    fn defaultResponseDate(self: *const Connection) ?[]const u8 {
        if (!self.limits.auto_date_header) return null;
        return http_date.valueNow(self.io);
    }

    pub fn serveOne(self: *Connection, context: anytype, comptime handler: anytype) Error!bool {
        return (try self.serveOneInternal(context, handler)) orelse
            error.ConnectionClosed;
    }

    /// Serve-loop-only tri-state: null is an orderly transport EOF before any
    /// byte of a new request; false finishes one exchange and retires; true
    /// permits another exchange. TLS close_notify is authenticated EOF. A raw
    /// TLS EOF is also safe only at this empty HTTP boundary; a partial TLS
    /// record has its own error and is never accepted. Keeping the read catch
    /// here prevents handler or response-write failures from being mistaken
    /// for a clean peer half-close.
    fn serveOneInternal(
        self: *Connection,
        context: anytype,
        comptime handler: anytype,
    ) Error!?bool {
        if (self.graceful_shutdown_requested) return false;
        const boundary_was_empty = self.inbuf.items.len == 0;
        var failure_stage: RequestReadStage = .head;
        var request = self.readRequestInternal(.{
            .max_headers = self.limits.max_request_headers,
            .max_request_target_bytes = self.limits.max_request_target_bytes,
        }, &failure_stage) catch |err| {
            const transport_eof = if (self.tls_server_conn) |tls_connection|
                (err == error.ConnectionClosed and
                    tls_connection.receivedCloseNotify()) or
                    err == error.UnexpectedEof
            else
                err == error.ConnectionClosed;
            if (transport_eof and
                boundary_was_empty and
                self.inbuf.items.len == 0)
            {
                return null;
            }
            const automatic_response: ?ResponseOptions = if (failure_stage != .head) null else switch (err) {
                error.HeadersTooLarge, error.TooManyHeaders => .{
                    .status = 431,
                    .reason = "Request Header Fields Too Large",
                    .headers = &.{.{
                        .name = "Connection",
                        .value = "close",
                    }},
                },
                error.MalformedStartLine,
                error.MalformedHeader,
                error.InvalidMethod,
                error.InvalidVersion,
                error.InvalidHost,
                => .{
                    .status = 400,
                    .reason = "Bad Request",
                    .headers = &.{.{
                        .name = "Connection",
                        .value = "close",
                    }},
                },
                error.UriTooLong => .{
                    .status = 414,
                    .reason = "URI Too Long",
                    .headers = &.{.{
                        .name = "Connection",
                        .value = "close",
                    }},
                },
                else => null,
            };
            if (automatic_response) |response| {
                // The connection-owning server can safely emit this standard
                // response because no application response has started. Keep
                // the original parse error for serveUntil observers.
                self.writeResponse(response) catch |write_err| {
                    self.writer_state.phase = .unusable;
                    return write_err;
                };
                self.writer_state.phase = .unusable;
            }
            return err;
        };
        defer request.deinit(self.allocator);
        return @as(?bool, try self.serveRequest(
            context,
            handler,
            request.request,
        ));
    }

    fn serveRequest(
        self: *Connection,
        context: anytype,
        comptime handler: anytype,
        request: http1.Request,
    ) Error!bool {
        const request_keep_alive = request.keepAlive();
        var response = try handler(context, request);
        if (response.status >= 100 and
            response.status < 200 and
            response.status != 101)
        {
            // A serve handler can return only one response, so treating an
            // informational head as complete would leave a conforming client
            // waiting for the final response while this loop reads the next
            // request. Keep low-level writeResponse available for callers that
            // explicitly send one or more 1xx heads before their final head.
            self.writeResponse(.{
                .status = 500,
                .reason = "Internal Server Error",
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .request_method = request.method,
            }) catch |err| {
                self.writer_state.phase = .unusable;
                return err;
            };
            self.writer_state.phase = .unusable;
            return error.InvalidResponse;
        }
        var adjusted = try adjustResponseForServeLoop(
            self.allocator,
            request,
            response,
            self.graceful_shutdown_requested or !self.limits.keep_alive,
        );
        defer adjusted.deinit(self.allocator);
        response = adjusted.response;
        if (response.request_method == null) response.request_method = request.method;
        const response_keep_alive = responseOptionsKeepAlive(response);
        try self.writeResponse(response);
        if (response.status == 101 or
            (request.method == .CONNECT and
                response.status >= 200 and response.status < 300))
        {
            // These final heads switch away from HTTP message framing. The
            // callback-only serve API cannot hand the transport to the
            // application, so stop before tunneled bytes can be parsed as a
            // subsequent request. Explicit handoff uses acceptUpgrade or
            // acceptConnectTunnel instead.
            self.writer_state.phase = .unusable;
            return false;
        }
        if (self.graceful_shutdown_requested or !self.limits.keep_alive) {
            self.writer_state.phase = .unusable;
            return false;
        }
        return request_keep_alive and response_keep_alive;
    }

    pub fn serve(self: *Connection, context: anytype, comptime handler: anytype, max_requests: usize) Error!usize {
        var served: usize = 0;
        while (served < max_requests) : (served += 1) {
            if (self.graceful_shutdown_requested) return served;
            const keep_going = (try self.serveOneInternal(
                context,
                handler,
            )) orelse return served;
            if (!keep_going) return served + 1;
        }
        return served;
    }

    pub fn acceptConnectTunnel(self: *Connection, request: http1.Request, response_headers: []const http1.Header) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        if (request.method != .CONNECT or request.body.len != 0 or request.trailers.len != 0) return error.InvalidResponse;
        try http1.validateConnectTarget(request.target);
        try self.writeResponseFailClosed(.{
            .status = 200,
            .reason = "Connection Established",
            .headers = response_headers,
            .request_method = .CONNECT,
        }, null);
        // The response switches this connection out of HTTP message framing.
        // Keep the parent unusable while Tunnel owns the transport.
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_server_conn = self.tls_server_conn,
            .inbuf = &self.inbuf,
        };
    }

    /// Accept a validated generic Upgrade request and hand off the same
    /// transport after sending 101. The request parser may already have read
    /// upgraded-protocol bytes; `Tunnel` preserves that buffered suffix.
    pub fn acceptUpgrade(
        self: *Connection,
        request: http1.Request,
        protocol: []const u8,
        response_headers: []const http1.Header,
    ) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try validateUpgradeProtocol(protocol);
        try rejectUpgradeManagedHeaders(response_headers);
        const requested = request.upgradeProtocol() orelse
            return error.InvalidResponse;
        if (request.version != .http_1_1 or
            !std.ascii.eqlIgnoreCase(requested, protocol) or
            request.body.len != 0 or request.trailers.len != 0)
        {
            return error.InvalidResponse;
        }
        var headers: [2]http1.Header = .{
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Upgrade", .value = protocol },
        };
        var merged: std.ArrayList(http1.Header) = .empty;
        defer merged.deinit(self.allocator);
        try merged.appendSlice(self.allocator, &headers);
        try merged.appendSlice(self.allocator, response_headers);
        try self.writeResponseFailClosed(.{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = merged.items,
            .request_method = request.method,
        }, null);
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_server_conn = self.tls_server_conn,
            .inbuf = &self.inbuf,
        };
    }
};
