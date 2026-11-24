//! Unified HTTP/1.1, HTTP/2 and explicit HTTP/3 URI client.
//!
//! HTTPS performs one vail TLS handshake offering the configured ALPN list,
//! then transfers that exact authenticated connection into the selected HTTP
//! runtime. Cleartext cannot negotiate ALPN and therefore uses an explicit
//! prior-knowledge policy.

const std = @import("std");
const http1 = @import("../http1/mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2 = @import("../http2/mod.zig");
const http2_runtime = @import("../http2/runtime.zig");
const http3_runtime = @import("../http3/runtime.zig");
const http3_connection = @import("client/http3_connection.zig");
const protocol_selection = @import("client/protocol_selection.zig");
const deadline_policy = @import("../internal/deadline.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const address_resolver = @import("../internal/address_resolver.zig");
const proxy_socks5 = @import("../proxy/socks5.zig");
const socket_options = @import("../internal/socket_options.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const uri_redirect = @import("../http1/runtime/redirect.zig");
const types = @import("client/types.zig");
const header_mapping = @import("client/header_mapping.zig");
const redirect = @import("client/redirect.zig");
const duplex = @import("client/duplex.zig");
const reader_io = @import("client/reader_io.zig");
const client_trust = @import("../quic/client_trust.zig");

pub const Error = http1_runtime.Error || http2_runtime.Error || http3_runtime.Error || std.Io.Timeout.Error || std.Io.ConcurrentError ||
    proxy_socks5.Error || uri_redirect.Error || error{
    InvalidAddressConnectPolicy,
    InvalidClientOptions,
    StreamingBodyUnsupported,
    /// A TCP CA bundle was configured without explicit H3 trust; QUIC cannot
    /// consume the TCP bundle representation.
    UnsupportedH3TrustConfiguration,
    /// A request source failed, independently of the connection transport.
    RequestBodyReadFailed,
};
pub const ResponseTimeoutError = Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;
pub const Protocol = types.Protocol;
pub const ProtocolPolicy = types.ProtocolPolicy;
pub const Http3ConnectOptions = types.Http3ConnectOptions;
pub const CleartextProtocol = types.CleartextProtocol;
pub const AddressResolver = types.AddressResolver;
pub const AddressConnectPolicy = types.AddressConnectPolicy;
pub const HappyEyeballsOptions = types.HappyEyeballsOptions;
pub const Socks5Options = types.Socks5Options;
pub const Socks5Proxy = types.Socks5Proxy;
pub const HttpProxy = types.HttpProxy;
pub const HttpProxyOptions = types.HttpProxyOptions;
pub const Header = types.Header;
pub const HeaderIterator = types.HeaderIterator;
pub const ReaderBody = types.ReaderBody;
pub const ReaderReplay = types.ReaderReplay;
pub const BodySource = types.BodySource;
pub const BodyLength = types.BodyLength;
pub const RequestHandle = duplex.Handle;
pub const ResponseSink = duplex.ResponseSink;
pub const ResponseHead = duplex.ResponseHead;
pub const UploadProgress = duplex.UploadProgress;
pub const DuplexHeader = duplex.Header;
pub const startHttp3Request = duplex.startHttp3;
pub const startHttp3RequestWithDeadline = duplex.startHttp3WithDeadline;
pub const startHttp3RequestWithTimeout = duplex.startHttp3WithTimeout;
pub const RequestOptions = types.RequestOptions;
pub const RedirectOptions = types.RedirectOptions;
pub const Options = types.Options;
pub const ResponseValue = types.ResponseValue;
pub const OwnedResponse = types.OwnedResponse;
pub const EarlyDataMetadata = types.EarlyDataMetadata;
pub const RedirectedResponse = types.RedirectedResponse;

const max_stack_headers = header_mapping.max_stack_headers;
const max_stack_trailers = header_mapping.max_stack_trailers;

const ConnectionProtocol = types.NegotiatedProtocol;

const ConnectionValue = union(ConnectionProtocol) {
    http1: http1_runtime.Client,
    http2: http2_runtime.Connection,
    http3: *http3_connection.Owner,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    value: ConnectionValue,
    /// Set only for cleartext HTTP/1.1 forward-proxy connections. Requests
    /// passed to this connection must use an absolute-form URI.
    forward_proxy: ?HttpProxy = null,

    pub fn isForwardProxy(self: *const Connection) bool {
        return self.forward_proxy != null;
    }

    pub fn close(self: *Connection) void {
        switch (self.value) {
            .http1 => |*client| client.close(),
            .http2 => |*connection| connection.close(),
            .http3 => |owner| {
                // Match the H1/H2 close-notify contract with a best-effort
                // QUIC CONNECTION_CLOSE carrying NO_ERROR.
                owner.client.established.connection.closeApplication(
                    0,
                    "",
                ) catch {};
                owner.deinit();
            },
        }
        self.* = undefined;
    }

    pub fn closeWithoutCloseNotify(self: *Connection) void {
        switch (self.value) {
            .http1 => |*value| value.closeWithoutCloseNotify(),
            .http2 => |*value| value.closeWithoutCloseNotify(),
            .http3 => |owner| owner.deinit(),
        }
        self.* = undefined;
    }

    pub fn closeWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!void {
        defer self.* = undefined;
        return switch (self.value) {
            .http1 => |*value| value.closeWithDeadline(deadline),
            .http2 => |*value| value.closeWithDeadline(deadline),
            .http3 => |owner| blk: {
                defer owner.deinit();
                _ = try deadline_policy.usableAwake(owner.client.connectionIo(), deadline);
                // Match `close()`: deliver a best-effort CONNECTION_CLOSE after
                // validating the deadline. The deadline bounds the call, not
                // the socket write, which is a single UDP datagram.
                owner.client.established.connection.closeApplication(0, "") catch {};
                break :blk {};
            },
        };
    }

    /// Convenience form of `closeWithDeadline` using an awake-clock budget.
    /// An expired budget still retires the transport, matching the deadline
    /// form's no-output cleanup contract.
    pub fn closeWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) {
            self.closeWithoutCloseNotify();
            return error.Timeout;
        }
        return self.closeWithDeadline(.fromNow(connectionIo(self), .{ .raw = timeout, .clock = .awake }));
    }

    pub fn protocol(self: Connection) Protocol {
        return switch (self.value) {
            .http1 => .http1,
            .http2 => .http2,
            .http3 => .http3,
        };
    }

    pub fn isReusable(self: *const Connection) bool {
        return switch (self.value) {
            .http1 => |*client| client.isReusableForPool(),
            .http2 => |*connection| connection.isReusable(),
            .http3 => |owner| owner.client.isReusable(),
        };
    }

    /// Current remote transport IP peer. H3 follows the current QUIC path;
    /// TCP proxy tunnels report the proxy. Unix streams and unavailable native
    /// socket queries return null.
    pub fn peerAddress(self: *const Connection) ?std.Io.net.IpAddress {
        return switch (self.value) {
            .http1 => |*client| client.peerAddress(),
            .http2 => |*connection| connection.peerAddress(),
            .http3 => |owner| owner.client.remoteAddress(),
        };
    }

    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedAlpn(),
            .http2 => |*connection| connection.negotiatedAlpn(),
            .http3 => |owner| owner.client.negotiatedAlpn(),
        };
    }

    /// Verified peer certificate chain for the authenticated transport.
    /// Cleartext connections return null; slices remain valid until close.
    pub fn peerCertificates(self: *const Connection) ?[]const []const u8 {
        return switch (self.value) {
            .http1 => |*client| client.peerCertificates(),
            .http2 => |*connection| connection.peerCertificates(),
            .http3 => |owner| owner.client.peerCertificates(),
        };
    }

    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedCipherSuite(),
            .http2 => |*connection| connection.negotiatedCipherSuite(),
            .http3 => |owner| @enumFromInt(
                @intFromEnum(owner.client.negotiatedCipherSuite()),
            ),
        };
    }

    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedTranscriptHash(),
            .http2 => |*connection| connection.negotiatedTranscriptHash(),
            .http3 => |owner| owner.client.negotiatedTranscriptHash(),
        };
    }

    /// Export RFC 8446 channel-bound keying material. Cleartext returns
    /// `error.PostHandshakeTlsUnavailable`.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return switch (self.value) {
            .http1 => |*client| client.exportKeyingMaterial(label, context, out),
            .http2 => |*connection| connection.exportKeyingMaterial(label, context, out),
            .http3 => |owner| owner.client.exportKeyingMaterial(label, context, out),
        };
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedTlsProtocol(),
            .http2 => |*connection| connection.negotiatedTlsProtocol(),
            .http3 => .tls13,
        };
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        return switch (self.value) {
            .http1 => |*client| client.wasTlsSessionResumed(),
            .http2 => |*connection| connection.wasTlsSessionResumed(),
            .http3 => |owner| owner.client.established.resumed,
        };
    }

    /// Whether the H3 connection accepted, rejected or never received a 0-RTT
    /// offer. H1/H2 return null because TCP TLS has no QUIC early data.
    pub fn earlyDataStatus(
        self: *const Connection,
    ) ?@TypeOf(self.value.http3.client.established.early_data_status) {
        return switch (self.value) {
            .http1, .http2 => null,
            .http3 => |owner| owner.client.established.early_data_status,
        };
    }

    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?tls_stream.Tls12SessionTicket {
        return switch (self.value) {
            .http1 => |*client| client.takeTls12SessionTicket(),
            .http2 => |*connection| connection.takeTls12SessionTicket(),
            .http3 => null,
        };
    }

    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        return switch (self.value) {
            .http1 => |*client| client.takeTls13SessionTicket(),
            .http2 => |*connection| connection.takeTls13SessionTicket(),
            .http3 => null,
        };
    }

    /// Start a TLS 1.3 application traffic-key update. H1/H2 rotate after the
    /// current write completes with `update_not_requested`; H3 advances the
    /// QUIC 1-RTT key phase. Use the protocol-specific connection when a
    /// peer-requested TCP update or the H3 acknowledgment flag is required.
    pub fn initiateKeyUpdate(self: *Connection) Error!void {
        return switch (self.value) {
            .http1 => |*client| client.updateTrafficKeys(false),
            .http2 => |*connection| connection.updateTrafficKeys(false),
            .http3 => |owner| owner.client.initiateKeyUpdate(),
        };
    }

    /// TLS 1.3 key-update counters. Cleartext returns null. QUIC reports its
    /// sent/received key phases with `awaiting_peer_response = false` because
    /// QUIC updates are unilateral; use the H3 owner for its ack flag.
    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        return switch (self.value) {
            .http1 => |*client| client.keyUpdateCounts(),
            .http2 => |*connection| connection.keyUpdateCounts(),
            .http3 => |owner| .{
                .sent = owner.client.localKeyUpdateCount(),
                .received = owner.client.peerKeyUpdateCount(),
                .awaiting_peer_response = false,
            },
        };
    }

    pub fn request(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
    ) Error!OwnedResponse {
        return self.requestBefore(target, options, null) catch |err| switch (err) {
            else => |other| return @errorCast(other),
        };
    }

    pub fn requestWithDeadline(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        _ = try deadline_policy.usableAwake(connectionIo(self), deadline);
        return self.requestBefore(target, options, deadline);
    }

    pub fn requestWithTimeout(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(
            target,
            options,
            .fromNow(connectionIo(self), .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Open a streaming request. The caller writes the request body and then
    /// consumes the response through a callback sink.
    pub fn startRequest(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
    ) Error!RequestHandle {
        return self.startRequestBefore(target, options, null);
    }

    /// Bound request-head setup; the returned handle takes explicit body and
    /// response deadlines for later operations.
    pub fn startRequestWithDeadline(self: *Connection, target: []const u8, options: RequestOptions, deadline: std.Io.Clock.Timestamp) Error!RequestHandle {
        _ = try deadline_policy.usableAwake(connectionIo(self), deadline);
        return self.startRequestBefore(target, options, deadline);
    }

    pub fn startRequestWithTimeout(self: *Connection, target: []const u8, options: RequestOptions, timeout: std.Io.Duration) Error!RequestHandle {
        return self.startRequestWithDeadline(target, options, (try deadline_policy.fromTimeout(connectionIo(self), timeout)).?);
    }

    fn startRequestBefore(self: *Connection, target: []const u8, options: RequestOptions, deadline: ?std.Io.Clock.Timestamp) Error!RequestHandle {
        if (self.forward_proxy != null) return error.StreamingBodyUnsupported;
        switch (self.value) {
            .http3 => |owner| return owner.start(target, options, requestBodyLength(options), deadline) catch |err| return @errorCast(err),
            .http1 => |*client| {
                var header_stack: [max_stack_headers]http1.Header = undefined;
                var trailer_stack: [max_stack_trailers]http1.Header = undefined;
                var headers = try header_mapping.mapHttp1(
                    self.allocator,
                    options.headers,
                    &header_stack,
                );
                defer headers.deinit(self.allocator);
                var trailers = try header_mapping.mapHttp1(
                    self.allocator,
                    options.trailers,
                    &trailer_stack,
                );
                defer trailers.deinit(self.allocator);
                var trailer_names: [max_stack_trailers][]const u8 = undefined;
                var names = try header_mapping.names(self.allocator, trailers.items, &trailer_names);
                defer names.deinit(self.allocator);
                const request_options: http1_runtime.StreamingRequestOptions = .{
                    .method = try http1.Method.parse(options.method),
                    .target = target,
                    .headers = headers.items,
                    .body_length = requestBodyLength(options),
                    .trailer_names = names.items,
                };
                const writer = if (deadline) |absolute| try client.startRequestWithDeadline(request_options, absolute) else try client.startRequest(request_options);
                return RequestHandle.initHttp1(self.allocator, writer);
            },
            .http2 => |*connection| {
                var header_stack: [max_stack_headers]http2.Hpack.HeaderField =
                    undefined;
                var trailer_stack: [max_stack_trailers]http2.Hpack.HeaderField =
                    undefined;
                var headers = try header_mapping.mapHttp2(
                    self.allocator,
                    options.headers,
                    &header_stack,
                );
                defer headers.deinit(self.allocator);
                var trailers = try header_mapping.mapHttp2(
                    self.allocator,
                    options.trailers,
                    &trailer_stack,
                );
                defer trailers.deinit(self.allocator);
                const request_options: http2_runtime.StreamingRequestOptions = .{
                    .method = options.method,
                    .path = target,
                    .headers = headers.items,
                    .body_length = requestBodyLength(options),
                };
                const writer = if (deadline) |absolute| try connection.startRequestWithDeadline(request_options, absolute) else try connection.startRequest(request_options);
                return RequestHandle.initHttp2(self.allocator, writer);
            },
        }
    }

    fn requestBefore(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        const body_slice = if (options.body_source) |source| switch (source) {
            .slice => |body| body,
            .reader => options.body,
        } else options.body;
        switch (self.value) {
            .http3 => |owner| return owner.request(target, options, deadline) catch |err| return @errorCast(err),
            .http1 => |*client| {
                var header_stack: [max_stack_headers]http1.Header = undefined;
                var trailer_stack: [max_stack_trailers]http1.Header = undefined;
                var headers = try header_mapping.mapHttp1(
                    self.allocator,
                    options.headers,
                    &header_stack,
                );
                defer headers.deinit(self.allocator);
                var trailers = try header_mapping.mapHttp1(
                    self.allocator,
                    options.trailers,
                    &trailer_stack,
                );
                defer trailers.deinit(self.allocator);
                const method = try http1.Method.parse(options.method);
                if (options.body_source) |source| {
                    switch (source) {
                        .reader => |reader_body| {
                            if (self.forward_proxy != null) {
                                return error.StreamingBodyUnsupported;
                            }
                            return streamHttp1Body(
                                self.allocator,
                                client,
                                target,
                                method,
                                headers.items,
                                trailers.items,
                                reader_body,
                                deadline,
                            );
                        },
                        .slice => {},
                    }
                }
                const request_options: http1_runtime.RequestOptions = .{
                    .method = method,
                    .target = target,
                    .headers = headers.items,
                    .body = body_slice,
                    .trailers = trailers.items,
                };
                if (self.forward_proxy) |proxy| {
                    var proxy_stack: [max_stack_headers]http1.Header = undefined;
                    var proxy_headers = try header_mapping.mapHttp1(
                        self.allocator,
                        proxy.headers,
                        &proxy_stack,
                    );
                    defer proxy_headers.deinit(self.allocator);
                    const proxy_options: http1_runtime.ProxyOptions = .{
                        .headers = proxy_headers.items,
                        .address_resolver = proxy.options.address_resolver,
                        .address_connect_policy = proxy.options.address_connect_policy,
                    };
                    const response = if (deadline) |absolute|
                        try client.requestForwardProxyUriWithDeadline(
                            target,
                            request_options,
                            proxy_options,
                            absolute,
                        )
                    else
                        try client.requestForwardProxyUri(
                            target,
                            request_options,
                            proxy_options,
                        );
                    return .{
                        .allocator = self.allocator,
                        .value = .{ .http1 = response },
                    };
                }
                const response = if (deadline) |absolute|
                    try client.requestWithDeadline(request_options, absolute)
                else
                    try client.request(request_options);
                return .{
                    .allocator = self.allocator,
                    .value = .{ .http1 = response },
                };
            },
            .http2 => |*connection| {
                var header_stack: [max_stack_headers]http2.Hpack.HeaderField =
                    undefined;
                var trailer_stack: [max_stack_trailers]http2.Hpack.HeaderField =
                    undefined;
                var headers = try header_mapping.mapHttp2(
                    self.allocator,
                    options.headers,
                    &header_stack,
                );
                defer headers.deinit(self.allocator);
                var trailers = try header_mapping.mapHttp2(
                    self.allocator,
                    options.trailers,
                    &trailer_stack,
                );
                defer trailers.deinit(self.allocator);
                if (options.body_source) |source| {
                    switch (source) {
                        .reader => |reader_body| return streamHttp2Body(
                            self.allocator,
                            connection,
                            target,
                            options.method,
                            headers.items,
                            trailers.items,
                            reader_body,
                            deadline,
                        ),
                        .slice => {},
                    }
                }
                const request_options: http2_runtime.RequestOptions = .{
                    .method = options.method,
                    .path = target,
                    .headers = headers.items,
                    .body = body_slice,
                    .trailers = trailers.items,
                };
                var response = if (deadline) |absolute|
                    try connection.requestWithDeadline(
                        request_options,
                        absolute,
                    )
                else
                    try connection.request(request_options);
                errdefer response.deinit(self.allocator);
                return .{
                    .allocator = self.allocator,
                    .value = .{ .http2 = response },
                };
            },
        }
    }

    fn connectionIo(self: *const Connection) std.Io {
        return switch (self.value) {
            .http1 => |client| client.io,
            .http2 => |connection| connection.io,
            .http3 => |owner| owner.client.connectionIo(),
        };
    }
};

const streaming_chunk_size = 16 * 1024;

fn streamHttp1Body(
    allocator: std.mem.Allocator,
    client: *http1_runtime.Client,
    target: []const u8,
    method: http1.Method,
    headers: []const http1.Header,
    trailers: []const http1.Header,
    body: types.ReaderBody,
    deadline: ?std.Io.Clock.Timestamp,
) ResponseTimeoutError!OwnedResponse {
    var trailer_names: [max_stack_trailers][]const u8 = undefined;
    var names = try header_mapping.names(allocator, trailers, &trailer_names);
    defer names.deinit(allocator);
    const request_options: http1_runtime.StreamingRequestOptions = .{
        .method = method,
        .target = target,
        .headers = headers,
        .body_length = body.length,
        .trailer_names = names.items,
    };
    var writer = if (deadline) |until| try client.startRequestWithDeadline(request_options, until) else try client.startRequest(request_options);
    defer writer.deinit();

    if (writer.expects_continue) {
        const continued = if (deadline) |until| try writer.waitForContinueWithDeadline(until) else try writer.waitForContinue();
        switch (continued) {
            .proceed => {},
            .final_response => |response| {
                return .{
                    .allocator = allocator,
                    .value = .{ .http1 = response },
                };
            },
        }
    }

    var buffer: [streaming_chunk_size]u8 = undefined;
    while (true) {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(client.io, absolute);
        }
        const read = try reader_io.readBefore(client.io, body.reader, &buffer, deadline);
        if (read == 0) break;
        if (deadline) |until| try writer.writeWithDeadline(buffer[0..read], until) else try writer.write(buffer[0..read]);
    }

    if (trailers.len != 0) {
        if (deadline) |until| try writer.finishTrailersWithDeadline(trailers, until) else try writer.finishTrailers(trailers);
    } else {
        if (deadline) |until| try writer.finishWithDeadline(until) else try writer.finish();
    }

    const response = if (deadline) |absolute|
        try writer.readResponseWithDeadline(absolute)
    else
        try writer.readResponse();
    return .{
        .allocator = allocator,
        .value = .{ .http1 = response },
    };
}

fn streamHttp2Body(
    allocator: std.mem.Allocator,
    connection: *http2_runtime.Connection,
    target: []const u8,
    method: []const u8,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
    body: types.ReaderBody,
    deadline: ?std.Io.Clock.Timestamp,
) ResponseTimeoutError!OwnedResponse {
    const request_options: http2_runtime.StreamingRequestOptions = .{
        .method = method,
        .path = target,
        .headers = headers,
        .body_length = body.length,
    };
    var writer = if (deadline) |absolute|
        try connection.startRequestWithDeadline(request_options, absolute)
    else
        try connection.startRequest(request_options);
    defer writer.deinit();

    var buffer: [streaming_chunk_size]u8 = undefined;
    while (true) {
        const read = try reader_io.readBefore(connection.io, body.reader, &buffer, deadline);
        if (read == 0) break;
        if (deadline) |absolute| {
            writer.writeWithDeadline(buffer[0..read], absolute) catch |err| switch (err) {
                error.ResponseAvailable => break,
                else => return err,
            };
        } else {
            writer.write(buffer[0..read]) catch |err| switch (err) {
                error.ResponseAvailable => break,
                else => return err,
            };
        }
    }

    if (!writer.body_finished) {
        if (trailers.len != 0) {
            if (deadline) |absolute| {
                writer.finishTrailersWithDeadline(trailers, absolute) catch |err| switch (err) {
                    error.ResponseAvailable => {},
                    else => return err,
                };
            } else {
                writer.finishTrailers(trailers) catch |err| switch (err) {
                    error.ResponseAvailable => {},
                    else => return err,
                };
            }
        } else {
            if (deadline) |absolute| {
                writer.finishWithDeadline(absolute) catch |err| switch (err) {
                    error.ResponseAvailable => {},
                    else => return err,
                };
            } else {
                writer.finish() catch |err| switch (err) {
                    error.ResponseAvailable => {},
                    else => return err,
                };
            }
        }
    }

    const response = if (deadline) |absolute|
        try writer.readResponseWithDeadline(absolute)
    else
        try writer.readResponse();
    return .{
        .allocator = allocator,
        .value = .{ .http2 = response },
    };
}

fn requestBodyLength(options: RequestOptions) ?usize {
    return options.bodyLength();
}

fn connectAuthority(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
) std.mem.Allocator.Error![]u8 {
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        return std.fmt.allocPrint(allocator, "[{s}]:{d}", .{ host, port });
    }
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
}

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) Error!Client {
        if (options.protocol_policy == .http3_only and (options.http_proxy != null or !options.tls.protocol_policy.offersTls13())) return error.InvalidClientOptions;
        if (options.protocol_policy.attemptsHttp3()) {
            const handshake = options.http3.handshake;
            if (handshake.handshake.alpn_protocols.len != 1 or !std.mem.eql(u8, handshake.handshake.alpn_protocols[0], "h3") or handshake.handshake.early_data != null) return error.InvalidClientOptions;
            if (options.protocol_policy == .http3_only and
                options.tls.ca_bundle != null and
                !client_trust.hasExplicitTrust(&handshake.handshake))
            {
                return error.UnsupportedH3TrustConfiguration;
            }
            // The 1-RTT packetizer may only emit what the endpoint socket can
            // accept; catch a larger send size before any connection attempt.
            if (handshake.handshake.initial_one_rtt_config.max_datagram_size >
                options.http3.limits.quic.max_datagram_size) return error.InvalidClientOptions;
            if (handshake.connect_timeout) |duration| if (duration.nanoseconds <= 0) return error.InvalidClientOptions;
            if (handshake.address_attempt_timeout) |duration| if (duration.nanoseconds <= 0) return error.InvalidClientOptions;
            if (options.http3.preference_timeout.nanoseconds <= 0) return error.InvalidClientOptions;
            try tcp_connect.validateAddressConnectPolicy(options.http3.address_connect_policy);
        }
        if (options.connect_timeout) |timeout| {
            if (timeout.nanoseconds <= 0) return error.InvalidClientOptions;
        }
        if (options.socks5_proxy != null and options.http_proxy != null) {
            return error.InvalidClientOptions;
        }
        if (options.http_proxy != null and
            options.cleartext_protocol == .http2_prior_knowledge)
        {
            return error.InvalidClientOptions;
        }
        if (options.http_proxy) |proxy| {
            const uri = std.Uri.parse(proxy.uri) catch return error.InvalidClientOptions;
            if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") or
                uri.query != null or uri.fragment != null or
                uri.user != null or uri.password != null)
            {
                return error.InvalidClientOptions;
            }
            const path = switch (uri.path) {
                .raw, .percent_encoded => |value| value,
            };
            if (path.len != 0 and !std.mem.eql(u8, path, "/")) {
                return error.InvalidClientOptions;
            }
            if (proxy.options.connect_timeout) |timeout| {
                if (timeout.nanoseconds <= 0) return error.InvalidClientOptions;
            }
            if (proxy.options.address_connect_policy) |policy| {
                try tcp_connect.validateAddressConnectPolicy(policy);
            }
        }
        try tcp_connect.validateAddressConnectPolicy(
            options.address_connect_policy,
        );
        return .{ .allocator = allocator, .io = io, .options = options };
    }

    pub fn deinit(self: *Client) void {
        self.* = undefined;
    }

    pub fn connectUri(
        self: *Client,
        uri_text: []const u8,
    ) Error!Connection {
        return self.connectUriBefore(uri_text, null) catch |err| switch (err) {
            else => |other| return @errorCast(other),
        };
    }

    pub fn connectUriWithDeadline(
        self: *Client,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Connection {
        return self.connectUriBefore(
            uri_text,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    pub fn connectUriWithTimeout(
        self: *Client,
        uri_text: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectUriWithDeadline(
            uri_text,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriBefore(
        self: *Client,
        uri_text: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Connection {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https"))
            true
        else if (std.ascii.eqlIgnoreCase(uri.scheme, "http"))
            false
        else
            return error.UnsupportedScheme;
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (secure) 443 else 80,
        );
        defer endpoint.deinit();
        const connect_deadline = if (deadline) |absolute|
            try deadline_policy.capTimeout(
                self.io,
                absolute,
                self.options.connect_timeout,
            )
        else
            try deadline_policy.fromTimeout(
                self.io,
                self.options.connect_timeout,
            );
        if (try protocol_selection.selectHttp3(self.allocator, self.io, uri, self.options, connect_deadline)) |owner| {
            return .{ .allocator = self.allocator, .value = .{ .http3 = owner } };
        }
        if (self.options.http_proxy) |proxy| {
            if (secure) {
                return self.connectTunnelProxyBefore(
                    endpoint,
                    proxy,
                    connect_deadline,
                    deadline,
                );
            }
            return self.connectForwardProxyBefore(proxy, connect_deadline);
        }
        const stream = if (self.options.socks5_proxy) |proxy|
            try self.connectEndpointViaSocks5Before(
                endpoint,
                proxy,
                connect_deadline,
            )
        else
            try self.connectEndpointBefore(endpoint, connect_deadline);
        if (self.options.tcp_nodelay) {
            socket_options.setTcpNoDelay(stream) catch {
                stream.close(self.io);
                return error.SocketOptionFailed;
            };
        }
        if (!secure) {
            return switch (self.options.cleartext_protocol) {
                .http1 => .{
                    .allocator = self.allocator,
                    .value = .{ .http1 = try http1_runtime.Client.adoptStream(
                        self.allocator,
                        self.io,
                        stream,
                        endpoint.authority,
                        self.options.http1_limits,
                    ) },
                },
                .http2_prior_knowledge => .{
                    .allocator = self.allocator,
                    .value = .{ .http2 = if (deadline) |absolute|
                        try http2_runtime.Client.adoptPriorKnowledgeStreamWithDeadline(
                            self.allocator,
                            self.io,
                            stream,
                            endpoint.authority,
                            self.options.http2_limits,
                            absolute,
                        )
                    else
                        try http2_runtime.Client.adoptPriorKnowledgeStream(
                            self.allocator,
                            self.io,
                            stream,
                            endpoint.authority,
                            self.options.http2_limits,
                        ) },
                },
            };
        }

        return self.adoptTlsStream(stream, endpoint, deadline);
    }

    fn adoptTlsStream(
        self: *Client,
        stream: std.Io.net.Stream,
        endpoint: http1_runtime.UriEndpoint,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        const tls_options = types.verifiedTlsOptions(
            endpoint.tls_host,
            self.options,
        );
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ClientConnection.initVerifiedWithDeadline(
                self.allocator,
                self.io,
                stream,
                tls_options,
                absolute,
            )
        else
            try tls_stream.ClientConnection.initVerified(
                self.allocator,
                self.io,
                stream,
                tls_options,
            );
        stream_owned = false;
        var tls_owned = true;
        errdefer if (tls_owned) tls_connection.deinit();
        const protocol = try types.selectedProtocol(
            tls_connection.negotiatedAlpn(),
            self.options,
        );
        // Both protocol adoption helpers own the TLS connection on every
        // return path from this point.
        tls_owned = false;
        return switch (protocol) {
            .http3 => unreachable,
            .http1 => .{
                .allocator = self.allocator,
                .value = .{ .http1 = try http1_runtime.Client.adoptNegotiatedTls(
                    self.allocator,
                    self.io,
                    tls_connection,
                    endpoint.authority,
                    self.options.http1_limits,
                ) },
            },
            .http2 => .{
                .allocator = self.allocator,
                .value = .{ .http2 = if (deadline) |absolute|
                    try http2_runtime.Client.adoptNegotiatedTlsWithDeadline(
                        self.allocator,
                        self.io,
                        tls_connection,
                        endpoint.authority,
                        self.options.http2_limits,
                        absolute,
                    )
                else
                    try http2_runtime.Client.adoptNegotiatedTls(
                        self.allocator,
                        self.io,
                        tls_connection,
                        endpoint.authority,
                        self.options.http2_limits,
                    ) },
            },
        };
    }

    fn connectForwardProxyBefore(
        self: *Client,
        proxy: HttpProxy,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Connection {
        if (self.options.protocol_policy == .http2_only) return error.UnsupportedScheme;
        const proxy_uri = std.Uri.parse(proxy.uri) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(proxy_uri.scheme, "http")) {
            return error.UnsupportedScheme;
        }
        if (proxy_uri.query != null or proxy_uri.fragment != null) return error.InvalidUri;
        const path = switch (proxy_uri.path) {
            .raw, .percent_encoded => |value| value,
        };
        if (path.len != 0 and !std.mem.eql(u8, path, "/")) return error.InvalidUri;
        var proxy_endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            proxy_uri,
            80,
        );
        defer proxy_endpoint.deinit();
        const stream = try self.connectEndpointWithOptionsBefore(
            proxy_endpoint,
            proxy.options.address_resolver,
            proxy.options.address_connect_policy,
            deadline,
        );
        if (self.options.tcp_nodelay) {
            socket_options.setTcpNoDelay(stream) catch {
                stream.close(self.io);
                return error.SocketOptionFailed;
            };
        }
        return .{
            .allocator = self.allocator,
            .value = .{ .http1 = try http1_runtime.Client.adoptStream(
                self.allocator,
                self.io,
                stream,
                proxy_endpoint.authority,
                self.options.http1_limits,
            ) },
            .forward_proxy = proxy,
        };
    }

    fn connectTunnelProxyBefore(
        self: *Client,
        endpoint: http1_runtime.UriEndpoint,
        proxy: HttpProxy,
        connect_deadline: ?std.Io.Clock.Timestamp,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Connection {
        const proxy_uri = std.Uri.parse(proxy.uri) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(proxy_uri.scheme, "http")) {
            return error.UnsupportedScheme;
        }
        if (proxy_uri.query != null or proxy_uri.fragment != null) return error.InvalidUri;
        const path = switch (proxy_uri.path) {
            .raw, .percent_encoded => |value| value,
        };
        if (path.len != 0 and !std.mem.eql(u8, path, "/")) return error.InvalidUri;
        var proxy_stack: [max_stack_headers]http1.Header = undefined;
        var proxy_headers = try header_mapping.mapHttp1(
            self.allocator,
            proxy.headers,
            &proxy_stack,
        );
        defer proxy_headers.deinit(self.allocator);
        const proxy_options: http1_runtime.ProxyOptions = .{
            .headers = proxy_headers.items,
            .address_resolver = proxy.options.address_resolver,
            .address_connect_policy = proxy.options.address_connect_policy,
        };
        const authority = try connectAuthority(
            self.allocator,
            endpoint.tls_host,
            endpoint.port,
        );
        defer self.allocator.free(authority);
        var proxy_limits = self.options.http1_limits;
        proxy_limits.local_address = self.options.local_address;
        proxy_limits.network_interface = self.options.network_interface;
        const stream = if (connect_deadline) |absolute|
            try http1_runtime.Client.connectTunnelViaProxyUriWithDeadline(
                self.allocator,
                self.io,
                proxy.uri,
                authority,
                proxy_options,
                proxy_limits,
                absolute,
            )
        else
            try http1_runtime.Client.connectTunnelViaProxyUri(
                self.allocator,
                self.io,
                proxy.uri,
                authority,
                proxy_options,
                proxy_limits,
            );
        if (self.options.tcp_nodelay) {
            socket_options.setTcpNoDelay(stream) catch {
                stream.close(self.io);
                return error.SocketOptionFailed;
            };
        }
        return self.adoptTlsStream(stream, endpoint, deadline);
    }

    fn connectEndpointBefore(
        self: *Client,
        endpoint: http1_runtime.UriEndpoint,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!std.Io.net.Stream {
        return self.connectEndpointWithOptionsBefore(
            endpoint,
            null,
            null,
            deadline,
        );
    }

    fn connectEndpointWithOptionsBefore(
        self: *Client,
        endpoint: http1_runtime.UriEndpoint,
        resolver_option: ?AddressResolver,
        policy_option: ?AddressConnectPolicy,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!std.Io.net.Stream {
        return tcp_connect.endpointWithOptions(
            self.allocator,
            self.io,
            switch (endpoint.target) {
                .ip => |address| address,
                .host => null,
            },
            endpoint.tls_host,
            endpoint.port,
            resolver_option orelse self.options.address_resolver,
            policy_option orelse self.options.address_connect_policy,
            deadline,
            .fromOptions(self.options),
        );
    }

    fn connectEndpointViaSocks5Before(
        self: *Client,
        endpoint: http1_runtime.UriEndpoint,
        proxy: Socks5Proxy,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!std.Io.net.Stream {
        var options = proxy.options;
        // The owning client's binding governs the actual proxy socket.
        if (self.options.local_address) |address| options.local_address = address;
        if (self.options.network_interface) |interface| options.network_interface = interface;
        if (options.address_resolver == null) {
            options.address_resolver = self.options.address_resolver;
        }
        if (options.address_connect_policy == null) {
            options.address_connect_policy =
                self.options.address_connect_policy;
        }
        return if (deadline) |absolute|
            proxy_socks5.connectHostWithDeadline(
                self.allocator,
                self.io,
                proxy.host,
                proxy.port,
                endpoint.tls_host,
                endpoint.port,
                options,
                absolute,
            )
        else
            proxy_socks5.connectHost(
                self.allocator,
                self.io,
                proxy.host,
                proxy.port,
                endpoint.tls_host,
                endpoint.port,
                options,
            );
    }

    pub fn requestUri(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
    ) Error!OwnedResponse {
        return self.requestUriBefore(uri_text, request, null) catch |err| switch (err) {
            else => |other| return @errorCast(other),
        };
    }

    pub fn requestUriWithDeadline(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        return self.requestUriBefore(
            uri_text,
            request,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    pub fn requestUriWithTimeout(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriWithDeadline(
            uri_text,
            request,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestUriBefore(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const target = try uriTargetAlloc(self.allocator, uri);
        defer self.allocator.free(target);
        var connection = try self.connectUriBefore(uri_text, deadline);
        defer connection.close();
        const request_target = if (connection.isForwardProxy()) uri_text else target;
        return connection.requestBefore(request_target, request, deadline);
    }

    pub fn requestUriFollowingRedirects(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
    ) Error!OwnedResponse {
        var result = try self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request,
            redirect_options,
            null,
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailed(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
    ) Error!RedirectedResponse {
        return self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request,
            redirect_options,
            null,
        );
    }

    pub fn requestUriFollowingRedirectsWithDeadline(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        var result = try self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request,
            redirect_options,
            try deadline_policy.usableAwake(self.io, deadline),
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailedWithDeadline(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!RedirectedResponse {
        return self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request,
            redirect_options,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    pub fn requestUriFollowingRedirectsWithTimeout(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsWithDeadline(
            uri_text,
            request,
            redirect_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsDetailedWithTimeout(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!RedirectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsDetailedWithDeadline(
            uri_text,
            request,
            redirect_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestUriFollowingRedirectsDetailedBefore(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
        redirect_options: RedirectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!RedirectedResponse {
        return redirect.followDetailed(
            ResponseTimeoutError,
            self,
            uri_text,
            request,
            redirect_options,
            deadline,
            RedirectAdapter,
        );
    }

    const RedirectAdapter = struct {
        pub fn request(
            client: *Client,
            uri_text: []const u8,
            request_options: RequestOptions,
            deadline: ?std.Io.Clock.Timestamp,
            crossed_origin: bool,
            policy: uri_redirect.Policy,
        ) ResponseTimeoutError!OwnedResponse {
            var hop_client = client.*;
            if (crossed_origin) {
                hop_client.options.tls.tls12_ticket_resumption = null;
                hop_client.options.tls.tls13_ticket_resumption = null;
                hop_client.options.http3.handshake.handshake.resumption_session = null;
                hop_client.options.http3.handshake.handshake.resumption_server_id = null;
                hop_client.options.http3.handshake.handshake.auto_resumption = null;
                hop_client.options.http3.handshake.handshake.early_data = null;
                if (!policy.allow_cross_origin_client_identity) {
                    hop_client.options.tls.client_identity = null;
                    hop_client.options.http3.handshake.handshake.client_identity = null;
                }
            }
            return hop_client.requestUriBefore(
                uri_text,
                request_options,
                deadline,
            );
        }

        pub fn clientIdentityConfigured(client: *const Client) bool {
            return client.options.tls.client_identity != null or client.options.http3.handshake.handshake.client_identity != null;
        }
    };
};

fn uriTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    const path = switch (uri.path) {
        .raw, .percent_encoded => |value| value,
    };
    const effective_path = if (path.len == 0) "/" else path;
    if (uri.query) |query| {
        const bytes = switch (query) {
            .raw, .percent_encoded => |value| value,
        };
        return std.fmt.allocPrint(
            allocator,
            "{s}?{s}",
            .{ effective_path, bytes },
        );
    }
    return allocator.dupe(u8, effective_path);
}

test {
    _ = types;
}
