//! Unified HTTP/1.1 and HTTP/2 URI client.
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
const deadline_policy = @import("../internal/deadline.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const address_resolver = @import("../internal/address_resolver.zig");
const socket_options = @import("../internal/socket_options.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const uri_redirect = @import("../http1/runtime/redirect.zig");
const types = @import("client/types.zig");
const header_mapping = @import("client/header_mapping.zig");
const redirect = @import("client/redirect.zig");

pub const Error = http1_runtime.Error || http2_runtime.Error ||
    uri_redirect.Error || error{
    InvalidAddressConnectPolicy,
    InvalidClientOptions,
};
pub const ResponseTimeoutError = Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;
pub const Protocol = types.Protocol;
pub const ProtocolPolicy = types.ProtocolPolicy;
pub const CleartextProtocol = types.CleartextProtocol;
pub const AddressResolver = types.AddressResolver;
pub const AddressConnectPolicy = types.AddressConnectPolicy;
pub const HappyEyeballsOptions = types.HappyEyeballsOptions;
pub const Header = types.Header;
pub const HeaderIterator = types.HeaderIterator;
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
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    value: ConnectionValue,

    pub fn close(self: *Connection) void {
        switch (self.value) {
            .http1 => |*client| client.close(),
            .http2 => |*connection| connection.close(),
        }
        self.* = undefined;
    }

    pub fn protocol(self: Connection) Protocol {
        return switch (self.value) {
            .http1 => .http1,
            .http2 => .http2,
        };
    }

    pub fn isReusable(self: *const Connection) bool {
        return switch (self.value) {
            .http1 => |*client| client.isReusableForPool(),
            .http2 => |*connection| connection.isReusable(),
        };
    }

    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedAlpn(),
            .http2 => |*connection| connection.negotiatedAlpn(),
        };
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        return switch (self.value) {
            .http1 => |*client| client.negotiatedTlsProtocol(),
            .http2 => |*connection| connection.negotiatedTlsProtocol(),
        };
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        return switch (self.value) {
            .http1 => |*client| client.wasTlsSessionResumed(),
            .http2 => |*connection| connection.wasTlsSessionResumed(),
        };
    }

    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?tls_stream.Tls12SessionTicket {
        return switch (self.value) {
            .http1 => |*client| client.takeTls12SessionTicket(),
            .http2 => |*connection| connection.takeTls12SessionTicket(),
        };
    }

    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        return switch (self.value) {
            .http1 => |*client| client.takeTls13SessionTicket(),
            .http2 => |*connection| connection.takeTls13SessionTicket(),
        };
    }

    pub fn request(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
    ) Error!OwnedResponse {
        return self.requestBefore(target, options, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
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

    fn requestBefore(
        self: *Connection,
        target: []const u8,
        options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        switch (self.value) {
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
                const request_options: http1_runtime.RequestOptions = .{
                    .method = try http1.Method.parse(options.method),
                    .target = target,
                    .headers = headers.items,
                    .body = options.body,
                    .trailers = trailers.items,
                };
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
                const request_options: http2_runtime.RequestOptions = .{
                    .method = options.method,
                    .path = target,
                    .headers = headers.items,
                    .body = options.body,
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
        };
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) Error!Client {
        if (options.connect_timeout) |timeout| {
            if (timeout.nanoseconds <= 0) return error.InvalidClientOptions;
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
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
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
        const stream = try self.connectEndpointBefore(
            endpoint,
            connect_deadline,
        );
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

    fn connectEndpointBefore(
        self: *Client,
        endpoint: http1_runtime.UriEndpoint,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!std.Io.net.Stream {
        switch (endpoint.target) {
            .ip => |address| return if (deadline) |absolute|
                tcp_connect.ipWithDeadline(self.io, address, absolute)
            else
                tcp_connect.ip(self.io, address, null),
            .host => {},
        }
        const resolver = self.options.address_resolver;
        if (resolver == null and self.options.address_connect_policy == .ordered) {
            return if (deadline) |absolute|
                endpoint.connectWithDeadline(self.io, absolute)
            else
                endpoint.connect(self.io);
        }
        const addresses = if (resolver) |configured|
            try configured.resolve(
                configured.context,
                self.allocator,
                self.io,
                endpoint.tls_host,
                endpoint.port,
                deadline,
            )
        else
            try address_resolver.resolveSystem(
                self.allocator,
                self.io,
                endpoint.tls_host,
                endpoint.port,
                deadline,
            );
        defer self.allocator.free(addresses);
        return if (deadline) |absolute|
            tcp_connect.resolvedWithPolicyAndDeadline(
                self.allocator,
                self.io,
                addresses,
                absolute,
                self.options.address_connect_policy,
            )
        else
            tcp_connect.resolvedWithPolicy(
                self.allocator,
                self.io,
                addresses,
                null,
                self.options.address_connect_policy,
            );
    }

    pub fn requestUri(
        self: *Client,
        uri_text: []const u8,
        request: RequestOptions,
    ) Error!OwnedResponse {
        return self.requestUriBefore(uri_text, request, null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
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
        return connection.requestBefore(target, request, deadline);
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
                if (!policy.allow_cross_origin_client_identity) {
                    hop_client.options.tls.client_identity = null;
                }
            }
            return hop_client.requestUriBefore(
                uri_text,
                request_options,
                deadline,
            );
        }

        pub fn clientIdentityConfigured(client: *const Client) bool {
            return client.options.tls.client_identity != null;
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
