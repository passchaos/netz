const std = @import("std");
const content_digest = @import("../http/digest.zig");
pub const builtin = @import("builtin");
const http1 = @import("mod.zig");
pub const http3 = @import("../http3/mod.zig");
pub const runtime_write = @import("runtime/write.zig");
pub const connect_udp_runtime = @import("runtime/connect_udp.zig");
pub const uri_redirect = @import("runtime/redirect.zig");
pub const wire = @import("../internal/wire.zig");
pub const body_writer = @import("runtime/body_writer.zig");
const body_reader = @import("runtime/body_reader.zig");
const body_pull = @import("runtime/body_pull.zig");
pub const message_framing = @import("runtime/message/framing.zig");
pub const message_reuse = @import("runtime/message/reuse.zig");
const message_head = @import("runtime/message/head.zig");
pub const message_continue = @import("runtime/message/continue.zig");
const buffered_input = @import("runtime/message/buffered_input.zig");
pub const close_delimited = @import("runtime/message/close_delimited.zig");
pub const request_batch = @import("runtime/message/batch.zig");
pub const stream_io = @import("../internal/stream_io.zig");
const tls_client_reader = @import("runtime/tls_client/reader.zig");
const tls_write_retry = @import("../tls/stream/write_retry.zig");
pub const deadline_policy = @import("../internal/deadline.zig");
const accept_deadline = @import("../internal/accept.zig");
pub const http_date = @import("../internal/http_date.zig");
pub const tcp_connect = @import("../internal/tcp_connect.zig");
const address_resolver = @import("../internal/address_resolver.zig");
const socket_options = @import("../internal/socket_options.zig");
pub const tls_stream = @import("../tls/mod.zig").stream;
const root_trust = @import("../trust.zig");
pub const vail = @import("vail");

const net = std.Io.net;
pub const tls = std.crypto.tls;
pub const CertificateBundle = std.crypto.Certificate.Bundle;

pub const findHttpHeadEndWithinLimit = message_framing.findHeadEndWithinLimit;
const informationalResponseToSkip = message_framing.informationalResponseToSkip;
pub const requestShouldSendContinue = message_framing.requestShouldSendContinue;
pub const RequestReadStage = enum { head, continue_write, body };

pub const Error = tcp_connect.BindingResolvedConnectError || http1.Error || tls_stream.Error || uri_redirect.Error || error{
    HeadersTooLarge,
    BodyTooLarge,
    ConnectionClosed,
    InvalidUri,
    InvalidResponse,
    SocketOptionFailed,
    UnsupportedScheme,
    UnsupportedEndpoint,
    ConnectionBusy,
    ConnectionUnusable,
    InvalidWriterState,
    UnsupportedDeadline,
    InvalidServeOptions,
    TooManyInformationalResponses,
    PostHandshakeTlsUnavailable,
    WriteInProgress,
    InvalidAddressConnectPolicy,
    InvalidTarget,
    InvalidUriTemplate,
    MissingTemplateVariable,
    DuplicateTemplateVariable,
    InvalidTemplateExpansion,
    InvalidScope,
    EncryptionRequired,
    PayloadTooLarge,
    UnexpectedContextId,
    ExcessiveLoad,
    PlatformVerifierUnavailable,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError ||
    net.UnixAddress.ListenError || net.UnixAddress.ConnectError ||
    net.HostName.ValidateError || net.HostName.ConnectError ||
    net.Server.AcceptError || net.Stream.Reader.Error ||
    net.Stream.Writer.Error || net.ShutdownError || tls.Client.InitError ||
    CertificateBundle.RescanError || std.Io.RandomSecureError ||
    std.Io.Reader.ShortError || std.Io.Writer.Error ||
    std.Thread.SpawnError;

pub fn setTcpNoDelay(stream: net.Stream) Error!void {
    socket_options.setTcpNoDelay(stream) catch return error.SocketOptionFailed;
}

/// Select how an HTTP/1 connection submits one logical write to its transport.
///
/// `auto` preserves the runtime's size-based policy, `vectored` keeps caller
/// bodies borrowed, and `flatten` copies all parts into connection-owned
/// reusable storage before issuing the write. TLS transports retain one flush
/// boundary under every policy.
pub const WriteStrategy = enum {
    auto,
    vectored,
    flatten,
};

pub const PreparedForwardProxyRequest = struct {
    allocator: std.mem.Allocator,
    endpoint: UriEndpoint,
    absolute_target: []u8,
    owned_headers: ?[]http1.Header,
    options: RequestOptions,

    pub fn init(
        allocator: std.mem.Allocator,
        uri_text: []const u8,
        request_options: RequestOptions,
        proxy_options: ProxyOptions,
    ) Error!PreparedForwardProxyRequest {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) {
            return error.UnsupportedScheme;
        }
        var endpoint = try uriEndpoint(allocator, uri, 80);
        errdefer endpoint.deinit();
        const origin_target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(origin_target);
        const absolute_target = try std.fmt.allocPrint(
            allocator,
            "http://{s}{s}",
            .{ endpoint.authority, origin_target },
        );
        errdefer allocator.free(absolute_target);

        const owned_headers = if (proxy_options.headers.len == 0)
            null
        else blk: {
            const count = std.math.add(
                usize,
                request_options.headers.len,
                proxy_options.headers.len,
            ) catch return error.IntegerOverflow;
            const headers = try allocator.alloc(http1.Header, count);
            @memcpy(
                headers[0..request_options.headers.len],
                request_options.headers,
            );
            @memcpy(
                headers[request_options.headers.len..],
                proxy_options.headers,
            );
            break :blk headers;
        };
        var options = request_options;
        options.target = absolute_target;
        options.host = endpoint.authority;
        if (owned_headers) |headers| options.headers = headers;
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .absolute_target = absolute_target,
            .owned_headers = owned_headers,
            .options = options,
        };
    }

    pub fn deinit(self: *PreparedForwardProxyRequest) void {
        if (self.owned_headers) |headers| self.allocator.free(headers);
        self.allocator.free(self.absolute_target);
        self.endpoint.deinit();
        self.* = undefined;
    }
};

pub fn requestUriViaProxyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_uri: []const u8,
    target_uri: []const u8,
    request_options: RequestOptions,
    proxy_options: ProxyOptions,
    limits: Limits,
    tls_options: TlsClientOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    var client = try connectProxyUriBefore(
        allocator,
        io,
        proxy_uri,
        proxy_options,
        limits,
        deadline,
    );
    defer client.close();

    const target = std.Uri.parse(target_uri) catch return error.InvalidUri;
    const is_http = std.ascii.eqlIgnoreCase(target.scheme, "http");
    const is_https = std.ascii.eqlIgnoreCase(target.scheme, "https");
    if (!is_http and !is_https) return error.UnsupportedScheme;
    if (is_http) {
        return if (deadline) |absolute|
            client.requestForwardProxyUriWithDeadline(
                target_uri,
                request_options,
                proxy_options,
                absolute,
            )
        else
            client.requestForwardProxyUri(
                target_uri,
                request_options,
                proxy_options,
            );
    }

    var endpoint = try uriEndpoint(allocator, target, 443);
    defer endpoint.deinit();
    const connect_target = try std.fmt.allocPrint(
        allocator,
        "{s}:{d}",
        .{ endpoint.host_storage, endpoint.port },
    );
    defer allocator.free(connect_target);
    try client.promoteConnectTunnelToTls(
        connect_target,
        endpoint.tls_host,
        endpoint.authority,
        proxy_options.headers,
        tls_options,
        deadline,
    );
    const origin_target = try uriTargetAlloc(allocator, target);
    defer allocator.free(origin_target);
    var options = request_options;
    options.target = origin_target;
    options.host = endpoint.authority;
    return if (deadline) |absolute|
        client.requestWithDeadline(options, absolute)
    else
        client.request(options);
}

fn connectProxyUriBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_uri: []const u8,
    proxy_options: ProxyOptions,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Client {
    const uri = std.Uri.parse(proxy_uri) catch return error.InvalidUri;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) {
        return error.UnsupportedScheme;
    }
    if (uri.query != null or uri.fragment != null) return error.InvalidUri;
    const path = uriComponentBytes(uri.path);
    if (path.len != 0 and !std.mem.eql(u8, path, "/")) {
        return error.InvalidUri;
    }
    var endpoint = try uriEndpoint(allocator, uri, 80);
    defer endpoint.deinit();
    const connect_deadline = if (deadline) |absolute|
        try deadline_policy.capTimeout(io, absolute, limits.connect_timeout)
    else
        try deadline_policy.fromTimeout(io, limits.connect_timeout);
    const stream = try tcp_connect.endpointWithOptions(
        allocator,
        io,
        switch (endpoint.target) {
            .ip => |address| address,
            .host => null,
        },
        endpoint.tls_host,
        endpoint.port,
        proxy_options.address_resolver orelse limits.address_resolver,
        proxy_options.address_connect_policy orelse limits.address_connect_policy orelse .ordered,
        connect_deadline,
        .fromOptions(limits),
    );
    return Client.adoptStream(
        allocator,
        io,
        stream,
        endpoint.authority,
        limits,
    );
}

pub fn connectTunnelViaProxyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_uri: []const u8,
    target: []const u8,
    proxy_options: ProxyOptions,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    try http1.validateConnectTarget(target);
    var client = try connectProxyUriBefore(
        allocator,
        io,
        proxy_uri,
        proxy_options,
        limits,
        deadline,
    );
    var client_owned = true;
    defer if (client_owned) client.close();
    const tunnel = if (deadline) |absolute|
        try client.openConnectTunnelWithDeadline(
            target,
            proxy_options.headers,
            absolute,
        )
    else
        try client.openConnectTunnel(target, proxy_options.headers);
    if (tunnel.inbuf.items.len != 0 or tunnel.tls_conn != null or
        tunnel.tls_vail_conn != null or tunnel.tls_server_conn != null)
    {
        return error.InvalidResponse;
    }
    const stream = client.stream;
    if (client.default_host) |host| allocator.free(host);
    client.inbuf.deinit(allocator);
    client.write_scratch.deinit(allocator);
    client = undefined;
    client_owned = false;
    return stream;
}

pub const Limits = struct {
    /// Source IP/port for newly opened TCP sockets.
    /// Null leaves source selection to the OS. Requires Netz's zio backend.
    local_address: ?std.Io.net.IpAddress = null,
    /// Constrain the socket's network interface independently of source IP.
    /// Names are borrowed; unsupported platforms/backends fail explicitly.
    network_interface: ?tcp_connect.NetworkInterface = null,
    /// Application resolution for named and URI client connections.
    /// Returned peers do not replace TLS identity or HTTP authority.
    address_resolver: ?AddressResolver = null,
    /// Null uses ordered fallback. Explicit values also govern inherited
    /// proxy transport policy unless a proxy-specific option overrides it.
    address_connect_policy: ?AddressConnectPolicy = null,

    max_head_bytes: usize = 64 * 1024,
    /// Maximum request fields accepted by connection-owning `serve*` helpers.
    /// Direct read APIs continue to use their explicit `ParseOptions`.
    max_request_headers: usize = 100,
    /// Maximum request-target bytes accepted by connection-owning `serve*`
    /// helpers, matching Hyper's URI safety bound.
    max_request_target_bytes: usize = std.math.maxInt(u16) - 1,
    max_body_bytes: usize = 16 * 1024 * 1024,
    /// Optional absolute budget for each request head. The deadline begins
    /// when a server read first needs transport bytes and is not extended by
    /// partial progress, preventing Slowloris-style trickle attacks. Message
    /// bodies and response reads use independent policies.
    request_head_timeout: ?std.Io.Duration = null,
    /// Optional absolute budget for a client-side response-head sequence. The
    /// deadline is not renewed by partial bytes or interim 1xx responses and
    /// stops once the final response head is complete; body reads are outside
    /// this budget.
    response_head_timeout: ?std.Io.Duration = null,
    /// Maximum interim responses accepted before one final response. This
    /// bounds callback work even when a peer emits an endless 1xx sequence.
    max_informational_responses: usize = 16,
    /// Absolute budget for DNS resolution plus all TCP connection attempts.
    /// TLS and HTTP response-head timeouts remain independent.
    connect_timeout: ?std.Io.Duration = null,
    /// Disable Nagle for application-driven streaming writes. HTTP/1 has no
    /// frame coalescer, so a complete chunk followed by a small terminator or
    /// response can otherwise stall behind Linux delayed ACKs.
    tcp_nodelay: bool = true,
    /// Add a current IMF-fixdate Date field to server final responses that do
    /// not already contain one. The shared value is cached once per second.
    auto_date_header: bool = true,
    /// Permit the connection-owning `serve*` helpers to process another
    /// request after a response. Disabling this forces `Connection: close` on
    /// every served response and retires after the current exchange; direct
    /// read/write APIs remain caller-controlled.
    keep_alive: bool = true,
    /// Override the HTTP/1 write shape for complete messages, response
    /// batches, and incremental body chunks. The default retains the existing
    /// size-based behavior.
    write_strategy: WriteStrategy = .auto,
};

pub const TlsCaBundle = struct {
    bundle: *CertificateBundle,
    lock: *std.Io.RwLock,
};

pub const TlsClientOptions = struct {
    /// Verify the certificate chain and hostname.  Leave this enabled for
    /// production HTTPS/WSS clients; tests or private tunnels can opt out.
    verify_host: bool = true,
    /// Optional caller-managed CA bundle. When omitted and host verification
    /// is enabled, the runtime uses `root_source` (system roots by default) and
    /// frees a temporary store after TLS session establishment.
    ca_bundle: ?TlsCaBundle = null,
    /// Optional process environment for vail's native trust store. When set,
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR` take precedence over the platform
    /// roots, matching rustls-native-certs.
    environ: ?std.process.Environ = null,
    /// Optional caller-owned native trust store reused across handshakes.
    system_store: ?*const vail.x509.trust.SystemStore = null,
    /// Selects the default root set when no explicit verifier, CA bundle, or
    /// store is supplied. `.platform` uses the OS verifier; `.bundled` uses
    /// the compiled-in Mozilla roots.
    root_source: tls_stream.RootSource = .system,
    /// Forward EOF without close_notify.  This is useful only when the HTTP
    /// layer independently verifies body length (for example Content-Length).
    allow_truncation_attacks: bool = false,
    /// Absolute receive budget for the TLS 1.3 handshake. This is independent
    /// from the TCP connect and HTTP response-head budgets.
    handshake_timeout: ?std.Io.Duration = null,
};

/// Opt-in vail TLS 1.2/1.3 client features that Zig's standard client does not
/// expose: client authentication, ALPN, peer chains, exporters and KeyUpdate.
/// Supplying this object selects the vail transport while preserving the same
/// hostname/system-root defaults through `initVerified`.
pub const StapledOcspPolicy = tls_stream.StapledOcspPolicy;

pub const VailTlsClientOptions = struct {
    verify_host: bool = true,
    ca_bundle: ?tls_stream.ClientCaBundle = null,
    /// Optional process environment for vail's native trust store. When set,
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR` take precedence over the platform
    /// roots, matching rustls-native-certs.
    environ: ?std.process.Environ = null,
    /// Optional caller-owned native trust store reused across handshakes.
    system_store: ?*const vail.x509.trust.SystemStore = null,
    /// Selects the default root set when no explicit verifier, CA bundle, or
    /// store is supplied. `.platform` uses the OS verifier; `.bundled` uses
    /// the compiled-in Mozilla roots.
    root_source: tls_stream.RootSource = .system,
    server_verifier: ?vail.tls.auth.ClientVerifier = null,
    /// Built-in verifier policy for RFC 6066 stapled OCSP responses.
    stapled_ocsp: StapledOcspPolicy = .ignore,
    /// Emit status_request. Must remain enabled for `.require` and defaults on
    /// so RFC 7633 Must-Staple certificates work without another option.
    request_ocsp: bool = true,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    /// ALPN offer list. A negotiated protocol other than `http/1.1` fails the
    /// connect with `error.InvalidAlpn`; an empty list keeps legacy no-ALPN
    /// HTTPS origins working.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const tls_stream.CipherSuite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    request_tls12_session_ticket: bool = true,
    tls12_ticket_resumption: ?*const tls_stream.Tls12SessionTicket = null,
    request_tls13_session_ticket: bool = true,
    tls13_ticket_resumption: ?*const tls_stream.Tls13SessionTicket = null,
    max_server_handshake_size: usize = 256 * 1024,
    handshake_timeout: ?std.Io.Duration = null,
};

pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;

/// HTTP forward-proxy policy shared by one-shot cleartext and CONNECT-tunneled
/// URI requests. These fields are sent only to the proxy: for HTTPS they are
/// carried by CONNECT and never appear inside the authenticated origin tunnel.
pub const ProxyOptions = struct {
    headers: []const http1.Header = &.{},
    /// Optional resolver for the proxy transport endpoint. Literal IP proxy
    /// hosts bypass it; CONNECT continues to carry the origin authority text so
    /// proxy-side origin resolution and TLS identity remain unchanged.
    address_resolver: ?AddressResolver = null,
    /// Optional proxy-specific multi-address policy. Null lets protocol
    /// adapters inherit their origin policy; direct HTTP proxy helpers use
    /// ordered fallback.
    address_connect_policy: ?AddressConnectPolicy = null,
};

pub const RedirectPolicy = uri_redirect.Policy;

pub const RedirectProxy = struct {
    uri: []const u8,
    options: ProxyOptions = .{},
};

pub const RedirectOptions = struct {
    policy: RedirectPolicy = .{},
    tls: TlsClientOptions = .{},
    proxy: ?RedirectProxy = null,
};

/// Synchronous observer for HTTP/1 informational response heads.
///
/// The head and its header slices borrow the connection's response buffer and
/// remain valid only for the duration of `on_response`. Status 101 is excluded
/// because it is a final protocol-switch response, not an interim response.
pub const InformationalResponseHead = http1.InformationalResponseHead;

pub const InformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        response: InformationalResponseHead,
    ) void,
};

pub const UriEndpoint = struct {
    allocator: std.mem.Allocator,
    /// Host text exactly as it belongs in HTTP authority syntax. This slice
    /// aliases the prefix of `authority`; IPv6 literals intentionally keep
    /// their RFC 3986 brackets so synthesized Host / `:authority` fields are
    /// valid.
    host_storage: []u8,
    /// Owns the single allocation backing `host_storage` and `tls_host`.
    authority: []u8,
    port: u16,
    target: Target,
    /// Borrowed from `host_storage`; bracketed IPv6 literals drop the brackets
    /// here because TCP/TLS APIs expect the address text, not URI authority
    /// syntax.
    tls_host: []const u8,

    pub const Target = union(enum) {
        host: net.HostName,
        ip: net.IpAddress,
    };

    pub fn deinit(self: *UriEndpoint) void {
        self.allocator.free(self.authority);
        self.* = undefined;
    }

    pub fn connect(self: UriEndpoint, io: std.Io) Error!net.Stream {
        return switch (self.target) {
            .host => |host| host.connect(io, self.port, .{ .mode = .stream }),
            .ip => |address| address.connect(io, .{ .mode = .stream }),
        };
    }

    pub fn connectWithDeadline(
        self: UriEndpoint,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) Error!net.Stream {
        const absolute = try deadline_policy.usableAwake(io, deadline);
        return switch (self.target) {
            .host => |host| tcp_connect.hostWithDeadline(
                io,
                host,
                self.port,
                absolute,
            ),
            .ip => |address| tcp_connect.ipWithDeadline(
                io,
                address,
                absolute,
            ),
        };
    }

    pub fn connectWithTimeout(
        self: UriEndpoint,
        io: std.Io,
        timeout: std.Io.Duration,
    ) Error!net.Stream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(
            io,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
};

pub fn uriEndpoint(allocator: std.mem.Allocator, uri: std.Uri, default_port: u16) Error!UriEndpoint {
    if (uri.user != null or uri.password != null) return error.InvalidUri;
    const host_component = uri.host orelse return error.InvalidUri;
    var host_buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw_host = host_component.toRaw(&host_buffer) catch
        return error.InvalidUri;
    if (raw_host.len == 0) return error.InvalidUri;

    const port = uri.port orelse default_port;
    const authority = if (uri.port == null)
        try allocator.dupe(u8, raw_host)
    else blk: {
        var port_buffer: [5]u8 = undefined;
        const port_text = std.fmt.bufPrint(
            &port_buffer,
            "{d}",
            .{port},
        ) catch unreachable;
        const value = try allocator.alloc(
            u8,
            raw_host.len + 1 + port_text.len,
        );
        @memcpy(value[0..raw_host.len], raw_host);
        value[raw_host.len] = ':';
        @memcpy(value[raw_host.len + 1 ..], port_text);
        break :blk value;
    };
    errdefer allocator.free(authority);

    const host_storage = authority[0..raw_host.len];
    const target, const tls_host = try uriTargetForHost(host_storage, port);
    return .{
        .allocator = allocator,
        .host_storage = host_storage,
        .authority = authority,
        .port = port,
        .target = target,
        .tls_host = tls_host,
    };
}

fn uriTargetForHost(host: []const u8, port: u16) Error!struct { UriEndpoint.Target, []const u8 } {
    if (host[0] == '[') {
        if (host[host.len - 1] != ']') return error.InvalidUri;
        const inner = host[1 .. host.len - 1];
        if (inner.len == 0) return error.InvalidUri;
        const ip6 = net.IpAddress.parseIp6(inner, port) catch return error.InvalidUri;
        return .{ .{ .ip = ip6 }, inner };
    }
    if (std.mem.indexOfScalar(u8, host, '[') != null or std.mem.indexOfScalar(u8, host, ']') != null) {
        return error.InvalidUri;
    }
    if (net.IpAddress.parse(host, port)) |address| {
        return .{ .{ .ip = address }, host };
    } else |_| {}
    return .{ .{ .host = try net.HostName.init(host) }, host };
}

pub fn localTestCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { CertificateBundle, std.Io.RwLock } {
    const tls_testing = @import("../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: CertificateBundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

// Listener and transport owners live in runtime/transports.zig.
const transports = @import("runtime/transports.zig");

pub const TlsClientConnection = transports.TlsClientConnection;
pub const RuntimeTransport = transports.RuntimeTransport;
pub const Server = transports.Server;
pub const UnixServer = transports.UnixServer;
pub const TlsServer = transports.TlsServer;

/// Validate an HTTP/1.1 TLS listener's ALPN offer list. HTTP/1.1 is the only
/// application protocol this runtime can speak, so a configured list may only
/// contain `http/1.1`; anything else could negotiate a connection the parser
/// cannot use. An empty list keeps legacy no-ALPN HTTPS support.
pub fn validateHttp1AlpnProtocols(protocols: []const []const u8) Error!void {
    for (protocols) |protocol| {
        if (!std.mem.eql(u8, protocol, "http/1.1")) return error.InvalidAlpn;
    }
}

/// Adopt a TLS server connection whose handshake, including ALPN, was already
/// negotiated by `netz.tls.alpn_server` or a raw `tls_stream.ServerConnection`.
///
/// Peers that selected `http/1.1`, and legacy peers that sent no ALPN
/// extension, are accepted; any other selected protocol fails closed with
/// `error.InvalidAlpn`. Ownership of `tls_connection` transfers at entry: it is
/// deinitialized (closing the socket) on failure and owned by the returned
/// `Connection` on success.
pub fn adoptNegotiatedTlsServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_connection: *tls_stream.ServerConnection,
    limits: Limits,
) Error!Connection {
    var tls_owned = true;
    errdefer if (tls_owned) tls_connection.deinit();
    if (tls_connection.selected_alpn) |alpn| {
        if (!std.mem.eql(u8, alpn, "http/1.1")) return error.InvalidAlpn;
    }
    if (limits.tcp_nodelay) try setTcpNoDelay(stream);
    tls_owned = false;
    return .{
        .io = io,
        .allocator = allocator,
        .stream = stream,
        .limits = limits,
        .tls_server_conn = tls_connection,
    };
}

/// Once an authenticated TLS close_notify has reached the transport, a peer
/// that concurrently closes the socket can make shutdown(SHUT_WR) report
/// ENOTCONN. The TLS write half is already terminal in that case, so preserve
/// closeWrite's idempotent completion while propagating all other I/O errors.
pub fn shutdownAfterTlsCloseNotify(
    io: std.Io,
    stream: net.Stream,
) Error!void {
    stream.shutdown(io, .send) catch |err| switch (err) {
        error.SocketUnconnected => {},
        else => return err,
    };
}

pub fn mapHttpTimedReadError(err: stream_io.TimedReadError) Error {
    return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.Canceled => error.Canceled,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.NetworkDown => error.NetworkDown,
        error.SocketUnconnected => error.SocketUnconnected,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => error.SystemResources,
        error.Timeout => error.Timeout,
        else => error.Unexpected,
    };
}

pub const WriteScratch = runtime_write.Scratch;
pub const StreamingBodyWriter = body_writer.Writer(Error);
pub const StreamingBodyReader = body_reader.Reader(Error);
const PullBodyReader = body_pull.Reader(Connection, Error);

pub fn flattenWriteParts(
    allocator: std.mem.Allocator,
    scratch: *WriteScratch,
    parts: []const []const u8,
) Error![]const u8 {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.ContentLengthOverflow;
    }
    const flattened = try scratch.flattenedBuffer(allocator);
    flattened.clearRetainingCapacity();
    try flattened.ensureTotalCapacity(allocator, total);
    for (parts) |part| flattened.appendSliceAssumeCapacity(part);
    return flattened.items;
}

pub fn writeSlicesWithStrategy(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    strategy: WriteStrategy,
    parts: []const []const u8,
    scratch: *WriteScratch,
    transport_started: *bool,
) Error!void {
    switch (strategy) {
        .auto, .vectored => {
            transport_started.* = true;
            try transport.writeAllSlices(parts);
        },
        .flatten => {
            var only: ?[]const u8 = null;
            for (parts) |part| {
                if (part.len == 0) continue;
                if (only != null) {
                    only = null;
                    break;
                }
                only = part;
            }
            if (only) |bytes| {
                transport_started.* = true;
                return transport.writeAll(bytes);
            }
            const bytes = try flattenWriteParts(allocator, scratch, parts);
            transport_started.* = true;
            try transport.writeAll(bytes);
        },
    }
}

pub fn writeMessagePartsWithStrategy(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    strategy: WriteStrategy,
    parts: runtime_write.MessageParts,
    scratch: *WriteScratch,
    transport_started: *bool,
) Error!void {
    if (strategy == .flatten) {
        return writeSlicesWithStrategy(
            allocator,
            transport,
            strategy,
            &.{ parts.header, parts.body },
            scratch,
            transport_started,
        );
    }
    transport_started.* = true;
    try transport.writeAllParts(parts.header, parts.body);
}

pub const TlsListenOptions = struct {
    identity: vail.tls.auth.ServerIdentity,
    /// Optional late-bound identity source consulted once per handshake.
    /// Supports atomic certificate rotation without rebinding the listener.
    identity_provider: ?tls_stream.ServerIdentityProvider = null,
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    tls13_session_tickets: ?tls_stream.Tls13ServerTicketPolicy = null,
    tls12_session_tickets: ?tls_stream.Tls12ServerTicketPolicy = null,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for TLS setup, independent of HTTP request-head
    /// and body deadlines. Null preserves unbounded handshake behavior.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    /// Optional ALPN selection. Only `http/1.1` is accepted in the list;
    /// anything else returns `error.InvalidAlpn` at listen time. An empty list
    /// keeps legacy no-ALPN HTTPS working.
    alpn_protocols: []const []const u8 = &.{},
    tcp_nodelay: bool = true,
};

/// TLS 1.2/1.3 server transport for the same HTTP/1 parser and writer used by the
/// cleartext listener. Accepted connections own their TLS state and expose the
/// authenticated peer chain when client certificates are configured.
pub const AsyncServeError = Error || std.Io.Cancelable || std.Io.ConcurrentError;

pub const ConcurrentServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

pub const ServeErrorStage = enum {
    accept,
    connection,
};

pub const ServeErrorPolicy = enum {
    continue_serving,
    stop,
};

pub const ServeErrorEvent = struct {
    stage: ServeErrorStage,
    err: anyerror,
};

pub const ServeErrorObserver = struct {
    context: *anyopaque,
    /// May be invoked concurrently by independent connection workers.
    observe: *const fn (context: *anyopaque, event: ServeErrorEvent) void,
};

pub const ServeUntilOptions = struct {
    /// Setting this event cancels pending accepts and active request reads.
    shutdown: *std.Io.Event,
    accept_error_policy: ServeErrorPolicy = .continue_serving,
    connection_error_policy: ServeErrorPolicy = .continue_serving,
    /// Prevent a failed listener from becoming an unbounded retry loop.
    accept_error_backoff: std.Io.Duration = .fromMilliseconds(10),
    error_observer: ?ServeErrorObserver = null,
};

/// Optional serve-loop error observer. It forwards to kron's process-wide
/// logger installed by the execution layer; without one it is a no-op.
pub fn logErrorObserver() ServeErrorObserver {
    const Bridge = struct {
        var context: u8 = 0;

        fn observe(_: *anyopaque, event: ServeErrorEvent) void {
            @import("kron").warn("netz.http1", "http1 serve error", .{
                .stage = @tagName(event.stage),
                .err = @errorName(event.err),
            });
        }
    };
    return .{
        .context = @ptrCast(&Bridge.context),
        .observe = Bridge.observe,
    };
}

/// Shared bounded accept loop for TCP, Unix-domain, and TLS listeners.
/// Each accepted connection moves into exactly one task, which owns teardown
/// after either the handler response or a connection-local failure.
pub fn serveAcceptedConcurrent(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        http1.Request,
    ) Error!ResponseOptions,
    max_connections: usize,
) AsyncServeError!ConcurrentServeResult {
    var group: std.Io.Group = .init;
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    // Workers borrow result slots; join them before releasing that storage.
    defer group.cancel(io);
    @memset(results, null);

    for (results) |*result| {
        var connection = try server.accept();
        errdefer connection.close();
        const task = ServeTask(HandlerContext, handler){
            .connection = connection,
            .context = context,
            .result = result,
        };
        try group.concurrent(io, ServeTask(HandlerContext, handler).run, .{task});
    }

    try group.await(io);
    return .{ .allocator = allocator, .errors = results };
}

const ServeSupervisorState = struct {
    io: std.Io,
    options: ServeUntilOptions,
    stopping: std.atomic.Value(bool) = .init(false),
    failed: std.Io.Event = .unset,
    error_mutex: std.Io.Mutex = .init,
    first_error: ?anyerror = null,

    fn shouldStop(self: *@This()) bool {
        return self.stopping.load(.acquire) or self.options.shutdown.isSet();
    }

    fn report(self: *@This(), stage: ServeErrorStage, err: anyerror) void {
        if (self.options.error_observer) |observer| {
            observer.observe(observer.context, .{ .stage = stage, .err = err });
        }
        const policy = switch (stage) {
            .accept => self.options.accept_error_policy,
            .connection => self.options.connection_error_policy,
        };
        if (policy != .stop) return;
        self.error_mutex.lockUncancelable(self.io);
        if (self.first_error == null) self.first_error = err;
        self.error_mutex.unlock(self.io);
        self.stopping.store(true, .release);
        self.failed.set(self.io);
    }

    fn firstError(self: *@This()) ?anyerror {
        self.error_mutex.lockUncancelable(self.io);
        defer self.error_mutex.unlock(self.io);
        return self.first_error;
    }
};

pub fn serveAcceptedUntil(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        http1.Request,
    ) Error!ResponseOptions,
    max_connections: usize,
    max_requests_per_connection: usize,
    options: ServeUntilOptions,
) anyerror!void {
    if (max_connections == 0 or max_requests_per_connection == 0 or
        options.accept_error_backoff.nanoseconds < 0)
    {
        return error.InvalidServeOptions;
    }
    var group: std.Io.Group = .init;
    var supervisor = ServeSupervisorState{ .io = io, .options = options };
    var group_finished = false;
    defer if (!group_finished) {
        supervisor.stopping.store(true, .release);
        group.cancel(io);
    };
    for (0..max_connections) |_| {
        try group.concurrent(
            io,
            ServeUntilTask(ServerType, HandlerContext, handler).run,
            .{ServeUntilTask(ServerType, HandlerContext, handler){
                .supervisor = &supervisor,
                .server = server,
                .context = context,
                .max_requests_per_connection = max_requests_per_connection,
            }},
        );
    }

    const Wake = union(enum) {
        shutdown: std.Io.Cancelable!void,
        failure: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    try select.concurrent(
        .shutdown,
        waitForServeEvent,
        .{ options.shutdown, io },
    );
    try select.concurrent(
        .failure,
        waitForServeEvent,
        .{ &supervisor.failed, io },
    );
    switch (try select.await()) {
        .shutdown => |result| try result,
        .failure => |result| try result,
    }

    supervisor.stopping.store(true, .release);
    group.cancel(io);
    group_finished = true;
    select.cancelDiscard();
    if (supervisor.firstError()) |err| return err;
}

fn ServeUntilTask(
    comptime ServerType: type,
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        http1.Request,
    ) Error!ResponseOptions,
) type {
    return struct {
        supervisor: *ServeSupervisorState,
        server: *ServerType,
        context: *HandlerContext,
        max_requests_per_connection: usize,

        fn run(task: @This()) std.Io.Cancelable!void {
            while (!task.supervisor.shouldStop()) {
                var connection = task.server.accept() catch |err| {
                    if (err == error.Canceled or
                        task.supervisor.shouldStop())
                    {
                        return error.Canceled;
                    }
                    task.supervisor.report(.accept, err);
                    if (task.supervisor.shouldStop()) return;
                    const backoff =
                        task.supervisor.options.accept_error_backoff;
                    if (backoff.nanoseconds > 0) {
                        std.Io.sleep(
                            task.supervisor.io,
                            backoff,
                            .awake,
                        ) catch |sleep_err| switch (sleep_err) {
                            error.Canceled => return error.Canceled,
                        };
                    }
                    continue;
                };
                defer connection.close();
                _ = connection.serve(
                    task.context,
                    handler,
                    task.max_requests_per_connection,
                ) catch |err| {
                    if (err == error.Canceled and
                        task.supervisor.shouldStop()) return;
                    task.supervisor.report(.connection, err);
                };
            }
        }
    };
}

fn waitForServeEvent(
    event: *std.Io.Event,
    io: std.Io,
) std.Io.Cancelable!void {
    try event.wait(io);
}

fn ServeTask(
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        http1.Request,
    ) Error!ResponseOptions,
) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();
            _ = connection.serveOne(task.context, handler) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const Client = @import("runtime/client.zig").Client;

pub fn verifiedTlsClientOptions(
    tls_host: []const u8,
    options: VailTlsClientOptions,
) tls_stream.ClientVerifiedOptions {
    return .{
        .server_name = tls_host,
        .verify_host = options.verify_host,
        .ca_bundle = options.ca_bundle,
        .system_environ = options.environ,
        .system_store = options.system_store,
        .root_source = options.root_source,
        .server_verifier = options.server_verifier,
        .stapled_ocsp = options.stapled_ocsp,
        .request_ocsp = options.request_ocsp,
        .client_identity = options.client_identity,
        .alpn_protocols = options.alpn_protocols,
        .cipher_suites = options.cipher_suites,
        .tls12_cipher_suites = options.tls12_cipher_suites,
        .protocol_policy = options.protocol_policy,
        .request_tls12_session_ticket = options.request_tls12_session_ticket,
        .tls12_ticket_resumption = options.tls12_ticket_resumption,
        .request_tls13_session_ticket = options.request_tls13_session_ticket,
        .tls13_ticket_resumption = options.tls13_ticket_resumption,
        .max_server_handshake_size = options.max_server_handshake_size,
        .handshake_timeout = options.handshake_timeout,
    };
}

/// Upper bound on request bytes discarded by `Connection.drainAndClose`.
/// Error responses are small and the peer has normally stopped sending, so a
/// larger cap would only delay closing a misbehaving connection.
pub const max_error_drain_bytes: usize = 64 * 1024;

pub const Connection = @import("runtime/connection.zig").Connection;

pub fn validateUpgradeProtocol(protocol: []const u8) Error!void {
    http1.validateHeaderName(protocol) catch return error.InvalidResponse;
}

pub fn rejectUpgradeManagedHeaders(headers: []const http1.Header) Error!void {
    for (headers) |header| {
        if (header.eqlName("connection") or header.eqlName("upgrade")) {
            return error.InvalidResponse;
        }
    }
}

pub const TunnelWriteProgress = connect_udp_runtime.WriteProgress;

pub const Tunnel = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    inbuf: *std.ArrayList(u8),
    write_closed: bool = false,

    pub fn transport(self: *Tunnel) RuntimeTransport {
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls_client = conn };
        if (self.tls_server_conn) |conn| return .{ .tls_server = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn write(self: *Tunnel, bytes: []const u8) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        self.transport().writeAll(bytes) catch |err| {
            // A transport error can follow a socket-visible prefix. Retrying
            // on the same byte stream would duplicate or corrupt the tunneled
            // protocol, so retain read access but fail the write half closed.
            self.write_closed = true;
            return err;
        };
    }

    /// Write two borrowed slices as one ordered tunnel byte sequence. TCP can
    /// submit both ranges with vectored I/O; TLS retains one record-flush
    /// boundary without requiring the caller to concatenate them.
    pub fn writeParts(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        self.transport().writeAllParts(first, second) catch |err| {
            self.write_closed = true;
            return err;
        };
    }

    /// Write borrowed slices in order without first joining their contents.
    /// The call consumes every slice before returning. A transport failure is
    /// terminal because an unknown prefix may already be visible to the peer.
    pub fn writeSlices(
        self: *Tunnel,
        slices: []const []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        self.transport().writeAllSlices(slices) catch |err| {
            self.write_closed = true;
            return err;
        };
    }

    /// Write borrowed slices under one absolute deadline while reporting the
    /// exact plaintext prefix committed to the transport. A timeout is
    /// resumable from that prefix; every other transport failure closes the
    /// write half because replay safety can no longer be established.
    pub fn writeSlicesWithDeadline(
        self: *Tunnel,
        slices: []const []const u8,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        if (self.write_closed) return error.ConnectionClosed;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        for (slices) |slice| {
            if (slice.len == 0) continue;
            var part_committed: usize = 0;
            self.transport().writeAllWithDeadline(
                slice,
                &part_committed,
                deadline,
            ) catch |err| {
                progress.committed_bytes += part_committed;
                if (err != error.Timeout) self.write_closed = true;
                return err;
            };
            progress.committed_bytes += part_committed;
        }
    }

    /// Relative-timeout counterpart to `writeSlicesWithDeadline`. A
    /// non-positive duration returns `Timeout` with `progress` cleared and no
    /// bytes submitted to the transport.
    pub fn writeSlicesWithTimeout(
        self: *Tunnel,
        slices: []const []const u8,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (self.write_closed) return error.ConnectionClosed;
        return self.writeSlicesWithDeadline(
            slices,
            progress,
            (try deadline_policy.fromTimeout(self.io, timeout)).?,
        );
    }

    /// Finish the tunnel's write half while preserving buffered and future
    /// reads. TLS transports send close_notify before shutting down the
    /// underlying socket write direction. The transition is fail-closed: once
    /// shutdown begins, this tunnel never accepts application writes again.
    pub fn closeWrite(self: *Tunnel) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        self.write_closed = true;
        try self.transport().closeWrite();
    }

    /// Terminate an upgraded connection after a protocol error. Ownership of
    /// allocations and the socket remains with the parent Client/Connection,
    /// whose normal `close` call performs final cleanup.
    pub fn abort(self: *Tunnel) void {
        self.write_closed = true;
        self.transport().abort();
    }

    pub fn read(self: *Tunnel, buffer: []u8) Error!usize {
        if (self.inbuf.items.len != 0) {
            const n = @min(buffer.len, self.inbuf.items.len);
            @memcpy(buffer[0..n], self.inbuf.items[0..n]);
            discardPrefix(self.inbuf, n);
            return n;
        }
        return self.transport().read(buffer);
    }

    pub fn readWithTimeout(
        self: *Tunnel,
        buffer: []u8,
        timeout: std.Io.Duration,
    ) Error!usize {
        if (self.inbuf.items.len != 0) return self.read(buffer);
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readWithDeadline(
            buffer,
            try self.transport().deadlineFromNow(timeout),
        );
    }

    /// Read upgraded-protocol bytes without letting partial TLS records renew
    /// the caller's absolute budget. Parser-read bytes are always drained
    /// first and therefore do not require a live timeout backend.
    pub fn readWithDeadline(
        self: *Tunnel,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (self.inbuf.items.len != 0) return self.read(buffer);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.transport().readWithDeadline(buffer, deadline);
    }

    /// Preserve post-handshake TLS control for server-side CONNECT/Upgrade
    /// tunnels after the HTTP parser relinquishes ownership of the stream.
    pub fn updateTrafficKeys(
        self: *Tunnel,
        request_peer_update: bool,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.tls_vail_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        if (self.tls_server_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        return error.PostHandshakeTlsUnavailable;
    }

    pub fn keyUpdateCounts(
        self: *const Tunnel,
    ) ?tls_stream.KeyUpdateCounts {
        const connection = self.tls_vail_conn orelse
            self.tls_server_conn orelse return null;
        return connection.keyUpdateCounts();
    }
};

pub const ConnectUdpTunnel = connect_udp_runtime.TunnelAdapter(Tunnel);

pub const ConnectUdpSession = http3.connect_udp.CapsuleSession(
    connect_udp_runtime.ResetCode,
    ConnectUdpTunnel,
    TunnelWriteProgress,
);

pub const ConnectIpSession = http3.connect_ip.CapsuleSession(
    connect_udp_runtime.ResetCode,
    ConnectUdpTunnel,
    TunnelWriteProgress,
);

pub const AcceptedConnectUdp = struct {
    target: http3.connect_udp.Target,
    session: ConnectUdpSession,
};

pub const AcceptedConnectIp = struct {
    scope: http3.connect_ip.Scope,
    session: ConnectIpSession,
};

pub const OwnedRequest = struct {
    bytes: []u8,
    request: http1.Request,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn contentEncoding(
        self: OwnedRequest,
    ) http1.content_coding.Error!http1.content_coding.Chain {
        return self.request.contentEncoding();
    }

    pub fn decodeContentAlloc(
        self: OwnedRequest,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) http1.content_coding.Error!http1.content_coding.DecodedBody {
        return self.request.decodeContentAlloc(allocator, max_output_len);
    }

    pub fn decodeContentInto(
        self: OwnedRequest,
        out: []u8,
        scratch: []u8,
    ) http1.content_coding.Error![]u8 {
        return self.request.decodeContentInto(out, scratch);
    }
};

pub fn redirectHeaders(
    allocator: std.mem.Allocator,
    source: []const http1.Header,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http1.Header,
) std.mem.Allocator.Error![]const http1.Header {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectHeader(header.name, remove_credentials, remove_body)) {
            retained_count += 1;
        }
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(http1.Header, retained_count);
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectHeader(header.name, remove_credentials, remove_body)) {
            continue;
        }
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectHeader(
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

pub const OwnedResponse = struct {
    bytes: []u8,
    response: http1.Response,

    pub fn verifyContentDigest(self: OwnedResponse, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return self.response.verifyContentDigest(policy);
    }

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const RedirectedResponse = struct {
    allocator: std.mem.Allocator,
    response: OwnedResponse,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectedResponse) void {
        const allocator = self.allocator;
        self.response.deinit(allocator);
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn takeResponse(self: *RedirectedResponse) OwnedResponse {
        const response = self.response;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return response;
    }
};

pub const RequestOptions = runtime_write.RequestOptions;
pub const ResponseOptions = runtime_write.ResponseOptions;
pub const HeaderNameCasing = runtime_write.HeaderNameCasing;
pub const StreamingRequestOptions =
    runtime_write.streaming.RequestOptions;
pub const StreamingResponseOptions =
    runtime_write.streaming.ResponseOptions;

pub const StreamingRequest = StreamingBodyReader.Request;
pub const StreamingRequestHead = StreamingBodyReader.RequestHead;
pub const StreamingResponse = StreamingBodyReader.Response;
pub const StreamingResponseHead = StreamingBodyReader.ResponseHead;
/// Pull-style request-body reader; see `Connection.readRequestBody`.
pub const RequestBodyReader = PullBodyReader;
pub const RequestBodyHead = PullBodyReader.Head;

pub fn ignoreStreamingRequestHead(
    context: anytype,
    head: StreamingRequestHead,
) !void {
    _ = context;
    _ = head;
}

pub fn ignoreStreamingResponseHead(
    context: anytype,
    head: StreamingResponseHead,
) !void {
    _ = context;
    _ = head;
}

pub fn streamingRequestFromReader(
    request: StreamingBodyReader.Request,
) StreamingRequest {
    return request;
}

pub fn streamingResponseFromReader(
    response: StreamingBodyReader.Response,
) StreamingResponse {
    return response;
}

const request_writer = @import("runtime/request_writer.zig");
pub const RequestWriter = request_writer.RequestWriter;
pub const ExpectContinueResult = request_writer.ExpectContinueResult;

pub const ResponseWriter = @import("runtime/response_writer.zig").ResponseWriter;

pub fn clientWriteSlices(
    context: ?*anyopaque,
    parts: []const []const u8,
    transport_started: *bool,
) Error!void {
    const client: *Client = @ptrCast(@alignCast(context.?));
    try writeSlicesWithStrategy(
        client.allocator,
        client.transport(),
        client.limits.write_strategy,
        parts,
        &client.write_scratch,
        transport_started,
    );
}

pub fn clientReadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const client: *Client = @ptrCast(@alignCast(context.?));
    if (client.response_deadline) |deadline| {
        return client.transport().readWithDeadline(buffer, deadline);
    }
    return client.transport().read(buffer);
}

pub fn clientReadHeadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const client: *Client = @ptrCast(@alignCast(context.?));
    std.debug.assert(client.response_head_sequence_active);
    if (client.response_head_deadline == null) {
        client.response_head_deadline = if (client.limits.response_head_timeout) |timeout|
            earlierDeadline(
                client.response_deadline,
                try headReadDeadline(client.transport(), timeout),
            )
        else
            client.response_deadline;
    }
    const deadline = client.response_head_deadline orelse
        return client.transport().read(buffer);
    return client.transport().readWithDeadline(
        buffer,
        deadline,
    );
}

pub fn connectionReadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    return connection.transport().read(buffer);
}

pub fn connectionReadHeadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    const deadline = connection.request_head_deadline orelse
        return connection.transport().read(buffer);
    return connection.transport().readWithDeadline(buffer, deadline);
}

pub fn headReadDeadline(
    transport: RuntimeTransport,
    timeout: std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return transport.deadlineFromNow(timeout);
}

fn earlierDeadline(
    a: ?std.Io.Clock.Timestamp,
    b: std.Io.Clock.Timestamp,
) std.Io.Clock.Timestamp {
    const left = a orelse return b;
    return if (std.Io.Clock.Timestamp.compare(left, .lt, b)) left else b;
}

fn readTransportUntil(
    transport: RuntimeTransport,
    buffer: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!usize {
    return if (deadline) |absolute|
        transport.readWithDeadline(buffer, absolute)
    else
        transport.read(buffer);
}

const EofBodyReader = close_delimited.Reader(struct {
    pub const TransportType = RuntimeTransport;
    pub const ErrorType = Error;
    pub const readUntil = readTransportUntil;
});

const BufferedInputReader = buffered_input.Reader(struct {
    pub const TransportType = RuntimeTransport;
    pub const ErrorType = Error;
    pub const readUntil = readTransportUntil;
});

pub fn ensureResponseHeadDeadlineForBuffer(
    transport: RuntimeTransport,
    limits: Limits,
    buffered: []const u8,
    deadline: *?std.Io.Clock.Timestamp,
) Error!void {
    if (deadline.* != null or
        try findHttpHeadEndWithinLimit(
            buffered,
            limits.max_head_bytes,
        ) != null)
    {
        return;
    }
    const timeout = limits.response_head_timeout orelse return;
    deadline.* = try headReadDeadline(transport, timeout);
}

fn ensureResponseStartDeadlineForBuffer(
    transport: RuntimeTransport,
    limits: Limits,
    buffered: []const u8,
    deadline: *?std.Io.Clock.Timestamp,
) Error!void {
    try ensureResponseHeadDeadlineForBuffer(
        transport,
        limits,
        buffered,
        deadline,
    );
}

pub fn connectionMaybeWriteContinue(
    context: ?*anyopaque,
    head: http1.RequestHead,
) Error!void {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    try message_continue.send(Error, connection.transport(), RuntimeTransport.writeAll, &connection.request_continue, message_head.shouldContinue(head));
}

pub fn connectionWriteSlices(
    context: ?*anyopaque,
    parts: []const []const u8,
    transport_started: *bool,
) Error!void {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    try writeSlicesWithStrategy(
        connection.allocator,
        connection.transport(),
        connection.limits.write_strategy,
        parts,
        &connection.write_scratch,
        transport_started,
    );
}

pub const responseIsReusable = message_reuse.reusable;
pub const streamingResponseIsReusable = message_reuse.reusable;

pub fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const path_value = uriComponentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, uriComponentBytes(query) });
    }
    return try allocator.dupe(u8, path);
}

fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

pub fn readRequestFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytes(
        allocator,
        io,
        stream,
        limits,
        options,
    );
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

/// Read one complete request under a caller-owned absolute deadline. This
/// unbuffered adapter is intended for protocol handshakes such as h2c, where
/// the request head, body, and trailers must share one outer budget.
pub fn readRequestFromStreamWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedRequest {
    _ = try deadline_policy.usableAwake(io, deadline);
    const bytes = try readMessageBytesWithContext(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        limits,
        null,
        true,
        options,
        false,
        deadline,
        deadline,
    );
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

pub fn readRequestFromStreamWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    timeout: std.Io.Duration,
) Error!OwnedRequest {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readRequestFromStreamWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

/// Read one buffered request. Allocation failures retain accepted input,
/// including a complete message whose metadata decoder must be retried.
pub fn readRequestFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytesBuffered(allocator, io, stream, limits, options, inbuf);
    errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

/// Buffered counterpart to `readRequestFromStreamWithDeadline`. Bytes for a
/// later pipelined request remain in `inbuf`, while the supplied deadline
/// covers both this request's head and body.
pub fn readRequestFromStreamBufferedWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedRequest {
    _ = try deadline_policy.usableAwake(io, deadline);
    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        limits,
        options,
        inbuf,
        null,
        true,
        false,
        deadline,
        deadline,
        null,
        null,
    );
    errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

pub fn readRequestFromStreamBufferedWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    timeout: std.Io.Duration,
) Error!OwnedRequest {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readRequestFromStreamBufferedWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        .fromNow(io, .{ .clock = .awake, .raw = timeout }),
    );
}

pub fn readRequestFromTransportBufferedWithStage(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    head_deadline: ?std.Io.Clock.Timestamp,
    failure_stage: ?*RequestReadStage,
    continue_state: *message_continue.State,
) Error!OwnedRequest {
    if (failure_stage) |stage| stage.* = .head;
    const bytes = readMessageBytesBufferedWithContext(
        allocator,
        transport,
        limits,
        options,
        inbuf,
        null,
        true,
        false,
        head_deadline,
        null,
        failure_stage,
        continue_state,
    ) catch |err| {
        if (failure_stage) |stage| {
            if (err == error.HeadersTooLarge) {
                if (findHttpHeadEndWithinLimit(
                    inbuf.items,
                    limits.max_head_bytes,
                ) catch null != null) {
                    stage.* = .body;
                }
            }
        }
        return err;
    };
    if (failure_stage) |stage| stage.* = .body;
    errdefer |err| if (err == error.OutOfMemory) {
        buffered_input.restore(allocator, inbuf, bytes);
    } else {
        continue_state.reset();
        allocator.free(bytes);
    };
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    continue_state.reset();
    return .{ .bytes = bytes, .request = request };
}

pub fn readResponseFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedResponse {
    return readResponseFromStreamObserved(
        allocator,
        io,
        stream,
        limits,
        options,
        null,
    );
}

/// Read one final response from an unbuffered stream while observing each
/// preceding informational response.
pub fn readResponseFromStreamObserved(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    informational: ?InformationalObserver,
) Error!OwnedResponse {
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var informational_count: usize = 0;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseStartDeadlineForBuffer(
            transport,
            limits,
            &.{},
            &response_head_deadline,
        );
        const bytes = try readMessageBytesWithContext(
            allocator,
            transport,
            limits,
            null,
            false,
            options,
            true,
            response_head_deadline,
            null,
        );
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            try validateAndCountInformationalResponse(
                response,
                limits,
                &informational_count,
            );
            notifyInformationalResponse(informational, response);
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
) Error!OwnedResponse {
    return readResponseFromStreamForRequestObserved(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        null,
    );
}

/// Read one complete final response under a caller-owned absolute deadline.
/// This unbuffered adapter is intended for protocol handshakes such as h2c;
/// the same deadline covers informational heads, final head, body, and trailers.
pub fn readResponseFromStreamForRequestWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    return readResponseFromStreamForRequestObservedWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        null,
        deadline,
    );
}

/// Deadline-bounded response read that exposes every permitted informational
/// response without giving the final response a renewed budget.
pub fn readResponseFromStreamForRequestObservedWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    informational: ?InformationalObserver,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    _ = try deadline_policy.usableAwake(io, deadline);
    return readResponseFromStreamForRequestObservedUntil(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        informational,
        deadline,
    );
}

pub fn readResponseFromStreamForRequestWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    timeout: std.Io.Duration,
) Error!OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readResponseFromStreamForRequestWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn readResponseFromStreamForRequestObservedWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    informational: ?InformationalObserver,
    timeout: std.Io.Duration,
) Error!OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readResponseFromStreamForRequestObservedWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        informational,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn readResponseFromStreamForRequestObservedUntil(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    informational: ?InformationalObserver,
    response_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var informational_count: usize = 0;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseStartDeadlineForBuffer(
            transport,
            limits,
            &.{},
            &response_head_deadline,
        );
        const effective_head_deadline = if (response_deadline) |deadline|
            earlierDeadline(response_head_deadline, deadline)
        else
            response_head_deadline;
        const bytes = try readMessageBytesWithContext(
            allocator,
            transport,
            limits,
            request_method,
            false,
            options,
            true,
            effective_head_deadline,
            response_deadline,
        );
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(
            allocator,
            bytes,
            options,
            request_method,
        );
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            try validateAndCountInformationalResponse(
                response,
                limits,
                &informational_count,
            );
            notifyInformationalResponse(informational, response);
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamForRequestObserved(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
    informational: ?InformationalObserver,
) Error!OwnedResponse {
    return readResponseFromStreamForRequestObservedUntil(
        allocator,
        io,
        stream,
        limits,
        options,
        request_method,
        informational,
        null,
    );
}

pub fn readResponseFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedResponse {
    return readResponseFromStreamBufferedObserved(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        null,
    );
}

pub fn readResponseFromStreamBufferedObserved(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    informational: ?InformationalObserver,
) Error!OwnedResponse {
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var informational_count: usize = 0;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseStartDeadlineForBuffer(
            transport,
            limits,
            inbuf.items,
            &response_head_deadline,
        );
        const bytes = try readMessageBytesBufferedWithContext(
            allocator,
            transport,
            limits,
            options,
            inbuf,
            null,
            false,
            true,
            response_head_deadline,
            null,
            null,
            null,
        );
        errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            try validateAndCountInformationalResponse(
                response,
                limits,
                &informational_count,
            );
            notifyInformationalResponse(informational, response);
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamBufferedForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error!OwnedResponse {
    return readResponseFromStreamBufferedForRequestObserved(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        request_method,
        null,
    );
}

/// Read a buffered response under one caller-owned deadline. Informational
/// responses, the final head, body, and trailers all consume the same budget;
/// bytes belonging to a pipelined successor remain in `inbuf`.
pub fn readResponseFromStreamBufferedForRequestWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    return readResponseFromStreamBufferedForRequestObservedWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        request_method,
        null,
        deadline,
    );
}

/// Buffered deadline read with informational callbacks. All 1xx responses and
/// the final response consume one budget, while bytes for a later exchange
/// remain in the caller-owned input buffer.
pub fn readResponseFromStreamBufferedForRequestObservedWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    informational: ?InformationalObserver,
    deadline: std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    _ = try deadline_policy.usableAwake(io, deadline);
    return readResponseFromTransportBufferedForRequestObserved(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        limits,
        options,
        inbuf,
        request_method,
        informational,
        null,
        deadline,
    );
}

pub fn readResponseFromStreamBufferedForRequestWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    timeout: std.Io.Duration,
) Error!OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readResponseFromStreamBufferedForRequestWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        request_method,
        .fromNow(io, .{ .clock = .awake, .raw = timeout }),
    );
}

pub fn readResponseFromStreamBufferedForRequestObservedWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    informational: ?InformationalObserver,
    timeout: std.Io.Duration,
) Error!OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readResponseFromStreamBufferedForRequestObservedWithDeadline(
        allocator,
        io,
        stream,
        limits,
        options,
        inbuf,
        request_method,
        informational,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn readResponseFromStreamBufferedForRequestObserved(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    informational: ?InformationalObserver,
) Error!OwnedResponse {
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var informational_count: usize = 0;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseStartDeadlineForBuffer(
            transport,
            limits,
            inbuf.items,
            &response_head_deadline,
        );
        const bytes = try readMessageBytesBufferedWithContext(
            allocator,
            transport,
            limits,
            options,
            inbuf,
            request_method,
            false,
            true,
            response_head_deadline,
            null,
            null,
            null,
        );
        errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            try validateAndCountInformationalResponse(
                response,
                limits,
                &informational_count,
            );
            notifyInformationalResponse(informational, response);
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

const response_sequence = @import("runtime/message/response_sequence.zig");
const parseResponseForRuntime = response_sequence.parseResponseForRuntime;

pub fn writeRequestToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: RequestOptions) Error!void {
    try writeRequestToTransport(allocator, .{ .tcp = .{ .io = io, .stream = stream } }, options);
}

/// Validate and write one complete request under the caller's absolute
/// awake-clock deadline. Any error after output begins is terminal for this
/// byte stream; callers retain ownership and decide how to close it.
pub fn writeRequestToStreamWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: RequestOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    _ = try deadline_policy.usableAwake(io, deadline);
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeRequestToTransportScratchMaybeBefore(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        options,
        deadline,
        &scratch,
    );
}

pub fn writeRequestToStreamWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: RequestOptions,
    timeout: std.Io.Duration,
) Error!void {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return writeRequestToStreamWithDeadline(
        allocator,
        io,
        stream,
        options,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn writeRequestToTransport(allocator: std.mem.Allocator, transport: RuntimeTransport, options: RequestOptions) Error!void {
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeRequestToTransportScratchMaybeBefore(
        allocator,
        transport,
        options,
        null,
        &scratch,
    );
}

fn writeRequestToTransportScratchMaybeBefore(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareRequest(
        allocator,
        options,
        scratch,
    );
    if (deadline) |absolute| {
        var committed: usize = 0;
        try transport.writeAllPartsWithDeadline(
            parts.header,
            parts.body,
            &committed,
            absolute,
        );
    } else {
        try transport.writeAllParts(parts.header, parts.body);
    }
}

pub fn writeResponseToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: ResponseOptions) Error!void {
    try writeResponseToTransport(allocator, .{ .tcp = .{ .io = io, .stream = stream } }, options);
}

/// Validate and write one complete response under the caller's absolute
/// awake-clock deadline. The operation never renews the supplied budget.
pub fn writeResponseToStreamWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: ResponseOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    _ = try deadline_policy.usableAwake(io, deadline);
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeResponseToTransportScratchMaybeBefore(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        options,
        null,
        deadline,
        &scratch,
    );
}

pub fn writeResponseToStreamWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: ResponseOptions,
    timeout: std.Io.Duration,
) Error!void {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return writeResponseToStreamWithDeadline(
        allocator,
        io,
        stream,
        options,
        .fromNow(io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn writeResponseToTransport(allocator: std.mem.Allocator, transport: RuntimeTransport, options: ResponseOptions) Error!void {
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeResponseToTransportScratchMaybeBefore(
        allocator,
        transport,
        options,
        null,
        null,
        &scratch,
    );
}

fn writeResponseToTransportScratchMaybeBefore(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: ResponseOptions,
    default_date: ?[]const u8,
    deadline: ?std.Io.Clock.Timestamp,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareServerResponse(
        allocator,
        options,
        default_date,
        scratch,
    );
    if (deadline) |absolute| {
        var committed: usize = 0;
        try transport.writeAllPartsWithDeadline(
            parts.header,
            parts.body,
            &committed,
            absolute,
        );
    } else {
        try transport.writeAllParts(parts.header, parts.body);
    }
}

pub fn writeResponsesToTransportScratch(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *WriteScratch,
) Error!void {
    if (responseBatchBodyBytes(responses) > response_batch_borrow_threshold) {
        const parts = try runtime_write.prepareServerResponseParts(
            allocator,
            responses,
            default_date,
            scratch,
        );
        try transport.writeAllSlices(parts);
        return;
    }
    try writeResponsesCoalesced(
        allocator,
        transport,
        responses,
        default_date,
        scratch,
    );
}

pub const response_batch_borrow_threshold: usize = 16 * 1024;

pub fn responseBatchWriteStrategy(
    configured: WriteStrategy,
    body_bytes: usize,
) WriteStrategy {
    return switch (configured) {
        .auto => if (body_bytes > response_batch_borrow_threshold)
            .vectored
        else
            .flatten,
        else => |explicit| explicit,
    };
}

pub fn responseBatchBodyBytes(responses: []const ResponseOptions) usize {
    var total: usize = 0;
    for (responses) |response| total +|= response.body.len;
    return total;
}

fn writeResponsesCoalesced(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *WriteScratch,
) Error!void {
    try transport.writeAll(try prepareResponsesCoalesced(
        allocator,
        responses,
        default_date,
        scratch,
    ));
}

pub fn prepareResponsesCoalesced(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *WriteScratch,
) Error![]const u8 {
    const parts = try runtime_write.prepareServerResponseParts(
        allocator,
        responses,
        default_date,
        scratch,
    );
    scratch.encoded.clearRetainingCapacity();
    var total: usize = 0;
    for (parts) |part| total +|= part.len;
    try scratch.encoded.ensureTotalCapacity(allocator, total);
    for (parts) |part| scratch.encoded.appendSliceAssumeCapacity(part);
    return scratch.encoded.items;
}

const ServeLoopResponse = struct {
    response: ResponseOptions,
    headers_owned: bool = false,

    pub fn deinit(self: ServeLoopResponse, allocator: std.mem.Allocator) void {
        if (self.headers_owned) allocator.free(self.response.headers);
    }
};

pub fn adjustResponseForServeLoop(
    allocator: std.mem.Allocator,
    request: http1.Request,
    response: ResponseOptions,
    graceful_shutdown: bool,
) Error!ServeLoopResponse {
    var out = response;
    // The request is authoritative. A handler cannot opt itself into sending
    // trailers when the peer did not advertise support for receiving them.
    out.request_accepts_trailers = request.acceptsTrailers();
    const request_keep_alive = request.keepAlive();
    var adjusted = ServeLoopResponse{ .response = out };
    errdefer adjusted.deinit(allocator);

    if (graceful_shutdown) {
        adjusted = try ensureConnectionTokenForServeLoop(
            allocator,
            adjusted,
            "close",
        );
        out = adjusted.response;
    } else if (request.must_close) {
        // TE+CL is locally decoded as chunked, but the response must not
        // advertise persistence even when an application supplied other
        // Connection options. Preserve their hop-by-hop declarations and add
        // close as another field so the strongest token wins.
        adjusted = try ensureConnectionTokenForServeLoop(
            allocator,
            adjusted,
            "close",
        );
        out = adjusted.response;
    } else if (!request_keep_alive) {
        adjusted = try ensureConnectionTokenForServeLoop(
            allocator,
            adjusted,
            "close",
        );
        out = adjusted.response;
    }

    adjusted.response = out;
    return adjusted;
}

fn addConnectionHeaderForServeLoop(allocator: std.mem.Allocator, response: ResponseOptions, value: []const u8) Error!ServeLoopResponse {
    const headers = try allocator.alloc(http1.Header, response.headers.len + 1);
    @memcpy(headers[0..response.headers.len], response.headers);
    headers[response.headers.len] = .{ .name = "Connection", .value = value };
    var out = response;
    out.headers = headers;
    return .{ .response = out, .headers_owned = true };
}

fn ensureConnectionTokenForServeLoop(
    allocator: std.mem.Allocator,
    current: ServeLoopResponse,
    value: []const u8,
) Error!ServeLoopResponse {
    if (wire.anyHeaderContainsToken(
        current.response.headers,
        "connection",
        value,
    )) return current;
    const replacement = try addConnectionHeaderForServeLoop(
        allocator,
        current.response,
        value,
    );
    if (current.headers_owned) current.deinit(allocator);
    return replacement;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

pub fn responseOptionsKeepAlive(response: ResponseOptions) bool {
    return http1.headersKeepAlive(response.version, response.headers);
}

pub fn requestOptionsKeepAlive(request: RequestOptions) bool {
    return http1.headersKeepAlive(request.version, request.headers);
}

fn readRequestMessageBytes(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error![]u8 {
    const transport = RuntimeTransport{ .tcp = .{ .io = io, .stream = stream } };
    return readMessageBytesWithContext(
        allocator,
        transport,
        limits,
        null,
        true,
        options,
        false,
        if (limits.request_head_timeout) |timeout|
            try headReadDeadline(transport, timeout)
        else
            null,
        null,
    );
}

fn readMessageBytesWithContext(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    request_method: ?http1.Method,
    auto_continue: bool,
    options: http1.ParseOptions,
    close_delimited_when_unknown: bool,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = null;
    while (head_end == null) {
        head_end = try findHttpHeadEndWithinLimit(bytes.items, limits.max_head_bytes);
        if (head_end != null) break;
        // The non-buffered helpers have nowhere to keep bytes that belong to
        // the next pipelined message.  Read the head one byte at a time until
        // CRLFCRLF so this API remains safe even without an explicit inbuf.
        const read_buf = scratch[0..1];
        const n = if (head_deadline) |deadline|
            try transport.readWithDeadline(read_buf, deadline)
        else
            try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
    const plan = try message_head.inspect(allocator, bytes.items, options, request_method, auto_continue);
    try plan.validateBodyLimit(limits.max_body_bytes);
    if (auto_continue and plan.send_continue) try transport.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
    if (close_delimited_when_unknown and plan.body_framing == .close_delimited) {
        try EofBodyReader.collect(allocator, transport, &bytes, plan.head_len, limits.max_body_bytes, &scratch, body_deadline);
        return bytes.toOwnedSlice(allocator);
    }

    const target_len = while (true) {
        const len = plan.targetLength(
            bytes.items,
            limits.max_head_bytes,
            limits.max_body_bytes,
        ) catch |err| switch (err) {
            error.BufferTooShort => {
                // Unknown-length bodies such as chunked framing cannot safely
                // batch-read without an inbuf: the next read might cross the
                // terminating chunk into a pipelined message.  Read one byte
                // at a time until the body parser can compute the target.
                const read_buf = scratch[0..1];
                const n = try readTransportUntil(
                    transport,
                    read_buf,
                    body_deadline,
                );
                if (n == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..n]);
                continue;
            },
            else => |e| return e,
        };
        break len;
    };
    // Once framing has identified the complete message length, reserve the
    // final owned buffer size before the bulk body read.  This keeps
    // Content-Length responses from repeatedly growing the ArrayList while
    // preserving the one-byte reads required before chunked length discovery.
    try bytes.ensureTotalCapacity(allocator, target_len);
    while (bytes.items.len < target_len) {
        // Capacity is reserved above, so read the fixed-length body straight
        // into the owned buffer instead of copying through the stack scratch.
        const missing = target_len - bytes.items.len;
        const read_len = @min(scratch.len, missing);
        const spare = bytes.unusedCapacitySlice();
        const n = try readTransportUntil(
            transport,
            spare[0..read_len],
            body_deadline,
        );
        if (n == 0) return error.ConnectionClosed;
        bytes.items.len += n;
    }
    return bytes.toOwnedSlice(allocator);
}

fn readRequestMessageBytesBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error![]u8 {
    const transport = RuntimeTransport{ .tcp = .{ .io = io, .stream = stream } };
    return readMessageBytesBufferedWithContext(
        allocator,
        transport,
        limits,
        options,
        inbuf,
        null,
        true,
        false,
        if (limits.request_head_timeout) |timeout|
            try headReadDeadline(transport, timeout)
        else
            null,
        null,
        null,
        null,
    );
}

fn readResponseFromTransportBufferedForRequest(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error!OwnedResponse {
    return readResponseFromTransportBufferedForRequestObserved(
        allocator,
        transport,
        limits,
        options,
        inbuf,
        request_method,
        null,
        null,
        null,
    );
}

pub fn readResponseFromTransportBufferedForRequestObserved(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    informational: ?InformationalObserver,
    prior_informational_count: ?*usize,
    response_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    var local_informational_count: usize = 0;
    const informational_count = prior_informational_count orelse
        &local_informational_count;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseStartDeadlineForBuffer(
            transport,
            limits,
            inbuf.items,
            &response_head_deadline,
        );
        const effective_head_deadline = if (response_deadline) |deadline|
            earlierDeadline(response_head_deadline, deadline)
        else
            response_head_deadline;
        var response = try readOneResponseFromTransportBufferedForRequest(
            allocator,
            transport,
            limits,
            options,
            inbuf,
            request_method,
            effective_head_deadline,
            response_deadline,
        );
        if (informationalResponseToSkip(response.response.status)) {
            validateAndCountInformationalResponse(
                response.response,
                limits,
                informational_count,
            ) catch |err| {
                response.deinit(allocator);
                return err;
            };
            notifyInformationalResponse(informational, response.response);
            response.deinit(allocator);
            continue;
        }
        return response;
    }
}

const informationalResponseHead = response_sequence.informationalResponseHead;
const validateAndCountInformationalResponse = response_sequence.validateAndCountInformationalResponse;
const notifyInformationalResponse = response_sequence.notifyInformationalResponse;
const readOneResponseFromTransportBufferedForRequest = response_sequence.readOneResponseFromTransportBufferedForRequest;

pub fn readMessageBytesBufferedWithContext(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: ?http1.Method,
    auto_continue: bool,
    close_delimited_when_unknown: bool,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
    request_stage: ?*RequestReadStage,
    continue_state: ?*message_continue.State,
) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = null;
    while (head_end == null) {
        head_end = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
        if (head_end != null) break;
        const n = try BufferedInputReader.append(allocator, transport, inbuf, @min(scratch.len, limits.max_head_bytes - inbuf.items.len), head_deadline);
        if (n == 0) return error.ConnectionClosed;
    }
    const plan = try message_head.inspect(allocator, inbuf.items, options, request_method, auto_continue);
    if (request_stage) |stage| stage.* = .body;
    try plan.validateBodyLimit(limits.max_body_bytes);
    if (auto_continue and plan.send_continue) {
        if (request_stage) |stage| stage.* = .continue_write;
        try message_continue.send(Error, transport, RuntimeTransport.writeAll, continue_state, true);
        if (request_stage) |stage| stage.* = .body;
    }
    if (close_delimited_when_unknown and plan.body_framing == .close_delimited) {
        try EofBodyReader.collect(allocator, transport, inbuf, plan.head_len, limits.max_body_bytes, &scratch, body_deadline);
        const bytes = try inbuf.toOwnedSlice(allocator);
        inbuf.* = .empty;
        return bytes;
    }
    const target_len = while (true) {
        const len = plan.targetLength(
            inbuf.items,
            limits.max_head_bytes,
            limits.max_body_bytes,
        ) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try BufferedInputReader.append(allocator, transport, inbuf, scratch.len, body_deadline);
                if (n == 0) return error.ConnectionClosed;
                continue;
            },
            else => |e| return e,
        };
        break len;
    };

    // Buffered reads may deliberately carry bytes from the following pipelined
    // message, so this is only a lower-bound reservation.  It still avoids
    // repeated growth for the common case where the current message body is not
    // fully buffered yet.
    try inbuf.ensureTotalCapacity(allocator, target_len);
    while (inbuf.items.len < target_len) {
        const n = try BufferedInputReader.append(allocator, transport, inbuf, scratch.len, body_deadline);
        if (n == 0) return error.ConnectionClosed;
    }

    if (inbuf.items.len == target_len) {
        return inbuf.toOwnedSlice(allocator);
    }
    const bytes = try allocator.dupe(u8, inbuf.items[0..target_len]);
    discardPrefix(inbuf, target_len);
    return bytes;
}

pub fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    const remaining = list.items[len..];
    @memmove(list.items[0..remaining.len], remaining);
    list.shrinkRetainingCapacity(remaining.len);
}

pub fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    return stream_io.readSome(io, stream, buffer);
}

pub fn readExactForTest(io: std.Io, stream: net.Stream, buffer: []u8) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try readSome(io, stream, buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

pub fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

pub const IdleSocketState = enum { clean, data, eof, failed };

pub fn probeIdleSocket(stream: net.Stream) IdleSocketState {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return .clean;
    } else {
        var byte: [1]u8 = undefined;
        var iov: std.posix.iovec = .{
            .base = &byte,
            .len = byte.len,
        };
        var message: std.posix.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = (&iov)[0..1],
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        while (true) {
            const rc = std.posix.system.recvmsg(
                stream.socket.handle,
                &message,
                std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT,
            );
            return switch (std.posix.errno(rc)) {
                .SUCCESS => if (rc == 0) .eof else .data,
                .AGAIN => .clean,
                .INTR => continue,
                else => .failed,
            };
        }
    }
}

test {
    _ = @import("runtime/tests.zig");
}
