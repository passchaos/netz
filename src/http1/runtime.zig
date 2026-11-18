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

pub const Error = http1.Error || tls_stream.Error || uri_redirect.Error || error{
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
    const stream = switch (endpoint.target) {
        .ip => |address| if (connect_deadline) |absolute|
            try tcp_connect.ipWithDeadline(io, address, absolute)
        else
            try tcp_connect.ip(io, address, null),
        .host => |host| blk: {
            const policy = proxy_options.address_connect_policy orelse
                tcp_connect.AddressConnectPolicy.ordered;
            try tcp_connect.validateAddressConnectPolicy(policy);
            if (proxy_options.address_resolver == null and policy == .ordered) {
                break :blk if (connect_deadline) |absolute|
                    try tcp_connect.hostWithDeadline(
                        io,
                        host,
                        endpoint.port,
                        absolute,
                    )
                else
                    try tcp_connect.host(io, host, endpoint.port, null);
            }
            const addresses = if (proxy_options.address_resolver) |resolver|
                try resolver.resolve(
                    resolver.context,
                    allocator,
                    io,
                    endpoint.tls_host,
                    endpoint.port,
                    connect_deadline,
                )
            else
                try address_resolver.resolveSystem(
                    allocator,
                    io,
                    endpoint.tls_host,
                    endpoint.port,
                    connect_deadline,
                );
            defer allocator.free(addresses);
            break :blk if (connect_deadline) |absolute|
                try tcp_connect.resolvedWithPolicyAndDeadline(
                    allocator,
                    io,
                    addresses,
                    absolute,
                    policy,
                )
            else
                try tcp_connect.resolvedWithPolicy(
                    allocator,
                    io,
                    addresses,
                    null,
                    policy,
                );
        },
    };
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

pub const TlsClientConnection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    net_read_buf: []u8,
    net_write_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
    net_reader: net.Stream.Reader,
    net_writer: net.Stream.Writer,
    client: tls.Client,
    // Only the thread currently driving this connection mutates the deadline.
    // `std.crypto.tls.Client` calls back into `net_reader` synchronously, so
    // this field scopes one application read without introducing shared timer
    // state or changing ordinary untimed reads.
    timed_read_deadline: ?std.Io.Clock.Timestamp = null,
    // std.Io.Reader erases the cause; net.Stream.Reader cannot represent
    // ConcurrencyUnavailable. Consume this cause once at the public boundary.
    timed_read_error: ?Error = null,
    /// Plaintext represented by the TLS ciphertext currently buffered in
    /// `net_writer` after a bounded application write timed out.
    pending_timed_plaintext_len: usize = 0,
    pending_timed_plaintext_fingerprint: tls_write_retry.Fingerprint = .{},
    write_closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
    ) Error!*TlsClientConnection {
        const deadline = if (options.handshake_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            break :blk std.Io.Clock.Timestamp.fromNow(io, .{
                .raw = timeout,
                .clock = .awake,
            });
        } else null;
        return initBefore(allocator, io, stream, host, options, deadline);
    }

    /// Complete the standard-library TLS handshake under the earlier of the
    /// caller's absolute deadline and `options.handshake_timeout`.
    pub fn initWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*TlsClientConnection {
        return initBefore(
            allocator,
            io,
            stream,
            host,
            options,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.handshake_timeout,
            ),
        );
    }

    pub fn initWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!*TlsClientConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return initWithDeadline(
            allocator,
            io,
            stream,
            host,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn initBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        host: []const u8,
        options: TlsClientOptions,
        handshake_deadline: ?std.Io.Clock.Timestamp,
    ) Error!*TlsClientConnection {
        const net_read_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(net_read_buf);
        const net_write_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(net_write_buf);
        const tls_read_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(tls_read_buf);
        const tls_write_buf = try allocator.alloc(u8, tls.Client.min_buffer_len);
        errdefer allocator.free(tls_write_buf);

        const conn = try allocator.create(TlsClientConnection);
        errdefer allocator.destroy(conn);
        conn.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .net_read_buf = net_read_buf,
            .net_write_buf = net_write_buf,
            .tls_read_buf = tls_read_buf,
            .tls_write_buf = tls_write_buf,
            .net_reader = undefined,
            .net_writer = undefined,
            .client = undefined,
        };
        conn.net_reader = net.Stream.reader(stream, io, conn.net_read_buf);
        conn.net_reader.interface.vtable = &tls_client_reader.vtable;
        conn.net_writer = net.Stream.writer(stream, io, conn.net_write_buf);
        conn.timed_read_deadline = handshake_deadline;
        defer conn.timed_read_deadline = null;

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try std.Io.randomSecure(io, &entropy);
        const now = std.Io.Timestamp.now(io, .real);

        // Zig's standard TLS client accepts only a certificate bundle, not a
        // platform verification callback. Callers that need OS policy should
        // use the Vail-backed transport.
        if (options.root_source == .platform) {
            return error.PlatformVerifierUnavailable;
        }

        var local_bundle: CertificateBundle = .empty;
        var local_lock: std.Io.RwLock = .init;
        var loaded_local_bundle = false;
        defer if (loaded_local_bundle) local_bundle.deinit(allocator);

        var client_options: tls.Client.Options = .{
            .host = if (options.verify_host) .{ .explicit = host } else .no_verification,
            .ca = .no_verification,
            .write_buffer = conn.tls_write_buf,
            .read_buffer = conn.tls_read_buf,
            .entropy = &entropy,
            .realtime_now = now,
            .allow_truncation_attacks = options.allow_truncation_attacks,
        };
        if (options.verify_host) {
            client_options.ca = if (options.ca_bundle) |ca_bundle|
                .{ .bundle = .{ .gpa = allocator, .io = io, .lock = ca_bundle.lock, .bundle = ca_bundle.bundle } }
            else if (options.root_source == .bundled) blk: {
                local_bundle = root_trust.initBundledBundle(
                    allocator,
                    now,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.CertificateUntrusted,
                };
                loaded_local_bundle = true;
                break :blk .{ .bundle = .{ .gpa = allocator, .io = io, .lock = &local_lock, .bundle = &local_bundle } };
            } else blk: {
                try local_bundle.rescan(allocator, io, now);
                loaded_local_bundle = true;
                break :blk .{ .bundle = .{ .gpa = allocator, .io = io, .lock = &local_lock, .bundle = &local_bundle } };
            };
        }

        conn.client = tls.Client.init(
            &conn.net_reader.interface,
            &conn.net_writer.interface,
            client_options,
        ) catch |err| {
            if (err == error.ReadFailed and
                (conn.timed_read_error != null or conn.net_reader.err != null))
            {
                return conn.takeReadError();
            }
            return err;
        };
        return conn;
    }

    pub fn deinit(self: *TlsClientConnection) void {
        self.pending_timed_plaintext_fingerprint.clear();
        if (!self.write_closed) {
            self.client.end() catch {};
            self.net_writer.interface.flush() catch {};
        }
        self.stream.close(self.io);
        const allocator = self.allocator;
        allocator.free(self.net_read_buf);
        allocator.free(self.net_write_buf);
        allocator.free(self.tls_read_buf);
        allocator.free(self.tls_write_buf);
        allocator.destroy(self);
    }

    pub fn read(self: *TlsClientConnection, buffer: []u8) Error!usize {
        if (buffer.len == 0) return 0;
        const available = self.client.reader.peekGreedy(1) catch |err|
            switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => return self.takeReadError(),
            };
        const count = @min(buffer.len, available.len);
        @memcpy(buffer[0..count], available[0..count]);
        self.client.reader.toss(count);
        return count;
    }

    /// True only when the standard TLS wrapper retains no decrypted
    /// application bytes and is still open for both directions. Ciphertext in
    /// the network Reader remains for TLS to authenticate and classify.
    pub fn isReusableBoundary(self: *const TlsClientConnection) bool {
        return self.client.reader.bufferedLen() == 0 and
            !self.client.eof() and
            self.pending_timed_plaintext_len == 0 and
            !self.write_closed;
    }

    /// Read decrypted application bytes under one absolute socket deadline.
    ///
    /// Zig's TLS client owns the record parser and its plaintext/ciphertext
    /// buffers. Rather than duplicating that private state machine, the
    /// network Reader consults this transient deadline only when TLS needs
    /// more ciphertext. Already-buffered plaintext and complete encrypted
    /// records therefore remain immediately available.
    pub fn readWithDeadline(
        self: *TlsClientConnection,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (buffer.len == 0) return 0;
        // TLS may have decrypted an entire record to satisfy an earlier short
        // read. Consume that plaintext before consulting the socket deadline:
        // returning already-owned bytes performs no blocking I/O and must not
        // fail merely because the caller's deadline expired meanwhile.
        const buffered = self.client.reader.buffered();
        if (buffered.len != 0) {
            const count = @min(buffer.len, buffered.len);
            @memcpy(buffer[0..count], buffered[0..count]);
            self.client.reader.toss(count);
            return count;
        }
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.timed_read_deadline == null);
        self.timed_read_deadline = deadline;
        defer self.timed_read_deadline = null;
        return self.read(buffer);
    }

    fn takeReadError(self: *TlsClientConnection) Error {
        if (self.timed_read_error) |err| {
            self.timed_read_error = null;
            return err;
        }
        if (self.net_reader.err) |err| {
            self.net_reader.err = null;
            return err;
        }
        if (self.client.read_err) |err| return switch (err) {
            error.TlsBadLength => error.TlsDecodeError,
            error.TlsSequenceOverflow => error.SequenceOverflow,
            else => |value| value,
        };
        return error.ReadFailed;
    }

    pub fn writeAll(self: *TlsClientConnection, bytes: []const u8) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        if (bytes.len == 0) return;
        try self.client.writer.writeAll(bytes);
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    /// Write a protocol header and payload with one TLS/network flush.
    ///
    /// Framed protocols such as WebSocket commonly keep their fixed header on
    /// the stack and borrow the application payload. Accepting both slices
    /// avoids concatenating them into a temporary allocation while preserving
    /// one TLS record flush boundary for the logical write.
    pub fn writeAllParts(
        self: *TlsClientConnection,
        header: []const u8,
        payload: []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        if (header.len == 0 and payload.len == 0) return;
        if (header.len != 0) try self.client.writer.writeAll(header);
        if (payload.len != 0) try self.client.writer.writeAll(payload);
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    pub fn writeAllSlices(
        self: *TlsClientConnection,
        parts: []const []const u8,
    ) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        var has_bytes = false;
        for (parts) |part| {
            if (part.len == 0) continue;
            has_bytes = true;
            try self.client.writer.writeAll(part);
        }
        if (!has_bytes) return;
        try self.client.writer.flush();
        try self.net_writer.interface.flush();
    }

    /// Write plaintext under an absolute socket deadline. Progress advances
    /// only after the complete TLS record carrying that plaintext has reached
    /// the socket. Timeout, cancellation and executor admission failure retain
    /// the encrypted record and consumed sequence number for a later retry.
    /// Retry with the identical pending-record prefix, optionally relocated or
    /// extended with unaccepted tail bytes. A mismatch returns WriteInProgress
    /// before socket I/O. finishPendingTimedWrite explicitly drains that record
    /// without consuming replacement plaintext.
    pub fn writeAllWithDeadline(
        self: *TlsClientConnection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        if (self.write_closed) return error.ConnectionClosed;

        if (self.pending_timed_plaintext_len != 0) {
            try self.pending_timed_plaintext_fingerprint.validate(self.pending_timed_plaintext_len, bytes);
            try self.finishTimedRecord(committed, deadline);
        }
        while (committed.* < bytes.len) {
            const chunk_len = @min(
                tls.max_ciphertext_inner_record_len,
                bytes.len - committed.*,
            );
            std.debug.assert(self.client.writer.buffered().len == 0);
            std.debug.assert(self.net_writer.interface.buffered().len == 0);
            const plaintext = bytes[committed.*..][0..chunk_len];
            try self.client.writer.writeAll(plaintext);
            // This encrypts into the connection-owned network writer buffer;
            // that buffer is one full TLS record and performs no socket I/O.
            try self.client.writer.flush();
            self.pending_timed_plaintext_len = chunk_len;
            self.finishTimedRecord(committed, deadline) catch |err| {
                self.pending_timed_plaintext_fingerprint.capture(plaintext);
                return err;
            };
        }
    }

    pub fn finishPendingTimedWrite(
        self: *TlsClientConnection,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len == 0) return;
        try self.net_writer.interface.flush();
        committed.* = self.pending_timed_plaintext_len;
        self.pending_timed_plaintext_len = 0;
        self.pending_timed_plaintext_fingerprint.clear();
    }

    fn finishTimedRecord(
        self: *TlsClientConnection,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(self.pending_timed_plaintext_len != 0);
        while (self.net_writer.interface.buffered().len != 0) {
            const count = try stream_io.writeSomeWithDeadline(
                self.io,
                self.stream,
                self.net_writer.interface.buffered(),
                deadline,
            );
            _ = self.net_writer.interface.consume(count);
        }
        committed.* += self.pending_timed_plaintext_len;
        self.pending_timed_plaintext_len = 0;
        self.pending_timed_plaintext_fingerprint.clear();
    }

    pub fn closeWrite(self: *TlsClientConnection) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        if (self.pending_timed_plaintext_len != 0) {
            return error.WriteInProgress;
        }
        // Once TLS shutdown starts, application writes cannot be retried even
        // if flushing the alert or the socket half-close fails.
        self.write_closed = true;
        try self.client.end();
        try self.net_writer.interface.flush();
        try shutdownAfterTlsCloseNotify(self.io, self.stream);
    }
};

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

pub const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls_client: *TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    pub fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls_client => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
        };
    }

    pub fn readWithDeadline(
        self: RuntimeTransport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self) {
            .tcp => |tcp| stream_io.readSomeWithDeadline(
                tcp.io,
                tcp.stream,
                buffer,
                deadline,
            ) catch |err| return mapHttpTimedReadError(err),
            .tls_client => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_vail => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_server => |conn| conn.readWithDeadline(buffer, deadline),
        };
    }

    pub fn deadlineFromNow(
        self: RuntimeTransport,
        duration: std.Io.Duration,
    ) Error!std.Io.Clock.Timestamp {
        const io = switch (self) {
            .tcp => |tcp| tcp.io,
            .tls_client => |conn| conn.io,
            .tls_vail => |conn| conn.io,
            .tls_server => |conn| conn.io,
        };
        return .fromNow(io, .{ .raw = duration, .clock = .awake });
    }

    pub fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls_client => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
        };
    }

    /// Write one logical plaintext slice under an absolute deadline while
    /// reporting the exact prefix committed to the transport.
    pub fn writeAllWithDeadline(
        self: RuntimeTransport,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllTrackedWithDeadline(
                tcp.io,
                tcp.stream,
                bytes,
                committed,
                deadline,
            ),
            .tls_client => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_vail => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_server => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
        };
    }

    pub fn writeAllPartsWithDeadline(
        self: RuntimeTransport,
        header: []const u8,
        body: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        var part_committed: usize = 0;
        self.writeAllWithDeadline(
            header,
            &part_committed,
            deadline,
        ) catch |err| {
            committed.* = part_committed;
            return err;
        };
        committed.* = part_committed;
        part_committed = 0;
        self.writeAllWithDeadline(
            body,
            &part_committed,
            deadline,
        ) catch |err| {
            committed.* += part_committed;
            return err;
        };
        committed.* += part_committed;
    }

    fn writeAllParts(
        self: RuntimeTransport,
        header: []const u8,
        body: []const u8,
    ) Error!void {
        if (body.len == 0) return self.writeAll(header);
        if (header.len == 0) return self.writeAll(body);
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllParts(
                tcp.io,
                tcp.stream,
                header,
                body,
            ),
            .tls_client => |conn| conn.writeAllParts(header, body),
            .tls_vail => |conn| conn.writeAllParts(header, body),
            .tls_server => |conn| conn.writeAllParts(header, body),
        };
    }

    fn writeAllSlices(
        self: RuntimeTransport,
        parts: []const []const u8,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllSlicesWide(
                tcp.io,
                tcp.stream,
                parts,
            ),
            .tls_client => |conn| conn.writeAllSlices(parts),
            .tls_vail => |conn| conn.writeAllSlices(parts),
            .tls_server => |conn| conn.writeAllSlices(parts),
        };
    }

    pub fn closeWrite(self: RuntimeTransport) Error!void {
        return switch (self) {
            .tcp => |tcp| tcp.stream.shutdown(tcp.io, .send),
            .tls_client => |conn| conn.closeWrite(),
            .tls_vail => |conn| {
                try conn.sendCloseNotify();
                try shutdownAfterTlsCloseNotify(conn.io, conn.stream);
            },
            .tls_server => |conn| {
                try conn.sendCloseNotify();
                try shutdownAfterTlsCloseNotify(conn.io, conn.stream);
            },
        };
    }

    /// Abort both directions without releasing transport-owned TLS state.
    /// The owning Client/Connection still performs the eventual deinit, while
    /// the shutdown ensures no more HTTP/1 bytes can be misinterpreted after
    /// an upgraded protocol error.
    pub fn abort(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.shutdown(tcp.io, .both) catch {},
            .tls_client => |conn| conn.stream.shutdown(conn.io, .both) catch {},
            .tls_vail => |conn| conn.stream.shutdown(conn.io, .both) catch {},
            .tls_server => |conn| conn.stream.shutdown(conn.io, .both) catch {},
        }
    }

    pub fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls_client => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
        }
    }
};

fn mapHttpTimedReadError(err: stream_io.TimedReadError) Error {
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

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return initWithListener(
            allocator,
            io,
            try bind_address.listen(io, .{ .reuse_address = true }),
            limits,
        );
    }

    /// Adopt an already-bound TCP listener. Ownership transfers to the
    /// returned server, which closes it from `deinit`.
    pub fn initWithListener(
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: net.Server,
        limits: Limits,
    ) Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = listener,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStream(stream);
    }

    /// Adopt an already accepted cleartext stream. Protocol adapters can
    /// consume trusted transport prefaces before handing ownership to HTTP/1.
    pub fn acceptStream(
        self: *Server,
        stream: net.Stream,
    ) Error!Connection {
        errdefer stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try setTcpNoDelay(stream);
        }
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn serveOne(self: *Server, context: anytype, comptime handler: anytype) Error!void {
        var connection = try self.accept();
        defer connection.close();
        _ = try connection.serveOne(context, handler);
    }

    pub fn serveConnection(self: *Server, context: anytype, comptime handler: anytype, max_requests: usize) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *Server,
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
        return serveAcceptedUntil(
            Server,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

/// HTTP/1 listener over a Unix-domain stream socket.
///
/// Parsing, body framing, pipelining and response handling are delegated to
/// the same `Connection` used by TCP. Only the accept/address lifecycle is
/// Unix-specific. The socket path itself remains caller-owned; applications
/// are responsible for removing a filesystem socket after `deinit`.
pub const UnixServer = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        limits: Limits,
    ) Error!UnixServer {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try address.listen(io, .{}),
            .limits = limits,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn accept(self: *UnixServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *UnixServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        errdefer stream.close(self.io);
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
        };
    }

    pub fn serveOne(
        self: *UnixServer,
        context: anytype,
        comptime handler: anytype,
    ) Error!void {
        var connection = try self.accept();
        defer connection.close();
        try connection.serveOne(context, handler);
    }

    pub fn serveConnection(
        self: *UnixServer,
        context: anytype,
        comptime handler: anytype,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *UnixServer,
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
        return serveAcceptedUntil(
            UnixServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

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
    /// Optional ALPN selection. HTTP/1 accepts empty negotiation for legacy
    /// HTTPS, while configured servers require a shared protocol.
    alpn_protocols: []const []const u8 = &.{},
    tcp_nodelay: bool = true,
};

/// TLS 1.2/1.3 server transport for the same HTTP/1 parser and writer used by the
/// cleartext listener. Accepted connections own their TLS state and expose the
/// authenticated peer chain when client certificates are configured.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) Error!TlsServer {
        if (options.identity_provider) |provider| {
            var lease = provider.acquire();
            defer lease.deinit();
            try lease.identity.validate();
        } else {
            try options.identity.validate();
        }
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try bind_address.listen(
                io,
                .{ .reuse_address = true },
            ),
            .limits = options.limits,
            .tls = .{
                .identity = options.identity,
                .identity_provider = options.identity_provider,
                .cipher_suites = options.cipher_suites,
                .tls12_cipher_suites = options.tls12_cipher_suites,
                .protocol_policy = options.protocol_policy,
                .tls13_session_tickets = options.tls13_session_tickets,
                .tls12_session_tickets = options.tls12_session_tickets,
                .max_client_hello_size = options.max_client_hello_size,
                .max_client_handshake_size = options.max_client_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
                .client_auth = options.client_auth,
                .alpn_protocols = options.alpn_protocols,
            },
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *TlsServer) Error!Connection {
        const stream = try self.listener.accept(self.io);
        return self.acceptStream(stream);
    }

    /// Perform the TLS handshake on an already accepted stream. Ownership
    /// transfers at entry, matching the deadline-bounded adoption helpers.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
    ) Error!Connection {
        return self.acceptStreamMaybeBefore(stream, null);
    }

    /// Apply one caller-owned deadline to TCP accept and TLS setup.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    /// Perform the TLS handshake on an already accepted stream under one
    /// caller-owned deadline. Ownership transfers at entry.
    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptStreamMaybeBefore(stream, deadline);
    }

    pub fn acceptStreamWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        timeout: std.Io.Duration,
    ) Error!Connection {
        // As with the deadline form, validation precedes ownership transfer.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn acceptStreamMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ServerConnection.initWithDeadline(
                self.allocator,
                self.io,
                stream,
                self.tls,
                absolute,
            )
        else
            try tls_stream.ServerConnection.init(
                self.allocator,
                self.io,
                stream,
                self.tls,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .limits = self.limits,
            .tls_server_conn = tls_connection,
        };
    }

    pub fn serveOne(
        self: *TlsServer,
        context: anytype,
        comptime handler: anytype,
    ) Error!void {
        var connection = try self.accept();
        defer connection.close();
        _ = try connection.serveOne(context, handler);
    }

    pub fn serveConnection(
        self: *TlsServer,
        context: anytype,
        comptime handler: anytype,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            http1.Request,
        ) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            TlsServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
        );
    }

    pub fn serveUntil(
        self: *TlsServer,
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
        return serveAcceptedUntil(
            TlsServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            max_requests_per_connection,
            options,
        );
    }
};

pub const AsyncServeError = Error || std.Io.Cancelable;

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
fn serveAcceptedConcurrent(
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
    @memset(results, null);

    for (results) |*result| {
        var connection = try server.accept();
        errdefer connection.close();
        const task = ServeTask(HandlerContext, handler){
            .connection = connection,
            .context = context,
            .result = result,
        };
        group.async(io, ServeTask(HandlerContext, handler).run, .{task});
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

fn serveAcceptedUntil(
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

pub const RequestWriter = struct {
    client: *Client,
    method: http1.Method,
    /// True only when the serialized HTTP/1.1 request has a body and its sole
    /// Expect value is 100-continue. This value is immutable across writer
    /// copies; the one-shot observation state lives in shared connection state.
    expects_continue: bool,
    body: StreamingBodyWriter,

    pub fn deinit(self: *RequestWriter) void {
        self.body.deinit();
    }

    pub fn write(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        try self.body.write(data);
    }

    pub fn writeChunks(
        self: *RequestWriter,
        chunks: []const []const u8,
    ) Error!void {
        try self.body.writeChunks(chunks);
    }

    pub fn finish(self: *RequestWriter) Error!void {
        try self.body.finish();
    }

    pub fn finishTrailers(
        self: *RequestWriter,
        trailers: []const http1.Header,
    ) Error!void {
        try self.body.finishTrailers(trailers);
    }

    /// Wait for `100 Continue` before transmitting an expected request body.
    ///
    /// Other informational responses are consumed while waiting. A final
    /// response is returned to the caller and makes the HTTP/1 connection
    /// unusable: without sending the declared request body, the connection
    /// cannot safely begin another exchange even if the peer advertises
    /// keep-alive. The returned final response is owned by the caller.
    pub fn waitForContinue(
        self: *RequestWriter,
    ) Error!ExpectContinueResult {
        return self.waitForContinueWithInformational(null);
    }

    /// Wait for 100 Continue while observing every preceding informational
    /// head, including the 100 response which releases the request body.
    pub fn waitForContinueWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!ExpectContinueResult {
        try self.body.ensureExchangeActive();
        if (!self.expects_continue or
            self.body.state.expect_continue_received or
            self.body.isBodyFinished() or
            self.body.state.phase != .writing or self.body.state.written != 0)
        {
            return error.InvalidWriterState;
        }

        self.client.beginResponseHeadSequence();
        defer self.client.endResponseHeadSequence();
        while (true) {
            const response_head_deadline =
                try self.client.ensureResponseHeadDeadline();
            var response = readOneResponseFromTransportBufferedForRequest(
                self.client.allocator,
                self.client.transport(),
                self.client.limits,
                .{},
                &self.client.inbuf,
                self.method,
                response_head_deadline,
                null,
            ) catch |err| {
                self.body.fail();
                return err;
            };
            if (informationalResponseToSkip(response.response.status)) {
                validateAndCountInformationalResponse(
                    response.response,
                    self.client.limits,
                    &self.body.state.informational_responses_seen,
                ) catch |err| {
                    response.deinit(self.client.allocator);
                    self.body.fail();
                    return err;
                };
                notifyInformationalResponse(
                    informational,
                    response.response,
                );
            }
            if (response.response.status == 100) {
                response.deinit(self.client.allocator);
                self.body.state.expect_continue_received = true;
                return .proceed;
            }
            if (informationalResponseToSkip(response.response.status)) {
                response.deinit(self.client.allocator);
                continue;
            }

            // The peer rejected or otherwise answered the request before its
            // body. Transfer response ownership while retiring this writer.
            self.body.release(false);
            return .{ .final_response = response };
        }
    }

    /// Read the response and release the connection exchange slot exactly once.
    pub fn readResponse(self: *RequestWriter) Error!OwnedResponse {
        return self.readResponseWithInformational(null);
    }

    pub fn readResponseWithParseOptions(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
    ) Error!OwnedResponse {
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            null,
        );
    }

    pub fn readResponseWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithDeadline(.fromNow(
            self.client.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readResponseWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.readResponseWithInformationalAndDeadline(
            null,
            deadline,
        );
    }

    pub fn readResponseWithParseOptionsAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithParseOptionsAndDeadline(
            parse_options,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readResponseWithParseOptionsAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            null,
        );
    }

    pub fn readResponseWithParseOptionsAndInformationalAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithParseOptionsAndInformationalAndDeadline(
            parse_options,
            informational,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readResponseWithParseOptionsAndInformationalAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            informational,
        );
    }

    pub fn readResponseWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithInformational(informational);
    }

    pub fn readResponseWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithInformationalAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Read the final response while synchronously observing preceding 1xx
    /// heads. This is the streaming-request counterpart to
    /// `Client.requestWithInformational`.
    pub fn readResponseWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.readResponseWithParseOptionsAndInformational(
            .{},
            informational,
        );
    }

    pub fn readResponseWithParseOptionsAndInformational(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        try self.body.ensureExchangeActive();
        if (!self.body.isBodyFinished()) return error.InvalidWriterState;

        const response = readResponseFromTransportBufferedForRequestObserved(
            self.client.allocator,
            self.client.transport(),
            self.client.limits,
            parse_options,
            &self.client.inbuf,
            self.method,
            informational,
            &self.body.state.informational_responses_seen,
            self.client.response_deadline,
        ) catch |err| {
            self.body.fail();
            return err;
        };
        self.body.release(responseIsReusable(response.response, self.method));
        return response;
    }

    pub fn readResponseStreaming(
        self: *RequestWriter,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHead(
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithDeadline(
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndDeadline(
            null,
            deadline,
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithInformational(
            informational,
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptions(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformational(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithParseOptionsAndDeadline(
            parse_options,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformationalAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithParseOptionsAndInformationalAndDeadline(
            parse_options,
            informational,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformationalAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Stream the final response body while observing preceding 1xx heads.
    pub fn readResponseStreamingWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHead(
        self: *RequestWriter,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            null,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHead(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            .{},
            informational,
            context,
            begin,
            consume,
        );
    }

    /// Finish the request and stream the final response under one absolute
    /// deadline while observing every interim head and the final head.
    pub fn readResponseStreamingWithInformationalAndHeadAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithInformationalAndHead(
            informational,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHeadAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithOptionsAndHead(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        try self.body.ensureExchangeActive();
        if (!self.body.isBodyFinished()) {
            return error.InvalidWriterState;
        }
        const response = self.client.readStreamingResponse(
            self.method,
            parse_options,
            informational,
            &self.body.state.informational_responses_seen,
            context,
            begin,
            consume,
        ) catch |err| {
            self.body.fail();
            return err;
        };
        self.body.release(streamingResponseIsReusable(
            response,
            self.method,
        ));
        return response;
    }
};

pub const ExpectContinueResult = union(enum) {
    proceed,
    final_response: OwnedResponse,
};

pub const ResponseWriter = struct {
    body: StreamingBodyWriter,

    pub fn deinit(self: *ResponseWriter) void {
        self.body.deinit();
    }

    pub fn write(
        self: *ResponseWriter,
        data: []const u8,
    ) Error!void {
        try self.body.write(data);
    }

    pub fn writeChunks(
        self: *ResponseWriter,
        chunks: []const []const u8,
    ) Error!void {
        try self.body.writeChunks(chunks);
    }

    pub fn finish(self: *ResponseWriter) Error!void {
        try self.body.finish();
    }

    pub fn finishTrailers(
        self: *ResponseWriter,
        trailers: []const http1.Header,
    ) Error!void {
        try self.body.finishTrailers(trailers);
    }
};

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

fn parseResponseForRuntime(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
    request_method: ?http1.Method,
) Error!http1.Response {
    return if (request_method) |method|
        try http1.parseResponseForRequest(allocator, bytes, options, method)
    else
        try http1.parseResponse(allocator, bytes, options);
}

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
        const read_buf = scratch[0..@min(scratch.len, target_len - bytes.items.len)];
        const n = try readTransportUntil(
            transport,
            read_buf,
            body_deadline,
        );
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
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

fn informationalResponseHead(response: http1.Response) InformationalResponseHead {
    return .{
        .version = response.version,
        .status = response.status,
        .reason = response.reason,
        .headers = response.headers,
    };
}

fn validateAndCountInformationalResponse(
    response: http1.Response,
    limits: Limits,
    count: *usize,
) Error!void {
    try http1.validateResponseBodyForStatus(
        response.status,
        response.headers,
        response.body,
        response.trailers,
    );
    count.* += 1;
    if (count.* > limits.max_informational_responses) {
        return error.TooManyInformationalResponses;
    }
}

fn notifyInformationalResponse(
    informational: ?InformationalObserver,
    response: http1.Response,
) void {
    if (informational) |observer| {
        observer.on_response(
            observer.context,
            informationalResponseHead(response),
        );
    }
}

fn readOneResponseFromTransportBufferedForRequest(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        transport,
        limits,
        options,
        inbuf,
        request_method,
        false,
        true,
        head_deadline,
        body_deadline,
        null,
        null,
    );
    errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
    var response = try parseResponseForRuntime(
        allocator,
        bytes,
        options,
        request_method,
    );
    errdefer response.deinit(allocator);
    return .{ .bytes = bytes, .response = response };
}

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
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
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
