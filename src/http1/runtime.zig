const std = @import("std");
const builtin = @import("builtin");
const http1 = @import("mod.zig");
const runtime_write = @import("runtime/write.zig");
const body_writer = @import("runtime/body_writer.zig");
const body_reader = @import("runtime/body_reader.zig");
const message_framing = @import("runtime/message/framing.zig");
const request_batch = @import("runtime/message/batch.zig");
const stream_io = @import("../internal/stream_io.zig");
const deadline_policy = @import("../internal/deadline.zig");
const accept_deadline = @import("../internal/accept.zig");
const http_date = @import("../internal/http_date.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const vail = @import("vail");

const net = std.Io.net;
const tls = std.crypto.tls;
const CertificateBundle = std.crypto.Certificate.Bundle;

const messageTargetLength = message_framing.messageTargetLength;
const findHttpHeadEndWithinLimit = message_framing.findHeadEndWithinLimit;
const responseHeadUsesCloseDelimitedBody =
    message_framing.responseHeadUsesCloseDelimitedBody;
const informationalResponseToSkip = message_framing.informationalResponseToSkip;
const requestShouldSendContinue = message_framing.requestShouldSendContinue;
const RequestReadStage = enum { head, continue_write, body };

test "HTTP/1 connections keep optional write scratch compact" {
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 448), @sizeOf(Client));
        try std.testing.expectEqual(@as(usize, 384), @sizeOf(Connection));
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(WriteScratch));
    }
}

pub const Error = http1.Error || tls_stream.Error || error{
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
} || net.IpAddress.ListenError || net.IpAddress.ConnectError ||
    net.UnixAddress.ListenError || net.UnixAddress.ConnectError ||
    net.HostName.ValidateError || net.HostName.ConnectError ||
    net.Server.AcceptError || net.Stream.Reader.Error ||
    net.Stream.Writer.Error || net.ShutdownError || tls.Client.InitError ||
    CertificateBundle.RescanError || std.Io.RandomSecureError ||
    std.Io.Reader.ShortError || std.Io.Writer.Error ||
    std.Thread.SpawnError;

fn setTcpNoDelay(stream: net.Stream) Error!void {
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
    /// Optional caller-managed CA bundle.  When omitted and host verification is
    /// enabled, the runtime loads the operating-system root store for the
    /// handshake and frees it after TLS session establishment.
    ca_bundle: ?TlsCaBundle = null,
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
    max_server_handshake_size: usize = 256 * 1024,
    handshake_timeout: ?std.Io.Duration = null,
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

test "URI endpoint handles bracketed IPv6 literals" {
    const allocator = std.testing.allocator;
    const uri = try std.Uri.parse("http://[::1]:8080/ipv6?x=1");
    var endpoint = try uriEndpoint(allocator, uri, 80);
    defer endpoint.deinit();

    try std.testing.expectEqualStrings("[::1]:8080", endpoint.authority);
    try std.testing.expectEqualStrings("::1", endpoint.tls_host);
    switch (endpoint.target) {
        .ip => |address| switch (address) {
            .ip6 => |ip6| try std.testing.expectEqual(@as(u16, 8080), ip6.port),
            .ip4 => return error.InvalidUri,
        },
        .host => return error.InvalidUri,
    }

    const default_port_uri = try std.Uri.parse("http://example.com/path");
    var default_endpoint = try uriEndpoint(allocator, default_port_uri, 80);
    defer default_endpoint.deinit();
    try std.testing.expectEqualStrings("example.com", default_endpoint.authority);
    try std.testing.expectEqual(@as(u16, 80), default_endpoint.port);
}

test "URI endpoint retains host and authority in one allocation" {
    const allocator = std.testing.allocator;

    var implicit_one_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    const implicit = try std.Uri.parse("http://example.com/path");
    var implicit_endpoint = try uriEndpoint(
        implicit_one_alloc.allocator(),
        implicit,
        80,
    );
    defer implicit_endpoint.deinit();
    try std.testing.expect(!implicit_one_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(implicit_endpoint.host_storage.ptr),
        @intFromPtr(implicit_endpoint.authority.ptr),
    );

    var explicit_one_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    const explicit = try std.Uri.parse("https://[::1]:8443/path");
    var explicit_endpoint = try uriEndpoint(
        explicit_one_alloc.allocator(),
        explicit,
        443,
    );
    defer explicit_endpoint.deinit();
    try std.testing.expect(!explicit_one_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("[::1]", explicit_endpoint.host_storage);
    try std.testing.expectEqualStrings("[::1]:8443", explicit_endpoint.authority);
    try std.testing.expectEqualStrings("::1", explicit_endpoint.tls_host);
    try std.testing.expectEqual(
        @intFromPtr(explicit_endpoint.host_storage.ptr),
        @intFromPtr(explicit_endpoint.authority.ptr),
    );
}

test "HTTP/1 TLS server exchanges persistent requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            try std.testing.expect(connection.peerCertificates() == null);
            try std.testing.expectEqual(
                tls_stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
                connection.negotiatedCipherSuite().?,
            );
            try std.testing.expectEqual(
                tls_stream.TranscriptHash.sha256,
                connection.negotiatedTranscriptHash().?,
            );
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/first" else "/second",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
                if (index == 0) try connection.updateTrafficKeys(false);
            }
            const updates = connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 0), updates.received);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca = try localTestCaBundle(allocator, io);
    defer ca[0].deinit(allocator);
    var client = try Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .ca_bundle = .{
            .bundle = &ca[0],
            .lock = &ca[1],
        } },
    );
    defer client.close();
    var first = try client.request(.{ .target = "/first" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 negotiates TLS 1.2 with ALPN and serves a request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            if (connection.negotiatedTlsProtocol() != .tls12) {
                shared.err = error.InvalidProtocolVersion;
                return;
            }
            var request = connection.readRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(std.testing.allocator);
            if (!std.mem.eql(u8, request.request.target, "/tls12")) {
                shared.err = error.InvalidTarget;
                return;
            }
            connection.writeResponse(.{
                .body = "tls12-http1",
                .request_method = request.request.method,
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        },
    );
    defer client.close();
    try std.testing.expectEqual(
        tls_stream.Protocol.tls12,
        client.negotiatedTlsProtocol().?,
    );
    var response = try client.request(.{ .target = "/tls12" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("tls12-http1", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 vail TLS client exposes mTLS metadata and key updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        certificate: *const [tls_testing.certificate_der_len]u8,
        exporter: [32]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const chain = connection.peerCertificates() orelse
                return error.MissingPeerCertificate;
            try std.testing.expectEqual(@as(usize, 1), chain.len);
            try std.testing.expectEqualSlices(
                u8,
                shared.certificate,
                chain[0],
            );
            try std.testing.expectEqual(
                tls_stream.NegotiatedCipherSuite.aes_256_gcm_sha384,
                connection.negotiatedCipherSuite().?,
            );
            try std.testing.expectEqual(
                tls_stream.TranscriptHash.sha384,
                connection.negotiatedTranscriptHash().?,
            );
            try connection.exportKeyingMaterial(
                "EXPORTER-netz-http1",
                "context",
                &shared.exporter,
            );
            try connection.updateTrafficKeys(true);
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/before" else "/after",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
            }
            const updates = connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 1), updates.received);
            try std.testing.expect(!updates.awaiting_peer_response);
        }
    };
    var shared = Shared{
        .server = &server,
        .certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer client.close();
    const chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqualSlices(u8, &certificate_der, chain[0]);
    try std.testing.expectEqualStrings(
        "http/1.1",
        client.negotiatedAlpn().?,
    );
    try std.testing.expectEqual(
        tls_stream.NegotiatedCipherSuite.aes_256_gcm_sha384,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        tls_stream.TranscriptHash.sha384,
        client.negotiatedTranscriptHash().?,
    );
    var exporter: [32]u8 = undefined;
    try client.exportKeyingMaterial(
        "EXPORTER-netz-http1",
        "context",
        &exporter,
    );
    var first = try client.request(.{ .target = "/before" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/after" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqualSlices(u8, &shared.exporter, &exporter);
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    try std.testing.expect(!updates.awaiting_peer_response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn localTestCaBundle(
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
    /// Plaintext represented by the TLS ciphertext currently buffered in
    /// `net_writer` after a bounded application write timed out.
    pending_timed_plaintext_len: usize = 0,
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
        conn.net_reader.interface.vtable = &tls_client_reader_vtable;
        conn.net_writer = net.Stream.writer(stream, io, conn.net_write_buf);
        conn.timed_read_deadline = handshake_deadline;
        defer conn.timed_read_deadline = null;

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        try std.Io.randomSecure(io, &entropy);
        const now = std.Io.Timestamp.now(io, .real);

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
            else blk: {
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
            if (err == error.ReadFailed and conn.net_reader.err != null) {
                return conn.takeReadError();
            }
            return err;
        };
        return conn;
    }

    pub fn deinit(self: *TlsClientConnection) void {
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
    /// the socket. On timeout the already-encrypted record remains buffered,
    /// preserving the consumed TLS sequence number for a later retry.
    pub fn writeAllWithDeadline(
        self: *TlsClientConnection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        if (self.write_closed) return error.ConnectionClosed;

        if (self.pending_timed_plaintext_len != 0) {
            try self.finishTimedRecord(committed, deadline);
        }
        while (committed.* < bytes.len) {
            const chunk_len = @min(
                tls.max_ciphertext_inner_record_len,
                bytes.len - committed.*,
            );
            std.debug.assert(self.client.writer.buffered().len == 0);
            std.debug.assert(self.net_writer.interface.buffered().len == 0);
            try self.client.writer.writeAll(
                bytes[committed.*..][0..chunk_len],
            );
            // This encrypts into the connection-owned network writer buffer;
            // that buffer is one full TLS record and performs no socket I/O.
            try self.client.writer.flush();
            self.pending_timed_plaintext_len = chunk_len;
            try self.finishTimedRecord(committed, deadline);
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
fn shutdownAfterTlsCloseNotify(
    io: std.Io,
    stream: net.Stream,
) Error!void {
    stream.shutdown(io, .send) catch |err| switch (err) {
        error.SocketUnconnected => {},
        else => return err,
    };
}

const tls_client_reader_vtable: std.Io.Reader.VTable = .{
    .stream = tlsClientReaderStream,
    .readVec = tlsClientReaderReadVec,
};

fn tlsClientReaderStream(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    const destination = limit.slice(try writer.writableSliceGreedy(1));
    var data: [1][]u8 = .{destination};
    const count = try tlsClientReaderReadVec(reader, &data);
    writer.advance(count);
    return count;
}

fn tlsClientReaderReadVec(
    reader: *std.Io.Reader,
    data: [][]u8,
) std.Io.Reader.Error!usize {
    const net_reader: *net.Stream.Reader = @alignCast(
        @fieldParentPtr("interface", reader),
    );
    const connection: *TlsClientConnection = @alignCast(
        @fieldParentPtr("net_reader", net_reader),
    );
    var vectors: [8][]u8 = undefined;
    const vector_count, const direct_bytes = try reader.writableVector(
        &vectors,
        data,
    );
    const destinations = vectors[0..vector_count];
    std.debug.assert(destinations.len != 0 and destinations[0].len != 0);

    const count = if (connection.timed_read_deadline) |deadline|
        readTlsClientTransportWithDeadline(
            connection,
            destinations,
            deadline,
        ) catch |err| {
            net_reader.err = mapTimedReadError(err);
            return error.ReadFailed;
        }
    else
        connection.io.vtable.netRead(
            connection.io.userdata,
            connection.stream.socket.handle,
            destinations,
        ) catch |err| {
            net_reader.err = err;
            return error.ReadFailed;
        };
    if (count == 0) return error.EndOfStream;
    if (count > direct_bytes) {
        reader.end += count - direct_bytes;
        return direct_bytes;
    }
    return count;
}

fn mapTimedReadError(err: stream_io.TimedReadError) net.Stream.Reader.Error {
    // std.Io.Reader deliberately erases transport errors into ReadFailed. Keep
    // the precise errors representable by net.Stream.Reader; collapse only
    // file-operation details which cannot be expressed by that public type.
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

fn readTlsClientTransportWithDeadline(
    connection: *TlsClientConnection,
    destinations: [][]u8,
    deadline: std.Io.Clock.Timestamp,
) stream_io.TimedReadError!usize {
    var total: usize = 0;
    for (destinations) |destination| {
        if (destination.len == 0) continue;
        const count = try stream_io.readSomeWithDeadline(
            connection.io,
            connection.stream,
            destination,
            deadline,
        );
        total += count;
        // One read is enough to preserve ordinary stream short-read behavior.
        // Continue only when it completely filled this vector so a following
        // TLS-owned buffer can receive bytes already available in the socket.
        if (count != destination.len) break;
    }
    return total;
}

const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls_client: *TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls_client => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
        };
    }

    fn readWithDeadline(
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

    fn deadlineFromNow(
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

    fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls_client => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
        };
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

    fn closeWrite(self: RuntimeTransport) Error!void {
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

    fn close(self: RuntimeTransport) void {
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

const WriteScratch = runtime_write.Scratch;
const StreamingBodyWriter = body_writer.Writer(Error);
const StreamingBodyReader = body_reader.Reader(Error);

fn flattenWriteParts(
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

fn writeSlicesWithStrategy(
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

fn writeMessagePartsWithStrategy(
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
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
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
        try options.identity.validate();
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
                .cipher_suites = options.cipher_suites,
                .tls12_cipher_suites = options.tls12_cipher_suites,
                .protocol_policy = options.protocol_policy,
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

pub const Client = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    write_scratch: WriteScratch = .{},
    writer_state: body_writer.State = .{},
    default_host: ?[]u8 = null,
    tls_conn: ?*TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    response_head_deadline: ?std.Io.Clock.Timestamp = null,
    response_deadline: ?std.Io.Clock.Timestamp = null,
    response_head_sequence_active: bool = false,

    fn transport(self: *Client) RuntimeTransport {
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls_client = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
        };
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
        };
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect over a Unix-domain socket while retaining ordinary HTTP/1 Host
    /// semantics. `host` is copied because later requests may omit it and use
    /// the connection default. TCP_NODELAY is deliberately not applied.
    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
    ) Error!Client {
        const stream = try tcp_connect.unix(io, address, limits.connect_timeout);
        errdefer stream.close(io);
        const owned_host = try allocator.dupe(u8, host);
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        const owned_host = try allocator.dupe(u8, host);
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        host: []const u8,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            host,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const owned_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(owned_host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    /// Resolve a hostname and connect under a caller-owned awake-clock
    /// deadline. A configured connect timeout can only shorten that budget.
    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        errdefer allocator.free(owned_host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.init(allocator, io, stream, host, tls_options);
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_conn = tls_conn,
        };
    }

    /// Share one absolute deadline across DNS/TCP and the TLS handshake while
    /// retaining stricter connect and TLS phase limits.
    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.initWithDeadline(
            allocator,
            io,
            stream,
            host,
            tls_options,
            deadline,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.init(
            allocator,
            io,
            stream,
            tls_host,
            tls_options,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_authority = try allocator.dupe(u8, authority);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_conn = try TlsClientConnection.initWithDeadline(
            allocator,
            io,
            stream,
            tls_host,
            tls_options,
            deadline,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        const owned_authority = try allocator.dupe(u8, authority);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_authority,
            .tls_conn = tls_conn,
        };
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            authority,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectVailTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(io, host_name, port, limits.connect_timeout);
        return connectVailTlsStream(
            allocator,
            io,
            stream,
            host,
            port,
            limits,
            tls_options,
        );
    }

    pub fn connectVailTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        return connectVailTlsStreamBefore(
            allocator,
            io,
            stream,
            host,
            port,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectVailTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectVailTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectVailTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        const stream = try tcp_connect.ip(io, address, limits.connect_timeout);
        const port = switch (address) {
            .ip4 => |ip4| ip4.port,
            .ip6 => |ip6| ip6.port,
        };
        return connectVailTlsStream(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
        );
    }

    pub fn connectVailTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                limits.connect_timeout,
            ),
        );
        return connectVailTlsStreamBefore(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectVailTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectVailTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectVailTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!Client {
        return connectVailTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
            null,
        );
    }

    fn connectVailTlsStreamBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectVailTlsStreamMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            limits,
            tls_options,
            deadline,
        );
    }

    fn connectVailTlsStreamMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Client {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        const options = verifiedTlsClientOptions(tls_host, tls_options);
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ClientConnection.initVerifiedWithDeadline(
                allocator,
                io,
                stream,
                options,
                absolute,
            )
        else
            try tls_stream.ClientConnection.initVerified(
                allocator,
                io,
                stream,
                options,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        const owned_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ tls_host, port },
        );
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .limits = limits,
            .default_host = owned_host,
            .tls_vail_conn = tls_connection,
        };
    }

    pub fn close(self: *Client) void {
        if (self.default_host) |host| self.allocator.free(host);
        self.inbuf.deinit(self.allocator);
        self.write_scratch.deinit(self.allocator);
        if (self.tls_conn) |conn| {
            conn.deinit();
        } else if (self.tls_vail_conn) |conn| {
            conn.deinit();
        } else {
            self.stream.close(self.io);
        }
        self.* = undefined;
    }

    pub fn peerCertificates(
        self: *const Client,
    ) ?[]const []const u8 {
        const connection = self.tls_vail_conn orelse return null;
        return connection.peerCertificates();
    }

    pub fn negotiatedAlpn(self: *const Client) ?[]const u8 {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedAlpn();
    }

    pub fn negotiatedTlsProtocol(
        self: *const Client,
    ) ?tls_stream.Protocol {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedProtocol();
    }

    pub fn negotiatedCipherSuite(
        self: *const Client,
    ) ?tls_stream.NegotiatedCipherSuite {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const Client,
    ) ?tls_stream.TranscriptHash {
        const connection = self.tls_vail_conn orelse return null;
        return connection.negotiatedTranscriptHash();
    }

    pub fn exportKeyingMaterial(
        self: *const Client,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        const connection = self.tls_vail_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try connection.exportKeyingMaterial(label, context, out);
    }

    pub fn updateTrafficKeys(
        self: *Client,
        request_peer_update: bool,
    ) Error!void {
        const connection = self.tls_vail_conn orelse
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
        self: *const Client,
    ) ?tls_stream.KeyUpdateCounts {
        const connection = self.tls_vail_conn orelse return null;
        return connection.keyUpdateCounts();
    }

    pub fn isReusable(self: *const Client) bool {
        return self.writer_state.phase == .idle and
            !self.writer_state.reading and
            self.inbuf.items.len == 0;
    }

    /// Reject clients that retain unread HTTP or TLS input. Cleartext sockets
    /// additionally probe the kernel queue for unsolicited bytes or EOF. TLS
    /// records still in the kernel cannot be classified without advancing the
    /// decryptor, so only already-buffered TLS state is inspected. Unsupported
    /// native backends conservatively skip the cleartext socket probe.
    pub fn isReusableForPool(self: *const Client) bool {
        if (!self.isReusable()) return false;
        if (self.tls_conn) |connection| {
            return connection.isReusableBoundary();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.isReusableBoundary();
        }
        return probeIdleSocket(self.stream) == .clean;
    }

    /// Validate and encode before touching the transport. Once a complete
    /// request write starts, any transport error is terminal: the peer may
    /// have observed an arbitrary prefix and HTTP/1 has no stream reset with
    /// which to restore the message boundary.
    fn writeRequestFailClosed(
        self: *Client,
        options: RequestOptions,
    ) Error!void {
        const parts = try runtime_write.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        var transport_started = false;
        writeMessagePartsWithStrategy(
            self.allocator,
            self.transport(),
            self.limits.write_strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        return self.requestWithParseOptions(
            request_options,
            .{},
        );
    }

    /// Send a complete request with explicit response parser compatibility.
    pub fn requestWithParseOptions(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformational(
            request_options,
            parse_options,
            null,
        );
    }

    pub fn requestWithParseOptionsAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithParseOptionsAndDeadline(
            request_options,
            parse_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestWithParseOptionsAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            null,
            deadline,
        );
    }

    pub fn requestWithParseOptionsAndInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Bound the complete response, including its body and trailers, with one
    /// absolute awake-clock budget. The existing response-head timeout remains
    /// active and whichever deadline expires first wins. HTTP/1 has no stream
    /// reset, so any read failure after the request write marks the connection
    /// unusable through the ordinary request error path.
    pub fn requestWithTimeout(
        self: *Client,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(
            request_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestWithDeadline(
        self: *Client,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
        );
    }

    /// Observe interim responses while bounding the request write and complete
    /// response with one caller-owned deadline.
    pub fn requestWithInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformationalAndDeadline(
            request_options,
            .{},
            informational,
            deadline,
        );
    }

    pub fn requestWithParseOptionsAndInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestWithParseOptionsAndInformational(
            request_options,
            parse_options,
            informational,
        );
    }

    pub fn requestWithInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Send a complete request and observe each valid interim response before
    /// returning the final response. The observer borrows parser storage only
    /// for the callback duration.
    pub fn requestWithInformational(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.requestWithParseOptionsAndInformational(
            request_options,
            .{},
            informational,
        );
    }

    pub fn requestWithParseOptionsAndInformational(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        const generation = try self.writer_state.begin();
        _ = generation;
        errdefer if (self.writer_state.phase == .writing) {
            // Local request validation can fail before any byte reaches the
            // transport. Preserve the caller's ability to correct and retry.
            self.writer_state.phase = .idle;
        };
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        try self.writeRequestFailClosed(options);
        self.writer_state.phase = .awaiting_peer;
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        const response = readResponseFromTransportBufferedForRequestObserved(
            self.allocator,
            self.transport(),
            self.limits,
            parse_options,
            &self.inbuf,
            request_options.method,
            informational,
            null,
            self.response_deadline,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        self.writer_state.phase = if (requestOptionsKeepAlive(options) and
            responseIsReusable(response.response))
            .idle
        else
            .unusable;
        return response;
    }

    /// Send a complete request and receive response body slices incrementally.
    ///
    /// The returned head/trailers are owned. Each body slice borrows reusable
    /// connection storage and is valid only until `consume` returns.
    pub fn requestStreaming(
        self: *Client,
        request_options: RequestOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithHead(
            request_options,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithTimeout(
        self: *Client,
        request_options: RequestOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithDeadline(
            request_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithDeadline(
        self: *Client,
        request_options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndDeadline(
            request_options,
            null,
            deadline,
            context,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithInformational(
            request_options,
            informational,
            context,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithInformationalAndDeadline(
            request_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Streaming response counterpart that enables explicit parser
    /// compatibility options, including obsolete line folding in trailers.
    pub fn requestStreamingWithParseOptions(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformational(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithParseOptionsAndDeadline(
            request_options,
            parse_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformationalAndTimeout(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithParseOptionsAndInformationalAndDeadline(
            request_options,
            parse_options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn requestStreamingWithParseOptionsAndInformationalAndDeadline(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Stream a response body while observing informational and final heads.
    pub fn requestStreamingWithInformational(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHead(
            request_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithHead(
        self: *Client,
        request_options: RequestOptions,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHead(
            request_options,
            null,
            context,
            begin,
            consume,
        );
    }

    /// Streaming response receive with ordered observation of preceding 1xx
    /// heads. Informational callbacks run before the final-head callback.
    pub fn requestStreamingWithInformationalAndHead(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithOptionsAndHead(
            request_options,
            .{},
            informational,
            context,
            begin,
            consume,
        );
    }

    pub fn requestStreamingWithOptionsAndHead(
        self: *Client,
        request_options: RequestOptions,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        const generation = try self.writer_state.begin();
        _ = generation;
        errdefer if (self.writer_state.phase == .writing) {
            self.writer_state.phase = .idle;
        };
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        const parts = try runtime_write.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        var transport_started = false;
        writeMessagePartsWithStrategy(
            self.allocator,
            self.transport(),
            self.limits.write_strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
            if (transport_started) self.writer_state.phase = .unusable;
            return err;
        };
        self.writer_state.phase = .awaiting_peer;
        const response = try self.readStreamingResponse(
            request_options.method,
            parse_options,
            informational,
            null,
            context,
            begin,
            consume,
        );
        self.writer_state.phase =
            if (requestOptionsKeepAlive(options) and
            streamingResponseIsReusable(
                response,
                request_options.method,
            ))
                .idle
            else
                .unusable;
        return response;
    }

    /// Start a request whose body is supplied incrementally.
    ///
    /// HTTP/1 serializes exchanges on a connection. The returned writer owns
    /// that slot through body completion and response receive; abandoning it
    /// makes the connection unusable because HTTP/1 has no per-message reset.
    pub fn startRequest(
        self: *Client,
        request_options: StreamingRequestOptions,
    ) Error!RequestWriter {
        const generation = try self.writer_state.begin();
        errdefer if (self.writer_state.phase == .writing) {
            self.writer_state.phase = .idle;
        };

        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        const prepared = try runtime_write.streaming.prepareRequest(
            self.allocator,
            options,
            &self.write_scratch,
        );
        const announced_trailers = self.write_scratch.trailerHeaders();
        self.transport().writeAll(prepared.head) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return .{
            .client = self,
            .method = options.method,
            .expects_continue = requestShouldSendContinue(prepared.head),
            .body = StreamingBodyWriter.init(
                self.allocator,
                &self.writer_state,
                generation,
                self,
                clientWriteSlices,
                &self.write_scratch,
                prepared,
                announced_trailers,
                false,
            ),
        };
    }

    pub fn requestUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        return requestUriTls(allocator, io, uri_text, request_options, limits, .{});
    }

    pub fn requestUriTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, if (is_https) 443 else 80);
        defer endpoint.deinit();

        const stream = switch (endpoint.target) {
            .host => |host| try tcp_connect.host(
                io,
                host,
                endpoint.port,
                limits.connect_timeout,
            ),
            .ip => |address| try tcp_connect.ip(
                io,
                address,
                limits.connect_timeout,
            ),
        };
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (limits.tcp_nodelay) try setTcpNoDelay(stream);
        var client = if (is_https) blk: {
            const tls_conn = try TlsClientConnection.init(allocator, io, stream, endpoint.tls_host, tls_options);
            stream_owned = false;
            errdefer tls_conn.deinit();
            const default_host = try allocator.dupe(u8, endpoint.authority);
            break :blk Client{
                .io = io,
                .allocator = allocator,
                .stream = stream,
                .limits = limits,
                .default_host = default_host,
                .tls_conn = tls_conn,
            };
        } else blk: {
            const default_host = try allocator.dupe(u8, endpoint.authority);
            stream_owned = false;
            break :blk Client{
                .io = io,
                .allocator = allocator,
                .stream = stream,
                .limits = limits,
                .default_host = default_host,
            };
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        return client.request(options);
    }

    pub fn requestUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return requestUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .{},
            deadline,
        );
    }

    pub fn requestUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Perform a one-shot HTTP/HTTPS request under one absolute deadline. DNS,
    /// TCP, TLS, response heads, body, and trailers all consume the same
    /// budget; configured connect, TLS, and response-head limits may shorten
    /// their own phases but never extend the caller deadline.
    pub fn requestUriTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
        const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!is_http and !is_https) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(
            allocator,
            uri,
            if (is_https) 443 else 80,
        );
        defer endpoint.deinit();

        var client = if (is_https) switch (endpoint.target) {
            .host => try connectTlsHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                endpoint.port,
                limits,
                tls_options,
                deadline,
            ),
            .ip => |address| try connectTlsAddressWithDeadline(
                allocator,
                io,
                address,
                endpoint.tls_host,
                endpoint.authority,
                limits,
                tls_options,
                deadline,
            ),
        } else switch (endpoint.target) {
            .host => try connectHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                endpoint.port,
                limits,
                deadline,
            ),
            .ip => |address| blk: {
                var connected = try connectWithDeadline(
                    allocator,
                    io,
                    address,
                    limits,
                    deadline,
                );
                connected.default_host = try allocator.dupe(
                    u8,
                    endpoint.authority,
                );
                break :blk connected;
            },
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        return client.requestWithDeadline(options, deadline);
    }

    pub fn requestUriTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// One-shot HTTPS request through the vail TLS 1.3 client. Use this when
    /// the caller needs mTLS, ALPN, peer identity, exporter, or KeyUpdate; for
    /// persistent connections call `connectVailTlsHost` directly.
    pub fn requestUriVailTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, 443);
        defer endpoint.deinit();
        var client = switch (endpoint.target) {
            .host => try connectVailTlsHost(
                allocator,
                io,
                endpoint.tls_host,
                uri.port orelse 443,
                limits,
                tls_options,
            ),
            .ip => |address| try connectVailTlsAddress(
                allocator,
                io,
                address,
                endpoint.tls_host,
                limits,
                tls_options,
            ),
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        if (options.host == null) options.host = endpoint.authority;
        return client.request(options);
    }

    pub fn requestUriVailTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, 443);
        defer endpoint.deinit();
        var client = switch (endpoint.target) {
            .host => try connectVailTlsHostWithDeadline(
                allocator,
                io,
                endpoint.tls_host,
                uri.port orelse 443,
                limits,
                tls_options,
                deadline,
            ),
            .ip => |address| try connectVailTlsAddressWithDeadline(
                allocator,
                io,
                address,
                endpoint.tls_host,
                limits,
                tls_options,
                deadline,
            ),
        };
        defer client.close();
        var options = request_options;
        options.target = target;
        if (options.host == null) options.host = endpoint.authority;
        return client.requestWithDeadline(options, deadline);
    }

    pub fn requestUriVailTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
        tls_options: VailTlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return requestUriVailTlsWithDeadline(
            allocator,
            io,
            uri_text,
            request_options,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openConnectTunnel(self: *Client, target: []const u8, headers: []const http1.Header) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try http1.validateConnectTarget(target);
        try self.writeRequestFailClosed(.{
            .method = .CONNECT,
            .target = target,
            .host = target,
            .headers = headers,
        });
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var response = readResponseFromTransportBufferedForRequest(
            self.allocator,
            self.transport(),
            self.limits,
            .{},
            &self.inbuf,
            .CONNECT,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        errdefer response.deinit(self.allocator);
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidResponse;
        if (response.response.body.len != 0 or response.response.trailers.len != 0) return error.InvalidResponse;
        response.deinit(self.allocator);
        // A successful CONNECT transfers exclusive ownership of the byte
        // stream to Tunnel. The HTTP client must never issue another request
        // or let a pool return this socket to its idle set.
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_conn = self.tls_conn,
            .tls_vail_conn = self.tls_vail_conn,
            .inbuf = &self.inbuf,
        };
    }

    /// Perform a generic HTTP/1.1 Upgrade and transfer the underlying byte
    /// stream to the caller after validating the peer's 101 response. Bytes
    /// already read beyond the response head remain available through
    /// `Tunnel.read`, which is essential when the upgraded peer sends its
    /// protocol preface immediately with the 101.
    pub fn openUpgrade(
        self: *Client,
        target: []const u8,
        host: ?[]const u8,
        protocol: []const u8,
        headers: []const http1.Header,
    ) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try validateUpgradeProtocol(protocol);
        try rejectUpgradeManagedHeaders(headers);
        var upgrade_headers: std.ArrayList(http1.Header) = .empty;
        defer upgrade_headers.deinit(self.allocator);
        try upgrade_headers.ensureTotalCapacity(
            self.allocator,
            headers.len + 2,
        );
        upgrade_headers.appendAssumeCapacity(.{
            .name = "Connection",
            .value = "Upgrade",
        });
        upgrade_headers.appendAssumeCapacity(.{
            .name = "Upgrade",
            .value = protocol,
        });
        upgrade_headers.appendSliceAssumeCapacity(headers);
        try self.writeRequestFailClosed(.{
            .method = .GET,
            .target = target,
            .host = host orelse self.default_host,
            .headers = upgrade_headers.items,
        });
        return self.finishUpgrade(protocol);
    }

    /// Complete a generic Upgrade from an already-written request. This split
    /// form supports callers that must coalesce their first protocol bytes
    /// with the HTTP request while preserving any response suffix read ahead.
    pub fn finishUpgrade(
        self: *Client,
        protocol: []const u8,
    ) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try validateUpgradeProtocol(protocol);
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var response = readResponseFromTransportBufferedForRequest(
            self.allocator,
            self.transport(),
            self.limits,
            .{},
            &self.inbuf,
            .GET,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        errdefer response.deinit(self.allocator);
        const selected = response.response.upgradeProtocol() orelse
            return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(selected, protocol) or
            response.response.body.len != 0 or
            response.response.trailers.len != 0)
        {
            return error.InvalidResponse;
        }
        response.deinit(self.allocator);
        self.writer_state.phase = .unusable;
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .tls_conn = self.tls_conn,
            .tls_vail_conn = self.tls_vail_conn,
            .inbuf = &self.inbuf,
        };
    }

    fn readStreamingResponse(
        self: *Client,
        request_method: http1.Method,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        informational_responses_seen: ?*usize,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        var reader = StreamingBodyReader{
            .allocator = self.allocator,
            .context = self,
            .read_some = clientReadSome,
            .read_head_some = clientReadHeadSome,
            .inbuf = &self.inbuf,
            .limits = .{
                .max_head_bytes = self.limits.max_head_bytes,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_informational_responses = self.limits.max_informational_responses,
            },
            .options = parse_options,
            .informational_context = if (informational) |observer|
                observer.context
            else
                null,
            .on_informational = if (informational) |observer|
                observer.on_response
            else
                null,
            .informational_responses_seen = informational_responses_seen,
        };
        const result = reader.readResponse(
            request_method,
            context,
            begin,
            consume,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return streamingResponseFromReader(result);
    }

    fn beginResponseHeadSequence(self: *Client) void {
        std.debug.assert(!self.response_head_sequence_active);
        std.debug.assert(self.response_head_deadline == null);
        self.response_head_sequence_active = true;
    }

    fn ensureResponseHeadDeadline(
        self: *Client,
    ) Error!?std.Io.Clock.Timestamp {
        try ensureResponseHeadDeadlineForBuffer(
            self.transport(),
            self.limits,
            self.inbuf.items,
            &self.response_head_deadline,
        );
        return self.response_head_deadline;
    }

    fn endResponseHeadSequence(self: *Client) void {
        self.response_head_deadline = null;
        self.response_head_sequence_active = false;
    }
};

fn verifiedTlsClientOptions(
    tls_host: []const u8,
    options: VailTlsClientOptions,
) tls_stream.ClientVerifiedOptions {
    return .{
        .server_name = tls_host,
        .verify_host = options.verify_host,
        .ca_bundle = options.ca_bundle,
        .server_verifier = options.server_verifier,
        .stapled_ocsp = options.stapled_ocsp,
        .request_ocsp = options.request_ocsp,
        .client_identity = options.client_identity,
        .alpn_protocols = options.alpn_protocols,
        .cipher_suites = options.cipher_suites,
        .tls12_cipher_suites = options.tls12_cipher_suites,
        .protocol_policy = options.protocol_policy,
        .max_server_handshake_size = options.max_server_handshake_size,
        .handshake_timeout = options.handshake_timeout,
    };
}

test "HTTP/1 vail TLS options preserve stapled OCSP policy" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .stapled_ocsp = .require,
        .request_ocsp = true,
    });
    try std.testing.expectEqual(StapledOcspPolicy.require, mapped.stapled_ocsp);
    try std.testing.expect(mapped.request_ocsp);
}

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

    fn transport(self: *Connection) RuntimeTransport {
        if (self.tls_server_conn) |connection| {
            return .{ .tls_server = connection };
        }
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
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

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedProtocol();
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
        self.inbuf.deinit(self.allocator);
        self.write_scratch.deinit(self.allocator);
        if (self.tls_server_conn) |connection| {
            connection.deinit();
        } else {
            self.stream.close(self.io);
        }
        self.* = undefined;
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
        return readRequestFromTransportBufferedWithStage(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            self.request_head_deadline,
            &stage,
        ) catch |read_err| {
            if (failure_stage) |out| out.* = stage;
            if (read_err == error.Timeout or stage == .continue_write) {
                self.writer_state.phase = .unusable;
            }
            return read_err;
        };
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
    pub fn readRequestWithDeadline(
        self: *Connection,
        options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.writer_state.ensureReadable();
        var stage: RequestReadStage = .head;
        return readRequestFromTransportBufferedWithStage(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            deadline,
            &stage,
        ) catch |err| {
            if (stage == .continue_write) {
                self.writer_state.phase = .unusable;
            }
            return err;
        };
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
            .before_request_body = connectionMaybeWriteContinue,
            .inbuf = &self.inbuf,
            .limits = .{
                .max_head_bytes = self.limits.max_head_bytes,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_informational_responses = self.limits.max_informational_responses,
            },
            .options = options,
        };
        const result = reader.readRequest(
            context,
            begin,
            consume,
        ) catch |err| {
            self.writer_state.failRead();
            return err;
        };
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
    }

    pub fn writeResponse(self: *Connection, response: ResponseOptions) Error!void {
        try self.writer_state.ensureAvailable();
        try self.writeResponseFailClosed(
            response,
            self.defaultResponseDate(),
        );
    }

    /// Keep deterministic validation/allocation failures retryable, but retire
    /// the connection after any transport write error because an unknown wire
    /// prefix may already be visible to the peer.
    fn writeResponseFailClosed(
        self: *Connection,
        response: ResponseOptions,
        default_date: ?[]const u8,
    ) Error!void {
        const parts = try runtime_write.prepareServerResponse(
            self.allocator,
            response,
            default_date,
            &self.write_scratch,
        );
        var transport_started = false;
        writeMessagePartsWithStrategy(
            self.allocator,
            self.transport(),
            self.limits.write_strategy,
            parts,
            &self.write_scratch,
            &transport_started,
        ) catch |err| {
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
        active_transport.writeAll(prepared.head) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        return .{
            .body = StreamingBodyWriter.init(
                self.allocator,
                &self.writer_state,
                generation,
                self,
                connectionWriteSlices,
                &self.write_scratch,
                prepared,
                announced_trailers,
                true,
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

fn validateUpgradeProtocol(protocol: []const u8) Error!void {
    http1.validateHeaderName(protocol) catch return error.InvalidResponse;
}

fn rejectUpgradeManagedHeaders(headers: []const http1.Header) Error!void {
    for (headers) |header| {
        if (header.eqlName("connection") or header.eqlName("upgrade")) {
            return error.InvalidResponse;
        }
    }
}

pub const Tunnel = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    inbuf: *std.ArrayList(u8),
    write_closed: bool = false,

    fn transport(self: *Tunnel) RuntimeTransport {
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

    /// Finish the tunnel's write half while preserving buffered and future
    /// reads. TLS transports send close_notify before shutting down the
    /// underlying socket write direction. The transition is fail-closed: once
    /// shutdown begins, this tunnel never accepts application writes again.
    pub fn closeWrite(self: *Tunnel) Error!void {
        if (self.write_closed) return error.ConnectionClosed;
        self.write_closed = true;
        try self.transport().closeWrite();
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

pub const OwnedResponse = struct {
    bytes: []u8,
    response: http1.Response,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
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

fn ignoreStreamingRequestHead(
    context: anytype,
    head: StreamingRequestHead,
) !void {
    _ = context;
    _ = head;
}

fn ignoreStreamingResponseHead(
    context: anytype,
    head: StreamingResponseHead,
) !void {
    _ = context;
    _ = head;
}

fn streamingRequestFromReader(
    request: StreamingBodyReader.Request,
) StreamingRequest {
    return request;
}

fn streamingResponseFromReader(
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
        self.body.release(responseIsReusable(response.response));
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

fn clientWriteSlices(
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

fn clientReadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const client: *Client = @ptrCast(@alignCast(context.?));
    if (client.response_deadline) |deadline| {
        return client.transport().readWithDeadline(buffer, deadline);
    }
    return client.transport().read(buffer);
}

fn clientReadHeadSome(
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

fn connectionReadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    return connection.transport().read(buffer);
}

fn connectionReadHeadSome(
    context: ?*anyopaque,
    buffer: []u8,
) Error!usize {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    const deadline = connection.request_head_deadline orelse
        return connection.transport().read(buffer);
    return connection.transport().readWithDeadline(buffer, deadline);
}

fn headReadDeadline(
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

fn readHttp09Body(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    max_body_bytes: usize,
    bytes: *std.ArrayList(u8),
    scratch: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]u8 {
    // HTTP/0.9 has no framing metadata; EOF is the only message boundary.
    // Keep the same decoded-body and outer-deadline guarantees as an HTTP/1.x
    // close-delimited response, and reject an empty EOF so a stale connection
    // cannot masquerade as a successful legacy response.
    while (true) {
        if (bytes.items.len > max_body_bytes) return error.BodyTooLarge;
        const remaining = max_body_bytes - bytes.items.len;
        const read_buf = scratch[0..@min(scratch.len, remaining +| 1)];
        const n = try readTransportUntil(transport, read_buf, deadline);
        if (n == 0) {
            if (bytes.items.len == 0) return error.ConnectionClosed;
            return bytes.toOwnedSlice(allocator);
        }
        try bytes.appendSlice(allocator, read_buf[0..n]);
    }
}

fn ensureResponseHeadDeadlineForBuffer(
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
    allow_http_0_9_response: bool,
    deadline: *?std.Io.Clock.Timestamp,
) Error!void {
    if (allow_http_0_9_response and
        http1.classifyResponsePrefix(buffered) == .http_0_9)
    {
        return;
    }
    try ensureResponseHeadDeadlineForBuffer(
        transport,
        limits,
        buffered,
        deadline,
    );
}

fn connectionMaybeWriteContinue(
    context: ?*anyopaque,
    head: []const u8,
) Error!void {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    try maybeWriteContinue(
        connection.transport(),
        head,
        connection.inbuf.items.len,
        true,
    );
}

fn connectionWriteSlices(
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

fn responseIsReusable(response: http1.Response) bool {
    // Close-delimited bodies consume EOF as their message boundary, and 101
    // transfers the socket to another protocol. Neither can begin another
    // HTTP/1 exchange even if the header block omitted Connection: close.
    return response.version != .http_0_9 and
        response.keepAlive() and
        response.body_framing != .close_delimited and
        response.status != 101;
}

fn streamingResponseIsReusable(
    response: StreamingResponse,
    request_method: http1.Method,
) bool {
    return response.version != .http_0_9 and
        response.keepAlive() and
        response.body_framing != .close_delimited and
        response.status != 101 and
        !(request_method == .CONNECT and
            response.status >= 200 and response.status < 300);
}

fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
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

pub fn readRequestFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytesBuffered(allocator, io, stream, limits, options, inbuf);
    errdefer allocator.free(bytes);
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
        false,
        deadline,
        deadline,
        null,
    );
    errdefer allocator.free(bytes);
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

fn readRequestFromTransportBufferedWithStage(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    head_deadline: ?std.Io.Clock.Timestamp,
    failure_stage: ?*RequestReadStage,
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
        false,
        head_deadline,
        null,
        failure_stage,
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
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
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
            options.allow_http_0_9_responses,
            &response_head_deadline,
        );
        const bytes = try readMessageBytesWithContext(
            allocator,
            transport,
            limits,
            null,
            false,
            null,
            true,
            options.allow_http_0_9_responses,
            response_head_deadline,
            null,
        );
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, null);
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
            options.allow_http_0_9_responses,
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
            null,
            true,
            options.allow_http_0_9_responses,
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
        applyCloseDelimitedResponseBody(&response, bytes, request_method);
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
            options.allow_http_0_9_responses,
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
            options.allow_http_0_9_responses,
            response_head_deadline,
            null,
            null,
        );
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, null);
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
            options.allow_http_0_9_responses,
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
            options.allow_http_0_9_responses,
            response_head_deadline,
            null,
            null,
        );
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, request_method);
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
    if (options.allow_http_0_9_responses and bytes.len != 0 and
        http1.classifyResponsePrefix(bytes) != .http_1_x)
    {
        if (request_method != null and request_method.? != .GET) {
            return error.InvalidResponse;
        }
        // Aggregate readers reach this point only after EOF established the
        // legacy boundary. That distinction lets `parseResponse` itself keep
        // returning BufferTooShort for a potentially fragmented `HTTP/`
        // prefix while accepting the same bytes here once EOF is definitive.
        return .{
            .version = .http_0_9,
            .status = 200,
            .reason = "",
            .headers = @constCast(&[_]http1.Header{}),
            .body = bytes,
            .body_framing = .close_delimited,
            .trailers = @constCast(&[_]http1.Header{}),
            .consumed = bytes.len,
        };
    }
    if (request_method) |method| {
        return http1.parseResponseForRequest(
            allocator,
            bytes,
            options,
            method,
        );
    }
    return http1.parseResponse(allocator, bytes, options);
}

fn applyCloseDelimitedResponseBody(response: *http1.Response, bytes: []const u8, request_method: ?http1.Method) void {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return;
    if (!responseHeadUsesCloseDelimitedBody(bytes[0..head_end], request_method)) return;
    const body_start = head_end + 4;
    if (bytes.len < body_start) return;
    response.body = bytes[body_start..];
    response.body_framing = .close_delimited;
    response.consumed = bytes.len;
}

pub fn writeRequestToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: RequestOptions) Error!void {
    try writeRequestToTransport(allocator, .{ .tcp = .{ .io = io, .stream = stream } }, options);
}

fn writeRequestToTransport(allocator: std.mem.Allocator, transport: RuntimeTransport, options: RequestOptions) Error!void {
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeRequestToTransportScratch(
        allocator,
        transport,
        options,
        &scratch,
    );
}

fn writeRequestToTransportScratch(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: RequestOptions,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareRequest(
        allocator,
        options,
        scratch,
    );
    try transport.writeAllParts(parts.header, parts.body);
}

pub fn writeResponseToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: ResponseOptions) Error!void {
    try writeResponseToTransport(allocator, .{ .tcp = .{ .io = io, .stream = stream } }, options);
}

fn writeResponseToTransport(allocator: std.mem.Allocator, transport: RuntimeTransport, options: ResponseOptions) Error!void {
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try writeResponseToTransportScratch(
        allocator,
        transport,
        options,
        null,
        &scratch,
    );
}

fn writeResponseToTransportScratch(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareServerResponse(
        allocator,
        options,
        default_date,
        scratch,
    );
    try transport.writeAllParts(parts.header, parts.body);
}

fn writeResponsesToTransportScratch(
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

const response_batch_borrow_threshold: usize = 16 * 1024;

fn responseBatchWriteStrategy(
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

fn responseBatchBodyBytes(responses: []const ResponseOptions) usize {
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

fn prepareResponsesCoalesced(
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

    fn deinit(self: ServeLoopResponse, allocator: std.mem.Allocator) void {
        if (self.headers_owned) allocator.free(self.response.headers);
    }
};

fn adjustResponseForServeLoop(
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
    const response_wants_keep_alive = responseOptionsKeepAlive(response);
    var adjusted = ServeLoopResponse{ .response = out };

    if (request.version == .http_1_0) {
        // Match Hyper's h1 behavior for old peers: speak HTTP/1.0 back to an
        // HTTP/1.0 request, and only keep the connection alive when both sides
        // opted in and the response would otherwise be persistent.
        out.version = .http_1_0;
        if (request_keep_alive and response_wants_keep_alive and !hasHeader(out.headers, "connection")) {
            adjusted = try addConnectionHeaderForServeLoop(allocator, out, "keep-alive");
            out = adjusted.response;
        }
    }

    if (graceful_shutdown) {
        if (adjusted.headers_owned) adjusted.deinit(allocator);
        adjusted = try replaceConnectionHeaderForServeLoop(
            allocator,
            out,
            "close",
        );
        out = adjusted.response;
    } else if (request.must_close) {
        // TE+CL is locally decoded as chunked, but the response must not
        // advertise persistence even when an application supplied its own
        // Connection field. Replace every such field to make the wire signal
        // agree with the serve loop's decision to retire the connection.
        if (adjusted.headers_owned) adjusted.deinit(allocator);
        adjusted = try replaceConnectionHeaderForServeLoop(
            allocator,
            out,
            "close",
        );
        out = adjusted.response;
    } else if (!request_keep_alive and
        !hasHeader(out.headers, "connection"))
    {
        if (adjusted.headers_owned) adjusted.deinit(allocator);
        adjusted = try addConnectionHeaderForServeLoop(
            allocator,
            out,
            "close",
        );
        out = adjusted.response;
    }

    adjusted.response = out;
    return adjusted;
}

test "HTTP/1 serve response derives trailer capability from request" {
    const allocator = std.testing.allocator;
    var accepted_headers = [_]http1.Header{
        .{ .name = "Host", .value = "example.test" },
        .{ .name = "TE", .value = "gzip" },
        .{ .name = "te", .value = "Trailers" },
        .{ .name = "Connection", .value = "TE" },
    };
    var accepted = try adjustResponseForServeLoop(
        allocator,
        .{
            .method = .GET,
            .target = "/",
            .version = .http_1_1,
            .headers = &accepted_headers,
            .body = &.{},
            .consumed = 0,
        },
        .{},
        false,
    );
    defer accepted.deinit(allocator);
    try std.testing.expect(accepted.response.request_accepts_trailers);

    var refused_headers = [_]http1.Header{
        .{ .name = "Host", .value = "example.test" },
    };
    var refused = try adjustResponseForServeLoop(
        allocator,
        .{
            .method = .GET,
            .target = "/",
            .version = .http_1_1,
            .headers = &refused_headers,
            .body = &.{},
            .consumed = 0,
        },
        .{ .request_accepts_trailers = true },
        false,
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.response.request_accepts_trailers);
}

fn addConnectionHeaderForServeLoop(allocator: std.mem.Allocator, response: ResponseOptions, value: []const u8) Error!ServeLoopResponse {
    const headers = try allocator.alloc(http1.Header, response.headers.len + 1);
    @memcpy(headers[0..response.headers.len], response.headers);
    headers[response.headers.len] = .{ .name = "Connection", .value = value };
    var out = response;
    out.headers = headers;
    return .{ .response = out, .headers_owned = true };
}

fn replaceConnectionHeaderForServeLoop(
    allocator: std.mem.Allocator,
    response: ResponseOptions,
    value: []const u8,
) Error!ServeLoopResponse {
    var retained: usize = 0;
    for (response.headers) |header| {
        retained += @intFromBool(!header.eqlName("connection"));
    }
    const headers = try allocator.alloc(http1.Header, retained + 1);
    var index: usize = 0;
    for (response.headers) |header| {
        if (header.eqlName("connection")) continue;
        headers[index] = header;
        index += 1;
    }
    headers[index] = .{ .name = "Connection", .value = value };
    var out = response;
    out.headers = headers;
    return .{ .response = out, .headers_owned = true };
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn responseOptionsKeepAlive(response: ResponseOptions) bool {
    return http1.headersKeepAlive(response.version, response.headers);
}

fn requestOptionsKeepAlive(request: RequestOptions) bool {
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
    request_options: ?http1.ParseOptions,
    close_delimited_when_unknown: bool,
    allow_http_0_9_response: bool,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = null;
    while (head_end == null) {
        if (allow_http_0_9_response and
            (request_method == null or request_method.? == .GET)) switch (http1.classifyResponsePrefix(bytes.items)) {
            .http_0_9 => return readHttp09Body(
                allocator,
                transport,
                limits.max_body_bytes,
                &bytes,
                &scratch,
                body_deadline,
            ),
            .incomplete, .http_1_x => {},
        };
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
        if (n == 0) {
            if (allow_http_0_9_response and
                (request_method == null or request_method.? == .GET) and
                bytes.items.len != 0 and
                http1.classifyResponsePrefix(bytes.items) == .incomplete)
            {
                // EOF disambiguates a legacy body that happens to be a proper
                // prefix of `HTTP/`; it does not bypass the body-size budget.
                if (bytes.items.len > limits.max_body_bytes) {
                    return error.BodyTooLarge;
                }
                return bytes.toOwnedSlice(allocator);
            }
            return error.ConnectionClosed;
        }
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
    if (auto_continue) {
        const options = request_options orelse return error.InvalidResponse;
        const head = bytes.items[0..head_end.?];
        if (requestShouldSendContinue(head)) {
            try http1.validateRequestHead(allocator, bytes.items, options);
            if (try message_framing.transferEncodingState(head) == .none) {
                if (try message_framing.contentLengthFromHead(head)) |len| {
                    if (len > limits.max_body_bytes) {
                        return error.BodyTooLarge;
                    }
                }
            }
            try maybeWriteContinue(
                transport,
                head,
                bytes.items.len - (head_end.? + 4),
                true,
            );
        }
    }

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(bytes.items[0..head_end.?], request_method)) {
        const body_start = head_end.? + 4;
        while (true) {
            const n = try readTransportUntil(
                transport,
                &scratch,
                body_deadline,
            );
            if (n == 0) break;
            try bytes.appendSlice(allocator, scratch[0..n]);
            if (bytes.items.len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        }
        return bytes.toOwnedSlice(allocator);
    }

    const target_len = while (true) {
        const len = messageTargetLength(
            bytes.items,
            head_end.?,
            limits.max_head_bytes,
            limits.max_body_bytes,
            request_method,
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
        false,
        if (limits.request_head_timeout) |timeout|
            try headReadDeadline(transport, timeout)
        else
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

fn readResponseFromTransportBufferedForRequestObserved(
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
            options.allow_http_0_9_responses,
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
        options.allow_http_0_9_responses,
        head_deadline,
        body_deadline,
        null,
    );
    errdefer allocator.free(bytes);
    var response = try parseResponseForRuntime(
        allocator,
        bytes,
        options,
        request_method,
    );
    errdefer response.deinit(allocator);
    applyCloseDelimitedResponseBody(&response, bytes, request_method);
    return .{ .bytes = bytes, .response = response };
}

fn readMessageBytesBufferedWithContext(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: ?http1.Method,
    auto_continue: bool,
    close_delimited_when_unknown: bool,
    allow_http_0_9_response: bool,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
    request_stage: ?*RequestReadStage,
) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = null;
    while (head_end == null) {
        if (allow_http_0_9_response and
            (request_method == null or request_method.? == .GET)) switch (http1.classifyResponsePrefix(inbuf.items)) {
            .http_0_9 => {
                const bytes = try readHttp09Body(
                    allocator,
                    transport,
                    limits.max_body_bytes,
                    inbuf,
                    &scratch,
                    body_deadline,
                );
                inbuf.* = .empty;
                return bytes;
            },
            .incomplete, .http_1_x => {},
        };
        head_end = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
        if (head_end != null) break;
        const read_buf = scratch[0..@min(scratch.len, limits.max_head_bytes - inbuf.items.len)];
        const n = if (head_deadline) |deadline|
            try transport.readWithDeadline(read_buf, deadline)
        else
            try transport.read(read_buf);
        if (n == 0) {
            if (allow_http_0_9_response and
                (request_method == null or request_method.? == .GET) and
                inbuf.items.len != 0 and
                http1.classifyResponsePrefix(inbuf.items) == .incomplete)
            {
                // This is the buffered counterpart of the EOF-only prefix
                // fallback above and must enforce the identical body limit.
                if (inbuf.items.len > limits.max_body_bytes) {
                    return error.BodyTooLarge;
                }
                const bytes = try inbuf.toOwnedSlice(allocator);
                inbuf.* = .empty;
                return bytes;
            }
            return error.ConnectionClosed;
        }
        try inbuf.appendSlice(allocator, scratch[0..n]);
    }
    var borrowed_headers_stack: [128]http1.Header = undefined;
    const borrowed_headers = if (options.max_headers <= borrowed_headers_stack.len)
        borrowed_headers_stack[0..options.max_headers]
    else
        try allocator.alloc(http1.Header, options.max_headers);
    defer if (borrowed_headers.ptr != borrowed_headers_stack[0..].ptr) allocator.free(borrowed_headers);

    const known_target_len: ?usize = if (auto_continue) request: {
        const request_head = try http1.parseRequestHead(inbuf.items, borrowed_headers, options);
        break :request try request_head.messageLength();
    } else response: {
        const response_head = try http1.parseResponseHead(
            inbuf.items,
            borrowed_headers,
            options,
            .{ .request_method = request_method },
        );
        break :response try response_head.messageLength();
    };

    const head = inbuf.items[0..head_end.?];
    if (auto_continue and requestShouldSendContinue(head)) {
        if (request_stage) |stage| stage.* = .continue_write;
        try maybeWriteContinue(
            transport,
            head,
            inbuf.items.len - (head_end.? + 4),
            true,
        );
    }
    if (request_stage) |stage| stage.* = .body;

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(head, request_method)) {
        const body_start = head_end.? + 4;
        while (true) {
            const n = try readTransportUntil(
                transport,
                &scratch,
                body_deadline,
            );
            if (n == 0) break;
            try inbuf.appendSlice(allocator, scratch[0..n]);
            if (inbuf.items.len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        }
        const bytes = try inbuf.toOwnedSlice(allocator);
        inbuf.* = .empty;
        return bytes;
    }

    const body_start = std.math.add(usize, head_end.?, 4) catch
        return error.HeadersTooLarge;
    const target_len = if (known_target_len) |len| blk: {
        if (len < body_start) return error.InvalidResponse;
        if (len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        break :blk len;
    } else while (true) {
        const len = messageTargetLength(
            inbuf.items,
            head_end.?,
            limits.max_head_bytes,
            limits.max_body_bytes,
            request_method,
        ) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try readTransportUntil(
                    transport,
                    &scratch,
                    body_deadline,
                );
                if (n == 0) return error.ConnectionClosed;
                try inbuf.appendSlice(allocator, scratch[0..n]);
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
        const n = try readTransportUntil(
            transport,
            &scratch,
            body_deadline,
        );
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
    }

    if (inbuf.items.len == target_len) {
        return inbuf.toOwnedSlice(allocator);
    }
    const bytes = try allocator.dupe(u8, inbuf.items[0..target_len]);
    discardPrefix(inbuf, target_len);
    return bytes;
}

test "HTTP/1 buffered reader transfers exact message buffer ownership" {
    const allocator = std.testing.allocator;
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    var inbuf: std.ArrayList(u8) = .fromOwnedSlice(try allocator.dupe(u8, raw));
    const original_ptr = inbuf.items.ptr;

    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        .{ .tcp = .{ .io = undefined, .stream = undefined } },
        .{},
        .{},
        &inbuf,
        null,
        false,
        true,
        false,
        null,
        null,
        null,
    );
    defer allocator.free(bytes);

    try std.testing.expectEqual(original_ptr, bytes.ptr);
    try std.testing.expectEqual(@as(usize, 0), inbuf.items.len);
    try std.testing.expectEqualStrings(raw, bytes);
}

test "HTTP/1 borrowed pipeline batch preserves bodies until consume" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    const pipeline =
        "GET /one HTTP/1.1\r\nHost: example\r\n\r\n" ++
        "POST /two HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 3\r\n\r\nabc" ++
        "GET /next HTTP/1.1\r\nHost: example\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, pipeline);

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    const consumed = try connection.readRequestBatchInto(
        &heads,
        &headers,
        &bodies,
        .{ .max_headers = 4 },
    );
    try std.testing.expect(heads[0].method == .GET);
    try std.testing.expectEqualStrings("/one", heads[0].target);
    try std.testing.expect(heads[1].method == .POST);
    try std.testing.expectEqualStrings("abc", bodies[1]);
    try std.testing.expectEqualStrings(
        pipeline[0..consumed],
        connection.inbuf.items[0..consumed],
    );

    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqualStrings(
        "GET /next HTTP/1.1\r\nHost: example\r\n\r\n",
        connection.inbuf.items,
    );
    try std.testing.expectError(
        error.InvalidResponse,
        connection.consumeRequestBatch(
            connection.inbuf.items.len + 1,
        ),
    );
}

test "HTTP/1 borrowed pipeline batch decodes chunked bodies in place" {
    const allocator = std.testing.allocator;
    const chunked_head =
        "POST /chunked HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    const empty_head =
        "POST /empty HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    const fixed =
        "POST /fixed HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Content-Length: 3\r\n\r\nabc";
    const suffix = "GET /next HTTP/1.1\r\nHost: example\r\n\r\n";
    const pipeline = chunked_head ++
        "2;foo=bar\r\nhe\r\n3\r\nllo\r\n" ++
        "0\r\nDigest: sha-256=demo\r\n\r\n" ++
        empty_head ++ "0\r\n\r\n" ++ fixed ++ suffix;
    const compacted = chunked_head ++ "hello" ++ empty_head ++ fixed;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    try connection.inbuf.appendSlice(allocator, pipeline);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = no_alloc.allocator();

    var heads: [3]http1.RequestHead = undefined;
    var headers: [12]http1.Header = undefined;
    var bodies: [3][]const u8 = undefined;
    const consumed = try connection.readRequestBatchInto(
        &heads,
        &headers,
        &bodies,
        .{ .max_headers = 4 },
    );

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("/chunked", heads[0].target);
    try std.testing.expectEqual(http1.BodyFraming.chunked, heads[0].body_framing);
    try std.testing.expect(!heads[0].must_close);
    try std.testing.expect(heads[0].header("content-length") == null);
    try std.testing.expectEqualStrings("hello", bodies[0]);
    try std.testing.expectEqualStrings("/empty", heads[1].target);
    try std.testing.expectEqual(http1.BodyFraming.chunked, heads[1].body_framing);
    try std.testing.expectEqual(@as(usize, 0), bodies[1].len);
    try std.testing.expectEqualStrings("/fixed", heads[2].target);
    try std.testing.expectEqual(http1.BodyFraming.content_length, heads[2].body_framing);
    try std.testing.expectEqualStrings("abc", bodies[2]);
    try std.testing.expectEqual(compacted.len, consumed);
    try std.testing.expectEqualStrings(
        compacted ++ suffix,
        connection.inbuf.items,
    );

    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqualStrings(suffix, connection.inbuf.items);
}

test "HTTP/1 borrowed chunked batch validation is transactional" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    const invalid =
        "POST /first HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nx\r\n0\r\n\r\n" ++
        "POST /second HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\ny\r\n0\r\nContent-Length: 1\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, invalid);

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    try std.testing.expectError(
        error.InvalidTrailer,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectEqualStrings(invalid, connection.inbuf.items);

    connection.inbuf.clearRetainingCapacity();
    const ambiguous =
        "POST /first HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nx\r\n0\r\n\r\n" ++
        "GET /second HTTP/1.1\r\nHost: example\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, ambiguous);
    try std.testing.expectError(
        error.InvalidResponse,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectEqualStrings(ambiguous, connection.inbuf.items);

    connection.inbuf.clearRetainingCapacity();
    const terminal_ambiguous =
        "POST /terminal HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nz\r\n0\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, terminal_ambiguous);
    const terminal_consumed = try connection.readRequestBatchInto(
        heads[0..1],
        headers[0..4],
        bodies[0..1],
        .{ .max_headers = 4 },
    );
    try std.testing.expect(heads[0].must_close);
    try std.testing.expect(heads[0].header("content-length") == null);
    try std.testing.expectEqualStrings("z", bodies[0]);
    try connection.consumeRequestBatch(terminal_consumed);

    connection.inbuf.clearRetainingCapacity();
    const folded =
        "POST /folded HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "0\r\nX-Trace: one\r\n two\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, folded);
    try std.testing.expectError(
        error.MalformedHeader,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );
    const consumed = try connection.readRequestBatchInto(
        heads[0..1],
        headers[0..4],
        bodies[0..1],
        .{ .max_headers = 4, .allow_obs_fold = true },
    );
    try std.testing.expectEqualStrings("", bodies[0]);
    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqual(@as(usize, 0), connection.inbuf.items.len);
}

test "HTTP/1 borrowed chunked batch reads fragmented transport" {
    const allocator = std.testing.allocator;
    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
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
            var connection = try self.server.accept();
            defer connection.close();
            var heads: [2]http1.RequestHead = undefined;
            var headers: [8]http1.Header = undefined;
            var bodies: [2][]const u8 = undefined;
            const consumed = try connection.readRequestBatchInto(
                &heads,
                &headers,
                &bodies,
                .{ .max_headers = 4 },
            );
            try std.testing.expectEqualStrings("/chunked", heads[0].target);
            try std.testing.expectEqualStrings("hello", bodies[0]);
            try std.testing.expectEqualStrings("/fixed", heads[1].target);
            try std.testing.expectEqualStrings("x", bodies[1]);
            try connection.consumeRequestBatch(consumed);

            var suffix = try connection.readRequest(.{});
            defer suffix.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/suffix", suffix.request.target);
        }
    };
    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAllToStream(
        io,
        client,
        "POST /chunked HTTP/1.1\r\nHost: example\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n2\r\nh",
    );
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try writeAllToStream(
        io,
        client,
        "e\r\n3\r\nllo\r\n0\r\nDigest: ok\r\n\r\n" ++
            "POST /fixed HTTP/1.1\r\nHost: example\r\n" ++
            "Content-Length: 1\r\n\r\nx" ++
            "GET /suffix HTTP/1.1\r\nHost: example\r\n\r\n",
    );

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "HTTP/1 borrowed pipeline batch enforces limits before I/O" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 24, .max_body_bytes = 2 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    try connection.inbuf.appendSlice(
        allocator,
        "GET /long HTTP/1.1\r\nHost: example\r\n\r\n",
    );
    try std.testing.expectError(
        error.HeadersTooLarge,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );

    connection.inbuf.clearRetainingCapacity();
    connection.limits.max_head_bytes = 1024;
    try connection.inbuf.appendSlice(
        allocator,
        "POST / HTTP/1.1\r\nHost: example\r\n" ++
            "Content-Length: 3\r\n\r\nabc",
    );
    try std.testing.expectError(
        error.BodyTooLarge,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );

    connection.inbuf.clearRetainingCapacity();
    connection.limits = .{
        .max_head_bytes = std.math.maxInt(usize),
        .max_body_bytes = 0,
    };
    try std.testing.expectError(
        error.BodyTooLarge,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectError(
        error.TooManyHeaders,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = std.math.maxInt(usize) },
        ),
    );
}

test "HTTP/1 response batch validation is transactional" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    const responses = [_]ResponseOptions{
        .{ .body = "ok" },
        .{ .status = 204, .body = "forbidden" },
    };
    try std.testing.expectError(
        error.InvalidContentLength,
        writeResponsesToTransportScratch(
            allocator,
            .{ .tcp = .{ .io = undefined, .stream = undefined } },
            &responses,
            null,
            &scratch,
        ),
    );
    // The invalid batch never reaches the transport. Scratch content itself is
    // internal and may be reused/partially encoded for the next attempt.
}

test "HTTP/1 write strategy controls complete message transport shape" {
    const Observer = struct {
        bytes: [8192]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) {
                for (data[0 .. data.len - 1]) |bytes| {
                    non_empty += @intFromBool(bytes.len != 0);
                    written += self.append(bytes);
                }
                const pattern = data[data.len - 1];
                non_empty += @intFromBool(pattern.len != 0 and splat != 0);
                for (0..splat) |_| written += self.append(pattern);
            }
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            std.debug.assert(self.len + bytes.len <= self.bytes.len);
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    const request_options = RequestOptions{
        .method = .POST,
        .target = "/shape",
        .host = "example.test",
        .body = "request-body",
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var vectored_request: Observer = .{};
    var vectored_request_vtable = threaded.io().vtable.*;
    vectored_request_vtable.netWrite = Observer.write;
    var vectored_client = Client{
        .io = .{
            .userdata = &vectored_request,
            .vtable = &vectored_request_vtable,
        },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .vectored },
    };
    defer {
        vectored_client.inbuf.deinit(std.testing.allocator);
        vectored_client.write_scratch.deinit(std.testing.allocator);
    }
    try vectored_client.writeRequestFailClosed(request_options);
    try std.testing.expectEqual(@as(usize, 1), vectored_request.calls);
    try std.testing.expectEqual(@as(usize, 2), vectored_request.max_non_empty_parts);

    var flat_request: Observer = .{};
    var flat_request_vtable = threaded.io().vtable.*;
    flat_request_vtable.netWrite = Observer.write;
    var flat_client = Client{
        .io = .{ .userdata = &flat_request, .vtable = &flat_request_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .flatten },
    };
    defer {
        flat_client.inbuf.deinit(std.testing.allocator);
        flat_client.write_scratch.deinit(std.testing.allocator);
    }
    try flat_client.writeRequestFailClosed(request_options);
    try std.testing.expectEqual(@as(usize, 1), flat_request.calls);
    try std.testing.expectEqual(@as(usize, 1), flat_request.max_non_empty_parts);
    try std.testing.expectEqualStrings(
        vectored_request.bytes[0..vectored_request.len],
        flat_request.bytes[0..flat_request.len],
    );

    const response_options = ResponseOptions{ .body = "response-body" };
    var vectored_response: Observer = .{};
    var vectored_response_vtable = threaded.io().vtable.*;
    vectored_response_vtable.netWrite = Observer.write;
    var vectored_connection = Connection{
        .io = .{
            .userdata = &vectored_response,
            .vtable = &vectored_response_vtable,
        },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .vectored,
        },
    };
    defer {
        vectored_connection.inbuf.deinit(std.testing.allocator);
        vectored_connection.write_scratch.deinit(std.testing.allocator);
    }
    try vectored_connection.writeResponse(response_options);
    try std.testing.expectEqual(@as(usize, 2), vectored_response.max_non_empty_parts);

    var flat_response: Observer = .{};
    var flat_response_vtable = threaded.io().vtable.*;
    flat_response_vtable.netWrite = Observer.write;
    var flat_connection = Connection{
        .io = .{
            .userdata = &flat_response,
            .vtable = &flat_response_vtable,
        },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        flat_connection.inbuf.deinit(std.testing.allocator);
        flat_connection.write_scratch.deinit(std.testing.allocator);
    }
    try flat_connection.writeResponse(response_options);
    try std.testing.expectEqual(@as(usize, 1), flat_response.max_non_empty_parts);
    try std.testing.expectEqualStrings(
        vectored_response.bytes[0..vectored_response.len],
        flat_response.bytes[0..flat_response.len],
    );
}

test "HTTP/1 flatten strategy applies to streaming chunks" {
    const Observer = struct {
        bytes: [1024]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                non_empty += @intFromBool(bytes.len != 0);
                written += self.append(bytes);
            };
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer: Observer = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = Observer.write;
    var connection = Connection{
        .io = .{ .userdata = &observer, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }
    var writer = try connection.startResponse(.{ .body_length = null });
    defer writer.deinit();
    observer.len = 0;
    observer.calls = 0;
    observer.max_non_empty_parts = 0;
    try writer.writeChunks(&.{ "a", "bc" });
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqual(@as(usize, 1), observer.max_non_empty_parts);
    try std.testing.expectEqualStrings("1\r\na\r\n2\r\nbc\r\n", observer.bytes[0..observer.len]);
    try writer.finish();
}

test "HTTP/1 response batch write strategy overrides the automatic threshold" {
    try std.testing.expectEqual(
        WriteStrategy.flatten,
        responseBatchWriteStrategy(.auto, response_batch_borrow_threshold),
    );
    try std.testing.expectEqual(
        WriteStrategy.vectored,
        responseBatchWriteStrategy(
            .auto,
            response_batch_borrow_threshold + 1,
        ),
    );
    try std.testing.expectEqual(
        WriteStrategy.vectored,
        responseBatchWriteStrategy(.vectored, 0),
    );
    try std.testing.expectEqual(
        WriteStrategy.flatten,
        responseBatchWriteStrategy(
            .flatten,
            response_batch_borrow_threshold + 1,
        ),
    );

    const Observer = struct {
        bytes: [2048]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                non_empty += @intFromBool(bytes.len != 0);
                written += self.append(bytes);
            };
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            std.debug.assert(self.len + bytes.len <= self.bytes.len);
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    const responses = [_]ResponseOptions{
        .{ .body = "one" },
        .{ .status = 201, .reason = "Created", .body = "two" },
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    var peer = try listener.accept(io);
    defer peer.close(io);
    var vectored = Connection{
        .io = io,
        .allocator = std.testing.allocator,
        .stream = stream,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .vectored,
        },
    };
    defer vectored.close();
    try vectored.writeResponses(&responses);

    var flat_observer: Observer = .{};
    var flat_vtable = threaded.io().vtable.*;
    flat_vtable.netWrite = Observer.write;
    var flat = Connection{
        .io = .{ .userdata = &flat_observer, .vtable = &flat_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        flat.inbuf.deinit(std.testing.allocator);
        flat.write_scratch.deinit(std.testing.allocator);
    }
    try flat.writeResponses(&responses);
    try std.testing.expectEqual(@as(usize, 1), flat_observer.calls);
    try std.testing.expectEqual(@as(usize, 1), flat_observer.max_non_empty_parts);
    var vectored_bytes: [2048]u8 = undefined;
    try readExactForTest(io, peer, vectored_bytes[0..flat_observer.len]);
    try std.testing.expectEqualStrings(
        flat_observer.bytes[0..flat_observer.len],
        vectored_bytes[0..flat_observer.len],
    );
}

test "HTTP/1 flatten allocation failure is retryable before transport" {
    const Observer = struct {
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var total = header.len;
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                total += bytes.len;
            };
            return total;
        }
    };

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var observer: Observer = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = Observer.write;
    var client = Client{
        .io = .{ .userdata = &observer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .flatten },
    };
    defer {
        client.inbuf.deinit(allocator);
        client.write_scratch.deinit(allocator);
    }
    const options = RequestOptions{
        .method = .POST,
        .host = "example.test",
        .body = "body",
    };
    _ = try runtime_write.prepareRequest(allocator, options, &client.write_scratch);
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    client.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        client.writeRequestFailClosed(options),
    );
    client.allocator = allocator;
    try std.testing.expect(client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
}

test "HTTP/1 aggregate write failures make connections unusable" {
    const FailingWriter = struct {
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var client_writer: FailingWriter = .{};
    var client_vtable = threaded.io().vtable.*;
    client_vtable.netWrite = FailingWriter.write;
    var client = Client{
        .io = .{ .userdata = &client_writer, .vtable = &client_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
    };
    defer {
        client.inbuf.deinit(std.testing.allocator);
        client.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        client.request(.{
            .method = .POST,
            .target = "/partial-request",
            .host = "example.test",
            .body = "body",
        }),
    );
    try std.testing.expect(!client.isReusable());
    const client_calls = client_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "example.test" }),
    );
    try std.testing.expectEqual(client_calls, client_writer.calls);

    var response_writer: FailingWriter = .{};
    var response_vtable = threaded.io().vtable.*;
    response_vtable.netWrite = FailingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &response_writer, .vtable = &response_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        connection.writeResponse(.{ .body = "body" }),
    );
    const response_calls = response_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.writeResponse(.{ .body = "must-not-write" }),
    );
    try std.testing.expectEqual(response_calls, response_writer.calls);

    var batch_writer: FailingWriter = .{};
    var batch_vtable = threaded.io().vtable.*;
    batch_vtable.netWrite = FailingWriter.write;
    var batch_connection = Connection{
        .io = .{ .userdata = &batch_writer, .vtable = &batch_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        batch_connection.inbuf.deinit(std.testing.allocator);
        batch_connection.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        batch_connection.writeResponses(&.{
            .{ .body = "one" },
            .{ .body = "two" },
        }),
    );
    const batch_calls = batch_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        batch_connection.writeResponses(&.{.{ .body = "must-not-write" }}),
    );
    try std.testing.expectEqual(batch_calls, batch_writer.calls);

    var continue_writer: FailingWriter = .{};
    var continue_vtable = threaded.io().vtable.*;
    continue_vtable.netWrite = FailingWriter.write;
    var continue_connection = Connection{
        .io = .{ .userdata = &continue_writer, .vtable = &continue_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        continue_connection.inbuf.deinit(std.testing.allocator);
        continue_connection.write_scratch.deinit(std.testing.allocator);
    }
    try continue_connection.inbuf.appendSlice(
        std.testing.allocator,
        "POST /continue HTTP/1.1\r\n" ++
            "Host: example.test\r\n" ++
            "Content-Length: 1\r\n" ++
            "Expect: 100-continue\r\n\r\nx",
    );
    try std.testing.expectError(
        error.NetworkDown,
        continue_connection.readRequest(.{}),
    );
    const continue_calls = continue_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        continue_connection.readRequest(.{}),
    );
    try std.testing.expectEqual(continue_calls, continue_writer.calls);
}

test "HTTP/1 TLS key updates require an idle HTTP exchange" {
    const fake_client: *tls_stream.ClientConnection = @ptrFromInt(4096);
    var client = Client{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls_vail_conn = fake_client,
    };
    client.writer_state.phase = .writing;
    try std.testing.expectError(
        error.ConnectionBusy,
        client.updateTrafficKeys(false),
    );
    client.writer_state.phase = .unusable;
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.updateTrafficKeys(false),
    );

    const fake_server: *tls_stream.ServerConnection = @ptrFromInt(4096);
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls_server_conn = fake_server,
    };
    connection.writer_state.phase = .awaiting_peer;
    try std.testing.expectError(
        error.ConnectionBusy,
        connection.updateTrafficKeys(false),
    );
    connection.writer_state.phase = .unusable;
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.updateTrafficKeys(false),
    );
}

test "HTTP/1 large response batch write failure makes connection unusable" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = try listener.accept(io);
    const abortive: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(
        peer.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.LINGER,
        std.mem.asBytes(&abortive),
    );
    peer.close(io);
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectError(
        error.ConnectionResetByPeer,
        io.vtable.netRead(io.userdata, stream.socket.handle, &buffers),
    );

    var connection = Connection{
        .io = io,
        .allocator = allocator,
        .stream = stream,
        .limits = .{ .auto_date_header = false },
    };
    defer connection.close();
    const large_body = "x" ** (response_batch_borrow_threshold + 1);
    var failed = false;
    connection.writeResponses(&.{.{ .body = large_body }}) catch |err| {
        failed = true;
        try std.testing.expect(err == error.SocketUnconnected or
            err == error.ConnectionResetByPeer);
    };
    try std.testing.expect(failed);
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.writeResponse(.{ .body = "must-not-write" }),
    );
}

test "HTTP/1 aggregate 100 Continue partial write is terminal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .auto_date_header = false },
    );
    defer server.deinit();

    const FailingWriter = struct {
        base_io: std.Io,
        calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            clock: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return self.base_io.vtable.now(self.base_io.userdata, clock);
        }

        fn write(
            context: ?*anyopaque,
            handle: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls != 1) return error.NetworkDown;
            return self.base_io.vtable.netWrite(
                self.base_io.userdata,
                handle,
                header[0..@min(header.len, 4)],
                &.{""},
                0,
            );
        }
    };

    const Shared = struct {
        server: *Server,
        io: std.Io,
        writer_calls: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var writer = FailingWriter{ .base_io = self.io };
            var vtable = self.io.vtable.*;
            vtable.netWrite = FailingWriter.write;
            vtable.now = FailingWriter.now;
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            });
            connection.io = .{ .userdata = &writer, .vtable = &vtable };

            try std.testing.expectError(
                error.NetworkDown,
                connection.readRequestWithDeadline(.{}, deadline),
            );
            const calls = writer.calls;
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.writeResponse(.{ .body = "must-not-write" }),
            );
            try std.testing.expectEqual(calls, writer.calls);
            self.writer_calls = writer.calls;
            // Connection.close uses the ordinary vtable methods and therefore
            // must receive the Threaded backend's original userdata.
            connection.io = self.io;
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAllToStream(
        io,
        client,
        "POST /continue HTTP/1.1\r\n" ++
            "Host: example.test\r\n" ++
            "Content-Length: 4\r\n" ++
            "Expect: 100-continue\r\n\r\n",
    );
    var visible_prefix: [4]u8 = undefined;
    try readExactForTest(io, client, &visible_prefix);
    try std.testing.expectEqualStrings("HTTP", &visible_prefix);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.writer_calls);
}

test "HTTP/1 aggregate write validation errors remain retryable" {
    var client = Client{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
    };
    defer {
        client.inbuf.deinit(std.testing.allocator);
        client.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.InvalidContentLength,
        client.request(.{
            .method = .POST,
            .host = "example.test",
            .headers = &.{.{
                .name = "Content-Length",
                .value = "2",
            }},
            .body = "x",
        }),
    );
    try std.testing.expect(client.isReusable());

    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponse(.{ .status = 204, .body = "forbidden" }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponse(.{ .status = 205, .body = "forbidden" }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponses(&.{
            .{ .body = "ok" },
            .{ .status = 205, .body = "forbidden" },
        }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
}

test "HTTP/1 response batch borrows fixed bodies after validation" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    var first_body = [_]u8{ 'f', 'i', 'r', 's', 't' };
    var second_body = [_]u8{ 's', 'e', 'c', 'o', 'n', 'd' };
    const responses = [_]ResponseOptions{
        .{ .body = &first_body },
        .{ .body = &second_body },
    };
    const parts = try runtime_write.prepareResponseParts(
        allocator,
        &responses,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 4), parts.len);
    try std.testing.expect(parts[1].ptr == first_body[0..].ptr);
    try std.testing.expect(parts[3].ptr == second_body[0..].ptr);
    try std.testing.expect(std.mem.startsWith(
        u8,
        parts[0],
        "HTTP/1.1 200 OK\r\n",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        parts[2],
        "HTTP/1.1 200 OK\r\n",
    ));

    // Borrowing is observable: mutation after validation changes the body
    // slice that would be submitted, while encoded heads remain stable.
    first_body[0] = 'F';
    try std.testing.expectEqualStrings("First", parts[1]);
}

test "HTTP/1 response batch retains chunk framing beside borrowed bodies" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    const responses = [_]ResponseOptions{
        .{ .body = "fixed" },
        .{
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
            .body = "chunk",
        },
    };
    const parts = try runtime_write.prepareResponseParts(
        allocator,
        &responses,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 4), parts.len);
    try std.testing.expectEqualStrings("fixed", parts[1]);
    try std.testing.expectEqualStrings(
        "5\r\nchunk\r\n0\r\n\r\n",
        parts[3],
    );
}

fn maybeWriteContinue(transport: RuntimeTransport, head: []const u8, already_buffered_body_bytes: usize, auto_continue: bool) Error!void {
    _ = already_buffered_body_bytes;
    if (!auto_continue) return;
    if (!requestShouldSendContinue(head)) return;
    try transport.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
}

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    const remaining = list.items[len..];
    @memmove(list.items[0..remaining.len], remaining);
    list.shrinkRetainingCapacity(remaining.len);
}

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn readExactForTest(io: std.Io, stream: net.Stream, buffer: []u8) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try readSome(io, stream, buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

test "HTTP/1 runtime accepts matching absolute-form target" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("http://example.com:8080/absolute?x=1", request.request.target);
            try std.testing.expectEqualStrings("example.com:8080", request.request.header("host").?);
            try connection.writeResponse(.{ .body = "absolute-ok", .request_method = request.request.method });
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .target = "http://example.com:8080/absolute?x=1",
        .headers = &.{.{ .name = "Connection", .value = "close" }},
    });
    var response = try readResponseFromStreamForRequest(allocator, io, stream, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    }, .{}, .GET);
    defer response.deinit(allocator);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("absolute-ok", response.response.body);
}

test "HTTP/1 runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expect(request.request.method == .POST);
            try std.testing.expectEqualStrings("/echo", request.request.target);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.header("host").?);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 201,
                .reason = "Created",
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/echo",
        .host = "127.0.0.1",
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 201), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expectEqualStrings("text/plain", response.response.header("content-type").?);
}

test "HTTP/1 runtime preserves extension methods end to end" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "PURGE",
                request.request.method.string(),
            );
            switch (request.request.method) {
                .extension => {},
                else => return error.TestUnexpectedResult,
            }
            try connection.writeResponse(.{
                .body = "purged",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.request(.{
        .method = try http1.Method.parse("PURGE"),
        .target = "/cache",
        .host = "127.0.0.1",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("purged", response.response.body);
}

test "HTTP/1 runtime opens CONNECT tunnel" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expect(request.request.method == .CONNECT);
            try std.testing.expectEqualStrings("example.com:443", request.request.target);
            try std.testing.expectEqualStrings("example.com:443", request.request.header("host").?);

            var tunnel = try connection.acceptConnectTunnel(request.request, &.{});
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.writeResponse(.{ .status = 204 }),
            );
            var buf: [64]u8 = undefined;
            const n = try tunnel.read(&buf);
            try std.testing.expectEqualStrings("client tunnel bytes", buf[0..n]);
            try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));
            try tunnel.writeParts("server tunnel ", "bytes");
            try tunnel.closeWrite();
            try std.testing.expectError(
                error.ConnectionClosed,
                tunnel.write("late server bytes"),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var tunnel = try client.openConnectTunnel("example.com:443", &.{});
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = .GET,
            .target = "/after-connect",
            .host = "example.com",
        }),
    );
    try tunnel.writeSlices(&.{ "client ", "", "tunnel ", "bytes" });
    try tunnel.closeWrite();
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.closeWrite(),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("late client bytes"),
    );
    var buf: [64]u8 = undefined;
    const n = try tunnel.read(&buf);
    try std.testing.expectEqualStrings("server tunnel bytes", buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(
        error.ConnectionUnusable,
        client.openConnectTunnel("/not-authority", &.{}),
    );
}

test "HTTP/1 TLS tunnels close the write half and retain reads" {
    const allocator = std.testing.allocator;
    const tls_testing = @import("../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    inline for (.{ false, true }) |use_vail_client| {
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            } },
        );
        defer server.deinit();

        const Shared = struct {
            server: *TlsServer,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                var tunnel = try connection.acceptConnectTunnel(
                    request.request,
                    &.{},
                );
                var received: [12]u8 = undefined;
                var offset: usize = 0;
                while (true) {
                    const count = try tunnel.read(received[offset..]);
                    if (count == 0) break;
                    offset += count;
                }
                try std.testing.expectEqualStrings(
                    "client bytes",
                    received[0..offset],
                );
                try tunnel.writeParts("server ", "bytes");
                try tunnel.closeWrite();
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.write("late server bytes"),
                );
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.updateTrafficKeys(false),
                );
            }
        };
        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();

        var ca: ?struct { CertificateBundle, std.Io.RwLock } = null;
        defer if (ca) |*value| value[0].deinit(allocator);
        var client = if (use_vail_client)
            try Client.connectVailTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                } },
            )
        else client: {
            ca = try localTestCaBundle(allocator, io);
            break :client try Client.connectTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .ca_bundle = .{
                    .bundle = &ca.?[0],
                    .lock = &ca.?[1],
                } },
            );
        };
        defer client.close();
        var tunnel = try client.openConnectTunnel(
            "example.com:443",
            &.{},
        );
        try tunnel.writeSlices(&.{ "client", "", " ", "bytes" });
        try tunnel.closeWrite();
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.closeWrite(),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.write("late client bytes"),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.updateTrafficKeys(false),
        );
        var received: [12]u8 = undefined;
        var offset: usize = 0;
        while (true) {
            const count = try tunnel.read(received[offset..]);
            if (count == 0) break;
            offset += count;
        }
        try std.testing.expectEqualStrings(
            "server bytes",
            received[0..offset],
        );

        thread.join();
        joined = true;
        if (shared.err) |err| return err;
    }
}

test "HTTP/1 tunnel write-half close failure is terminal" {
    const PartialFailWriter = struct {
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    const FailingIo = struct {
        shutdown_calls: usize = 0,
        write_calls: usize = 0,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.shutdown_calls += 1;
            return error.NetworkDown;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.write_calls += 1;
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var write_failure: FailingIo = .{};
    var write_failure_vtable = threaded.io().vtable.*;
    write_failure_vtable.netWrite = FailingIo.write;
    var write_failure_inbuf: std.ArrayList(u8) = .empty;
    defer write_failure_inbuf.deinit(std.testing.allocator);
    var write_failure_tunnel = Tunnel{
        .io = .{
            .userdata = &write_failure,
            .vtable = &write_failure_vtable,
        },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &write_failure_inbuf,
    };
    try std.testing.expectError(
        error.NetworkDown,
        write_failure_tunnel.write("first-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        write_failure_tunnel.write("must-not-write"),
    );
    try std.testing.expectEqual(@as(usize, 1), write_failure.write_calls);

    var partial: PartialFailWriter = .{};
    var partial_vtable = threaded.io().vtable.*;
    partial_vtable.netWrite = PartialFailWriter.write;
    var partial_inbuf: std.ArrayList(u8) = .empty;
    defer partial_inbuf.deinit(std.testing.allocator);
    var partial_tunnel = Tunnel{
        .io = .{ .userdata = &partial, .vtable = &partial_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &partial_inbuf,
    };

    try std.testing.expectError(
        error.NetworkDown,
        partial_tunnel.writeParts("head", "payload"),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeParts("must", "not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeSlices(&.{ "must", "not", "write" }),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);

    var failing: FailingIo = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netShutdown = FailingIo.shutdown;
    vtable.netWrite = FailingIo.write;
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(std.testing.allocator);
    var tunnel = Tunnel{
        .io = .{ .userdata = &failing, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &inbuf,
    };

    try std.testing.expectError(error.NetworkDown, tunnel.closeWrite());
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectError(error.ConnectionClosed, tunnel.closeWrite());
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.updateTrafficKeys(false),
    );
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectEqual(@as(usize, 0), failing.write_calls);
}

test "HTTP/1 TLS post-close-notify shutdown treats disconnected peer as complete" {
    const ShutdownIo = struct {
        calls: usize = 0,
        result: enum { disconnected, failed } = .disconnected,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            return switch (self.result) {
                .disconnected => error.SocketUnconnected,
                .failed => error.NetworkDown,
            };
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state: ShutdownIo = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netShutdown = ShutdownIo.shutdown;
    const io = std.Io{ .userdata = &state, .vtable = &vtable };
    const stream: net.Stream = undefined;

    try shutdownAfterTlsCloseNotify(io, stream);
    try std.testing.expectEqual(@as(usize, 1), state.calls);

    state.result = .failed;
    try std.testing.expectError(
        error.NetworkDown,
        shutdownAfterTlsCloseNotify(io, stream),
    );
    try std.testing.expectEqual(@as(usize, 2), state.calls);
}

test "HTTP/1 tunnel deadline preserves buffered bytes and recovers after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        buffered_read: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.buffered_read.set(self.io);
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-timeout",
                &.{},
            );

            var buffer: [16]u8 = undefined;
            const buffered = try tunnel.readWithTimeout(
                &buffer,
                .fromNanoseconds(0),
            );
            try std.testing.expectEqualStrings(
                "buffered",
                buffer[0..buffered],
            );
            self.buffered_read.set(self.io);

            try std.testing.expectError(
                error.Timeout,
                tunnel.readWithTimeout(
                    &buffer,
                    .fromMilliseconds(20),
                ),
            );
            self.timed_out.set(self.io);

            const resumed = try tunnel.readWithDeadline(
                &buffer,
                .fromNow(
                    self.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            );
            try std.testing.expectEqualStrings(
                "after-timeout",
                buffer[0..resumed],
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: netz-timeout\r\n\r\nbuffered",
    );
    var tunnel = try client.finishUpgrade("netz-timeout");
    try shared.buffered_read.wait(io);
    try shared.timed_out.wait(io);
    try tunnel.write("after-timeout");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime hands off generic Upgrade with buffered bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-test",
                &.{},
            );
            try tunnel.write("server-preface");
            var payload: [14]u8 = undefined;
            var read: usize = 0;
            while (read < payload.len) {
                const count = try tunnel.read(payload[read..]);
                if (count == 0) return error.ConnectionClosed;
                read += count;
            }
            try std.testing.expectEqualStrings(
                "client-preface",
                &payload,
            );
            try tunnel.closeWrite();
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: keep-alive, Upgrade\r\n" ++
            "Upgrade: netz-test\r\n\r\nclient-preface",
    );
    var tunnel = try client.finishUpgrade("netz-test");
    try tunnel.closeWrite();
    var preface: [14]u8 = undefined;
    var read: usize = 0;
    while (read < preface.len) {
        const count = try tunnel.read(preface[read..]);
        if (count == 0) return error.ConnectionClosed;
        read += count;
    }
    try std.testing.expectEqualStrings("server-preface", &preface);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&preface));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            var expected_host: [32]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "dns-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{});
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("dns-ok", response.response.body);
}

test "HTTP/1 client sends request to URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/uri?x=1", request.request.target);
            var expected_host: [32]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("uri-ok", response.response.body);

    try std.testing.expectError(error.UnsupportedScheme, Client.requestUri(allocator, io, "ftp://localhost/", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http:///missing-host", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http://user:pass@localhost/", .{}, .{}));
}

test "HTTP/1 client sends request to bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/ipv6?x=1", request.request.target);
            var expected_host: [64]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "[::1]:{d}", .{server_ptr.address().ip6.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "ipv6-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://[::1]:{d}/ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("ipv6-uri-ok", response.response.body);
}

test "HTTP/1 server sends 100 Continue before reading expected body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expect(request.request.method == .POST);
            try std.testing.expectEqualStrings("/expect", request.request.target);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 200,
                .reason = "OK",
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    // Send only the head first.  A Hyper-compatible HTTP/1 server must emit
    // 100 Continue after seeing a valid HTTP/1.1 request with a body so the
    // client can safely stream a large payload without deadlocking.
    try writeAllToStream(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-Continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    try writeAllToStream(io, client.stream, "ping");
    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 server suppresses 100 Continue for invalid request head" {
    const bad_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: http://example.com\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(bad_host));

    const duplicate_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Host: other.example\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(duplicate_host));

    const mixed_expect = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Expect: 100-continue, custom\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(mixed_expect));
}

test "HTTP/1 unbuffered server validates full head before 100 Continue" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        const Expected = struct { request: []const u8, err: anyerror };
        const cases = [_]Expected{
            .{
                .request = "POST /malformed HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Malformed Header\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4\r\n\r\n",
                .err = error.MalformedHeader,
            },
            .{
                .request = "POST /conflict HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Content-Length: 5\r\n\r\n",
                .err = error.ConflictingContentLength,
            },
            .{
                .request = "POST /duplicate-chunked HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Transfer-Encoding: chunked, chunked\r\n\r\n",
                .err = error.InvalidTransferEncoding,
            },
            .{
                .request = "POST /oversized HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4097\r\n\r\n",
                .err = error.BodyTooLarge,
            },
        };

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (@This().cases) |case| {
                const stream = try self.server.listener.accept(self.server.io);
                defer stream.close(self.server.io);
                const result = readRequestFromStream(
                    self.server.allocator,
                    self.server.io,
                    stream,
                    self.server.limits,
                    .{},
                );
                try std.testing.expectError(case.err, result);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (Shared.cases) |case| {
        const stream = try server.address().connect(io, .{ .mode = .stream });
        defer stream.close(io);
        try writeAllToStream(io, stream, case.request);
        var received: [25]u8 = undefined;
        try std.testing.expectEqual(
            @as(usize, 0),
            try readSome(io, stream, &received),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 server sends 100 Continue even when body was pre-read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("ping", request.request.body);
            try connection.writeResponse(.{ .body = "accepted" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    try writeAllToStream(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "ping");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client skips interim responses before final response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/interim", request.request.target);

            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 100 Continue\r\n\r\n" ++
                "HTTP/1.1 102 Processing\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/interim",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 client observes informational response heads in order" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\n" ++
                    "Link: </style.css>; rel=preload\r\n\r\n" ++
                    "HTTP/1.1 102 Processing\r\n" ++
                    "X-Progress: indexed\r\n\r\n" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\nConnection: close\r\n\r\nfinal",
            );
        }
    };

    const Observer = struct {
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn onResponse(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.count >= self.statuses.len) @panic(
                "too many informational callbacks",
            );
            self.statuses[self.count] = head.status;
            if (head.status == 103) {
                if (!std.mem.eql(
                    u8,
                    head.header("link") orelse @panic("missing Link"),
                    "</style.css>; rel=preload",
                )) @panic("unexpected Link");
            } else if (head.status == 102) {
                if (!std.mem.eql(
                    u8,
                    head.header("x-progress") orelse
                        @panic("missing X-Progress"),
                    "indexed",
                )) @panic("unexpected X-Progress");
            }
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var observer = Observer{};
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.requestWithInformational(
        .{
            .method = .GET,
            .target = "/informational",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        },
        .{
            .context = &observer,
            .on_response = Observer.onResponse,
        },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), observer.count);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        &observer.statuses,
    );
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 aggregate request rejects informational callback reentry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest(.{});
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/first",
                first.request.target,
            );
            try writeAllToStream(
                shared.server.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\n" ++
                    "Link: </next>; rel=preload\r\n\r\n" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\n\r\nfirst",
            );

            var second = try connection.readRequest(.{});
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/after",
                second.request.target,
            );
            try writeAllToStream(
                shared.server.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\n" ++
                    "Connection: close\r\n\r\nafter",
            );
        }
    };

    const Observer = struct {
        client: *Client,
        error_seen: ?anyerror = null,
        unexpectedly_started: bool = false,

        fn onResponse(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (head.status != 103) @panic("unexpected interim status");
            var nested = self.client.startRequest(.{
                .method = .GET,
                .target = "/nested",
                .host = "localhost",
                .body_length = 0,
            }) catch |err| {
                self.error_seen = err;
                return;
            };
            self.unexpectedly_started = true;
            nested.deinit();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var observer = Observer{ .client = &client };
    var first = try client.requestWithInformational(
        .{
            .method = .GET,
            .target = "/first",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        },
        .{ .context = &observer, .on_response = Observer.onResponse },
    );
    defer first.deinit(allocator);
    try std.testing.expect(!observer.unexpectedly_started);
    switch (observer.error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConnectionBusy => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("first", first.response.body);
    try std.testing.expect(client.isReusable());

    var second = try client.request(.{
        .method = .GET,
        .target = "/after",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("after", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client bounds informational response chains" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 102 Processing\r\n\r\n" ** 3 ++
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
            .max_informational_responses = 2,
        },
    );
    defer client.close();
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .method = .GET,
            .target = "/informational-limit",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        }),
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = .GET,
            .target = "/must-not-reuse",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        }),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming client waits for 100 Continue before body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var head: [256]u8 = undefined;
            var used: usize = 0;
            while (std.mem.indexOf(u8, head[0..used], "\r\n\r\n") == null) {
                if (used == head.len) return error.HeadersTooLarge;
                const count = try readSome(
                    server_ptr.io,
                    connection.stream,
                    head[used..],
                );
                if (count == 0) return error.ConnectionClosed;
                used += count;
            }
            const head_end = std.mem.indexOf(
                u8,
                head[0..used],
                "\r\n\r\n",
            ).? + 4;
            try std.testing.expectEqual(head_end, used);
            try std.testing.expect(std.mem.indexOf(
                u8,
                head[0..head_end],
                "Expect: 100-continue\r\n",
            ) != null);

            // Send an unrelated hint first to prove waitForContinue consumes
            // multiple informational heads rather than accepting any 1xx.
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n" ++
                    "HTTP/1.1 100 Continue\r\n\r\n",
            );
            var body: [4]u8 = undefined;
            try readExactForTest(
                server_ptr.io,
                connection.stream,
                &body,
            );
            try std.testing.expectEqualStrings("ping", &body);
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/expect-client",
        .host = "localhost",
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
        .body_length = 4,
    });
    defer writer.deinit();
    const Observer = struct {
        count: usize = 0,

        fn observe(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const expected_status: u16 = switch (self.count) {
                0 => 103,
                1 => 100,
                else => @panic("too many informational responses"),
            };
            if (head.status != expected_status) {
                @panic("unexpected informational status");
            }
            self.count += 1;
        }
    };
    var observer = Observer{};
    try std.testing.expect((try writer.waitForContinueWithInformational(.{
        .context = &observer,
        .on_response = Observer.observe,
    })) == .proceed);
    try std.testing.expectEqual(@as(usize, 2), observer.count);
    try std.testing.expectError(
        error.InvalidWriterState,
        writer.waitForContinue(),
    );
    try writer.write("ping");
    try writer.finish();
    var response = try writer.readResponseWithInformational(.{
        .context = &observer,
        .on_response = Observer.observe,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(usize, 2), observer.count);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming client returns final response before expected body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var head: [256]u8 = undefined;
            var used: usize = 0;
            while (std.mem.indexOf(u8, head[0..used], "\r\n\r\n") == null) {
                if (used == head.len) return error.HeadersTooLarge;
                const count = try readSome(
                    server_ptr.io,
                    connection.stream,
                    head[used..],
                );
                if (count == 0) return error.ConnectionClosed;
                used += count;
            }
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 417 Expectation Failed\r\n" ++
                    "Content-Length: 8\r\nConnection: close\r\n\r\nrejected",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/expect-reject",
        .host = "localhost",
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
        .body_length = 4,
    });
    defer writer.deinit();
    switch (try writer.waitForContinue()) {
        .proceed => return error.TestUnexpectedResult,
        .final_response => |value| {
            var response = value;
            defer response.deinit(allocator);
            try std.testing.expectEqual(
                @as(u16, 417),
                response.response.status,
            );
            try std.testing.expectEqualStrings(
                "rejected",
                response.response.body,
            );
        },
    }
    try std.testing.expectError(error.InvalidWriterState, writer.write("ping"));
    try std.testing.expectError(
        error.InvalidWriterState,
        writer.readResponse(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: http1.Request) Error!ResponseOptions {
            if (request.method != .POST) return error.InvalidMethod;
            if (std.mem.eql(u8, request.target, "/one")) {
                return .{ .status = 200, .body = "handled-one" };
            }
            if (std.mem.eql(u8, request.target, "/two")) {
                return .{ .status = 200, .body = "handled-two" };
            }
            return .{ .status = 404, .reason = "Not Found", .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        target: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
            defer client.close();
            var response = try client.request(.{
                .method = .POST,
                .target = task.target,
                .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(task.expected, response.response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/one", .expected = "handled-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/two", .expected = "handled-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/1 serveConnection handles keep-alive requests" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,

        fn handle(ctx: *@This(), request: http1.Request) Error!ResponseOptions {
            ctx.count += 1;
            if (std.mem.eql(u8, request.target, "/first")) {
                return .{
                    .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                    .body = "one",
                };
            }
            if (std.mem.eql(u8, request.target, "/second")) {
                return .{
                    .headers = &.{.{ .name = "Connection", .value = "close" }},
                    .body = "two",
                };
            }
            return .{ .status = 404, .reason = "Not Found", .headers = &.{.{ .name = "Connection", .value = "close" }} };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(&shared.context, Context.handle, 8) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    var first = try client.request(.{ .target = "/first", .headers = &keep_alive });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
}

test "HTTP/1 serveConnection can disable keep-alive without consuming pipeline suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
            .keep_alive = false,
        },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,

        fn handle(ctx: *@This(), request: http1.Request) Error!ResponseOptions {
            ctx.count += 1;
            if (!std.mem.eql(u8, "/first", request.target)) {
                return error.InvalidResponse;
            }
            return .{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "keep-alive",
                }},
                .body = "one",
            };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.served = try self.server.serveConnection(
                &self.context,
                Context.handle,
                8,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .target = "/first",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    // Queue a second complete request before reading the first response. The
    // disabled serve policy must not dispatch this buffered suffix.
    try writeRequestToStream(allocator, io, stream, .{
        .target = "/second",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });

    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var first = try readResponseFromStreamBuffered(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
        &inbuf,
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expect(!first.response.keepAlive());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
    try std.testing.expectEqual(@as(usize, 1), shared.context.count);
}

test "HTTP/1 serveConnection adds close for request close" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(_: *@This(), _: http1.Request) Error!ResponseOptions {
            return .{ .body = "closing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            _ = shared.server.serveConnection(&shared.context, Context.handle, 4) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const close_header = [_]http1.Header{.{ .name = "Connection", .value = "close" }};
    var response = try client.request(.{ .target = "/close", .headers = &close_header });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("closing", response.response.body);
    try std.testing.expectEqualStrings("close", response.response.header("connection").?);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "HTTP/1 serveConnection retires TE plus CL requests before pipeline suffix" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,

        fn handle(self: *@This(), request: http1.Request) Error!ResponseOptions {
            self.count += 1;
            if (!request.must_close or request.keepAlive() or
                !std.mem.eql(u8, "payload", request.body) or
                request.header("content-length") != null)
            {
                return error.InvalidResponse;
            }
            return .{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "keep-alive",
                }},
                .body = "handled",
            };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(
                &shared.context,
                Context.handle,
                4,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(
        io,
        stream,
        "POST /ambiguous HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Content-Length: 1\r\n\r\n" ++
            "7\r\npayload\r\n0\r\n\r\n" ++
            "GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    var response = try readResponseFromStreamForRequest(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
        .POST,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("handled", response.response.body);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
    try std.testing.expectEqual(@as(usize, 1), shared.context.count);
}

test "HTTP/1 serveConnection fixes HTTP/1.0 keep-alive response" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,
        fn handle(ctx: *@This(), _: http1.Request) Error!ResponseOptions {
            ctx.count += 1;
            return .{ .body = if (ctx.count == 1) "first" else "second" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        err: ?anyerror = null,
        served: usize = 0,
        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(&shared.context, Context.handle, 4) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    var first = try client.request(.{ .version = .http_1_0, .target = "/first", .headers = &keep_alive });
    defer first.deinit(allocator);
    try std.testing.expectEqual(http1.Version.http_1_0, first.response.version);
    try std.testing.expectEqualStrings("keep-alive", first.response.header("connection").?);
    try std.testing.expectEqualStrings("first", first.response.body);

    var second = try client.request(.{ .version = .http_1_0, .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqual(http1.Version.http_1_0, second.response.version);
    try std.testing.expectEqualStrings("close", second.response.header("connection").?);
    try std.testing.expectEqualStrings("second", second.response.body);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
}

test "HTTP/1 runtime reuses persistent connection and preserves pipelined bytes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/one", first.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                .body = "first",
            });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/two", second.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "close" }},
                .body = "second",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/one",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/two",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings("first", first_response.response.body);
    try std.testing.expect(first_response.response.keepAlive());

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("second", second_response.response.body);
    try std.testing.expect(!second_response.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client reuses default HTTP/1.1 persistent connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-one", first.request.target);
            try std.testing.expect(first.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "first" });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-two", second.request.target);
            try std.testing.expect(second.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "second" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var first = try client.request(.{
        .target = "/default-one",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    try std.testing.expect(first.response.keepAlive());

    var second = try client.request(.{
        .target = "/default-two",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.response.body);
    try std.testing.expect(second.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client keeps pipelined response after HEAD response headers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expect(first.request.method == .HEAD);

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expect(second.request.method == .GET);

            // A HEAD response can advertise the Content-Length a GET would have
            // returned, but no body bytes follow.  Send the next response
            // immediately to prove the client does not consume it as a HEAD
            // body.
            const raw =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
            try writeAllToStream(server_ptr.io, connection.stream, raw);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .HEAD,
        .target = "/head",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/next",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var head_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .HEAD);
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.none, head_response.response.body_framing);
    try std.testing.expectEqualStrings("", head_response.response.body);

    var get_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .GET);
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.response.status);
    try std.testing.expectEqualStrings("pong", get_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime writes request trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);

            try std.testing.expect(request.request.method == .POST);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("upload", request.request.body);
            try std.testing.expectEqualStrings("chunked", request.request.header("transfer-encoding").?);
            try std.testing.expectEqualStrings("Digest, X-Upload-Complete", request.request.header("trailer").?);
            try std.testing.expectEqual(@as(usize, 2), request.request.trailers.len);
            try std.testing.expectEqualStrings("Digest", request.request.trailers[0].name);
            try std.testing.expectEqualStrings("sha-256=demo, sha-256=second", request.request.trailers[0].value);
            try std.testing.expectEqualStrings("X-Upload-Complete", request.request.trailers[1].name);
            try std.testing.expectEqualStrings("yes", request.request.trailers[1].value);

            try connection.writeResponse(.{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/upload",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        .body = "upload",
        .trailers = &.{
            .{ .name = "Digest", .value = "sha-256=demo" },
            .{ .name = "digest", .value = "sha-256=second" },
            .{ .name = "X-Upload-Complete", .value = "yes" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
}

test "HTTP/1 runtime writes response trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/download", request.request.target);
            try std.testing.expectEqualStrings("trailers", request.request.header("te").?);

            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "download",
                .request_accepts_trailers = request.request.acceptsTrailers(),
                .trailers = &.{
                    .{ .name = "Digest", .value = "sha-256=response" },
                    .{ .name = "digest", .value = "sha-256=second" },
                },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/download",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "TE", .value = "trailers" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("download", response.response.body);
    try std.testing.expectEqualStrings("chunked", response.response.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("Digest", response.response.header("trailer").?);
    try std.testing.expectEqual(@as(usize, 1), response.response.trailers.len);
    try std.testing.expectEqualStrings("Digest", response.response.trailers[0].name);
    try std.testing.expectEqualStrings("sha-256=response, sha-256=second", response.response.trailers[0].value);
}

test "HTTP/1 runtime honors explicit transfer-encoding chunked writes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("streamed", request.request.body);
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("content-length"));
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("trailer"));

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/explicit-chunked",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Content-Length", .value = "999" },
        },
        .body = "streamed",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(?[]const u8, null), response.response.header("content-length"));
    try std.testing.expectEqual(@as(usize, 0), response.response.trailers.len);
}

test "HTTP/1 client reads close-delimited response body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/close-delimited", request.request.target);

            // No Content-Length or Transfer-Encoding: the response body is
            // delimited by closing the connection, which remains common for
            // simple HTTP/1.0-style origin/proxy responses.
            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 client treats non-chunked response transfer coding as close-delimited" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/te-close-delimited", request.request.target);

            // Hyper treats a response with a non-chunked transfer coding as
            // close-delimited.  Requests remain strict because accepting
            // unsupported request transfer codings is a smuggling risk.
            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: yolo\r\nContent-Length: 999\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/te-close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("yolo", response.response.header("transfer-encoding").?);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 client rejects Transfer-Encoding on HTTP/1.0 response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.0 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        client.request(.{
            .target = "/http10-te",
            .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        }),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 status-forbidden body preserves pipelined response without request context" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);

            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/no-content", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/next", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), first_response.response.status);
    try std.testing.expectEqualStrings("", first_response.response.body);

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), second_response.response.status);
    try std.testing.expectEqualStrings("pong", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client consumes framed 205 content before next response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
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
            var connection = try server_ptr.accept();
            defer connection.close();
            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);

            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 205 Reset Content\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Connection: keep-alive\r\n\r\nbody" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Connection: close\r\n\r\npong",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const headers = [_]http1.Header{
        .{ .name = "Connection", .value = "keep-alive" },
        .{ .name = "Host", .value = "localhost" },
    };
    try writeRequestToStream(allocator, io, client.stream, .{
        .target = "/reset",
        .headers = &headers,
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .target = "/next",
        .headers = &headers,
    });

    var first_response = try readResponseFromStreamBuffered(
        allocator,
        io,
        client.stream,
        client.limits,
        .{},
        &client.inbuf,
    );
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), first_response.response.status);
    try std.testing.expectEqualStrings("body", first_response.response.body);

    var second_response = try readResponseFromStreamBuffered(
        allocator,
        io,
        client.stream,
        client.limits,
        .{},
        &client.inbuf,
    );
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("pong", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime does not default Content-Length for status-forbidden responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            connection.writeResponse(.{ .status = 204, .reason = "No Content" }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var response = try client.request(.{
        .target = "/no-content",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("", response.response.body);
}

test "HTTP/1 runtime does not default Connection close on writes" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    const defaulted = try runtime_write.prepareResponse(
        allocator,
        .{},
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, defaulted.header, "Connection:") == null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            defaulted.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const explicit_close = try runtime_write.prepareResponse(
        allocator,
        .{ .headers = &.{.{
            .name = "Connection",
            .value = "close",
        }} },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            explicit_close.header,
            "Connection: close\r\n",
        ) != null,
    );
}

test "HTTP/1 request writers default Content-Length by method" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    inline for (.{ http1.Method.GET, .HEAD, .CONNECT }) |method| {
        const safe = try runtime_write.prepareRequest(
            allocator,
            .{
                .method = method,
                .target = if (method == .CONNECT)
                    "example.com:443"
                else
                    "/",
                .host = if (method == .CONNECT)
                    "example.com:443"
                else
                    "example.com",
            },
            &scratch,
        );
        try std.testing.expect(
            std.mem.indexOf(u8, safe.header, "Content-Length:") == null,
        );
    }

    const post = try runtime_write.prepareRequest(
        allocator,
        .{ .method = .POST, .host = "example.com" },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            post.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const get_body = try runtime_write.prepareRequest(
        allocator,
        .{ .host = "example.com", .body = "x" },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            get_body.header,
            "Content-Length: 1\r\n",
        ) != null,
    );
}

test "HTTP/1 request writer omits zero Content-Length for bodyless safe methods" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expect(first.request.method == .GET);
            try std.testing.expect(first.request.header("content-length") == null);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expect(second.request.method == .POST);
            try std.testing.expectEqualStrings("0", second.request.header("content-length").?);

            var third = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer third.deinit(shared.allocator);
            try std.testing.expect(third.request.method == .GET);
            try std.testing.expectEqualStrings("/cache/http://example.com/object", third.request.target);
            try std.testing.expectEqualStrings("proxy.local", third.request.header("host").?);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/safe",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });
    try writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/entity",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });
    try writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/cache/http://example.com/object",
        .headers = &.{.{ .name = "Host", .value = "proxy.local" }},
    });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime validates outbound request and response framing before writing" {
    const allocator = std.testing.allocator;
    const io: std.Io = undefined;
    const stream: net.Stream = undefined;

    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/missing-host",
    }));
    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http://example.com/absolute",
        .headers = &.{.{ .name = "Host", .value = "other.example" }},
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http:///absolute",
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http://?q=1",
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "1http://example.com/absolute",
        .headers = &.{.{ .name = "Host", .value = "example.com" }},
    }));
    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{.{ .name = "Host", .value = "other.example:443" }},
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/bad-length",
        .headers = &.{
            .{ .name = "Host", .value = "example" },
            .{ .name = "Content-Length", .value = "5" },
        },
        .body = "ping",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{.{ .name = "Host", .value = "example.com:443" }},
        .body = "not allowed",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{
            .{ .name = "Host", .value = "example.com:443" },
            .{ .name = "Content-Length", .value = "0" },
        },
    }));
    try std.testing.expectError(error.InvalidTransferEncoding, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{
            .{ .name = "Host", .value = "example.com:443" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
        },
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "5" }},
        .body = "pong",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "0" }},
        .request_method = .CONNECT,
    }));

    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    const connect = try runtime_write.prepareResponse(
        allocator,
        .{ .request_method = .CONNECT },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, connect.header, "Content-Length:") == null,
    );

    const connect_error = try runtime_write.prepareResponse(
        allocator,
        .{ .status = 400, .request_method = .CONNECT },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            connect_error.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const no_content = try runtime_write.prepareResponse(
        allocator,
        .{ .status = 204 },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, no_content.header, "Content-Length:") == null,
    );
}

test "HTTP/0.9 aggregate body reader is opt in and bounded" {
    const allocator = std.testing.allocator;
    // Public parsing keeps legacy responses strict by default and exposes the
    // same synthetic metadata used by the aggregate runtime after EOF.
    try std.testing.expectError(error.BufferTooShort, http1.parseResponse(
        allocator,
        "legacy",
        .{},
    ));
    var response = try http1.parseResponse(allocator, "legacy", .{
        .allow_http_0_9_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(http1.Version.http_0_9, response.version);
    try std.testing.expectEqualStrings("legacy", response.body);
    try std.testing.expect(!responseIsReusable(response));

    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    try std.testing.expectError(error.InvalidVersion, runtime_write.prepareResponse(
        allocator,
        .{ .version = .http_0_9, .body = "legacy" },
        &scratch,
    ));
    try std.testing.expectError(error.InvalidVersion, runtime_write.prepareRequest(
        allocator,
        .{ .version = .http_0_9 },
        &scratch,
    ));
}

test "HTTP/1 buffered aggregate chunk limit ignores pipeline suffix" {
    const allocator = std.testing.allocator;
    const first = "POST /first HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const second = "GET /second HTTP/1.1\r\nHost: example\r\n\r\n";
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(allocator, first ++ second);

    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        .{ .tcp = .{ .io = undefined, .stream = undefined } },
        .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
        .{},
        &inbuf,
        null,
        true,
        false,
        false,
        null,
        null,
        null,
    );
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(first, bytes);
    try std.testing.expectEqualStrings(second, inbuf.items);
}

test "HTTP/1 non-buffered request reader preserves pipelined bytes on socket" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/first", first.request.target);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(io, stream, "POST /first HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nhello" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 non-buffered chunked reader preserves pipelined bytes on socket" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/chunked", first.request.target);
            try std.testing.expectEqual(http1.BodyFraming.chunked, first.request.body_framing);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(io, stream, "POST /chunked HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nDigest: ok\r\n\r\n" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 non-buffered chunked reader accepts exact and zero body limits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            var exact = try readRequestFromStream(
                shared.allocator,
                shared.io,
                stream,
                .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
                .{},
            );
            defer exact.deinit(shared.allocator);
            try std.testing.expectEqualStrings("hello", exact.request.body);

            var empty = try readRequestFromStream(
                shared.allocator,
                shared.io,
                stream,
                .{ .max_head_bytes = 1024, .max_body_bytes = 0 },
                .{},
            );
            defer empty.deinit(shared.allocator);
            try std.testing.expectEqual(@as(usize, 0), empty.request.body.len);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(
        io,
        stream,
        "POST /exact HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n" ++
            "POST /empty HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );

    thread.join();
    if (shared.err) |err| return err;
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

test "HTTP/1 native nonblocking peek distinguishes idle data and EOF" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    try std.testing.expectEqual(IdleSocketState.clean, probeIdleSocket(client));

    const write_parts = [_][]const u8{""};
    _ = try io.vtable.netWrite(
        io.userdata,
        server.socket.handle,
        "x",
        &write_parts,
        0,
    );
    var attempts: usize = 0;
    while (probeIdleSocket(client) == .clean and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(IdleSocketState.data, probeIdleSocket(client));
    var read_byte: [1]u8 = undefined;
    var read_parts = [_][]u8{&read_byte};
    try std.testing.expectEqual(
        @as(usize, 1),
        try io.vtable.netRead(
            io.userdata,
            client.socket.handle,
            &read_parts,
        ),
    );
    try std.testing.expectEqual(@as(u8, 'x'), read_byte[0]);

    try server.shutdown(io, .send);
    attempts = 0;
    while (probeIdleSocket(client) == .clean and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(IdleSocketState.eof, probeIdleSocket(client));
}

test {
    _ = runtime_write;
    _ = @import("runtime/message/batch.zig");
    _ = @import("runtime/message/tests/framing.zig");
    _ = @import("runtime/unix_tests.zig");
    _ = @import("runtime/http09_tests.zig");
    _ = @import("runtime/body_reader_tests.zig");
    _ = @import("runtime/body_writer_tests.zig");
    _ = @import("runtime/header_timeout_tests.zig");
    _ = @import("runtime/response_timeout_tests.zig");
    _ = @import("runtime/graceful_shutdown_tests.zig");
    _ = @import("runtime/tls_client_deadline_tests.zig");
    _ = @import("runtime/server_lifecycle_tests.zig");
    _ = @import("runtime/half_close_tests.zig");
    _ = @import("runtime/tls_close_tests.zig");
    _ = @import("runtime/tls_server_api_tests.zig");
    _ = @import("runtime/date_tests.zig");
}
