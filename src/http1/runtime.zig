const std = @import("std");
const builtin = @import("builtin");
const http1 = @import("mod.zig");
const runtime_write = @import("runtime/write.zig");
const body_writer = @import("runtime/body_writer.zig");
const body_reader = @import("runtime/body_reader.zig");
const stream_io = @import("../internal/stream_io.zig");
const deadline_policy = @import("../internal/deadline.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const wire = @import("../internal/wire.zig");
const vail = @import("vail");

const net = std.Io.net;
const linux = std.os.linux;
const posix = std.posix;
const tls = std.crypto.tls;
const CertificateBundle = std.crypto.Certificate.Bundle;

pub const Error = http1.Error || tls_stream.Error || error{
    HeadersTooLarge,
    BodyTooLarge,
    ConnectionClosed,
    InvalidUri,
    InvalidResponse,
    SocketOptionFailed,
    UnsupportedScheme,
    UnsupportedEndpoint,
    UnsupportedIoBackend,
    IoUringOperationFailed,
    UnexpectedCompletion,
    ConnectionBusy,
    ConnectionUnusable,
    InvalidWriterState,
    InvalidServeOptions,
    TimedReadUnsupported,
    TooManyInformationalResponses,
    PostHandshakeTlsUnavailable,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError ||
    net.UnixAddress.ListenError || net.UnixAddress.ConnectError ||
    net.HostName.ValidateError || net.HostName.ConnectError ||
    net.Server.AcceptError || net.Stream.Reader.Error ||
    net.Stream.Writer.Error || tls.Client.InitError ||
    CertificateBundle.RescanError || std.Io.RandomSecureError ||
    std.Io.Reader.ShortError || std.Io.Writer.Error ||
    std.Thread.SpawnError;

fn setTcpNoDelay(stream: net.Stream) Error!void {
    socket_options.setTcpNoDelay(stream) catch return error.SocketOptionFailed;
}

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
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

/// Opt-in vail TLS 1.3 client features that Zig's standard client does not
/// expose: client authentication, ALPN, peer chains, exporters and KeyUpdate.
/// Supplying this object selects the vail transport while preserving the same
/// hostname/system-root defaults through `initVerified`.
pub const VailTlsClientOptions = struct {
    verify_host: bool = true,
    ca_bundle: ?tls_stream.ClientCaBundle = null,
    server_verifier: ?vail.tls.auth.ClientVerifier = null,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const tls_stream.CipherSuite =
        &vail.tls.cipher_suite.default_preference,
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

pub const LinuxIoUringHandle = if (builtin.os.tag == .linux) linux.IoUring else opaque {};

pub const UriEndpoint = struct {
    allocator: std.mem.Allocator,
    /// Owned host text exactly as it belongs in HTTP authority syntax.  IPv6
    /// literals intentionally keep their RFC 3986 brackets so synthesized Host
    /// / `:authority` fields are valid.
    host_storage: []u8,
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
        self.allocator.free(self.host_storage);
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
    const host_storage = try uriHostToOwned(allocator, host_component);
    errdefer allocator.free(host_storage);

    const port = uri.port orelse default_port;
    const authority = if (uri.port == null)
        try allocator.dupe(u8, host_storage)
    else
        try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_storage, port });
    errdefer allocator.free(authority);

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

fn uriHostToOwned(allocator: std.mem.Allocator, host: std.Uri.Component) Error![]u8 {
    var buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw = host.toRaw(&buffer) catch return error.InvalidUri;
    if (raw.len == 0) return error.InvalidUri;
    return allocator.dupe(u8, raw);
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
                tls_stream.CipherSuite.aes_128_gcm_sha256,
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
                tls_stream.CipherSuite.aes_256_gcm_sha384,
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
        tls_stream.CipherSuite.aes_256_gcm_sha384,
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
        self.client.end() catch {};
        self.net_writer.interface.flush() catch {};
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
};

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
    linux_io_uring: LinuxIoUringStream,

    fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls_client => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
            .linux_io_uring => |transport| transport.read(buffer),
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
            // The raw io_uring adapter currently has no linked-timeout read.
            // Reject an explicitly configured deadline instead of silently
            // weakening the server's admission policy.
            .linux_io_uring => error.TimedReadUnsupported,
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
            .linux_io_uring => return error.TimedReadUnsupported,
        };
        return .fromNow(io, .{ .raw = duration, .clock = .awake });
    }

    fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls_client => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
            .linux_io_uring => |transport| transport.writeAll(bytes),
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
            // The raw io_uring adapter currently accepts one slice per SQE.
            // Two sends still avoid a body-sized temporary allocation.
            .linux_io_uring => |transport| {
                try transport.writeAll(header);
                try transport.writeAll(body);
            },
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
            // io_uring's adapter owns one buffer per send SQE. Preserve the
            // borrowed-slice behavior without allocating a concatenation.
            .linux_io_uring => |transport| {
                for (parts) |part| try transport.writeAll(part);
            },
        };
    }

    fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls_client => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
            .linux_io_uring => |transport| transport.close(),
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

pub const LinuxIoUringStream = if (builtin.os.tag == .linux) struct {
    ring: *linux.IoUring,
    fd: linux.fd_t,

    const Completion = enum(u64) {
        connect = 1,
        send = 2,
        recv = 3,
        close = 4,
        accept = 5,
    };

    pub fn connect(self: LinuxIoUringStream, address: net.IpAddress) Error!void {
        var storage: PosixAddress = undefined;
        const address_len = ipAddressToPosix(&address, &storage);
        _ = self.ring.connect(@intFromEnum(Completion.connect), self.fd, &storage.any, address_len) catch return error.IoUringOperationFailed;
        _ = try self.submitOne(.connect);
    }

    pub fn read(self: LinuxIoUringStream, buffer: []u8) Error!usize {
        if (buffer.len == 0) return 0;
        _ = self.ring.recv(@intFromEnum(Completion.recv), self.fd, .{ .buffer = buffer }, 0) catch return error.IoUringOperationFailed;
        const cqe = try self.submitOne(.recv);
        if (cqe.res < 0) return error.IoUringOperationFailed;
        return @intCast(cqe.res);
    }

    pub fn writeAll(self: LinuxIoUringStream, bytes: []const u8) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            _ = self.ring.send(@intFromEnum(Completion.send), self.fd, bytes[offset..], 0) catch return error.IoUringOperationFailed;
            const cqe = try self.submitOne(.send);
            if (cqe.res <= 0) return error.ConnectionClosed;
            offset += @intCast(cqe.res);
        }
    }

    pub fn close(self: LinuxIoUringStream) void {
        closeLinuxIoUringFd(self.ring, self.fd);
    }

    fn submitOne(self: LinuxIoUringStream, expected: Completion) Error!linux.io_uring_cqe {
        _ = self.ring.submit_and_wait(1) catch return error.IoUringOperationFailed;
        const cqe = self.ring.copy_cqe() catch return error.IoUringOperationFailed;
        if (cqe.user_data != @intFromEnum(expected)) return error.UnexpectedCompletion;
        if (cqe.err() != .SUCCESS) return error.IoUringOperationFailed;
        return cqe;
    }
} else struct {
    pub fn read(_: @This(), _: []u8) Error!usize {
        return error.UnsupportedIoBackend;
    }

    pub fn writeAll(_: @This(), _: []const u8) Error!void {
        return error.UnsupportedIoBackend;
    }

    pub fn close(_: @This()) void {}
};

const PosixAddress = if (builtin.os.tag == .linux) extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
} else void;

fn closeLinuxIoUringFd(ring: *LinuxIoUringHandle, fd: linux.fd_t) void {
    if (comptime builtin.os.tag != .linux) return;
    _ = ring.close(@intFromEnum(LinuxIoUringStream.Completion.close), fd) catch {
        _ = linux.close(fd);
        return;
    };
    _ = (LinuxIoUringStream{ .ring = ring, .fd = fd }).submitOne(.close) catch {
        _ = linux.close(fd);
    };
}

fn setLinuxSocketOption(fd: linux.fd_t, level: i32, opt_name: u32, option: u32) Error!void {
    const bytes: []const u8 = @ptrCast(&option);
    const rc = linux.setsockopt(fd, level, opt_name, bytes.ptr, @intCast(bytes.len));
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .BADF => error.IoUringOperationFailed,
        .FAULT => error.IoUringOperationFailed,
        .INVAL => error.IoUringOperationFailed,
        .NOMEM => error.SystemResources,
        .NOPROTOOPT => error.ProtocolUnsupportedBySystem,
        .NOTSOCK => error.IoUringOperationFailed,
        else => error.IoUringOperationFailed,
    };
}

fn bindLinuxSocket(fd: linux.fd_t, address: net.IpAddress) Error!void {
    var storage: PosixAddress = undefined;
    const len = ipAddressToPosix(&address, &storage);
    const rc = linux.bind(fd, &storage.any, len);
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => error.AccessDenied,
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .BADF => error.IoUringOperationFailed,
        .INVAL => error.IoUringOperationFailed,
        .LOOP => error.IoUringOperationFailed,
        .NAMETOOLONG => error.IoUringOperationFailed,
        .NOENT => error.IoUringOperationFailed,
        .NOMEM => error.SystemResources,
        .NOTDIR => error.IoUringOperationFailed,
        .ROFS => error.AccessDenied,
        else => error.IoUringOperationFailed,
    };
}

fn listenLinuxSocket(fd: linux.fd_t, backlog: u31) Error!void {
    const rc = linux.listen(fd, backlog);
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ADDRINUSE => error.AddressInUse,
        .BADF => error.IoUringOperationFailed,
        .DESTADDRREQ => error.IoUringOperationFailed,
        .INVAL => error.IoUringOperationFailed,
        .NOTSOCK => error.IoUringOperationFailed,
        .OPNOTSUPP => error.SocketModeUnsupported,
        else => error.IoUringOperationFailed,
    };
}

fn linuxSocketName(fd: linux.fd_t) Error!net.IpAddress {
    var storage: PosixAddress = undefined;
    var len: linux.socklen_t = @sizeOf(PosixAddress);
    const rc = linux.getsockname(fd, &storage.any, &len);
    return switch (linux.errno(rc)) {
        .SUCCESS => addressFromPosix(&storage),
        .BADF => error.IoUringOperationFailed,
        .FAULT => error.IoUringOperationFailed,
        .INVAL => error.IoUringOperationFailed,
        .NOTSOCK => error.IoUringOperationFailed,
        else => error.IoUringOperationFailed,
    };
}

fn addressFromPosix(posix_address: *const PosixAddress) net.IpAddress {
    return switch (posix_address.any.family) {
        linux.AF.INET => .{ .ip4 = .{
            .port = std.mem.bigToNative(u16, posix_address.in.port),
            .bytes = @bitCast(posix_address.in.addr),
        } },
        linux.AF.INET6 => .{ .ip6 = .{
            .port = std.mem.bigToNative(u16, posix_address.in6.port),
            .bytes = posix_address.in6.addr,
            .flow = posix_address.in6.flowinfo,
            .interface = .{ .index = posix_address.in6.scope_id },
        } },
        else => .{ .ip4 = .loopback(0) },
    };
}

fn ipAddressToPosix(address: *const net.IpAddress, storage: *PosixAddress) posix.socklen_t {
    return switch (address.*) {
        .ip4 => |ip4| {
            storage.in = .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

fn createLinuxTcpSocket(address: net.IpAddress) Error!linux.fd_t {
    const family: u32 = switch (address) {
        .ip4 => linux.AF.INET,
        .ip6 => linux.AF.INET6,
    };
    const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.AccessDenied,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM => error.SystemResources,
        .PROTONOSUPPORT => error.ProtocolUnsupportedBySystem,
        else => error.IoUringOperationFailed,
    };
}

pub fn connectIpLinuxIoUring(ring: *LinuxIoUringHandle, address: net.IpAddress) Error!LinuxIoUringStream {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedIoBackend;

    const fd = try createLinuxTcpSocket(address);
    var stream = LinuxIoUringStream{ .ring = ring, .fd = fd };
    errdefer stream.close();
    try stream.connect(address);
    return stream;
}

pub const LinuxIoUringServer = if (builtin.os.tag == .linux) struct {
    allocator: std.mem.Allocator,
    ring: *LinuxIoUringHandle,
    fd: linux.fd_t,
    address: net.IpAddress,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        ring: *LinuxIoUringHandle,
        bind_address: net.IpAddress,
        limits: Limits,
        options: net.IpAddress.ListenOptions,
    ) Error!LinuxIoUringServer {
        if (options.mode != .stream or options.protocol != .tcp) return error.SocketModeUnsupported;
        const fd = try createLinuxTcpSocket(bind_address);
        errdefer _ = linux.close(fd);
        if (options.reuse_address) {
            try setLinuxSocketOption(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1);
            try setLinuxSocketOption(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, 1);
        }
        try bindLinuxSocket(fd, bind_address);
        try listenLinuxSocket(fd, options.kernel_backlog);
        return .{
            .allocator = allocator,
            .ring = ring,
            .fd = fd,
            .address = try linuxSocketName(fd),
            .limits = limits,
        };
    }

    pub fn deinit(self: *LinuxIoUringServer) void {
        closeLinuxIoUringFd(self.ring, self.fd);
        self.* = undefined;
    }

    pub fn accept(self: *LinuxIoUringServer) Error!LinuxIoUringConnection {
        var storage: PosixAddress = undefined;
        var len: linux.socklen_t = @sizeOf(PosixAddress);
        _ = self.ring.accept(@intFromEnum(LinuxIoUringStream.Completion.accept), self.fd, &storage.any, &len, linux.SOCK.CLOEXEC) catch return error.IoUringOperationFailed;
        const cqe = try (LinuxIoUringStream{ .ring = self.ring, .fd = self.fd }).submitOne(.accept);
        if (cqe.res < 0) return error.IoUringOperationFailed;
        return .{
            .allocator = self.allocator,
            .stream = .{ .ring = self.ring, .fd = @intCast(cqe.res) },
            .limits = self.limits,
        };
    }
};

pub const LinuxIoUringConnection = if (builtin.os.tag == .linux) struct {
    allocator: std.mem.Allocator,
    stream: LinuxIoUringStream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    write_scratch: WriteScratch = .{},

    pub fn close(self: *LinuxIoUringConnection) void {
        self.inbuf.deinit(self.allocator);
        self.write_scratch.deinit(self.allocator);
        self.stream.close();
        self.* = undefined;
    }

    pub fn readRequest(self: *LinuxIoUringConnection, options: http1.ParseOptions) Error!OwnedRequest {
        if (self.limits.request_head_timeout != null) {
            return error.TimedReadUnsupported;
        }
        return readRequestFromTransportBuffered(
            self.allocator,
            .{ .linux_io_uring = self.stream },
            self.limits,
            options,
            &self.inbuf,
            null,
        );
    }

    pub fn writeResponse(self: *LinuxIoUringConnection, response: ResponseOptions) Error!void {
        try writeResponseToTransportScratch(
            self.allocator,
            .{ .linux_io_uring = self.stream },
            response,
            &self.write_scratch,
        );
    }
};

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
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
        try connection.serveOne(context, handler);
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

/// TLS 1.3 server transport for the same HTTP/1 parser and writer used by the
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
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) try setTcpNoDelay(stream);
        const tls_connection = try tls_stream.ServerConnection.init(
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
        const task = ServeTask(HandlerContext){
            .connection = connection,
            .context = context,
            .handler = handler,
            .result = result,
        };
        group.async(io, ServeTask(HandlerContext).run, .{task});
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

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            var request = connection.readRequest(.{}) catch |err| {
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            var response = task.handler(task.context, request.request) catch |err| {
                task.result.* = err;
                return;
            };
            if (response.request_method == null) response.request_method = request.request.method;
            connection.writeResponse(response) catch |err| {
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
        const options: tls_stream.ClientVerifiedOptions = .{
            .server_name = tls_host,
            .verify_host = tls_options.verify_host,
            .ca_bundle = tls_options.ca_bundle,
            .server_verifier = tls_options.server_verifier,
            .client_identity = tls_options.client_identity,
            .alpn_protocols = tls_options.alpn_protocols,
            .cipher_suites = tls_options.cipher_suites,
            .max_server_handshake_size = tls_options.max_server_handshake_size,
            .handshake_timeout = tls_options.handshake_timeout,
        };
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

    pub fn negotiatedCipherSuite(
        self: *const Client,
    ) ?tls_stream.CipherSuite {
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
        try connection.updateTrafficKeys(request_peer_update);
    }

    pub fn keyUpdateCounts(
        self: *const Client,
    ) ?tls_stream.KeyUpdateCounts {
        const connection = self.tls_vail_conn orelse return null;
        return connection.keyUpdateCounts();
    }

    pub fn isReusable(self: *const Client) bool {
        return self.writer_state.phase == .idle and
            !self.writer_state.reading;
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        return self.requestWithInformational(
            request_options,
            null,
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
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.request(request_options);
    }

    /// Send a complete request and observe each valid interim response before
    /// returning the final response. The observer borrows parser storage only
    /// for the callback duration.
    pub fn requestWithInformational(
        self: *Client,
        request_options: RequestOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        try self.writer_state.ensureAvailable();
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        try writeRequestToTransportScratch(
            self.allocator,
            self.transport(),
            options,
            &self.write_scratch,
        );
        self.beginResponseHeadSequence();
        defer self.endResponseHeadSequence();
        const response = readResponseFromTransportBufferedForRequestObserved(
            self.allocator,
            self.transport(),
            self.limits,
            .{},
            &self.inbuf,
            request_options.method,
            informational,
            null,
            self.response_deadline,
        ) catch |err| {
            self.writer_state.phase = .unusable;
            return err;
        };
        if (!requestOptionsKeepAlive(options) or
            !responseIsReusable(response.response))
        {
            self.writer_state.phase = .unusable;
        }
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
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.debug.assert(self.response_deadline == null);
        self.response_deadline = deadline;
        defer self.response_deadline = null;
        return self.requestStreaming(request_options, context, consume);
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
        self.transport().writeAllParts(
            parts.header,
            parts.body,
        ) catch |err| {
            self.writer_state.phase = .unusable;
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
        const announced_trailers = self.write_scratch.trailer_headers.items;
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

    /// Linux-only HTTP/1 client path backed directly by `std.os.linux.IoUring`.
    ///
    /// Zig 0.16 exposes a `std.Io.Uring` backend, but its `std.Io.net` vtable
    /// does not yet implement TCP listen/connect/read/write.  This helper uses
    /// the lower-level `std.os.linux.IoUring` operations directly and then
    /// feeds the same runtime parser/serializer used by the normal TCP client.
    /// It intentionally supports only literal IP URI authorities (`127.0.0.1`
    /// and bracketed IPv6 such as `[::1]`) because DNS lookup still belongs to
    /// the higher-level `std.Io.net` abstraction.
    pub fn requestUriLinuxIoUring(
        allocator: std.mem.Allocator,
        ring: *LinuxIoUringHandle,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedIoBackend;
        if (limits.response_head_timeout != null) {
            // The raw adapter has no linked timeout operation. Fail before
            // creating or writing a socket rather than silently weakening a
            // caller-specified response policy.
            return error.TimedReadUnsupported;
        }

        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();
        const address = switch (endpoint.target) {
            .ip => |address| address,
            .host => return error.UnsupportedEndpoint,
        };

        var uring_transport = try connectIpLinuxIoUring(ring, address);
        var fd_open = true;
        errdefer if (fd_open) uring_transport.close();
        var options = request_options;
        options.target = target;
        if (options.host == null) options.host = endpoint.authority;
        try writeRequestToTransport(allocator, .{ .linux_io_uring = uring_transport }, options);

        var inbuf: std.ArrayList(u8) = .empty;
        defer inbuf.deinit(allocator);
        var response = try readResponseFromTransportBufferedForRequest(
            allocator,
            .{ .linux_io_uring = uring_transport },
            limits,
            .{},
            &inbuf,
            request_options.method,
        );
        errdefer response.deinit(allocator);
        uring_transport.close();
        fd_open = false;
        return response;
    }

    pub fn openConnectTunnel(self: *Client, target: []const u8, headers: []const http1.Header) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        try http1.validateConnectTarget(target);
        try writeRequestToTransport(self.allocator, self.transport(), .{
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
        try writeRequestToTransport(self.allocator, self.transport(), .{
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

    /// Return authenticated TLS 1.3 negotiation metadata for HTTPS server
    /// connections. Cleartext connections return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.CipherSuite {
        const connection = self.tls_server_conn orelse return null;
        return connection.negotiatedCipherSuite();
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
        try connection.updateTrafficKeys(request_peer_update);
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
        try self.writer_state.ensureReadable();
        try self.beginRequestHeadDeadline();
        defer self.request_head_deadline = null;
        return readRequestFromTransportBuffered(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            self.request_head_deadline,
        ) catch |read_err| {
            if (read_err == error.Timeout) self.writer_state.phase = .unusable;
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
        try self.writer_state.ensureReadable();
        return readRequestFromTransportBuffered(
            self.allocator,
            self.transport(),
            self.limits,
            options,
            &self.inbuf,
            deadline,
        );
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

    /// Read and parse an exact batch of pipelined request heads without
    /// per-request allocation.
    ///
    /// `heads`, every head's header slice, and `bodies` borrow `self.inbuf`.
    /// They remain valid only until the next read or `consumeRequestBatch`.
    /// Chunked requests have no statically known message boundary and return
    /// `InvalidResponse`; callers can use `readRequest` for those.
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
        const max_batch_bytes = std.math.add(
            usize,
            max_batch_head_bytes,
            max_batch_body_bytes,
        ) catch return error.BodyTooLarge;
        var timed_head_index: ?usize = null;

        while (true) {
            var offset: usize = 0;
            var complete = true;
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
                const message_len = (try head.messageLength()) orelse
                    return error.InvalidResponse;
                if (message_len < head.head_len) {
                    return error.InvalidResponse;
                }
                if (message_len - head.head_len >
                    self.limits.max_body_bytes)
                {
                    return error.BodyTooLarge;
                }
                const next_offset = std.math.add(
                    usize,
                    offset,
                    message_len,
                ) catch return error.BodyTooLarge;
                if (next_offset > self.inbuf.items.len) {
                    complete = false;
                    break;
                }
                body.* = self.inbuf.items[offset + head.head_len .. next_offset];
                offset = next_offset;
            }
            if (complete) {
                self.request_head_deadline = null;
                return offset;
            }

            // Do not over-read merely to discover that the batch cannot fit.
            // A complete batch may coexist with a larger already-buffered
            // suffix, but an incomplete final request has no later message
            // boundary yet, so all current bytes belong to this batch.
            if (self.inbuf.items.len >= max_batch_bytes) {
                return error.BodyTooLarge;
            }
            var read_buffer: [16 * 1024]u8 = undefined;
            const remaining = max_batch_bytes - self.inbuf.items.len;
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
        try writeResponseToTransportScratch(
            self.allocator,
            self.transport(),
            response,
            &self.write_scratch,
        );
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

        const prepared = try runtime_write.streaming.prepareResponse(
            self.allocator,
            options,
            &self.write_scratch,
        );
        const announced_trailers = self.write_scratch.trailer_headers.items;
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
        try writeResponsesToTransportScratch(
            self.allocator,
            self.transport(),
            responses,
            &self.write_scratch,
        );
    }

    pub fn serveOne(self: *Connection, context: anytype, comptime handler: anytype) Error!bool {
        if (self.graceful_shutdown_requested) return false;
        var request = try self.readRequest(.{});
        defer request.deinit(self.allocator);
        const request_keep_alive = request.request.keepAlive();
        var response = try handler(context, request.request);
        var adjusted = try adjustResponseForServeLoop(
            self.allocator,
            request.request,
            response,
            self.graceful_shutdown_requested,
        );
        defer adjusted.deinit(self.allocator);
        response = adjusted.response;
        if (response.request_method == null) response.request_method = request.request.method;
        const response_keep_alive = responseOptionsKeepAlive(response);
        try self.writeResponse(response);
        if (self.graceful_shutdown_requested) {
            self.writer_state.phase = .unusable;
            return false;
        }
        return request_keep_alive and response_keep_alive;
    }

    pub fn serve(self: *Connection, context: anytype, comptime handler: anytype, max_requests: usize) Error!usize {
        var served: usize = 0;
        while (served < max_requests) : (served += 1) {
            if (self.graceful_shutdown_requested) return served;
            const keep_going = try self.serveOne(context, handler);
            if (!keep_going) return served + 1;
        }
        return served;
    }

    pub fn acceptConnectTunnel(self: *Connection, request: http1.Request, response_headers: []const http1.Header) Error!Tunnel {
        try self.writer_state.ensureAvailable();
        if (request.method != .CONNECT or request.body.len != 0 or request.trailers.len != 0) return error.InvalidResponse;
        try http1.validateConnectTarget(request.target);
        try writeResponseToTransport(self.allocator, self.transport(), .{
            .status = 200,
            .reason = "Connection Established",
            .headers = response_headers,
            .request_method = .CONNECT,
        });
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
        try writeResponseToTransport(self.allocator, self.transport(), .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = merged.items,
            .request_method = request.method,
        });
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

    fn transport(self: *Tunnel) RuntimeTransport {
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls_client = conn };
        if (self.tls_server_conn) |conn| return .{ .tls_server = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn write(self: *Tunnel, bytes: []const u8) Error!void {
        try self.transport().writeAll(bytes);
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
        return self.transport().readWithDeadline(buffer, deadline);
    }

    /// Preserve post-handshake TLS control for server-side CONNECT/Upgrade
    /// tunnels after the HTTP parser relinquishes ownership of the stream.
    pub fn updateTrafficKeys(
        self: *Tunnel,
        request_peer_update: bool,
    ) Error!void {
        const connection = self.tls_vail_conn orelse
            self.tls_server_conn orelse
            return error.PostHandshakeTlsUnavailable;
        try connection.updateTrafficKeys(request_peer_update);
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
        if (deadline.durationFromNow(self.client.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponse();
    }

    /// Read the final response while synchronously observing preceding 1xx
    /// heads. This is the streaming-request counterpart to
    /// `Client.requestWithInformational`.
    pub fn readResponseWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        try self.body.ensureExchangeActive();
        if (!self.body.isBodyFinished()) return error.InvalidWriterState;

        const response = readResponseFromTransportBufferedForRequestObserved(
            self.client.allocator,
            self.client.transport(),
            self.client.limits,
            .{},
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
        if (deadline.durationFromNow(self.client.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreaming(context, consume);
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
) Error!void {
    const client: *Client = @ptrCast(@alignCast(context.?));
    try client.transport().writeAllSlices(parts);
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
) Error!void {
    const connection: *Connection = @ptrCast(@alignCast(context.?));
    try connection.transport().writeAllSlices(parts);
}

fn responseIsReusable(response: http1.Response) bool {
    // Close-delimited bodies consume EOF as their message boundary, and 101
    // transfers the socket to another protocol. Neither can begin another
    // HTTP/1 exchange even if the header block omitted Connection: close.
    return response.keepAlive() and
        response.body_framing != .close_delimited and
        response.status != 101;
}

fn streamingResponseIsReusable(
    response: StreamingResponse,
    request_method: http1.Method,
) bool {
    return response.keepAlive() and
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
    const bytes = try readRequestMessageBytes(allocator, io, stream, limits);
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    try http1.validateRequestHost(request);
    return .{ .bytes = bytes, .request = request };
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
    try http1.validateRequestHost(request);
    return .{ .bytes = bytes, .request = request };
}

fn readRequestFromTransportBuffered(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    head_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedRequest {
    const bytes = try readMessageBytesBufferedWithContext(
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
    );
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    try http1.validateRequestHost(request);
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
        try ensureResponseHeadDeadlineForBuffer(
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
            true,
            response_head_deadline,
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
    _ = try deadline_policy.usableAwake(io, deadline);
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var informational_count: usize = 0;
    return readResponseFromTransportBufferedForRequestObserved(
        allocator,
        transport,
        limits,
        options,
        &inbuf,
        request_method,
        null,
        &informational_count,
        deadline,
    );
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
    const transport = RuntimeTransport{
        .tcp = .{ .io = io, .stream = stream },
    };
    var informational_count: usize = 0;
    var response_head_deadline: ?std.Io.Clock.Timestamp = null;
    while (true) {
        try ensureResponseHeadDeadlineForBuffer(
            transport,
            limits,
            &.{},
            &response_head_deadline,
        );
        const bytes = try readMessageBytesWithContext(
            allocator,
            transport,
            limits,
            request_method,
            false,
            true,
            response_head_deadline,
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
        try ensureResponseHeadDeadlineForBuffer(
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
        try ensureResponseHeadDeadlineForBuffer(
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
    if (request_method) |method| {
        return http1.parseResponseForRequest(allocator, bytes, options, method) catch |err| switch (err) {
            error.InvalidTransferEncoding => try parseNonChunkedTransferResponse(allocator, bytes, options, method),
            else => |e| return e,
        };
    }
    return http1.parseResponse(allocator, bytes, options) catch |err| switch (err) {
        error.InvalidTransferEncoding => try parseNonChunkedTransferResponse(allocator, bytes, options, null),
        else => |e| return e,
    };
}

fn parseNonChunkedTransferResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
    request_method: ?http1.Method,
) Error!http1.Response {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return error.InvalidTransferEncoding;
    if ((try transferEncodingState(head)) != .non_chunked) return error.InvalidTransferEncoding;

    var sanitized: std.ArrayList(u8) = .empty;
    errdefer sanitized.deinit(allocator);
    try appendHeadWithoutHeaders(&sanitized, allocator, head, &.{ "transfer-encoding", "content-length" });
    try sanitized.appendSlice(allocator, "\r\n\r\n");
    const sanitized_storage = try sanitized.toOwnedSlice(allocator);
    errdefer allocator.free(sanitized_storage);

    var response = if (request_method) |method|
        try http1.parseResponseForRequest(allocator, sanitized_storage, options, method)
    else
        try http1.parseResponse(allocator, sanitized_storage, options);
    errdefer response.deinit(allocator);
    try attachRuntimeHeaderStorage(allocator, &response, sanitized_storage);
    try appendOriginalHeaderLines(allocator, &response, head, "transfer-encoding");

    const body_start = head_end + 4;
    response.body = bytes[body_start..];
    response.body_framing = .close_delimited;
    response.consumed = bytes.len;
    return response;
}

fn attachRuntimeHeaderStorage(allocator: std.mem.Allocator, response: *http1.Response, storage: []u8) Error!void {
    const old = response.header_value_storage;
    const combined = try allocator.alloc([]u8, old.len + 1);
    @memcpy(combined[0..old.len], old);
    combined[old.len] = storage;
    allocator.free(old);
    response.header_value_storage = combined;
}

fn appendOriginalHeaderLines(
    allocator: std.mem.Allocator,
    response: *http1.Response,
    head: []const u8,
    name: []const u8,
) Error!void {
    var count: usize = 0;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) count += 1;
    }
    if (count == 0) return;

    const old = response.headers;
    const combined = try allocator.alloc(http1.Header, old.len + count);
    @memcpy(combined[0..old.len], old);

    var out_index = old.len;
    lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
        const value = wire.trimOws(line[colon + 1 ..]);
        try http1.validateHeader(.{ .name = line[0..colon], .value = value });
        combined[out_index] = .{ .name = line[0..colon], .value = value };
        out_index += 1;
    }
    allocator.free(old);
    response.headers = combined;
}

fn appendHeadWithoutHeaders(list: *std.ArrayList(u8), allocator: std.mem.Allocator, head: []const u8, names: []const []const u8) Error!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.InvalidResponse;
    try list.appendSlice(allocator, status_line);
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            try list.appendSlice(allocator, "\r\n");
            try list.appendSlice(allocator, line);
            continue;
        };
        if (headerNameInList(line[0..colon], names)) continue;
        try list.appendSlice(allocator, "\r\n");
        try list.appendSlice(allocator, line);
    }
}

fn headerNameInList(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
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
        &scratch,
    );
}

fn writeResponseToTransportScratch(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: ResponseOptions,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareResponse(
        allocator,
        options,
        scratch,
    );
    try transport.writeAllParts(parts.header, parts.body);
}

fn writeResponsesToTransportScratch(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    responses: []const ResponseOptions,
    scratch: *WriteScratch,
) Error!void {
    if (responseBatchBodyBytes(responses) > response_batch_borrow_threshold) {
        const parts = try runtime_write.prepareResponseParts(
            allocator,
            responses,
            scratch,
        );
        try transport.writeAllSlices(parts);
        return;
    }
    try writeResponsesCoalesced(
        allocator,
        transport,
        responses,
        scratch,
    );
}

const response_batch_borrow_threshold: usize = 16 * 1024;

fn responseBatchBodyBytes(responses: []const ResponseOptions) usize {
    var total: usize = 0;
    for (responses) |response| total +|= response.body.len;
    return total;
}

fn writeResponsesCoalesced(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    responses: []const ResponseOptions,
    scratch: *WriteScratch,
) Error!void {
    const parts = try runtime_write.prepareResponseParts(
        allocator,
        responses,
        scratch,
    );
    scratch.encoded.clearRetainingCapacity();
    var total: usize = 0;
    for (parts) |part| total +|= part.len;
    try scratch.encoded.ensureTotalCapacity(allocator, total);
    for (parts) |part| scratch.encoded.appendSliceAssumeCapacity(part);
    try transport.writeAll(scratch.encoded.items);
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
    for (response.headers) |header| {
        if (!header.eqlName("connection")) continue;
        if (wire.containsToken(header.value, "close")) return false;
        if (wire.containsToken(header.value, "keep-alive")) return true;
    }
    return response.version == .http_1_1;
}

fn requestOptionsKeepAlive(request: RequestOptions) bool {
    for (request.headers) |header| {
        if (!header.eqlName("connection")) continue;
        if (wire.containsToken(header.value, "close")) return false;
        if (wire.containsToken(header.value, "keep-alive")) return true;
    }
    return request.version == .http_1_1;
}

fn readRequestMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
    const transport = RuntimeTransport{ .tcp = .{ .io = io, .stream = stream } };
    return readMessageBytesWithContext(
        allocator,
        transport,
        limits,
        null,
        true,
        false,
        if (limits.request_head_timeout) |timeout|
            try headReadDeadline(transport, timeout)
        else
            null,
    );
}

fn readMessageBytesWithContext(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    request_method: ?http1.Method,
    auto_continue: bool,
    close_delimited_when_unknown: bool,
    head_deadline: ?std.Io.Clock.Timestamp,
) Error![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = try findHttpHeadEndWithinLimit(bytes.items, limits.max_head_bytes);
    while (head_end == null) {
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
        head_end = try findHttpHeadEndWithinLimit(bytes.items, limits.max_head_bytes);
    }
    try maybeWriteContinue(transport, bytes.items[0..head_end.?], bytes.items.len - (head_end.? + 4), auto_continue);

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(bytes.items[0..head_end.?], request_method)) {
        const body_start = head_end.? + 4;
        while (true) {
            const n = try transport.read(&scratch);
            if (n == 0) break;
            try bytes.appendSlice(allocator, scratch[0..n]);
            if (bytes.items.len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        }
        return bytes.toOwnedSlice(allocator);
    }

    const target_len = while (true) {
        const len = messageTargetLength(bytes.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                if (bytes.items.len >= head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                // Unknown-length bodies such as chunked framing cannot safely
                // batch-read without an inbuf: the next read might cross the
                // terminating chunk into a pipelined message.  Read one byte
                // at a time until the body parser can compute the target.
                const read_buf = scratch[0..1];
                const n = try transport.read(read_buf);
                if (n == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..n]);
                if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
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
        const n = try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
        if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
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
        try ensureResponseHeadDeadlineForBuffer(
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
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
    while (head_end == null) {
        const read_buf = scratch[0..@min(scratch.len, limits.max_head_bytes - inbuf.items.len)];
        const n = if (head_deadline) |deadline|
            try transport.readWithDeadline(read_buf, deadline)
        else
            try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
        head_end = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
    }
    try maybeWriteContinue(transport, inbuf.items[0..head_end.?], inbuf.items.len - (head_end.? + 4), auto_continue);

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

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(inbuf.items[0..head_end.?], request_method)) {
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

    const target_len = if (known_target_len) |len| blk: {
        if (len - (head_end.? + 4) > limits.max_body_bytes) return error.BodyTooLarge;
        break :blk len;
    } else while (true) {
        const len = messageTargetLength(inbuf.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try readTransportUntil(
                    transport,
                    &scratch,
                    body_deadline,
                );
                if (n == 0) return error.ConnectionClosed;
                try inbuf.appendSlice(allocator, scratch[0..n]);
                if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
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
        if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
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
    try std.testing.expectEqual(http1.Method.GET, heads[0].method);
    try std.testing.expectEqualStrings("/one", heads[0].target);
    try std.testing.expectEqual(http1.Method.POST, heads[1].method);
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
            &scratch,
        ),
    );
    // The invalid batch never reaches the transport. Scratch content itself is
    // internal and may be reused/partially encoded for the next attempt.
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

fn messageTargetLength(bytes: []const u8, head_end: usize, max_body_bytes: usize, request_method: ?http1.Method) Error!usize {
    const body_start = head_end + 4;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return body_start;
    switch (try transferEncodingState(head)) {
        .none => {},
        .chunked => return body_start + try chunkedWireLength(bytes[body_start..], max_body_bytes),
        .non_chunked => {
            if (request_method == null) return error.InvalidTransferEncoding;
            return body_start;
        },
    }
    if (try contentLengthFromHead(head)) |len| {
        if (len > max_body_bytes) return error.BodyTooLarge;
        return body_start + len;
    }
    return body_start;
}

fn findHttpHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

const TransferEncodingState = enum { none, chunked, non_chunked };

fn transferEncodingState(head: []const u8) Error!TransferEncodingState {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var saw_non_chunked = false;
    var final_is_chunked = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        saw_transfer_encoding = true;
        var tokens = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (tokens.next()) |raw| {
            const token = wire.trimOws(raw);
            if (token.len == 0) return error.InvalidTransferEncoding;
            const is_chunked = std.ascii.eqlIgnoreCase(token, "chunked");
            if (is_chunked) {
                if (saw_chunked) return error.InvalidTransferEncoding;
                saw_chunked = true;
            } else {
                saw_non_chunked = true;
            }
            final_is_chunked = is_chunked;
        }
    }
    if (!saw_transfer_encoding) return .none;
    if (saw_chunked and final_is_chunked) return .chunked;
    if (saw_non_chunked) return .non_chunked;
    if (saw_chunked) return .non_chunked;
    return error.InvalidTransferEncoding;
}

fn contentLengthFromHead(head: []const u8) Error!?usize {
    var found: ?usize = null;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        var parts = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (parts.next()) |raw_part| {
            const part = wire.trimOws(raw_part);
            if (part.len == 0) return error.InvalidContentLength;
            for (part) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            }
            const parsed = std.fmt.parseInt(usize, part, 10) catch |err| switch (err) {
                error.InvalidCharacter => return error.InvalidContentLength,
                error.Overflow => return error.ContentLengthOverflow,
            };
            if (found) |existing| {
                if (existing != parsed) return error.ConflictingContentLength;
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

fn responseHeadUsesCloseDelimitedBody(head: []const u8, request_method: ?http1.Method) bool {
    if (responseHeadForbidsBody(head, request_method)) return false;
    const te = transferEncodingState(head) catch return false;
    if (te == .chunked) return false;
    if (te == .non_chunked) return true;
    if (findHeaderValue(head, "content-length") != null) return false;
    return true;
}

fn responseHeadForbidsBody(head: []const u8, request_method: ?http1.Method) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return false;
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return false;
    const status_s = parts.next() orelse return false;
    if (status_s.len != 3) return false;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (request_method == null) return false;
    return switch (request_method.?) {
        .HEAD => true,
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

fn informationalResponseToSkip(status: u16) bool {
    // RFC 9110 allows one or more interim 1xx responses before the final
    // response.  101 is deliberately not skipped because it transfers the
    // connection to the upgraded protocol.
    return status >= 100 and status < 200 and status != 101;
}

fn requestShouldSendContinue(head: []const u8) bool {
    if (!requestHeadIsHttp11(head)) return false;
    if (!requestExpectIsOnlyContinue(head)) return false;
    if (!requestHeadHasValidHost(head)) return false;
    return requestHeadHasBody(head);
}

fn requestExpectIsOnlyContinue(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "expect")) continue;
        if (found) return false;
        found = true;
        // Hyper only recognizes an exact 100-continue expectation.  Be equally
        // conservative: comma-separated or unknown expectations require the
        // application to decide, not this auto-continue fast path.
        if (!std.ascii.eqlIgnoreCase(wire.trimOws(line[colon + 1 ..]), "100-continue")) return false;
    }
    return found;
}

fn requestHeadHasValidHost(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "host")) continue;
        if (found) return false;
        found = true;
        http1.validateHostValue(line[colon + 1 ..]) catch return false;
    }
    return found;
}

fn requestHeadIsHttp11(head: []const u8) bool {
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
    return std.mem.endsWith(u8, head[0..first_line_end], " HTTP/1.1");
}

fn requestHeadHasBody(head: []const u8) bool {
    if ((transferEncodingState(head) catch .none) == .chunked) return true;
    if (contentLengthFromHead(head) catch null) |len| return len > 0;
    return false;
}

fn chunkedWireLength(body: []const u8, max_body_bytes: usize) Error!usize {
    var pos: usize = 0;
    var decoded_total: usize = 0;
    var extension_bytes: usize = 0;
    while (true) {
        const line_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = body[pos .. pos + line_end];
        pos += line_end + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        if (semi != line.len) {
            extension_bytes = std.math.add(usize, extension_bytes, line.len - semi) catch return error.ChunkExtensionTooLarge;
            if (extension_bytes > http1.max_chunk_extension_bytes) return error.ChunkExtensionTooLarge;
        }
        const size = try http1.parseChunkSize(line[0..semi]);
        decoded_total = std.math.add(usize, decoded_total, size) catch return error.BodyTooLarge;
        if (decoded_total > max_body_bytes) return error.BodyTooLarge;
        if (size == 0) {
            const trailer_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
            if (trailer_end == 0) return pos + 2;
            const full_end = std.mem.indexOf(u8, body[pos..], "\r\n\r\n") orelse return error.BufferTooShort;
            return pos + full_end + 4;
        }
        if (body.len < pos + size + 2) return error.BufferTooShort;
        pos += size;
        if (!std.mem.eql(u8, body[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }
}

fn findHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return wire.trimOws(line[colon + 1 ..]);
    }
    return null;
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

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
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
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

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

    thread.join();
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
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
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
            try std.testing.expectEqual(http1.Method.CONNECT, request.request.method);
            try std.testing.expectEqualStrings("example.com:443", request.request.target);
            try std.testing.expectEqualStrings("example.com:443", request.request.header("host").?);

            var tunnel = try connection.acceptConnectTunnel(request.request, &.{});
            var buf: [64]u8 = undefined;
            const n = try tunnel.read(&buf);
            try std.testing.expectEqualStrings("client tunnel bytes", buf[0..n]);
            try tunnel.write("server tunnel bytes");
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
    try tunnel.write("client tunnel bytes");
    var buf: [64]u8 = undefined;
    const n = try tunnel.read(&buf);
    try std.testing.expectEqualStrings("server tunnel bytes", buf[0..n]);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(error.MalformedStartLine, client.openConnectTunnel("/not-authority", &.{}));
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
    var preface: [14]u8 = undefined;
    var read: usize = 0;
    while (read < preface.len) {
        const count = try tunnel.read(preface[read..]);
        if (count == 0) return error.ConnectionClosed;
        read += count;
    }
    try std.testing.expectEqualStrings("server-preface", &preface);

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

test "HTTP/1 Linux io_uring server accepts request" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var ring = linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => return error.SkipZigTest,
        else => |e| return e,
    };
    defer ring.deinit();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try LinuxIoUringServer.listen(
        allocator,
        &ring,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{ .reuse_address = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *LinuxIoUringServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *LinuxIoUringServer) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/uring-server", request.request.target);
            try connection.writeResponse(.{
                .body = "uring-server-ok",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/uring-server", .{server.address.ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("uring-server-ok", response.response.body);
}

test "HTTP/1 Linux io_uring client sends request to IP URI" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var ring = linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => return error.SkipZigTest,
        else => |e| return e,
    };
    defer ring.deinit();

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
            try std.testing.expectEqualStrings("/uring-runtime", request.request.target);
            var expected_host: [64]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "127.0.0.1:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{
                .body = "uring-runtime-ok",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/uring-runtime", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriLinuxIoUring(allocator, &ring, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("uring-runtime-ok", response.response.body);
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
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
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

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
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
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    var first = try client.request(.{ .target = "/first", .headers = &keep_alive });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
}

test "HTTP/1 serveConnection adds close for request close" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
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
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const close_header = [_]http1.Header{.{ .name = "Connection", .value = "close" }};
    var response = try client.request(.{ .target = "/close", .headers = &close_header });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("closing", response.response.body);
    try std.testing.expectEqualStrings("close", response.response.header("connection").?);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 serveConnection fixes HTTP/1.0 keep-alive response" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
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
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

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

    thread.join();
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
            try std.testing.expectEqual(http1.Method.HEAD, first.request.method);

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.GET, second.request.method);

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

            try std.testing.expectEqual(http1.Method.POST, request.request.method);
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
            try std.testing.expectEqual(http1.Method.GET, first.request.method);
            try std.testing.expect(first.request.header("content-length") == null);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqual(http1.Method.POST, second.request.method);
            try std.testing.expectEqualStrings("0", second.request.header("content-length").?);

            var third = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer third.deinit(shared.allocator);
            try std.testing.expectEqual(http1.Method.GET, third.request.method);
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

test "HTTP/1 runtime target length rejects ambiguous head framing" {
    const conflicting = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    const conflicting_head_end = std.mem.indexOf(u8, conflicting, "\r\n\r\n").?;
    try std.testing.expectError(error.ConflictingContentLength, messageTargetLength(conflicting, conflicting_head_end, 1024, null));

    const coalesced = "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello";
    const coalesced_head_end = std.mem.indexOf(u8, coalesced, "\r\n\r\n").?;
    try std.testing.expectEqual(coalesced.len, try messageTargetLength(coalesced, coalesced_head_end, 1024, null));

    const signed_length = "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello";
    const signed_length_head_end = std.mem.indexOf(u8, signed_length, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidContentLength, messageTargetLength(signed_length, signed_length_head_end, 1024, null));

    const stacked_te = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const stacked_te_head_end = std.mem.indexOf(u8, stacked_te, "\r\n\r\n").?;
    try std.testing.expectEqual(stacked_te.len, try messageTargetLength(stacked_te, stacked_te_head_end, 1024, null));

    const non_final_chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n";
    const non_final_chunked_head_end = std.mem.indexOf(u8, non_final_chunked, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidTransferEncoding, messageTargetLength(non_final_chunked, non_final_chunked_head_end, 1024, null));

    const signed_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
    const signed_chunk_head_end = std.mem.indexOf(u8, signed_chunk, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidChunk, messageTargetLength(signed_chunk, signed_chunk_head_end, 1024, null));
}

test "HTTP/1 runtime enforces header byte limit at delimiter" {
    const exact = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, exact.len - 4), try findHttpHeadEndWithinLimit(exact, exact.len));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(exact, exact.len - 1));

    const incomplete = "GET / HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(@as(?usize, null), try findHttpHeadEndWithinLimit(incomplete, incomplete.len + 1));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(incomplete, incomplete.len));
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

test {
    _ = @import("runtime/unix_tests.zig");
    _ = @import("runtime/body_reader_tests.zig");
    _ = @import("runtime/body_writer_tests.zig");
    _ = @import("runtime/header_timeout_tests.zig");
    _ = @import("runtime/response_timeout_tests.zig");
    _ = @import("runtime/graceful_shutdown_tests.zig");
    _ = @import("runtime/tls_client_deadline_tests.zig");
    _ = @import("runtime/server_lifecycle_tests.zig");
}
