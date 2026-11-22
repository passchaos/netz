//! Ordered protocol feasibility never replays an application request.
const std = @import("std");
const http = @import("../mod.zig");
const h1 = @import("../../http1/runtime.zig");
const h2 = @import("../../http2/runtime.zig");
const h3 = @import("../../http3/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const socks = @import("../../proxy/socks/server.zig");
const backends = @import("../../runtime.zig");
const selection = @import("../client/protocol_selection.zig");
const allocator = std.testing.allocator;

const Credentials = struct {
    certificate: [tls_testing.certificate_der_len]u8,
    chain: [1][]const u8,
    key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,

    fn init() !Credentials {
        var self: Credentials = undefined;
        try std.base64.standard.Decoder.decode(&self.certificate, tls_testing.certificate_base64);
        self.key = try tls_testing.serverKeyPair();
        return self;
    }

    fn identity(self: *Credentials) @FieldType(h1.TlsListenOptions, "identity") {
        self.chain[0] = &self.certificate;
        return .{ .certificate_chain = &self.chain, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } } };
    }

    fn options(self: *const Credentials, policy: http.ProtocolPolicy) http.ClientOptions {
        return .{ .protocol_policy = policy, .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.key.public_key.toUncompressedSec1() } }, .http3 = .{ .limits = .{ .quic = .{ .max_datagram_size = 4096 } }, .preference_timeout = .fromMilliseconds(100) } };
    }

    fn bind(self: *Credentials, io: std.Io) !h3.HandshakeServer {
        return h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .quic = .{ .max_datagram_size = 4096 } }, .{ .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = self.identity() } });
    }
};

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

fn fallback(io: std.Io, comptime http2: bool, comptime pooled: bool, comptime tight: bool) !void {
    var credentials = try Credentials.init();
    // The UDP endpoint deliberately sends no handshake response.
    var blackhole = try credentials.bind(io);
    defer blackhole.deinit();
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(blackhole.address().getPort()) };
    var server = if (http2)
        try h2.TlsServer.listen(allocator, io, address, .{ .identity = credentials.identity() })
    else
        try h1.TlsServer.listen(allocator, io, address, .{ .identity = credentials.identity(), .alpn_protocols = &.{"http/1.1"} });
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *@TypeOf(server), done: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            for (0..if (pooled) @as(usize, 2) else 1) |index| {
                const until = deadline(listener.io);
                var request = if (http2) try connection.readRequestWithDeadline(until) else try connection.readRequestWithDeadline(.{}, until);
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(if (index == 0) "payload" else "", if (http2) request.body else request.request.body);
                if (http2) try connection.writeResponseWithDeadline(request.stream_id, .{ .body = "tcp" }, until) else try connection.writeResponseWithDeadline(.{ .body = "tcp" }, until);
            }
            try done.wait(listener.io);
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, &release });
    defer _ = peer.cancel(io) catch {};
    defer release.set(io);
    var options = credentials.options(.prefer_http3);
    if (tight) options.http3.preference_timeout = .fromSeconds(5);
    var client = if (pooled) try http.Pool.init(allocator, io, .{ .max_connections = 1, .client = options }) else try http.Client.init(allocator, io, options);
    defer client.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/fallback", .{address.getPort()});
    defer allocator.free(uri);
    var reader = std.Io.Reader.fixed("payload");
    const until = if (tight) std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(700) }) else deadline(io);
    var response = try client.requestUriWithDeadline(uri, .{ .method = "POST", .body = "wrong", .body_source = .{ .reader = .{ .reader = &reader, .length = 7 } } }, until);
    defer response.deinit();
    try std.testing.expectEqual(if (http2) http.Protocol.http2 else .http1, response.protocol());
    try std.testing.expectEqualStrings("tcp", response.body());
    try std.testing.expectEqual(@as(usize, 7), reader.seek);
    if (pooled) {
        var later = try client.requestUri(uri, .{});
        defer later.deinit();
        try std.testing.expectEqual(response.protocol(), later.protocol());
        try std.testing.expectEqual(@as(usize, 1), client.connectionCount());
    }
    release.set(io);
    try peer.await(io);
}

test "unified HTTP protocol policy falls back H3 to H2 H1 before consuming a single-pass POST Reader" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try fallback(threaded.io(), true, false, false);
    try fallback(threaded.io(), false, false, false);
    try fallback(threaded.io(), true, true, false);
    try fallback(threaded.io(), false, true, false);
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    try fallback(backend.io(), true, false, false);
    try fallback(backend.io(), false, false, false);
    try fallback(backend.io(), true, true, false);
    try fallback(backend.io(), false, true, false);
}

test "unified HTTP protocol policy reserves the caller deadline for TCP fallback" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try fallback(threaded.io(), true, false, true);
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    try fallback(backend.io(), true, false, true);
}

fn pooledHttp3(io: std.Io, comptime policy: http.ProtocolPolicy) !void {
    var credentials = try Credentials.init();
    var server = try credentials.bind(io);
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *h3.HandshakeServer, task_io: std.Io, done: *std.Io.Event) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            for (0..3) |index| {
                var request = try session.receiveRequestWithDeadline(deadline(task_io));
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(if (index == 0) "payload" else if (index == 1) "stream" else "", request.request.body);
                try session.sendResponse(request.stream_id, .{ .status = 200, .body = "quic" });
            }
            try done.wait(task_io);
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io, &release });
    defer _ = peer.cancel(io) catch {};
    defer release.set(io);
    var pool = try http.Pool.init(allocator, io, .{ .max_connections = 1, .max_total_connections = 1, .client = credentials.options(policy) });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/h3", .{server.address().getPort()});
    defer allocator.free(uri);
    var reader = std.Io.Reader.fixed("payload");
    var response = try pool.requestUriWithDeadline(uri, .{ .method = "POST", .body_source = .{ .reader = .{ .reader = &reader } } }, deadline(io));
    defer response.deinit();
    try std.testing.expectEqual(http.Protocol.http3, response.protocol());
    try std.testing.expectEqualStrings("quic", response.body());
    {
        var handle = try pool.startRequestWithDeadline(uri, .{ .method = "POST", .body_length = .unknown }, deadline(io));
        defer handle.deinit();
        try std.testing.expectEqual(http.Protocol.http3, handle.protocol());
        try handle.writeBody("stream");
        try handle.finishBody();
        _ = try handle.readResponseWithDeadline(http.ResponseSink.discard(), deadline(io));
    }
    var lease = try pool.acquireUriWithDeadline(uri, deadline(io));
    defer if (lease.active) lease.discard();
    try std.testing.expect(lease.was_reused);
    try std.testing.expectEqual(http.Protocol.http3, lease.protocol());
    var last = try lease.connection().requestWithDeadline("/lease", .{}, deadline(io));
    defer last.deinit();
    lease.release();
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());
    release.set(io);
    try peer.await(io);
}

test "unified HTTP protocol policy pools direct H3 requests streams and raw leases" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try pooledHttp3(threaded.io(), .prefer_http3);
    try pooledHttp3(threaded.io(), .http3_only);
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    try pooledHttp3(backend.io(), .prefer_http3);
    try pooledHttp3(backend.io(), .http3_only);
}

test "unified HTTP protocol policy preserves certificate rejection configuration and cancellation errors" {
    try std.testing.expect(selection.unavailable(error.Timeout));
    try std.testing.expect(!selection.unavailable(error.CertificateUntrusted));
    try std.testing.expect(!selection.unavailable(error.Canceled));
    try std.testing.expect(!selection.unavailable(error.OutOfMemory));
    // A proxy that cannot relay UDP still supports the TCP fallback.
    try std.testing.expect(selection.unavailable(error.ProxyCommandUnsupported));
    try std.testing.expect(selection.unavailable(error.ProxyConnectionNotAllowed));
    try std.testing.expect(selection.unavailable(error.ProxyInvalidRelayAddress));
    // Proxy credentials and reachability are not protocol-selection signals.
    try std.testing.expect(!selection.unavailable(error.ProxyAuthenticationFailed));
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var credentials = try Credentials.init();
    var server = try credentials.bind(io);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *h3.HandshakeServer) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
        }
    };
    var peer = try io.concurrent(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var options = credentials.options(.prefer_http3);
    options.http3.preference_timeout = .fromSeconds(3);
    var wrong_pin = credentials.key.public_key.toUncompressedSec1();
    wrong_pin[1] ^= 1;
    options.tls.server_verifier = .{ .pinned_ecdsa_p256_public_key = wrong_pin };
    var client = try http.Client.init(allocator, io, options);
    defer client.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/", .{server.address().getPort()});
    defer allocator.free(uri);
    try std.testing.expectError(error.CertificateUntrusted, client.connectUriWithDeadline(uri, deadline(io)));
    options.http3.preference_timeout = .zero;
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, io, options));
}

fn canceledSelection(io: std.Io, comptime pooled: bool) !void {
    const Resolver = struct {
        io: std.Io,
        started: std.Io.Event = .unset,
        never: std.Io.Event = .unset,
        calls: usize = 0,
        canceled: bool = false,

        fn resolve(context: *anyopaque, _: std.mem.Allocator, _: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.started.set(self.io);
            self.never.wait(self.io) catch {
                self.canceled = true;
                return error.Canceled;
            };
            return error.UnknownHostName;
        }
    };
    var resolver = Resolver{ .io = io };
    var credentials = try Credentials.init();
    var options = credentials.options(.prefer_http3);
    options.http3.preference_timeout = .fromSeconds(5);
    options.address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve };
    var client = if (pooled) try http.Pool.init(allocator, io, .{ .client = options }) else try http.Client.init(allocator, io, options);
    defer client.deinit();
    var reader = std.Io.Reader.fixed("payload");
    const Caller = struct {
        fn run(owner: *@TypeOf(client), body: *std.Io.Reader, task_io: std.Io) !void {
            var response = try owner.requestUriWithDeadline("https://blocked.invalid/", .{ .method = "POST", .body_source = .{ .reader = .{ .reader = body } } }, deadline(task_io));
            defer response.deinit();
        }
    };
    var call = try io.concurrent(Caller.run, .{ &client, &reader, io });
    defer _ = call.cancel(io) catch {};
    try resolver.started.waitTimeout(io, .{ .deadline = deadline(io) });
    try std.testing.expectError(error.Canceled, call.cancel(io));
    try std.testing.expect(resolver.canceled);
    try std.testing.expectEqual(@as(usize, 1), resolver.calls);
    try std.testing.expectEqual(@as(usize, 0), reader.seek);
}

test "unified HTTP protocol policy joins canceled feasibility without TCP fallback or body reads" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try canceledSelection(threaded.io(), false);
    try canceledSelection(threaded.io(), true);
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    try canceledSelection(backend.io(), false);
    try canceledSelection(backend.io(), true);
}

test "unified HTTP prefer_http3 falls back to TCP when SOCKS5 denies UDP" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var credentials = try Credentials.init();
    var server = try h2.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = credentials.identity() },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *h2.TlsServer) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var request = try connection.readRequestWithDeadline(
                deadline(listener.io),
            );
            defer request.deinit(listener.allocator);
            try connection.writeResponse(request.stream_id, .{
                .body = "tcp-fallback",
                .request_method = request.method,
            });
        }
    };
    var peer = try io.concurrent(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};

    var proxy = try socks.Server.init(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .auth = .{ .allow_anonymous = true },
            .acl = .{ .default_action = .allow },
            .allow_udp = false,
        },
    );
    defer proxy.deinit();
    const Serve = struct {
        fn run(proxy_server: *socks.Server) !void {
            try proxy_server.serve();
        }
    };
    var proxy_loop = try io.concurrent(Serve.run, .{&proxy});
    defer _ = proxy_loop.cancel(io) catch {};

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/fallback",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var options = credentials.options(.prefer_http3);
    options.socks5_proxy = .{
        .host = "127.0.0.1",
        .port = proxy.listener.socket.address.ip4.port,
    };
    var client = try http.Client.init(allocator, io, options);
    defer client.deinit();
    var response = try client.requestUriWithDeadline(uri, .{}, deadline(io));
    defer response.deinit();
    try std.testing.expectEqual(http.Protocol.http2, response.protocol());
    try std.testing.expectEqualStrings("tcp-fallback", response.body());
    try peer.await(io);
}

test "unified HTTP protocol policy skips ineligible H3 without starting I/O" {
    const secure = try std.Uri.parse("https://127.0.0.1/");
    const cleartext = try std.Uri.parse("http://127.0.0.1/");
    var options: http.ClientOptions = .{ .protocol_policy = .prefer_http3 };
    try std.testing.expect((try selection.selectHttp3(allocator, std.Io.failing, cleartext, options, null)) == null);
    options.http_proxy = .{ .uri = "http://127.0.0.1:8080" };
    try std.testing.expect((try selection.selectHttp3(allocator, std.Io.failing, secure, options, null)) == null);
    options.http_proxy = null;
    options.tls.protocol_policy = .tls12_only;
    try std.testing.expect((try selection.selectHttp3(allocator, std.Io.failing, secure, options, null)) == null);
    options.tls.protocol_policy = .tls12_and_tls13;
    // SOCKS5 keeps H3 eligible: the proxy carries UDP and resolves the origin
    // domain, so only an HTTP CONNECT proxy or TLS 1.2-only policy skips H3.
    options.socks5_proxy = .{ .host = "localhost" };
    var socks_client = try http.Client.init(allocator, std.Io.failing, .{
        .protocol_policy = .http3_only,
        .socks5_proxy = .{ .host = "localhost" },
    });
    socks_client.deinit();
    options.socks5_proxy = null;
    options.protocol_policy = .http3_only;
    try std.testing.expectError(error.UnsupportedScheme, selection.selectHttp3(allocator, std.Io.failing, cleartext, options, null));
    options.tls.protocol_policy = .tls12_only;
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, std.Io.failing, options));
}
