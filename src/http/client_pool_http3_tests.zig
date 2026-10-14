const std = @import("std");
const http = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2_runtime = @import("../http2/runtime.zig");
const http3_runtime = @import("../http3/runtime.zig");
const quic = @import("../quic/mod.zig");
const tls_testing = @import("../tls/testing.zig");

test "unified HTTP pool learns Alt-Svc then reuses HTTP3" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const identity: @FieldType(http1_runtime.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    var tcp_server = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_server.deinit();
    const h3_limits: http3_runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    var h3_server = try http3_runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h3_limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer h3_server.deinit();
    const alt_svc = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{h3_server.address().ip4.port},
    );
    defer allocator.free(alt_svc);

    const TcpWorker = struct {
        server: *http2_runtime.TlsServer,
        alt_svc: []const u8,
        release: *std.Io.Event,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/discover",
                request.path,
            );
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = "tcp-discovery",
                .request_method = request.method,
            });
            self.requests += 1;
            try self.release.wait(self.server.io);
        }
    };
    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        expected_authority: []const u8,
        accepts: usize = 0,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            self.accepts += 1;
            defer session.deinit();
            for (0..2) |index| {
                var request = try session.receiveRequest();
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    self.expected_authority,
                    request.request.authority.?,
                );
                try std.testing.expectEqualStrings(
                    if (index == 0) "/h3-one" else "/h3-two",
                    request.request.path,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .request_method = request.request.method,
                    .body = if (index == 0) "h3-one" else "h3-two",
                });
                self.requests += 1;
            }
        }
    };
    var release: std.Io.Event = .unset;
    var tcp_worker = TcpWorker{
        .server = &tcp_server,
        .alt_svc = alt_svc,
        .release = &release,
    };
    const authority = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(authority);
    var h3_worker = H3Worker{
        .server = &h3_server,
        .expected_authority = authority,
    };
    const tcp_thread = try std.Thread.spawn(.{}, TcpWorker.run, .{&tcp_worker});
    var tcp_joined = false;
    defer if (!tcp_joined) {
        release.set(io);
        tcp_thread.join();
    };
    const h3_thread = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker});
    var h3_joined = false;
    defer if (!h3_joined) h3_thread.join();

    var pool = try http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
        .http3 = .{
            .limits = h3_limits,
            .handshake = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            } },
            .idle = .{ .max_idle_per_origin = 1, .max_idle_total = 1 },
            .max_connections = 1,
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(base);
    const paths = [_][]const u8{ "/discover", "/h3-one", "/h3-two" };
    const protocols = [_]http.Protocol{ .http2, .http3, .http3 };
    const bodies = [_][]const u8{ "tcp-discovery", "h3-one", "h3-two" };
    for (paths, protocols, bodies) |path, protocol, body| {
        const uri = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, path });
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(5),
        );
        defer response.deinit();
        try std.testing.expectEqual(protocol, response.protocol());
        try std.testing.expectEqualStrings(body, response.body());
    }
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
    try std.testing.expectEqual(@as(u64, 2), pool.altSvcStats().?.hits);

    release.set(io);
    tcp_thread.join();
    tcp_joined = true;
    h3_thread.join();
    h3_joined = true;
    if (tcp_worker.err) |err| return err;
    if (h3_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), tcp_worker.requests);
    try std.testing.expectEqual(@as(usize, 1), h3_worker.accepts);
    try std.testing.expectEqual(@as(usize, 2), h3_worker.requests);
}

test "unified HTTP pool backs off failed HTTP3 and preserves TCP reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const identity: @FieldType(http1_runtime.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    var tcp_server = try http1_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity, .alpn_protocols = &.{"http/1.1"} },
    );
    defer tcp_server.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    const alt_svc = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{silent.address().ip4.port},
    );
    defer allocator.free(alt_svc);

    const Worker = struct {
        server: *http1_runtime.TlsServer,
        alt_svc: []const u8,
        release: *std.Io.Event,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for (0..3) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqual(
                    http1.Method.GET,
                    request.request.method,
                );
                try connection.writeResponse(.{
                    .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                    .body = switch (index) {
                        0 => "discover",
                        1 => "fallback",
                        else => "backoff",
                    },
                    .request_method = request.request.method,
                });
                self.requests += 1;
            }
            try self.release.wait(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var worker = Worker{
        .server = &tcp_server,
        .alt_svc = alt_svc,
        .release = &release,
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        thread.join();
    };

    var pool = try http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
        .http3 = .{
            .handshake = .{
                .connect_timeout = .fromMilliseconds(20),
                .handshake = .{
                    .original_destination_connection_id = &.{},
                    .local_connection_id = &.{},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = public_key,
                    },
                    .handshake_recovery = .{
                        .initial_pto_ms = 1000,
                        .max_pto_ms = 4000,
                        .max_retries = 3,
                    },
                },
            },
            .alt_svc = .{
                .failure_backoff_initial = .fromMilliseconds(1),
                .failure_backoff_max = .fromMilliseconds(10),
            },
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(base);
    {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}/request-0",
            .{base},
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(2),
        );
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http1, response.protocol());
        try std.testing.expectEqualStrings("discover", response.body());
    }
    const unsafe_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/unsafe",
        .{base},
    );
    defer allocator.free(unsafe_uri);
    try std.testing.expectError(
        error.HandshakeTimeout,
        pool.requestUriWithTimeout(
            unsafe_uri,
            .{ .method = "POST", .body = "do-not-replay" },
            .fromSeconds(2),
        ),
    );
    try std.Io.sleep(io, .fromMilliseconds(5), .awake);

    const expected = [_][]const u8{ "fallback", "backoff" };
    for (expected, 1..) |body, index| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}/request-{d}",
            .{ base, index },
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(2),
        );
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http1, response.protocol());
        try std.testing.expectEqualStrings(body, response.body());
    }
    const stats = pool.altSvcStats().?;
    try std.testing.expectEqual(@as(u64, 2), stats.failures);
    try std.testing.expectEqual(@as(u64, 1), stats.backoff_suppressed);
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), worker.requests);
}
