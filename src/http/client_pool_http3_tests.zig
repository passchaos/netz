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
    var reuse_ticket_cache = try quic.resumption.Cache.init(allocator, 1);
    defer reuse_ticket_cache.deinit();
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
        .max_total_connections = 2,
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
                .auto_resumption = .{
                    .cache = &reuse_ticket_cache,
                    .server_id = "scoped-by-unified-pool",
                    .now_ms = 1500,
                },
            } },
            .idle = .{ .max_idle_per_origin = 1, .max_idle_total = 1 },
            .max_connections = 1,
            .early_data = .{},
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
        if (std.mem.eql(u8, path, "/h3-one")) {
            try reuse_ticket_cache.store(.{
                .server_id = authority,
                .alpn = "h3",
                .ticket = "unused-on-reused-connection",
                .psk = [_]u8{0x30} ** 32,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .age_add = 7,
                .max_early_data_size = quic.resumption.cache.quic_early_data_size,
                .transport_parameters = .fromTransportParameters(
                    quic.practical_transport_parameters,
                ),
            });
        }
        if (std.mem.eql(u8, path, "/h3-two")) {
            try std.testing.expect(response.early_data == null);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
    try std.testing.expectEqual(@as(usize, 2), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(u64, 2), pool.altSvcStats().?.hits);
    try std.testing.expectEqual(
        @as(usize, 1),
        pool.http3RememberedSettingsStats().?.entries,
    );

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

test "unified HTTP pool sends 0-RTT only on a new H3 connection" {
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
    const ticket = "unified-h3-early-ticket";
    const psk = [_]u8{0xf1} ** 32;
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    var ticket_cache = try quic.resumption.Cache.init(allocator, 2);
    defer ticket_cache.deinit();
    const server_cid = [_]u8{
        0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
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
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 41,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "unified-h3-early",
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
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = "discovered",
                .request_method = request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                first.established.early_data_status,
            );
            var learned = try first.receiveRequestWithTimeout(.fromSeconds(5));
            defer learned.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/learn-settings", learned.request.path);
            try std.testing.expect(!learned.was_early_data);
            try first.sendResponse(learned.stream_id, .{
                .status = 200,
                .body = "learned",
                .request_method = learned.request.method,
            });
            first.deinit();

            var second = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.accepted,
                second.established.early_data_status,
            );
            var early = try second.receiveRequestWithTimeout(.fromSeconds(5));
            defer early.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/early", early.request.path);
            try std.testing.expect(early.was_early_data);
            try second.sendResponse(early.stream_id, .{
                .status = 425,
                .request_method = early.request.method,
            });
            var retry = try second.receiveRequestWithTimeout(.fromSeconds(5));
            defer retry.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u62, 4), retry.stream_id);
            try std.testing.expectEqualStrings("/early", retry.request.path);
            try std.testing.expect(!retry.was_early_data);
            try second.sendResponse(retry.stream_id, .{
                .status = 200,
                .body = "retried",
                .request_method = retry.request.method,
            });
            second.deinit();

            self.server.handshake_options.early_data.?.accept = false;
            var third = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer third.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.rejected,
                third.established.early_data_status,
            );
            var replayed = try third.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer replayed.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/transport-rejected",
                replayed.request.path,
            );
            try std.testing.expect(!replayed.was_early_data);
            try third.sendResponse(replayed.stream_id, .{
                .status = 200,
                .body = "transport-replayed",
                .request_method = replayed.request.method,
            });

            self.server.handshake_options.early_data.?.accept = true;
            var fourth = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer fourth.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                fourth.established.early_data_status,
            );
            var unsafe = try fourth.receiveRequestWithTimeout(.fromSeconds(5));
            defer unsafe.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("POST", unsafe.request.method);
            try std.testing.expectEqualStrings("/unsafe", unsafe.request.path);
            try std.testing.expect(!unsafe.was_early_data);
            try fourth.sendResponse(unsafe.stream_id, .{
                .status = 200,
                .body = "ordinary-unsafe",
                .request_method = unsafe.request.method,
            });

            var fifth = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer fifth.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                fifth.established.early_data_status,
            );
            var opted_out = try fifth.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer opted_out.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/opt-out",
                opted_out.request.path,
            );
            try std.testing.expect(!opted_out.was_early_data);
            try fifth.sendResponse(opted_out.stream_id, .{
                .status = 200,
                .body = "ordinary-opt-out",
                .request_method = opted_out.request.method,
            });
        }
    };
    var release: std.Io.Event = .unset;
    var tcp_worker = TcpWorker{
        .server = &tcp_server,
        .alt_svc = alt_svc,
        .release = &release,
    };
    var h3_worker = H3Worker{ .server = &h3_server };
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
        .max_total_connections = 2,
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
                .auto_resumption = .{
                    .cache = &ticket_cache,
                    .server_id = "scoped-by-unified-pool",
                    .now_ms = 1500,
                },
            } },
            .idle = .{ .max_idle_per_origin = 0, .max_idle_total = 0 },
            .max_connections = 1,
            .fallback = .never,
            .early_data = .{},
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(base);

    const discover_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/discover",
        .{base},
    );
    defer allocator.free(discover_uri);
    var discovery = try pool.requestUriWithTimeout(
        discover_uri,
        .{},
        .fromSeconds(5),
    );
    discovery.deinit();

    const learn_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/learn-settings",
        .{base},
    );
    defer allocator.free(learn_uri);
    var learned = try pool.requestUriWithTimeout(
        learn_uri,
        .{},
        .fromSeconds(5),
    );
    try std.testing.expectEqual(http.Protocol.http3, learned.protocol());
    try std.testing.expect(learned.early_data == null);
    learned.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        pool.http3RememberedSettingsStats().?.entries,
    );

    const authority = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(authority);
    try ticket_cache.store(.{
        .server_id = authority,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });

    const early_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/early",
        .{base},
    );
    defer allocator.free(early_uri);
    var response = pool.requestUriWithTimeout(
        early_uri,
        .{},
        .fromSeconds(5),
    ) catch |err| {
        release.set(io);
        tcp_thread.join();
        tcp_joined = true;
        h3_thread.join();
        h3_joined = true;
        if (h3_worker.err) |server_err| return server_err;
        return err;
    };
    try std.testing.expectEqual(http.Protocol.http3, response.protocol());
    try std.testing.expectEqualStrings("retried", response.body());
    try std.testing.expectEqual(
        http3_runtime.EarlyRequestDisposition.accepted,
        response.early_data.?.disposition,
    );
    try std.testing.expectEqual(
        http3_runtime.EarlyDataRetryReason.too_early,
        response.early_data.?.retry_reason,
    );
    response.deinit();

    try ticket_cache.store(.{
        .server_id = authority,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    const rejected_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/transport-rejected",
        .{base},
    );
    defer allocator.free(rejected_uri);
    var rejected = pool.requestUriWithTimeout(
        rejected_uri,
        .{},
        .fromSeconds(5),
    ) catch |err| {
        release.set(io);
        tcp_thread.join();
        tcp_joined = true;
        h3_thread.join();
        h3_joined = true;
        if (h3_worker.err) |server_err| return server_err;
        return err;
    };
    try std.testing.expectEqualStrings("transport-replayed", rejected.body());
    try std.testing.expectEqual(
        http3_runtime.EarlyRequestDisposition.rejected,
        rejected.early_data.?.disposition,
    );
    try std.testing.expectEqual(
        http3_runtime.EarlyDataRetryReason.early_data_rejected,
        rejected.early_data.?.retry_reason,
    );
    rejected.deinit();

    try ticket_cache.store(.{
        .server_id = authority,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    const unsafe_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/unsafe",
        .{base},
    );
    defer allocator.free(unsafe_uri);
    var unsafe = try pool.requestUriWithTimeout(
        unsafe_uri,
        .{ .method = "POST", .body = "unsafe-body" },
        .fromSeconds(5),
    );
    defer unsafe.deinit();
    try std.testing.expectEqualStrings("ordinary-unsafe", unsafe.body());
    try std.testing.expect(unsafe.early_data == null);

    try ticket_cache.store(.{
        .server_id = authority,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    const opt_out_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/opt-out",
        .{base},
    );
    defer allocator.free(opt_out_uri);
    var opted_out = try pool.requestUriWithTimeout(
        opt_out_uri,
        .{ .allow_early_data = false },
        .fromSeconds(5),
    );
    defer opted_out.deinit();
    try std.testing.expectEqualStrings("ordinary-opt-out", opted_out.body());
    try std.testing.expect(opted_out.early_data == null);

    release.set(io);
    tcp_thread.join();
    tcp_joined = true;
    h3_thread.join();
    h3_joined = true;
    if (tcp_worker.err) |err| return err;
    if (h3_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 5), h3_worker.accepts);
}

test "unified HTTP pool global budget rebalances TCP and HTTP3 idle" {
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
    var return_server = try http1_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity, .alpn_protocols = &.{"http/1.1"} },
    );
    defer return_server.deinit();
    const h3_limits: http3_runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
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

    const Worker = struct {
        server: *http1_runtime.TlsServer,
        alt_svc: []const u8,
        release: *std.Io.Event,
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
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/discover",
                request.request.target,
            );
            try connection.writeResponse(.{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = "discovered",
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        expected_authority: []const u8,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                self.expected_authority,
                request.request.authority.?,
            );
            try std.testing.expectEqualStrings(
                "/migrated-h3",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .request_method = request.request.method,
                .body = "migrated",
            });
            self.requests += 1;
        }
    };
    const ReturnWorker = struct {
        server: *http1_runtime.TlsServer,
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
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/returned-tcp",
                request.request.target,
            );
            try connection.writeResponse(.{
                .body = "returned",
                .request_method = request.request.method,
            });
            self.requests += 1;
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
    const h3_thread = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker});
    var h3_joined = false;
    defer if (!h3_joined) h3_thread.join();
    var return_worker = ReturnWorker{ .server = &return_server };
    const return_thread = try std.Thread.spawn(
        .{},
        ReturnWorker.run,
        .{&return_worker},
    );
    var return_joined = false;
    defer if (!return_joined) return_thread.join();

    var pool = try http.Pool.init(allocator, io, .{
        .max_total_connections = 1,
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
        .http3 = .{
            .limits = h3_limits,
            .handshake = .{
                .connect_timeout = .fromSeconds(1),
                .handshake = .{
                    .original_destination_connection_id = &.{},
                    .local_connection_id = &.{},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = public_key,
                    },
                },
            },
            .idle = .{ .max_idle_per_origin = 1, .max_idle_total = 1 },
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(base);
    const discover_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/discover",
        .{base},
    );
    defer allocator.free(discover_uri);
    var discovered = try pool.requestUriWithTimeout(
        discover_uri,
        .{},
        .fromSeconds(2),
    );
    defer discovered.deinit();
    try std.testing.expectEqual(http.Protocol.http1, discovered.protocol());
    try std.testing.expectEqualStrings("discovered", discovered.body());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());

    const migrated_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/migrated-h3",
        .{base},
    );
    defer allocator.free(migrated_uri);
    var migrated = try pool.requestUriWithTimeout(
        migrated_uri,
        .{},
        .fromSeconds(2),
    );
    defer migrated.deinit();
    try std.testing.expectEqual(http.Protocol.http3, migrated.protocol());
    try std.testing.expectEqualStrings("migrated", migrated.body());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.totalWaitingCount());
    try std.testing.expectEqual(@as(u64, 0), pool.altSvcStats().?.failures);

    const return_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/returned-tcp",
        .{return_server.address().ip4.port},
    );
    defer allocator.free(return_uri);
    var returned = try pool.requestUriWithTimeout(
        return_uri,
        .{},
        .fromSeconds(2),
    );
    defer returned.deinit();
    try std.testing.expectEqual(http.Protocol.http1, returned.protocol());
    try std.testing.expectEqualStrings("returned", returned.body());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.http3IdleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.totalWaitingCount());

    release.set(io);
    thread.join();
    joined = true;
    h3_thread.join();
    h3_joined = true;
    return_thread.join();
    return_joined = true;
    if (worker.err) |err| return err;
    if (h3_worker.err) |err| return err;
    if (return_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), h3_worker.requests);
    try std.testing.expectEqual(@as(usize, 1), return_worker.requests);
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
