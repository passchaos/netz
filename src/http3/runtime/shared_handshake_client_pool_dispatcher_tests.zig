const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared endpoint dispatcher drives routes and isolated deadlines" {
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
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const cid_a = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const cid_b = [_]u8{ 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0 };
    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &cid_a,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &cid_b,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_b.deinit();

    var slow_received: std.Io.Event = .unset;
    var release_slow: std.Io.Event = .unset;
    const WorkerA = struct {
        server: *runtime.HandshakeServer,
        slow_received: *std.Io.Event,
        release_slow: *std.Io.Event,
        accepts: usize = 0,
        client_address: ?std.Io.net.IpAddress = null,
        stream_ids: [3]u62 = .{ 0, 0, 0 },
        cancellation_code: ?u64 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();
            var slow = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer slow.deinit(self.server.allocator);
            self.client_address = slow.from;
            self.stream_ids[0] = slow.stream_id;
            try std.testing.expectEqualStrings("/slow", slow.request.path);
            self.slow_received.set(self.server.quic_server.endpoint.io);
            try self.release_slow.waitTimeout(
                self.server.quic_server.endpoint.io,
                .{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(5),
                } },
            );
            try session.sendResponse(slow.stream_id, .{
                .status = 201,
                .request_method = slow.request.method,
                .body = "slow",
            });

            var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(self.server.allocator);
            var second = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer second.deinit(self.server.allocator);
            self.stream_ids[1] = first.stream_id;
            self.stream_ids[2] = second.stream_id;
            const timed, const sibling = if (std.mem.eql(
                u8,
                first.request.path,
                "/timeout",
            ) and std.mem.eql(u8, second.request.path, "/sibling"))
                .{ &first, &second }
            else if (std.mem.eql(u8, first.request.path, "/sibling") and
                std.mem.eql(u8, second.request.path, "/timeout"))
                .{ &second, &first }
            else
                return error.TestUnexpectedResult;
            const cancellation = try session
                .receivePeerResponseCancellationWithTimeout(
                timed.stream_id,
                .fromSeconds(5),
            );
            self.cancellation_code = cancellation.application_error_code;
            try session.sendResponse(sibling.stream_id, .{
                .status = 202,
                .request_method = sibling.request.method,
                .body = "sibling",
            });
        }
    };
    const WorkerB = struct {
        server: *runtime.HandshakeServer,
        accepts: usize = 0,
        client_address: ?std.Io.net.IpAddress = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            self.client_address = request.from;
            try std.testing.expectEqualStrings("/fast", request.request.path);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .request_method = request.request.method,
                .body = "fast",
            });
        }
    };
    var worker_a = WorkerA{
        .server = &server_a,
        .slow_received = &slow_received,
        .release_slow = &release_slow,
    };
    var worker_b = WorkerB{ .server = &server_b };
    const thread_a = try std.Thread.spawn(.{}, WorkerA.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, WorkerB.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 2,
        },
        .max_connections = 2,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 4096,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    var dispatcher = try runtime.SharedHandshakeClientPoolRequestDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_active_connections = 2 },
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();
    var driver = try std.Io.concurrent(
        io,
        runtime.SharedHandshakeClientPoolRequestDispatcher.run,
        .{&dispatcher},
    );
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
        driver.await(io) catch {};
    };

    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b);
    const slow_uri = try std.fmt.allocPrint(allocator, "{s}/slow", .{uri_a});
    defer allocator.free(slow_uri);
    const fast_uri = try std.fmt.allocPrint(allocator, "{s}/fast", .{uri_b});
    defer allocator.free(fast_uri);
    const timeout_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/timeout",
        .{uri_a},
    );
    defer allocator.free(timeout_uri);
    const sibling_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/sibling",
        .{uri_a},
    );
    defer allocator.free(sibling_uri);

    const Producer = struct {
        fn response(
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
            status: u16,
            body: []const u8,
            request_timeout: std.Io.Duration,
        ) !void {
            var value = try request_sender.requestWithTimeout(
                uri,
                .{},
                request_timeout,
            );
            defer value.deinit();
            try std.testing.expectEqual(status, value.response.status);
            try std.testing.expectEqualStrings(body, value.response.body);
        }

        fn timed(
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
        ) !void {
            var value = request_sender.requestWithTimeout(
                uri,
                .{},
                .fromMilliseconds(500),
            ) catch |err| {
                try std.testing.expectEqual(error.Timeout, err);
                return;
            };
            value.deinit();
            return error.TestUnexpectedResult;
        }
    };
    var slow = try std.Io.concurrent(
        io,
        Producer.response,
        .{ sender.clone(), slow_uri, @as(u16, 201), "slow", .fromSeconds(5) },
    );
    var slow_active = true;
    defer if (slow_active) {
        release_slow.set(io);
        slow.cancel(io) catch {};
    };
    try slow_received.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });
    var fast = try std.Io.concurrent(
        io,
        Producer.response,
        .{ sender.clone(), fast_uri, @as(u16, 200), "fast", .fromSeconds(2) },
    );
    try fast.await(io);
    release_slow.set(io);
    try slow.await(io);
    slow_active = false;

    var start_cancel: std.Io.Event = .unset;
    const CancelProducer = struct {
        fn timed(
            start: *std.Io.Event,
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
        ) !void {
            try start.wait(io_value);
            return Producer.timed(request_sender, uri);
        }

        fn sibling(
            start: *std.Io.Event,
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
        ) !void {
            try start.wait(io_value);
            return Producer.response(
                request_sender,
                uri,
                202,
                "sibling",
                .fromSeconds(5),
            );
        }
    };
    var timed = try std.Io.concurrent(
        io,
        CancelProducer.timed,
        .{ &start_cancel, io, sender.clone(), timeout_uri },
    );
    var sibling = try std.Io.concurrent(
        io,
        CancelProducer.sibling,
        .{ &start_cancel, io, sender.clone(), sibling_uri },
    );
    start_cancel.set(io);
    try timed.await(io);
    try sibling.await(io);

    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), worker_a.accepts);
    try std.testing.expectEqual(@as(usize, 1), worker_b.accepts);
    try std.testing.expectEqual(worker_a.client_address, worker_b.client_address);
    try std.testing.expectEqual([3]u62{ 0, 4, 8 }, worker_a.stream_ids);
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.request_cancelled),
        worker_a.cancellation_code,
    );
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
}

const SharedEarlyScenario = struct {
    reject_early_data: bool = false,
    silent_first: bool = false,
    initial_status: u16 = 425,
    retry_status: u16 = 201,
};

fn runSharedEarlyScenario(scenario: SharedEarlyScenario) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "shared-endpoint-early-ticket";
    const psk = [_]u8{0xc1} ** 32;
    const server_id = "localhost:9443";
    var cache = try quic.resumption.Cache.init(allocator, 2);
    defer cache.deinit();
    try cache.store(.{
        .server_id = server_id,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1_000,
        .lifetime_seconds = 3_600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9 };
    var server_options = runtime.HandshakeServerOptions{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xca} ** 32,
            .x25519_secret_key = [_]u8{0xcb} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 41,
                .issued_at_ms = 1_000,
                .lifetime_seconds = 3_600,
                .now_ms = 1_500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "shared-endpoint-early-request",
            },
        },
    };
    if (scenario.reject_early_data) {
        server_options.handshake.cipher_suites =
            &.{.chacha20_poly1305_sha256};
    }
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        server_options,
    );
    defer server.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{},
    );
    defer silent.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        scenario: SharedEarlyScenario,
        client_port: ?u16 = null,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn expectRequest(
            self: *@This(),
            request: *const runtime.OwnedHandshakeRequest,
            expected_stream_id: u62,
            expected_early: bool,
        ) !void {
            try std.testing.expectEqual(expected_stream_id, request.stream_id);
            try std.testing.expectEqual(expected_early, request.was_early_data);
            try std.testing.expectEqualStrings(
                "/shared-early",
                request.request.path,
            );
            try std.testing.expectEqualStrings(
                "shared request body",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "complete",
                request.request.trailers[0].value,
            );
            self.requests += 1;
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            try std.testing.expectEqual(
                if (self.scenario.silent_first)
                    quic.zero_rtt.handshake.Status.not_offered
                else if (self.scenario.reject_early_data)
                    quic.zero_rtt.handshake.Status.rejected
                else
                    quic.zero_rtt.handshake.Status.accepted,
                session.established.early_data_status,
            );
            var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(self.server.allocator);
            self.client_port = switch (first.from) {
                .ip4 => |address| address.port,
                .ip6 => |address| address.port,
            };
            try self.expectRequest(
                &first,
                0,
                !self.scenario.reject_early_data and
                    !self.scenario.silent_first,
            );
            if (self.scenario.reject_early_data) {
                try session.sendResponse(first.stream_id, .{
                    .status = self.scenario.retry_status,
                    .request_method = first.request.method,
                    .body = "rejected replay",
                });
            } else {
                try session.sendResponse(first.stream_id, .{
                    .status = self.scenario.initial_status,
                    .request_method = first.request.method,
                    .body = if (self.scenario.initial_status == 425)
                        ""
                    else
                        "accepted early",
                });
                if (self.scenario.initial_status == 425) {
                    var retry = try session.receiveRequestWithTimeout(
                        .fromSeconds(5),
                    );
                    defer retry.deinit(self.server.allocator);
                    try self.expectRequest(&retry, 4, false);
                    try session.sendResponse(retry.stream_id, .{
                        .status = self.scenario.retry_status,
                        .request_method = retry.request.method,
                        .body = if (self.scenario.retry_status == 425)
                            "still too early"
                        else
                            "accepted replay",
                    });
                }
            }

            var reused = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer reused.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(u62, if (!self.scenario.reject_early_data and
                    self.scenario.initial_status == 425) 8 else 4),
                reused.stream_id,
            );
            try std.testing.expect(!reused.was_early_data);
            try std.testing.expectEqualStrings(
                "/shared-reuse",
                reused.request.path,
            );
            self.requests += 1;
            try session.sendResponse(reused.stream_id, .{
                .status = 200,
                .request_method = reused.request.method,
                .body = "reused one-rtt",
            });
        }
    };
    var worker = Worker{ .server = &server, .scenario = scenario };
    const server_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    const EarlyResolver = struct {
        cache: *quic.resumption.Cache,
        address: std.Io.net.IpAddress,
        silent_address: std.Io.net.IpAddress,
        silent_first: bool,
        observed_unleased_ticket: std.atomic.Value(bool) = .init(false),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "early.resolve.test") or
                self.address.ip4.port != port)
            {
                return error.Unexpected;
            }
            const stats = self.cache.stats();
            if (stats.active_early_data_leases != 0 or
                stats.reusable_early_data_tickets != 1)
            {
                return error.Unexpected;
            }
            self.observed_unleased_ticket.store(true, .release);
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                if (self.silent_first) 2 else 1,
            );
            if (self.silent_first) {
                addresses[0] = self.silent_address;
                addresses[1] = self.address;
            } else {
                addresses[0] = self.address;
            }
            return addresses;
        }
    };
    var resolver = EarlyResolver{
        .cache = &cache,
        .address = server.address(),
        .silent_address = silent.address(),
        .silent_first = scenario.silent_first,
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = if (scenario.silent_first)
            .{ .ip6 = .loopback(0) }
        else
            .{ .ip4 = .unspecified(0) },
        .migration_local_address = if (scenario.silent_first)
            .{ .ip4 = .loopback(0) }
        else
            null,
        .limits = limits,
        .max_connections = 1,
        .client = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .random = [_]u8{0xcc} ** 32,
                .x25519_secret_key = [_]u8{0xcd} ** 32,
                .auto_resumption = .{
                    .cache = &cache,
                    .server_id = "replaced-by-origin",
                    .now_ms = 1_500,
                },
                .initial_one_rtt_config = .{
                    .max_datagram_size = 4096,
                    .enable_pacing = false,
                },
            },
            .connect_timeout = .fromSeconds(3),
            .address_attempt_timeout = if (scenario.silent_first)
                .fromSeconds(2)
            else
                null,
            .address_connect_policy = if (scenario.silent_first)
                .{ .happy_eyeballs = .{
                    .attempt_delay = .fromMilliseconds(20),
                    .max_in_flight = 2,
                } }
            else
                .ordered,
            .address_resolver = .{
                .context = &resolver,
                .resolve = EarlyResolver.resolve,
            },
        },
    });
    defer pool.deinit();
    var dispatcher = try runtime.SharedHandshakeClientPoolRequestDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_active_connections = 1 },
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();
    var driver = try std.Io.concurrent(
        io,
        runtime.SharedHandshakeClientPoolRequestDispatcher.run,
        .{&dispatcher},
    );
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
        driver.await(io) catch {};
    };

    const target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "early.resolve.test",
        .origin_host = "localhost",
        .port = server.address().ip4.port,
    };
    const NoReclaim = struct {
        fn reclaim(_: *anyopaque) bool {
            return false;
        }
    };
    var reclaimer_context: u8 = 0;
    const started = std.Io.Clock.awake.now(io);
    var result = try sender.requestAltSvcEarlyReclaiming(
        "https://localhost:9443/shared-early",
        target,
        .{
            .headers = &.{.{ .name = "x-early", .value = "original" }},
            .body = "shared request body",
            .trailers = &.{.{ .name = "x-finished", .value = "complete" }},
        },
        .{},
        .{},
        .{},
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }),
        .{ .context = &reclaimer_context, .reclaim = NoReclaim.reclaim },
    );
    defer result.response.deinit();
    if (scenario.silent_first) {
        try std.testing.expect(
            started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
                std.time.ns_per_s,
        );
    }
    try std.testing.expect(
        resolver.observed_unleased_ticket.load(.acquire),
    );
    try std.testing.expect(result.early_data != null);
    try std.testing.expectEqual(
        if (scenario.reject_early_data or scenario.silent_first)
            runtime.EarlyRequestDisposition.rejected
        else
            runtime.EarlyRequestDisposition.accepted,
        result.early_data.?.disposition,
    );
    try std.testing.expectEqual(
        if (scenario.reject_early_data or scenario.silent_first)
            runtime.EarlyDataRetryReason.early_data_rejected
        else if (scenario.initial_status == 425)
            runtime.EarlyDataRetryReason.too_early
        else
            runtime.EarlyDataRetryReason.none,
        result.early_data.?.retry_reason,
    );
    try std.testing.expectEqual(
        if (!scenario.reject_early_data and scenario.initial_status != 425)
            scenario.initial_status
        else
            scenario.retry_status,
        result.response.response.status,
    );
    try std.testing.expectEqualStrings(
        if (scenario.reject_early_data)
            "rejected replay"
        else if (scenario.initial_status != 425)
            "accepted early"
        else if (scenario.retry_status == 425)
            "still too early"
        else
            "accepted replay",
        result.response.response.body,
    );

    // A fresh ticket must remain unused when the established connection can
    // be reused: 0-RTT is a new-connection optimization, never a request mode
    // on an existing QUIC session.
    try cache.store(.{
        .server_id = server_id,
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1_000,
        .lifetime_seconds = 3_600,
        .age_add = 41,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var reused = try sender.requestAltSvcEarlyReclaiming(
        "https://localhost:9443/shared-reuse",
        target,
        .{},
        .{},
        .{},
        .{},
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }),
        .{ .context = &reclaimer_context, .reclaim = NoReclaim.reclaim },
    );
    defer reused.response.deinit();
    try std.testing.expect(reused.early_data == null);
    try std.testing.expectEqual(@as(u16, 200), reused.response.response.status);
    try std.testing.expectEqualStrings(
        "reused one-rtt",
        reused.response.response.body,
    );
    const cache_stats = cache.stats();
    try std.testing.expectEqual(@as(usize, 0), cache_stats.active_early_data_leases);
    try std.testing.expectEqual(@as(usize, 1), cache_stats.reusable_early_data_tickets);

    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, if (!scenario.reject_early_data and
            scenario.initial_status == 425) 3 else 2),
        worker.requests,
    );
    try std.testing.expectEqual(
        if (scenario.silent_first)
            pool.migrationAddress().?.getPort()
        else
            pool.address().getPort(),
        worker.client_port.?,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}

test "HTTP/3 shared endpoint dispatcher retries accepted 425 once" {
    try runSharedEarlyScenario(.{});
}

test "HTTP/3 shared endpoint dispatcher returns retry 425 without looping" {
    try runSharedEarlyScenario(.{ .retry_status = 425 });
}

test "HTTP/3 shared endpoint dispatcher replays TLS-rejected early data" {
    try runSharedEarlyScenario(.{
        .reject_early_data = true,
        .retry_status = 202,
    });
}

test "HTTP/3 shared endpoint replays early data after address timeout" {
    try runSharedEarlyScenario(.{
        .silent_first = true,
        .initial_status = 200,
        .retry_status = 200,
    });
}
