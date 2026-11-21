const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared endpoint pending handshake does not block established response" {
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
    const server_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();

    var request_received: std.Io.Event = .unset;
    var send_response: std.Io.Event = .unset;
    const Worker = struct {
        server: *runtime.HandshakeServer,
        request_received: *std.Io.Event,
        send_response: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/healthy",
                request.request.path,
            );
            self.request_received.set(self.server.quic_server.endpoint.io);
            try self.send_response.waitTimeout(
                self.server.quic_server.endpoint.io,
                .{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(5),
                } },
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .request_method = request.request.method,
                .body = "healthy",
            });
            var next = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer next.deinit(self.server.allocator);
            var third = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer third.deinit(self.server.allocator);
            const sibling, const timed = if (std.mem.eql(
                u8,
                next.request.path,
                "/sibling",
            ) and std.mem.eql(u8, third.request.path, "/timed"))
                .{ &next, &third }
            else if (std.mem.eql(u8, next.request.path, "/timed") and
                std.mem.eql(u8, third.request.path, "/sibling"))
                .{ &third, &next }
            else
                return error.TestUnexpectedResult;
            try session.sendResponse(sibling.stream_id, .{
                .status = 200,
                .request_method = sibling.request.method,
                .body = "sibling",
            });
            const cancellation = try session
                .receivePeerResponseCancellationWithTimeout(
                timed.stream_id,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                cancellation.application_error_code,
            );
        }
    };
    var worker = Worker{
        .server = &server,
        .request_received = &request_received,
        .send_response = &send_response,
    };
    const server_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) {
        send_response.set(io);
        server_thread.join();
    };

    const ResolveGate = struct {
        started: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        cancel_started: std.Io.Event = .unset,
        cancel_release: std.Io.Event = .unset,
        server_address: std.Io.net.IpAddress,
        silent_address: std.Io.net.IpAddress,

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            resolve_io: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (std.mem.eql(u8, host, "cancel.resolve.test")) {
                self.cancel_started.set(resolve_io);
                try self.cancel_release.wait(resolve_io);
                return error.Unexpected;
            }
            if (!std.mem.eql(u8, host, "slow.resolve.test")) {
                if (!std.mem.eql(u8, host, "localhost") or
                    self.server_address.ip4.port != port)
                {
                    return error.UnknownHostName;
                }
                const addresses = try resolve_allocator.alloc(
                    std.Io.net.IpAddress,
                    1,
                );
                addresses[0] = self.server_address;
                return addresses;
            }
            if (self.silent_address.ip4.port != port) {
                return error.Unexpected;
            }
            self.started.set(resolve_io);
            if (deadline) |absolute| {
                self.release.waitTimeout(
                    resolve_io,
                    .{ .deadline = absolute },
                ) catch |err| switch (err) {
                    error.Timeout => return error.Timeout,
                    error.Canceled => return error.Canceled,
                };
            } else {
                try self.release.wait(resolve_io);
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                1,
            );
            addresses[0] = self.silent_address;
            return addresses;
        }
    };
    var resolve_gate = ResolveGate{
        .server_address = server.address(),
        .silent_address = silent.address(),
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .handshake_poll_interval = .fromMilliseconds(500),
        .resolver = .{
            .context = &resolve_gate,
            .resolve = ResolveGate.resolve,
        },
        .client = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .handshake_recovery = .{
                    .initial_pto_ms = 1_000,
                    .max_pto_ms = 4_000,
                    .max_retries = 3,
                },
                .initial_one_rtt_config = .{
                    .max_datagram_size = 4096,
                    .enable_pacing = false,
                },
            },
            .connect_timeout = .fromMilliseconds(900),
        },
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

    const healthy_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/healthy",
        .{server.address().ip4.port},
    );
    defer allocator.free(healthy_uri);
    const sibling_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/sibling",
        .{server.address().ip4.port},
    );
    defer allocator.free(sibling_uri);
    const timed_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/timed",
        .{server.address().ip4.port},
    );
    defer allocator.free(timed_uri);
    const Producer = struct {
        fn expectResponse(
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
            expected_body: []const u8,
        ) !void {
            var response = try request_sender.requestWithTimeout(
                uri,
                .{},
                .fromMilliseconds(500),
            );
            defer response.deinit();
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(
                expected_body,
                response.response.body,
            );
        }

        fn stalled(
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
            target: http3.AltSvcTarget,
        ) !void {
            var response = request_sender.requestAltSvcWithTimeout(
                uri,
                target,
                .{},
                .fromMilliseconds(1_200),
            ) catch |err| {
                try std.testing.expectEqual(error.HandshakeTimeout, err);
                return;
            };
            response.deinit();
            return error.TestUnexpectedResult;
        }

        fn timed(
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
        ) !void {
            const started = std.Io.Clock.awake.now(io_value);
            var response = request_sender.requestWithTimeout(
                uri,
                .{},
                .fromMilliseconds(100),
            ) catch |err| {
                try std.testing.expectEqual(error.Timeout, err);
                const elapsed = started.durationTo(
                    std.Io.Clock.awake.now(io_value),
                );
                try std.testing.expect(
                    elapsed.nanoseconds < 300 * std.time.ns_per_ms,
                );
                return;
            };
            response.deinit();
            return error.TestUnexpectedResult;
        }

        fn resolutionTimed(
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            target: http3.AltSvcTarget,
        ) !void {
            const started = std.Io.Clock.awake.now(io_value);
            var response = request_sender.requestAltSvcWithTimeout(
                "https://cancelled.example:9443/cancel-resolve",
                target,
                .{},
                .fromMilliseconds(100),
            ) catch |err| {
                try std.testing.expectEqual(error.Timeout, err);
                const elapsed = started.durationTo(
                    std.Io.Clock.awake.now(io_value),
                );
                try std.testing.expect(
                    elapsed.nanoseconds < 300 * std.time.ns_per_ms,
                );
                return;
            };
            response.deinit();
            return error.TestUnexpectedResult;
        }

        fn observeSilent(endpoint: *quic.runtime.Endpoint) !void {
            var datagram = try endpoint.receiveBytesWithTimeout(
                .fromSeconds(2),
            );
            defer datagram.deinit(endpoint.allocator);
        }
    };
    var healthy = try std.Io.concurrent(
        io,
        Producer.expectResponse,
        .{ sender.clone(), healthy_uri, "healthy" },
    );
    var healthy_active = true;
    defer if (healthy_active) healthy.cancel(io) catch {};
    try request_received.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });

    var silent_observer = try std.Io.concurrent(
        io,
        Producer.observeSilent,
        .{&silent},
    );
    var silent_active = true;
    defer if (silent_active) silent_observer.cancel(io) catch {};
    const stalled_target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "slow.resolve.test",
        .origin_host = "stalled.example",
        .port = silent.address().ip4.port,
    };
    var stalled = try std.Io.concurrent(
        io,
        Producer.stalled,
        .{
            sender.clone(),
            "https://stalled.example:9443/stall",
            stalled_target,
        },
    );
    var stalled_active = true;
    defer if (stalled_active) stalled.cancel(io) catch {};
    try resolve_gate.started.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });
    var sibling = try std.Io.concurrent(
        io,
        Producer.expectResponse,
        .{ sender.clone(), sibling_uri, "sibling" },
    );
    var sibling_active = true;
    defer if (sibling_active) sibling.cancel(io) catch {};
    var timed = try std.Io.concurrent(
        io,
        Producer.timed,
        .{ io, sender.clone(), timed_uri },
    );
    var timed_active = true;
    defer if (timed_active) timed.cancel(io) catch {};
    send_response.set(io);

    try healthy.await(io);
    healthy_active = false;
    try sibling.await(io);
    sibling_active = false;
    try timed.await(io);
    timed_active = false;
    resolve_gate.release.set(io);
    try silent_observer.await(io);
    silent_active = false;
    try stalled.await(io);
    stalled_active = false;
    const cancel_target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "cancel.resolve.test",
        .origin_host = "cancelled.example",
        .port = silent.address().ip4.port,
    };
    var resolution_timed = try std.Io.concurrent(
        io,
        Producer.resolutionTimed,
        .{ io, sender.clone(), cancel_target },
    );
    var resolution_timed_active = true;
    defer if (resolution_timed_active) {
        resolve_gate.cancel_release.set(io);
        resolution_timed.cancel(io) catch {};
    };
    try resolve_gate.cancel_started.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });
    try resolution_timed.await(io);
    resolution_timed_active = false;
    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(usize, 0), stats.queued);
    try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.active_requests);
    // A deadline completion racing the producer's abandoned flag may be
    // counted or omitted; both paths publish the same Timeout and reclaim the
    // pending resolver before waking the producer.
    // The healthy, sibling, and stalled requests always complete. Each of the
    // two deadline-bound requests (timed and resolution-timed) independently
    // races its abandonment flag, so the counter can be 3, 4, or 5; all paths
    // publish the same Timeout and reclaim the pending resolver before waking
    // the producer.
    try std.testing.expect(
        stats.completed_requests >= 3 and stats.completed_requests <= 5,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
}
