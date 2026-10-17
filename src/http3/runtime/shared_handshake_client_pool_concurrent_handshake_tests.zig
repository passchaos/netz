const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared endpoint starts independent route handshakes concurrently" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var silent_a = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent_a.deinit();
    var silent_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent_b.deinit();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 2,
        .client = .{
            .connect_timeout = .fromMilliseconds(700),
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .handshake_recovery = .{
                    .initial_pto_ms = 1_000,
                    .max_pto_ms = 4_000,
                    .max_retries = 3,
                },
            },
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

    const Seen = struct {
        count: std.atomic.Value(u8) = .init(0),
        both: std.Io.Event = .unset,

        fn observe(
            self: *@This(),
            endpoint: *quic.runtime.Endpoint,
        ) !void {
            var datagram = try endpoint.receiveBytesWithTimeout(
                .fromSeconds(2),
            );
            defer datagram.deinit(endpoint.allocator);
            if (self.count.fetchAdd(1, .acq_rel) == 1) {
                self.both.set(endpoint.io);
            }
        }
    };
    var seen = Seen{};
    var observer_a = try std.Io.concurrent(
        io,
        Seen.observe,
        .{ &seen, &silent_a },
    );
    var observer_a_active = true;
    defer if (observer_a_active) observer_a.cancel(io) catch {};
    var observer_b = try std.Io.concurrent(
        io,
        Seen.observe,
        .{ &seen, &silent_b },
    );
    var observer_b_active = true;
    defer if (observer_b_active) observer_b.cancel(io) catch {};

    var start: std.Io.Event = .unset;
    const Producer = struct {
        fn run(
            start_event: *std.Io.Event,
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
            target: http3.AltSvcTarget,
            timeout: std.Io.Duration,
            expected_error: anyerror,
        ) !void {
            try start_event.wait(io_value);
            var response = request_sender.requestAltSvcWithTimeout(
                uri,
                target,
                .{},
                timeout,
            ) catch |err| {
                try std.testing.expectEqual(expected_error, err);
                return;
            };
            response.deinit();
            return error.TestUnexpectedResult;
        }
    };
    const target_a: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "a.example",
        .port = silent_a.address().ip4.port,
    };
    const target_b: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "b.example",
        .port = silent_b.address().ip4.port,
    };
    var request_a = try std.Io.concurrent(
        io,
        Producer.run,
        .{
            &start,
            io,
            sender.clone(),
            "https://a.example:9443/a",
            target_a,
            .fromMilliseconds(500),
            error.Timeout,
        },
    );
    var request_a_active = true;
    defer if (request_a_active) request_a.cancel(io) catch {};
    var request_b = try std.Io.concurrent(
        io,
        Producer.run,
        .{
            &start,
            io,
            sender.clone(),
            "https://b.example:9443/b",
            target_b,
            .fromMilliseconds(1_500),
            error.HandshakeTimeout,
        },
    );
    var request_b_active = true;
    defer if (request_b_active) request_b.cancel(io) catch {};

    start.set(io);
    try seen.both.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(400),
    } });
    try observer_a.await(io);
    observer_a_active = false;
    try observer_b.await(io);
    observer_b_active = false;
    try request_a.await(io);
    request_a_active = false;
    try request_b.await(io);
    request_b_active = false;

    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(usize, 0), stats.queued);
    try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.active_requests);
    // Producer-abandoned timeout commands are excluded from this counter;
    // the transport-level handshake failure remains observable.
    try std.testing.expectEqual(@as(u64, 1), stats.completed_requests);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());

    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
}

test "HTTP/3 shared endpoint promotes concurrent route handshakes" {
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
    const cid_a = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const cid_b = [_]u8{ 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0 };
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

    const Arrivals = struct {
        count: std.atomic.Value(u8) = .init(0),
        both: std.Io.Event = .unset,

        fn arrive(self: *@This(), io_value: std.Io) void {
            if (self.count.fetchAdd(1, .acq_rel) == 1) {
                self.both.set(io_value);
            }
        }
    };
    var arrivals = Arrivals{};
    const Worker = struct {
        server: *runtime.HandshakeServer,
        arrivals: *Arrivals,
        path: []const u8,
        body: []const u8,
        sibling_path: ?[]const u8 = null,
        sibling_body: []const u8 = "",
        client_address: ?std.Io.net.IpAddress = null,
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
            self.client_address = request.from;
            const first_body, const second_path, const second_body =
                if (std.mem.eql(u8, self.path, request.request.path))
                    .{ self.body, self.sibling_path, self.sibling_body }
                else if (self.sibling_path) |sibling_path|
                    if (std.mem.eql(u8, sibling_path, request.request.path))
                        .{ self.sibling_body, self.path, self.body }
                    else
                        return error.TestUnexpectedResult
                else
                    return error.TestUnexpectedResult;
            self.arrivals.arrive(self.server.quic_server.endpoint.io);
            try self.arrivals.both.waitTimeout(
                self.server.quic_server.endpoint.io,
                .{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } },
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .request_method = request.request.method,
                .body = first_body,
            });
            if (second_path) |path| {
                var sibling = try session.receiveRequestWithTimeout(
                    .fromSeconds(5),
                );
                defer sibling.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    path,
                    sibling.request.path,
                );
                try session.sendResponse(sibling.stream_id, .{
                    .status = 200,
                    .request_method = sibling.request.method,
                    .body = second_body,
                });
            }
        }
    };
    var worker_a = Worker{
        .server = &server_a,
        .arrivals = &arrivals,
        .path = "/a",
        .body = "a",
        .sibling_path = "/a-sibling",
        .sibling_body = "a-sibling",
    };
    var worker_b = Worker{
        .server = &server_b,
        .arrivals = &arrivals,
        .path = "/b",
        .body = "b",
    };
    const thread_a = try std.Thread.spawn(.{}, Worker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, Worker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 3,
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
        } },
    });
    defer pool.deinit();
    var dispatcher = try runtime.SharedHandshakeClientPoolRequestDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_active_connections = 3 },
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

    var start: std.Io.Event = .unset;
    const Producer = struct {
        fn run(
            start_event: *std.Io.Event,
            io_value: std.Io,
            request_sender: runtime.SharedHandshakeClientPoolRequestSender,
            uri: []const u8,
            body: []const u8,
        ) !void {
            try start_event.wait(io_value);
            var response = try request_sender.requestWithTimeout(
                uri,
                .{},
                .fromSeconds(5),
            );
            defer response.deinit();
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(body, response.response.body);
        }
    };
    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/b",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b);
    const uri_a_sibling = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/a-sibling",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a_sibling);
    var request_a = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &start, io, sender.clone(), uri_a, "a" },
    );
    var request_a_active = true;
    defer if (request_a_active) request_a.cancel(io) catch {};
    var request_b = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &start, io, sender.clone(), uri_b, "b" },
    );
    var request_b_active = true;
    defer if (request_b_active) request_b.cancel(io) catch {};
    var request_a_sibling = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &start, io, sender.clone(), uri_a_sibling, "a-sibling" },
    );
    var request_a_sibling_active = true;
    defer if (request_a_sibling_active) {
        request_a_sibling.cancel(io) catch {};
    };
    start.set(io);
    try request_a.await(io);
    request_a_active = false;
    try request_b.await(io);
    request_b_active = false;
    try request_a_sibling.await(io);
    request_a_sibling_active = false;

    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 3), stats.completed_requests);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expectEqual(worker_a.client_address, worker_b.client_address);

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
}
