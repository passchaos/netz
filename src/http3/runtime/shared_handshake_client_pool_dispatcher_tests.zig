const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
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
