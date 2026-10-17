const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "HTTP/3 shared route drivers avoid cross-origin head-of-line blocking" {
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
    const slow_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const fast_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0 };
    var slow_server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &slow_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer slow_server.deinit();
    var fast_server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &fast_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer fast_server.deinit();

    var slow_received: std.Io.Event = .unset;
    var release_slow: std.Io.Event = .unset;
    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_path: []const u8,
        status: u16,
        body: []const u8,
        received: ?*std.Io.Event = null,
        release: ?*std.Io.Event = null,
        accepts: usize = 0,
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
            try std.testing.expectEqualStrings(
                self.expected_path,
                request.request.path,
            );
            if (self.received) |event| {
                event.set(self.server.quic_server.endpoint.io);
            }
            if (self.release) |event| {
                try event.waitTimeout(
                    self.server.quic_server.endpoint.io,
                    .{ .duration = .{
                        .clock = .awake,
                        .raw = .fromSeconds(5),
                    } },
                );
            }
            try session.sendResponse(request.stream_id, .{
                .status = self.status,
                .request_method = request.request.method,
                .body = self.body,
            });
        }
    };
    var slow_worker = ServerWorker{
        .server = &slow_server,
        .expected_path = "/slow",
        .status = 201,
        .body = "slow",
        .received = &slow_received,
        .release = &release_slow,
    };
    var fast_worker = ServerWorker{
        .server = &fast_server,
        .expected_path = "/fast",
        .status = 202,
        .body = "fast",
    };
    const slow_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&slow_worker},
    );
    var slow_joined = false;
    defer if (!slow_joined) slow_thread.join();
    const fast_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&fast_worker},
    );
    var fast_joined = false;
    defer if (!fast_joined) fast_thread.join();

    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 2,
        },
        .max_connections = 2,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    try std.testing.expectError(
        error.InvalidSharedOptions,
        runtime.HandshakeClientPoolSharedDispatcher.init(
            allocator,
            io,
            &pool,
            .{ .max_connection_drivers = 0 },
        ),
    );
    var closed_dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_connection_drivers = 2 },
    );
    closed_dispatcher.close();
    try closed_dispatcher.run();
    closed_dispatcher.deinit();
    var dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_connection_drivers = 2 },
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();
    var driver = try std.Io.concurrent(
        io,
        runtime.HandshakeClientPoolSharedDispatcher.run,
        .{&dispatcher},
    );
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
        driver.await(io) catch {};
    };

    const slow_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/slow",
        .{slow_server.address().ip4.port},
    );
    defer allocator.free(slow_uri);
    const fast_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/fast",
        .{fast_server.address().ip4.port},
    );
    defer allocator.free(fast_uri);

    const Producer = struct {
        fn run(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
            status: u16,
            body: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            var response = try request_sender.requestWithTimeout(
                uri,
                .{},
                timeout,
            );
            defer response.deinit(std.testing.allocator);
            try std.testing.expectEqual(status, response.response.status);
            try std.testing.expectEqualStrings(body, response.response.body);
        }
    };

    var slow = try std.Io.concurrent(
        io,
        Producer.run,
        .{ sender.clone(), slow_uri, @as(u16, 201), "slow", .fromSeconds(5) },
    );
    var slow_released = false;
    var slow_active = true;
    defer if (slow_active) {
        if (!slow_released) release_slow.set(io);
        slow.cancel(io) catch {};
    };
    try slow_received.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });

    var fast = try std.Io.concurrent(
        io,
        Producer.run,
        .{ sender.clone(), fast_uri, @as(u16, 202), "fast", .fromSeconds(2) },
    );
    try fast.await(io);
    // The slow route is deliberately still blocked here. A single global
    // driver cannot complete the fast future before this release.
    release_slow.set(io);
    slow_released = true;
    try slow.await(io);
    slow_active = false;

    try std.testing.expectError(error.Canceled, driver.cancel(io));
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
    slow_thread.join();
    slow_joined = true;
    fast_thread.join();
    fast_joined = true;
    if (slow_worker.err) |err| return err;
    if (fast_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), slow_worker.accepts);
    try std.testing.expectEqual(@as(usize, 1), fast_worker.accepts);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
}
