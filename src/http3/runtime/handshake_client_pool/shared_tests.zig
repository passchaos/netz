const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "HTTP/3 cloneable senders coalesce requests through one pool driver" {
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
    const server_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
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

    const Worker = struct {
        server: *runtime.HandshakeServer,
        accepts: usize = 0,
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
            var requests: [4]runtime.OwnedHandshakeRequest = undefined;
            var received: usize = 0;
            defer for (requests[0..received]) |*request| {
                request.deinit(self.server.allocator);
            };
            while (received < requests.len) : (received += 1) {
                requests[received] = try session.receiveRequestWithTimeout(
                    .fromSeconds(5),
                );
            }
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                try session.sendResponse(requests[index].stream_id, .{
                    .status = 200,
                    .request_method = requests[index].request.method,
                    .body = requests[index].request.path,
                });
            }
            var alt = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer alt.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/alt", alt.request.path);
            try session.sendResponse(alt.stream_id, .{
                .status = 201,
                .request_method = alt.request.method,
                .body = "alt",
            });
            var canceled = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer canceled.deinit(self.server.allocator);
            var sibling = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/cancel", canceled.request.path);
            try std.testing.expectEqualStrings(
                "/cancel-sibling",
                sibling.request.path,
            );
            const cancellation = try session.receivePeerResponseCancellationWithTimeout(
                canceled.stream_id,
                .fromSeconds(5),
            );
            self.cancellation_code = cancellation.application_error_code;
            try session.sendResponse(sibling.stream_id, .{
                .status = 202,
                .request_method = sibling.request.method,
                .body = "cancel-sibling",
            });
        }
    };
    var worker = Worker{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

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
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    var dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{},
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();

    const Producer = struct {
        fn run(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
            expected: []const u8,
        ) !void {
            var response = try request_sender.requestWithTimeout(
                uri,
                .{},
                .fromSeconds(5),
            );
            defer response.deinit(std.testing.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(expected, response.response.body);
        }
    };
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    var uris: [7][]u8 = undefined;
    for (&uris, 0..) |*uri, index| {
        uri.* = switch (index) {
            0...3 => try std.fmt.allocPrint(
                allocator,
                "{s}/{d}",
                .{ base, index },
            ),
            4 => try std.fmt.allocPrint(allocator, "{s}/alt", .{base}),
            5 => try std.fmt.allocPrint(allocator, "{s}/cancel", .{base}),
            6 => try std.fmt.allocPrint(
                allocator,
                "{s}/cancel-sibling",
                .{base},
            ),
            else => unreachable,
        };
    }
    defer for (uris) |uri| allocator.free(uri);

    const first_producer = try std.Io.concurrent(
        io,
        Producer.run,
        .{ sender.clone(), uris[0], "/0" },
    );
    var producers: [4]@TypeOf(first_producer) = undefined;
    producers[0] = first_producer;
    const queued_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    while (dispatcher.queuedCount() != 1) {
        if (queued_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.Thread.yield() catch {};
    }
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
    while (dispatcher.queuedCount() != 0) {
        if (queued_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.Thread.yield() catch {};
    }
    // The first request is already owned by the running driver. These later
    // producers must interrupt its response wait and become independent
    // streams on that same connection; pre-start batch collection is not
    // sufficient to pass this gate.
    for (producers[1..], 1..) |*future, index| {
        const expected = switch (index) {
            1 => "/1",
            2 => "/2",
            3 => "/3",
            else => unreachable,
        };
        future.* = try std.Io.concurrent(
            io,
            Producer.run,
            .{ sender.clone(), uris[index], expected },
        );
    }
    for (&producers) |*future| try future.await(io);

    var alt_response = try sender.requestAltSvcWithTimeout(
        uris[4],
        .{
            .alpn = "h3",
            .connect_host = "127.0.0.1",
            .origin_host = "localhost",
            .port = server.address().ip4.port,
        },
        .{},
        .fromSeconds(5),
    );
    defer alt_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), alt_response.response.status);
    try std.testing.expectEqualStrings("alt", alt_response.response.body);

    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 2), stats.batches);
    try std.testing.expectEqual(@as(u64, 4), stats.coalesced_requests);
    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;

    var cancel_dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{},
    );
    defer cancel_dispatcher.deinit();
    const cancel_sender = cancel_dispatcher.sender();
    const CancelProducer = struct {
        fn short(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
        ) !void {
            try std.testing.expectError(
                error.Timeout,
                request_sender.requestWithTimeout(
                    uri,
                    .{},
                    .fromMilliseconds(500),
                ),
            );
        }

        fn sibling(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
        ) !void {
            var response = try request_sender.requestWithTimeout(
                uri,
                .{},
                .fromSeconds(5),
            );
            defer response.deinit(std.testing.allocator);
            try std.testing.expectEqual(@as(u16, 202), response.response.status);
            try std.testing.expectEqualStrings(
                "cancel-sibling",
                response.response.body,
            );
        }
    };
    var short = try std.Io.concurrent(
        io,
        CancelProducer.short,
        .{ cancel_sender.clone(), uris[5] },
    );
    const cancel_queue_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    while (cancel_dispatcher.queuedCount() != 1) {
        if (cancel_queue_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.Thread.yield() catch {};
    }
    var sibling = try std.Io.concurrent(
        io,
        CancelProducer.sibling,
        .{ cancel_sender.clone(), uris[6] },
    );
    while (cancel_dispatcher.queuedCount() != 2) {
        if (cancel_queue_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        std.Thread.yield() catch {};
    }
    var cancel_driver = try std.Io.concurrent(
        io,
        runtime.HandshakeClientPoolSharedDispatcher.run,
        .{&cancel_dispatcher},
    );
    var cancel_driver_active = true;
    defer if (cancel_driver_active) {
        cancel_dispatcher.close();
        cancel_driver.cancel(io) catch {};
        cancel_driver.await(io) catch {};
    };
    try short.await(io);
    try sibling.await(io);
    const cancel_stats = cancel_dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 1), cancel_stats.batches);
    try std.testing.expectEqual(@as(u64, 2), cancel_stats.coalesced_requests);
    cancel_dispatcher.close();
    try cancel_driver.await(io);
    cancel_driver_active = false;

    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual(
        @as(?u64, @import("../../mod.zig").ApplicationErrorCode.request_cancelled),
        worker.cancellation_code,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}
