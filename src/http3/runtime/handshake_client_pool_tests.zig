const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 URI connect timeout validates and preserves one deadline" {
    const quic = @import("../../quic/mod.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const base: @FieldType(
        quic.handshake.ClientOptions,
        "handshake_recovery",
    ) = .{
        .initial_pto_ms = 100,
        .max_pto_ms = 400,
        .max_retries = 3,
    };

    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.testing.handshakeRecoveryBeforeForTest(
            io,
            .fromNow(io, .{ .raw = .zero, .clock = .awake }),
            base,
        ),
    );
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    const bounded = try runtime.testing.handshakeRecoveryBeforeForTest(
        io,
        deadline,
        base,
    );
    try std.testing.expectEqual(deadline, bounded.deadline.?);
    try std.testing.expectEqual(base.initial_pto_ms, bounded.initial_pto_ms);
    try std.testing.expectEqual(base.max_pto_ms, bounded.max_pto_ms);
    try std.testing.expectEqual(base.max_retries, bounded.max_retries);
}

test "HTTP/3 pool releases a timed-out URI handshake reservation" {
    const quic = @import("../../quic/mod.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Keep a real UDP destination open but deliberately never service it.
    // This avoids an immediate ICMP refusal and exercises the deadline in the
    // actual Initial retransmission loop used by the default pool connector.
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .connect_timeout = .fromMilliseconds(20),
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .handshake_recovery = .{
                .initial_pto_ms = 1_000,
                .max_pto_ms = 4_000,
                .max_retries = 3,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        pool.acquireUri(uri),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
}

test "HTTP/3 handshake client pool replaces idle capacity across origins" {
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

    const server_a_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const server_b_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_a_cid,
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
            .local_connection_id = &server_b_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_b.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_paths: []const []const u8,
        response_bodies: []const []const u8,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            for (self.expected_paths, self.response_bodies) |expected_path, body| {
                var request = session.receiveRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                if (!std.mem.eql(u8, expected_path, request.request.path)) {
                    self.err = error.InvalidUri;
                    return;
                }
                session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .request_method = request.request.method,
                    .body = body,
                }) catch |err| {
                    self.err = err;
                    return;
                };
                self.requests += 1;
            }
        }
    };
    var worker_a = ServerWorker{
        .server = &server_a,
        .expected_paths = &.{"/origin-a"},
        .response_bodies = &.{"a"},
    };
    var worker_b = ServerWorker{
        .server = &server_b,
        .expected_paths = &.{ "/origin-b/one", "/origin-b/two" },
        .response_bodies = &.{ "b-one", "b-two" },
    };
    const thread_a = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    const CountingConnector = struct {
        inner: runtime.HandshakeClientPoolDefaultConnector,
        connects: usize = 0,

        fn connect(
            context: *anyopaque,
            allocator_value: std.mem.Allocator,
            io_value: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            client_limits: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connects += 1;
            return self.inner.connector().connect(
                &self.inner,
                allocator_value,
                io_value,
                local_address,
                uri,
                client_limits,
            );
        }
    };
    var connector = CountingConnector{ .inner = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = .{
            .context = &connector,
            .connect = CountingConnector.connect,
        },
    });
    defer pool.deinit();

    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b_one = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-b/one",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_one);
    const uri_b_two = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/origin-b/two",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_two);

    var response_a = try pool.requestUri(uri_a, .{});
    defer response_a.deinit(allocator);
    // The only connection slot is idle for origin A here. Acquiring origin B
    // must retire A before dialing B rather than rejecting the request or
    // temporarily exceeding the configured total.
    var response_b_one = try pool.requestUri(uri_b_one, .{});
    defer response_b_one.deinit(allocator);
    var response_b_two = try pool.requestUri(uri_b_two, .{});
    defer response_b_two.deinit(allocator);

    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;

    try std.testing.expectEqualStrings("a", response_a.response.body);
    try std.testing.expectEqualStrings("b-one", response_b_one.response.body);
    try std.testing.expectEqualStrings("b-two", response_b_two.response.body);
    try std.testing.expectEqual(@as(usize, 1), worker_a.requests);
    try std.testing.expectEqual(@as(usize, 2), worker_b.requests);
    try std.testing.expectEqual(@as(usize, 2), connector.connects);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);
}

test "HTTP/3 handshake client pool admits capacity waiters in FIFO order" {
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
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
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

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            for (0..3) |_| {
                var session = self.server.accept() catch |err| {
                    self.err = err;
                    return;
                };
                // The waiter deliberately discards each newly admitted client
                // immediately. Complete each server-side close before
                // accepting the next QUIC handshake on the same UDP socket.
                session.deinit();
            }
        }
    };
    const Waiter = struct {
        pool: *runtime.HandshakeClientPool,
        uri: []const u8,
        acquired: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        order: *std.atomic.Value(u32),
        position: u32 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                self.acquired.set(self.pool.io);
                return;
            };
            self.position = self.order.fetchAdd(1, .monotonic) + 1;
            self.acquired.set(self.pool.io);
            self.release.wait(self.pool.io) catch |err| {
                self.err = err;
            };
            lease.discard();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
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
            .max_idle_per_origin = 0,
            .max_idle_total = 0,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/fifo",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var held = try pool.acquireUri(uri);

    var order: std.atomic.Value(u32) = .init(0);
    var first = Waiter{ .pool = &pool, .uri = uri, .order = &order };
    var second = Waiter{ .pool = &pool, .uri = uri, .order = &order };
    const first_thread = try std.Thread.spawn(.{}, Waiter.run, .{&first});
    var first_joined = false;
    defer if (!first_joined) {
        first.release.set(io);
        first_thread.join();
    };
    while (pool.waitingCount() != 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const second_thread = try std.Thread.spawn(.{}, Waiter.run, .{&second});
    var second_joined = false;
    defer if (!second_joined) {
        second.release.set(io);
        second_thread.join();
    };
    while (pool.waitingCount() != 2) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    held.discard();
    try first.acquired.wait(io);
    if (first.err) |err| return err;
    try std.testing.expectEqual(@as(u32, 1), first.position);
    try std.testing.expect(!second.acquired.isSet());
    first.release.set(io);
    first_thread.join();
    first_joined = true;

    try second.acquired.wait(io);
    if (second.err) |err| return err;
    try std.testing.expectEqual(@as(u32, 2), second.position);
    second.release.set(io);
    second_thread.join();
    second_joined = true;
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}
