const std = @import("std");
const http = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2_runtime = @import("../http2/runtime.zig");
const tls_testing = @import("../tls/testing.zig");

test "unified HTTP pool exposes bounded lifecycle counters" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try http.Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{},
    );
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
}

test "unified HTTP pool configures HTTP3 through SOCKS5 without bypass" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try http.Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{
            .client = .{ .socks5_proxy = .{ .host = "proxy.invalid" } },
            .http3 = .{ .handshake = .{ .handshake = .{
                .original_destination_connection_id = &.{1},
                .local_connection_id = &.{2},
            } } },
        },
    );
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());

    try std.testing.expectError(
        error.InvalidProxyRouteCapacity,
        http.Pool.init(
            std.testing.allocator,
            threaded.io(),
            .{
                .client = .{ .socks5_proxy = .{ .host = "proxy.invalid" } },
                .http3 = .{
                    .handshake = .{ .handshake = .{
                        .original_destination_connection_id = &.{1},
                        .local_connection_id = &.{2},
                    } },
                    .max_socks5_shared_routes = 0,
                },
            },
        ),
    );
}

test "unified HTTP pool retains negotiated h1 and h2 connections by origin" {
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
    var h1_server = try http1_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = identity,
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    defer h1_server.deinit();
    var h2_server = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer h2_server.deinit();
    const h1_base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{h1_server.address().ip4.port},
    );
    defer allocator.free(h1_base);
    const h2_base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{h2_server.address().ip4.port},
    );
    defer allocator.free(h2_base);
    const redirect_location = try std.fmt.allocPrint(
        allocator,
        "{s}/redirected",
        .{h2_base},
    );
    defer allocator.free(redirect_location);

    const H1Worker = struct {
        server: *http1_runtime.TlsServer,
        release: *std.Io.Event,
        redirect_location: []const u8,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            self.accepts += 1;
            defer connection.close();
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/h1-one" else "/redirect",
                    request.request.target,
                );
                if (index == 0) {
                    try connection.writeResponse(.{
                        .body = "h1-one",
                        .request_method = request.request.method,
                    });
                } else {
                    try connection.writeResponse(.{
                        .status = 302,
                        .reason = "Found",
                        .headers = &.{.{
                            .name = "location",
                            .value = self.redirect_location,
                        }},
                        .request_method = request.request.method,
                    });
                }
            }
            try self.release.wait(self.server.io);
        }
    };
    const H2Worker = struct {
        server: *http2_runtime.TlsServer,
        release: *std.Io.Event,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            self.accepts += 1;
            defer connection.close();
            for (0..2) |index| {
                var request = try connection.readRequest();
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/h2-one" else "/redirected",
                    request.path,
                );
                try connection.writeResponse(request.stream_id, .{
                    .body = if (index == 0) "h2-one" else "redirected-h2",
                    .request_method = request.method,
                });
            }
            try self.release.wait(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var h1_worker = H1Worker{
        .server = &h1_server,
        .release = &release,
        .redirect_location = redirect_location,
    };
    var h2_worker = H2Worker{ .server = &h2_server, .release = &release };
    const h1_thread = try std.Thread.spawn(.{}, H1Worker.run, .{&h1_worker});
    var h1_joined = false;
    defer if (!h1_joined) {
        release.set(io);
        h1_thread.join();
    };
    const h2_thread = try std.Thread.spawn(.{}, H2Worker.run, .{&h2_worker});
    var h2_joined = false;
    defer if (!h2_joined) {
        release.set(io);
        h2_thread.join();
    };

    var pool = try http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
    });
    defer pool.deinit();
    const h1_uri = try std.fmt.allocPrint(allocator, "{s}/h1-one", .{h1_base});
    defer allocator.free(h1_uri);
    const h2_uri = try std.fmt.allocPrint(allocator, "{s}/h2-one", .{h2_base});
    defer allocator.free(h2_uri);
    const redirect_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/redirect",
        .{h1_base},
    );
    defer allocator.free(redirect_uri);
    {
        var response = try pool.requestUriWithTimeout(
            h1_uri,
            .{},
            .fromSeconds(5),
        );
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http1, response.protocol());
        try std.testing.expectEqualStrings("h1-one", response.body());
    }
    {
        var response = try pool.requestUriWithTimeout(
            h2_uri,
            .{},
            .fromSeconds(5),
        );
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http2, response.protocol());
        try std.testing.expectEqualStrings("h2-one", response.body());
    }
    var redirected = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        redirect_uri,
        .{},
        .{},
        .fromSeconds(5),
    );
    defer redirected.deinit();
    try std.testing.expectEqual(http.Protocol.http2, redirected.response.protocol());
    try std.testing.expectEqualStrings("redirected-h2", redirected.response.body());
    try std.testing.expectEqual(@as(usize, 1), redirected.redirect_count);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), try pool.idleCountForUri(
        h1_base,
    ));
    try std.testing.expectEqual(@as(usize, 1), try pool.idleCountForUri(
        h2_base,
    ));
    const stats = pool.stats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_reused);
    try std.testing.expectEqual(@as(u64, 2), stats.total_misses);

    release.set(io);
    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (h1_worker.err) |err| return err;
    if (h2_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), h1_worker.accepts);
    try std.testing.expectEqual(@as(usize, 1), h2_worker.accepts);
}

test "unified HTTP pool admits capacity waiters in FIFO order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const ServerWorker = struct {
        server: *http1_runtime.Server,
        accepted: *std.Io.Event,
        finish: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.finish.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *http.Pool,
        uri: []const u8,
        order_counter: *std.atomic.Value(usize),
        acquired: *std.atomic.Value(bool),
        order: usize = std.math.maxInt(usize),
        hold: ?*std.Io.Event = null,
        reused: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.reused = lease.was_reused;
            self.order = self.order_counter.fetchAdd(1, .acq_rel);
            self.acquired.store(true, .release);
            if (self.hold) |gate| {
                gate.wait(self.pool.io) catch |err| {
                    self.err = err;
                    lease.discard();
                    return;
                };
            }
            lease.release();
        }
    };
    var accepted: std.Io.Event = .unset;
    var finish_server: std.Io.Event = .unset;
    var server_worker = ServerWorker{
        .server = &server,
        .accepted = &accepted,
        .finish = &finish_server,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) {
        finish_server.set(io);
        server_thread.join();
    };
    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var pool = try http.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
    });
    defer pool.deinit();
    var first = try pool.acquireUri(uri);
    try accepted.wait(io);
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(uri, .fromMilliseconds(5)),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());

    var order_counter = std.atomic.Value(usize).init(0);
    var first_acquired = std.atomic.Value(bool).init(false);
    var second_acquired = std.atomic.Value(bool).init(false);
    var release_first_waiter: std.Io.Event = .unset;
    var first_waiter = Waiter{
        .pool = &pool,
        .uri = uri,
        .order_counter = &order_counter,
        .acquired = &first_acquired,
        .hold = &release_first_waiter,
    };
    const first_thread = try std.Thread.spawn(.{}, Waiter.run, .{&first_waiter});
    var first_joined = false;
    defer if (!first_joined) {
        release_first_waiter.set(io);
        first_thread.join();
    };
    try waitForWaiterCount(io, &pool, 1);
    var second_waiter = Waiter{
        .pool = &pool,
        .uri = uri,
        .order_counter = &order_counter,
        .acquired = &second_acquired,
    };
    const second_thread = try std.Thread.spawn(.{}, Waiter.run, .{&second_waiter});
    var second_joined = false;
    defer if (!second_joined) second_thread.join();
    try waitForWaiterCount(io, &pool, 2);

    first.release();
    try waitForFlag(io, &first_acquired);
    try std.testing.expect(!second_acquired.load(.acquire));
    release_first_waiter.set(io);
    first_thread.join();
    first_joined = true;
    second_thread.join();
    second_joined = true;
    if (first_waiter.err) |err| return err;
    if (second_waiter.err) |err| return err;
    try std.testing.expect(first_waiter.reused);
    try std.testing.expect(second_waiter.reused);
    try std.testing.expectEqual(@as(usize, 0), first_waiter.order);
    try std.testing.expectEqual(@as(usize, 1), second_waiter.order);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    finish_server.set(io);
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
}

test "unified HTTP pool retries one stale reused idempotent request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *http1_runtime.Server,
        close_seed: std.Io.Event = .unset,
        seed_closed: std.Io.Event = .unset,
        finish: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.seed_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/seed",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = "seed",
                    .request_method = request.request.method,
                });
                try self.close_seed.wait(self.server.io);
            }
            self.seed_closed.set(self.server.io);
            var connection = try self.server.acceptWithTimeout(
                .fromSeconds(3),
            );
            self.accepts += 1;
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqual(http1.Method.GET, request.request.method);
            try std.testing.expectEqualStrings(
                "/retry",
                request.request.target,
            );
            try connection.writeResponse(.{
                .body = "retried",
                .request_method = request.request.method,
            });
            try self.finish.wait(self.server.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.close_seed.set(io);
        shared.finish.set(io);
        thread.join();
    };
    var pool = try http.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.address().getPort()},
    );
    defer allocator.free(base);
    const seed_uri = try std.fmt.allocPrint(allocator, "{s}/seed", .{base});
    defer allocator.free(seed_uri);
    const retry_uri = try std.fmt.allocPrint(allocator, "{s}/retry", .{base});
    defer allocator.free(retry_uri);

    var seed = try pool.requestUriWithTimeout(
        seed_uri,
        .{},
        .fromSeconds(3),
    );
    defer seed.deinit();
    try std.testing.expectEqualStrings("seed", seed.body());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    shared.close_seed.set(io);
    try shared.seed_closed.wait(io);

    var retried = try pool.requestUriWithTimeout(
        retry_uri,
        .{},
        .fromSeconds(3),
    );
    defer retried.deinit();
    try std.testing.expectEqualStrings("retried", retried.body());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());

    shared.finish.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

fn waitForWaiterCount(
    io: std.Io,
    pool: *http.Pool,
    expected: usize,
) !void {
    for (0..200) |_| {
        if (pool.waitingCount() == expected) return;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

fn waitForFlag(io: std.Io, flag: *std.atomic.Value(bool)) !void {
    for (0..200) |_| {
        if (flag.load(.acquire)) return;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

test "unified HTTP pool streams a request over a leased connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Worker = struct {
        const Self = @This();
        server: *http1_runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *Self) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *Self) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "hello world",
                request.request.body,
            );
            var response = try connection.startResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body_length = null,
                .request_method = .POST,
            });
            try response.write("streamed");
            try response.finish();
            try self.release.wait(self.server.io);
        }
    };

    var release: std.Io.Event = .unset;
    var worker = Worker{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        thread.join();
    };

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);

    var pool = try http.Pool.init(allocator, io, .{});
    defer pool.deinit();

    const Sink = struct {
        allocator: std.mem.Allocator,
        status: u16 = 0,
        body: std.ArrayList(u8) = .empty,

        fn sink(self: *@This()) http.ResponseSink {
            return .{
                .context = self,
                .begin = begin,
                .data = data,
                .end = end,
            };
        }

        fn begin(context: *anyopaque, head: http.ResponseHead) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.status = head.status;
        }

        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try self.body.appendSlice(self.allocator, bytes);
        }

        fn end(context: *anyopaque, trailers: []const http.DuplexHeader) !void {
            _ = context;
            _ = trailers;
        }
    };

    var handle = try pool.startRequest(uri, .{
        .method = "POST",
        .body = "hello world",
    });
    var handle_closed = false;
    defer if (!handle_closed) handle.deinit();
    try std.testing.expectEqual(http.Protocol.http1, handle.protocol());

    try handle.writeBody("hello ");
    try handle.writeBody("world");
    try handle.finishBody();

    var sink = Sink{ .allocator = allocator };
    defer sink.body.deinit(allocator);
    const head = try handle.readResponse(sink.sink());
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqualStrings("streamed", sink.body.items);

    handle.deinit();
    handle_closed = true;
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
