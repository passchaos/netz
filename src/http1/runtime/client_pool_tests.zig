const std = @import("std");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

fn uriFor(
    allocator: std.mem.Allocator,
    address: std.Io.net.IpAddress,
    path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}{s}",
        .{ address.ip4.port, path },
    );
}

test "HTTP/1 client pool reuses one persistent connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
                    if (index == 0) "/first" else "/second?x=1",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(
        allocator,
        server.address(),
        "/second?x=1",
    );
    defer allocator.free(second_uri);
    var lease = try pool.acquireUri(first_uri);
    var first = try lease.client().request(.{ .target = "/first" });
    lease.release();
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "HTTP/1 client pool normalizes explicit default port keys" {
    const allocator = std.testing.allocator;
    // Parsing both spellings exercises the key path without requiring the
    // privileged default port to be bindable in a test environment.
    const implicit = try std.Uri.parse("http://example.com/");
    var implicit_endpoint = try runtime.uriEndpoint(allocator, implicit, 80);
    defer implicit_endpoint.deinit();
    const explicit = try std.Uri.parse("http://EXAMPLE.COM:80/");
    var explicit_endpoint = try runtime.uriEndpoint(allocator, explicit, 80);
    defer explicit_endpoint.deinit();
    try std.testing.expectEqual(implicit_endpoint.port, explicit_endpoint.port);
    try std.testing.expect(std.ascii.eqlIgnoreCase(
        implicit_endpoint.tls_host,
        explicit_endpoint.tls_host,
    ));
}

test "HTTP/1 client connect timeout is available through direct and pool APIs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1) };

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(allocator, io, address, .{
            .connect_timeout = .zero,
        }),
    );
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .limits = .{ .connect_timeout = .zero },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, address, "/connect-timeout");
    defer allocator.free(uri);
    try std.testing.expectError(error.Timeout, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool retries a stale idempotent connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            var request = try first.readRequest(.{});
            request.deinit(self.server.allocator);
            try first.writeResponse(.{ .body = "first" });
            first.close();

            var second = try self.server.accept();
            defer second.close();
            request = try second.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/retry", request.request.target);
            try second.writeResponse(.{ .body = "retried" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/seed");
    defer allocator.free(first_uri);
    const retry_uri = try uriFor(allocator, server.address(), "/retry");
    defer allocator.free(retry_uri);
    var first = try pool.requestUri(first_uri, .{});
    first.deinit(allocator);
    var retried = try pool.requestUri(retry_uri, .{});
    defer retried.deinit(allocator);
    try std.testing.expectEqualStrings("retried", retried.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool discards close in any Connection response field" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeResponse(.{
                // The first field alone advertises persistence. A later close
                // token must still make the parsed response and pool slot
                // non-reusable.
                .headers = &.{
                    .{ .name = "Connection", .value = "keep-alive" },
                    .{ .name = "connection", .value = "close" },
                },
                .body = "done",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/close");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    defer response.deinit(allocator);
    try std.testing.expect(!response.response.keepAlive());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool reuses verified TLS connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.TlsServer,
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
            for (0..2) |_| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try connection.writeResponse(.{ .body = "secure" });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/first",
        .{server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/second",
        .{server.address().ip4.port},
    );
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("secure", first.response.body);
    try std.testing.expectEqualStrings("secure", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "HTTP/1 client pool serves concurrent leases per authority" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const request_count = 4;
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var group: std.Io.Group = .init;
            defer group.cancel(self.server.io);
            var errors: [request_count]?anyerror = @splat(null);
            for (&errors) |*result| {
                const accepted = try self.server.accept();
                try group.concurrent(self.server.io, struct {
                    fn serve(
                        connection_value: runtime.Connection,
                        result_ptr: *?anyerror,
                        allocator_value: std.mem.Allocator,
                    ) std.Io.Cancelable!void {
                        var connection = connection_value;
                        defer connection.close();
                        var request = connection.readRequest(.{}) catch |err| {
                            result_ptr.* = err;
                            return;
                        };
                        defer request.deinit(allocator_value);
                        connection.writeResponse(.{ .body = "parallel" }) catch |err| {
                            result_ptr.* = err;
                        };
                    }
                }.serve, .{ accepted, result, self.server.allocator });
            }
            try group.await(self.server.io);
            for (errors) |err| if (err) |value| return value;
        }
    };
    const Requester = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired_count: *std.atomic.Value(usize),
        all_acquired: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var lease = self.pool.acquireUri(self.uri) catch |err| {
                self.err = err;
                // Avoid stranding peers at the barrier if setup itself fails;
                // their result still cannot make the test pass.
                self.all_acquired.set(self.pool.io);
                return;
            };
            defer if (lease.active) lease.discard();
            if (self.acquired_count.fetchAdd(1, .acq_rel) + 1 == request_count) {
                self.all_acquired.set(self.pool.io);
            }
            self.all_acquired.wait(self.pool.io) catch |err| {
                self.err = err;
                return;
            };
            var response = lease.client().request(.{
                .target = "/parallel",
            }) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit(self.pool.allocator);
            if (!std.mem.eql(u8, response.response.body, "parallel")) {
                self.err = error.InvalidResponse;
                return;
            }
            lease.release();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = request_count,
        .max_idle_connections = request_count,
        .max_idle_per_authority = request_count,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/parallel");
    defer allocator.free(uri);
    var acquired_count: std.atomic.Value(usize) = .init(0);
    var all_acquired: std.Io.Event = .unset;
    var requests: [request_count]Requester = undefined;
    var threads: [request_count]std.Thread = undefined;
    for (&requests, 0..) |*request, index| {
        request.* = .{
            .pool = &pool,
            .uri = uri,
            .acquired_count = &acquired_count,
            .all_acquired = &all_acquired,
        };
        threads[index] = try std.Thread.spawn(.{}, Requester.run, .{request});
    }
    for (&threads) |*thread| thread.join();
    for (requests) |request| if (request.err) |err| return err;
    try std.testing.expectEqual(request_count, pool.idleCount());
    try std.testing.expectEqual(
        request_count,
        try pool.idleCountForUri(uri),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool caps checked-out connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/limited");
    defer allocator.free(uri);
    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        pool.acquireUri(uri),
    );

    first.release();
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    var reused = try pool.acquireUri(uri);
    try std.testing.expect(reused.was_reused);
    reused.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool releases failed connection reservation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    const address = server.address();
    server.deinit();

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, address, "/unreachable");
    defer allocator.free(uri);
    try std.testing.expectError(error.ConnectionRefused, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectError(error.ConnectionRefused, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool waits for an idle lease within one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.acquired = lease.was_reused;
            lease.discard();
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) {
        shared.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/wait");
    defer allocator.free(uri);
    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;

    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    first.release();
    waiter_thread.join();
    if (waiter.err) |err| return err;
    try std.testing.expect(waiter.acquired);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool admits capacity waiters in FIFO order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            for (0..3) |_| {
                var connection = self.server.accept() catch |err| {
                    self.err = err;
                    return;
                };
                connection.close();
            }
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
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
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/fifo");
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

test "HTTP/1 client pool acquisition timeout preserves capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/timeout");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(uri, .fromMilliseconds(5)),
    );
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithDeadline(
            uri,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromMilliseconds(5),
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 pool request deadline spans capacity wait and response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        first_accepted: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_accepted.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            defer first.close();
            self.first_accepted.set(self.server.io);
            var second = try self.server.accept();
            defer second.close();
            var request = try second.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
        .limits = .{ .connect_timeout = .fromSeconds(1) },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/deadline");
    defer allocator.free(uri);
    var held = try pool.acquireUri(uri);
    try shared.first_accepted.wait(io);
    if (shared.err) |err| return err;

    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(60),
        .clock = .awake,
    });
    const Releaser = struct {
        io: std.Io,
        lease: *pool_mod.Lease,
        fn run(self: *@This()) void {
            std.Io.sleep(self.io, .fromMilliseconds(25), .awake) catch {};
            self.lease.discard();
        }
    };
    var releaser = Releaser{ .io = io, .lease = &held };
    const release_thread = try std.Thread.spawn(.{}, Releaser.run, .{&releaser});
    var release_joined = false;
    defer if (!release_joined) release_thread.join();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithDeadline(uri, .{}, deadline),
    );
    release_thread.join();
    release_joined = true;
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 pool request timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{},
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithTimeout(
            "http://localhost/",
            .{},
            .zero,
        ),
    );
}

test "HTTP/1 pool deadline rejects a non-awake clock before URI parsing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try pool_mod.Pool.init(std.testing.allocator, io, .{});
    defer pool.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .real },
    );

    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithDeadline("not a URI", deadline),
    );
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithDeadline("not a URI", .{}, deadline),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool close wakes blocked acquisition" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const ServerTask = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            lease.discard();
        }
    };

    var server_task = ServerTask{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerTask.run,
        .{&server_task},
    );
    var server_joined = false;
    defer if (!server_joined) {
        server_task.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/closed");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try server_task.accepted.wait(io);
    if (server_task.err) |err| return err;

    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    pool.close();
    waiter_thread.join();
    try std.testing.expectEqual(error.PoolClosed, waiter.err.?);
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_task.release.set(io);
    server_thread.join();
    server_joined = true;
    if (server_task.err) |err| return err;
}

test "HTTP/1 client pool enforces per-authority idle limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const request_count = 3;
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var group: std.Io.Group = .init;
            defer group.cancel(self.server.io);
            var errors: [request_count]?anyerror = @splat(null);
            for (&errors) |*result| {
                const accepted = try self.server.accept();
                try group.concurrent(self.server.io, struct {
                    fn serve(
                        connection_value: runtime.Connection,
                        result_ptr: *?anyerror,
                        allocator_value: std.mem.Allocator,
                    ) std.Io.Cancelable!void {
                        var connection = connection_value;
                        defer connection.close();
                        var request = connection.readRequest(.{}) catch |err| {
                            result_ptr.* = err;
                            return;
                        };
                        defer request.deinit(allocator_value);
                        connection.writeResponse(.{ .body = "bounded" }) catch |err| {
                            result_ptr.* = err;
                        };
                    }
                }.serve, .{ accepted, result, self.server.allocator });
            }
            try group.await(self.server.io);
            for (errors) |err| if (err) |value| return value;
        }
    };
    const Requester = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var response = self.pool.requestUri(self.uri, .{}) catch |err| {
                self.err = err;
                return;
            };
            response.deinit(self.pool.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = request_count,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/bounded");
    defer allocator.free(uri);
    var requests: [request_count]Requester = undefined;
    var threads: [request_count]std.Thread = undefined;
    for (&requests, 0..) |*request, index| {
        request.* = .{ .pool = &pool, .uri = uri };
        threads[index] = try std.Thread.spawn(.{}, Requester.run, .{request});
    }
    for (&threads) |*thread| thread.join();
    for (requests) |request| if (request.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        try pool.idleCountForUri(uri),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool zero idle capacity disables reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            for (0..2) |_| {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{ .body = "fresh" });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/fresh");
    defer allocator.free(uri);
    for (0..2) |_| {
        var response = try pool.requestUri(uri, .{});
        response.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool expires idle connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeResponse(.{ .body = "idle" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .idle_timeout = .fromMilliseconds(20),
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/idle");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool replaces an idle authority at total capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer first_server.deinit();
    var second_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer second_server.deinit();
    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeResponse(.{ .body = "ok" });
            // Give the pool time to evict and close the older idle socket.
            var byte: [1]u8 = undefined;
            const tcp = connection.stream;
            var bufs = [_][]u8{&byte};
            const count = try self.server.io.vtable.netRead(
                self.server.io.userdata,
                tcp.socket.handle,
                &bufs,
            );
            try std.testing.expectEqual(@as(usize, 0), count);
        }
    };
    const Once = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.writeResponse(.{ .body = "ok" }) catch |err| {
                self.err = err;
            };
        }
    };
    var first_shared = Shared{ .server = &first_server };
    var second_shared = Once{ .server = &second_server };
    const first_thread = try std.Thread.spawn(.{}, Shared.run, .{&first_shared});
    const second_thread = try std.Thread.spawn(.{}, Once.run, .{&second_shared});
    var first_joined = false;
    var second_joined = false;
    defer if (!first_joined) first_thread.join();
    defer if (!second_joined) second_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .idle_timeout = null,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, first_server.address(), "/one");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, second_server.address(), "/two");
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    second.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        try pool.idleCountForUri(first_uri),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        try pool.idleCountForUri(second_uri),
    );

    first_thread.join();
    first_joined = true;
    second_thread.join();
    second_joined = true;
    if (first_shared.err) |err| return err;
    if (second_shared.err) |err| return err;
}
