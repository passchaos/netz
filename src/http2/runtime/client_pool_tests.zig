const std = @import("std");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");
const http2 = @import("../mod.zig");
const tls_testing = @import("../../tls/testing.zig");
const tls_stream = @import("../../tls/mod.zig").stream;

fn findHeader(headers: anytype, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn uriFor(
    allocator: std.mem.Allocator,
    scheme: []const u8,
    address: std.Io.net.IpAddress,
    path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}{s}",
        .{ scheme, address.ip4.port, path },
    );
}

test "HTTP/2 client pool reuses one persistent connection" {
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
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.close();
            for (0..2) |index| {
                var request = connection.readRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                const expected = if (index == 0) "/one" else "/two?x=1";
                if (!std.mem.eql(u8, request.path, expected)) {
                    self.err = error.InvalidRequest;
                    return;
                }
                connection.writeResponse(request.stream_id, .{
                    .body = if (index == 0) "one" else "two",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, "http", server.address(), "/one");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(
        allocator,
        "http",
        server.address(),
        "/two?x=1",
    );
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.body);
    try std.testing.expectEqualStrings("two", second.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "HTTP/2 client pool multiplexes same-origin URI batch" {
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
        requests: usize = 0,
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
            var requests: [3]runtime.OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(self.server.allocator);
            };
            for (&requests) |*request| {
                request.* = try connection.readRequest();
                initialized += 1;
                self.requests += 1;
            }
            var stream_ids: [requests.len]u31 = undefined;
            var headers: [requests.len]http2.Hpack.HeaderField =
                undefined;
            var responses: [requests.len]runtime.ResponseOptions = undefined;
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                const output = requests.len - 1 - index;
                stream_ids[output] = requests[index].stream_id;
                headers[output] = .{
                    .name = "x-path",
                    .value = requests[index].path,
                };
                responses[output] = .{
                    .headers = headers[output..][0..1],
                    .request_method = requests[index].method,
                };
            }
            try connection.writeResponseBatch(&stream_ids, &responses);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const port = server.address().ip4.port;
    const first = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/one",
        .{port},
    );
    defer allocator.free(first);
    const second = try std.fmt.allocPrint(
        allocator,
        "http://LOCALHOST:{d}/two?x=1",
        .{port},
    );
    defer allocator.free(second);
    const third = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/three",
        .{port},
    );
    defer allocator.free(third);
    const requests = [_]pool_mod.UriBatchRequest{
        .{ .uri = first },
        .{ .uri = second },
        .{ .uri = third },
    };
    var responses: [requests.len]runtime.OwnedResponse = undefined;
    try pool.requestUriBatchWithTimeout(
        &requests,
        &responses,
        .fromSeconds(3),
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/one",
        findHeader(responses[0].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/two?x=1",
        findHeader(responses[1].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/three",
        findHeader(responses[2].headers, "x-path").?,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
    try std.testing.expectEqual(@as(usize, 3), shared.requests);
}

test "HTTP/2 client pool rejects mixed-origin and invalid trailer URI batches" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(allocator, threaded.io(), .{});
    defer pool.deinit();
    var responses: [2]runtime.OwnedResponse = undefined;
    try std.testing.expectError(
        error.MixedBatchOrigins,
        pool.requestUriBatch(&.{
            .{ .uri = "http://localhost:1/one" },
            .{ .uri = "http://localhost:2/two" },
        }, &responses),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        pool.requestUriBatch(&.{
            .{
                .uri = "http://localhost:1/one",
                .request = .{ .trailers = &.{.{
                    .name = "content-length",
                    .value = "0",
                }} },
            },
            .{ .uri = "http://localhost:1/two" },
        }, &responses),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/2 client connect timeout is available through direct and pool APIs" {
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
    const uri = try uriFor(
        allocator,
        "http",
        address,
        "/connect-timeout",
    );
    defer allocator.free(uri);
    try std.testing.expectError(error.Timeout, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/2 client pool retries stale reused idempotent connection once" {
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
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var first = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            var seed = first.readRequest() catch |err| {
                first.close();
                self.err = err;
                return;
            };
            const seed_stream_id = seed.stream_id;
            seed.deinit(self.server.allocator);
            first.writeResponse(seed_stream_id, .{ .body = "seed" }) catch |err| {
                first.close();
                self.err = err;
                return;
            };
            first.close();

            var second = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer second.close();
            var retried = second.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer retried.deinit(self.server.allocator);
            if (!std.mem.eql(u8, retried.path, "/retry")) {
                self.err = error.InvalidRequest;
                return;
            }
            if (!std.mem.eql(u8, retried.method, "QUERY")) {
                self.err = error.InvalidMethod;
                return;
            }
            second.writeResponse(retried.stream_id, .{
                .body = "retried",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const seed_uri = try uriFor(allocator, "http", server.address(), "/seed");
    defer allocator.free(seed_uri);
    const retry_uri = try uriFor(allocator, "http", server.address(), "/retry");
    defer allocator.free(retry_uri);
    var seed = try pool.requestUri(seed_uri, .{});
    seed.deinit(allocator);
    var retried = try pool.requestUri(retry_uri, .{ .method = "QUERY" });
    defer retried.deinit(allocator);
    try std.testing.expectEqualStrings("retried", retried.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/2 client pool retries stale idempotent URI batch once" {
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
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            self.accepts += 1;
            var seed = try first.readRequest();
            const seed_stream_id = seed.stream_id;
            seed.deinit(self.server.allocator);
            try first.writeResponse(seed_stream_id, .{ .body = "seed" });
            first.close();

            var second = try self.server.accept();
            self.accepts += 1;
            defer second.close();
            var requests: [2]runtime.OwnedRequest = undefined;
            for (&requests) |*request| request.* = try second.readRequest();
            defer for (&requests) |*request| {
                request.deinit(self.server.allocator);
            };
            try std.testing.expectEqualStrings("/batch-one", requests[0].path);
            try std.testing.expectEqualStrings("/batch-two", requests[1].path);
            try std.testing.expectEqualStrings("GET", requests[0].method);
            try std.testing.expectEqualStrings("QUERY", requests[1].method);
            try second.writeResponseBatch(
                &.{ requests[1].stream_id, requests[0].stream_id },
                &.{
                    .{ .headers = &.{.{ .name = "x-result", .value = "two" }} },
                    .{ .headers = &.{.{ .name = "x-result", .value = "one" }} },
                },
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const seed_uri = try uriFor(allocator, "http", server.address(), "/seed");
    defer allocator.free(seed_uri);
    const first_uri = try uriFor(
        allocator,
        "http",
        server.address(),
        "/batch-one",
    );
    defer allocator.free(first_uri);
    const second_uri = try uriFor(
        allocator,
        "http",
        server.address(),
        "/batch-two",
    );
    defer allocator.free(second_uri);
    var seed = try pool.requestUri(seed_uri, .{});
    seed.deinit(allocator);
    const batch_requests = [_]pool_mod.UriBatchRequest{
        .{ .uri = first_uri },
        .{ .uri = second_uri, .request = .{ .method = "QUERY" } },
    };
    var responses: [batch_requests.len]runtime.OwnedResponse = undefined;
    try pool.requestUriBatch(&batch_requests, &responses);
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "one",
        findHeader(responses[0].headers, "x-result").?,
    );
    try std.testing.expectEqualStrings(
        "two",
        findHeader(responses[1].headers, "x-result").?,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/2 client pool caps leases and discards active streams" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch {
                // The client deliberately closes an unfinished stream. Any
                // terminal transport result is sufficient here; the pool
                // assertions prove that the connection was not retained.
                return;
            };
            request.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, "http", server.address(), "/active");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try std.testing.expectError(
        error.ConnectionLimitReached,
        pool.acquireUri(uri),
    );
    _ = try lease.connection().startRequest(.{
        .method = "POST",
        .path = "/active",
        .body_length = null,
    });
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client pool discards GOAWAY connections" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.sendGoAway(
                request.stream_id,
                .no_error,
                "pool-drain",
            ) catch |err| {
                self.err = err;
                return;
            };
            connection.writeResponse(request.stream_id, .{
                .body = "done",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const uri = try uriFor(allocator, "http", server.address(), "/goaway");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("done", response.body);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client pool replaces an idle authority at total capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
    const Once = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.writeResponse(request.stream_id, .{
                .body = "ok",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var first_task = Once{ .server = &first_server };
    var second_task = Once{ .server = &second_server };
    const first_thread = try std.Thread.spawn(.{}, Once.run, .{&first_task});
    const second_thread = try std.Thread.spawn(.{}, Once.run, .{&second_task});
    var first_joined = false;
    var second_joined = false;
    defer if (!first_joined) first_thread.join();
    defer if (!second_joined) second_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const first_uri = try uriFor(
        allocator,
        "http",
        first_server.address(),
        "/one",
    );
    defer allocator.free(first_uri);
    const second_uri = try uriFor(
        allocator,
        "http",
        second_server.address(),
        "/two",
    );
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
    if (first_task.err) |err| return err;
    if (second_task.err) |err| return err;
}

test "HTTP/2 client pool expires idle connections" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.writeResponse(request.stream_id, .{
                .body = "idle",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .idle_timeout = .fromMilliseconds(10),
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, "http", server.address(), "/idle");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client pool waits for a released connection" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.writeResponse(request.stream_id, .{
                .body = "waited",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        reused: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.reused = lease.was_reused;
            lease.discard();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, "http", server.address(), "/wait");
    defer allocator.free(uri);
    var first = try pool.acquireUri(uri);
    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    var response = try first.connection().request(.{ .path = "/wait" });
    response.deinit(allocator);
    first.release();
    first.release();
    first.discard();
    try std.testing.expect(!first.active);
    waiter_thread.join();
    if (waiter.err) |err| return err;
    try std.testing.expect(waiter.reused);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client pool admits capacity waiters in FIFO order" {
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
    const uri = try uriFor(allocator, "http", server.address(), "/fifo");
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

test "HTTP/2 client pool wait times out and close wakes waiters" {
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
    const uri = try uriFor(allocator, "http", server.address(), "/timeout");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
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
    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    pool.close();
    waiter_thread.join();
    try std.testing.expectEqual(error.PoolClosed, waiter.err.?);
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 pool request deadline spans capacity wait and response" {
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
            var request = try second.readRequest();
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
        .limits = .{
            .connect_timeout = .fromSeconds(1),
            .handshake_timeout = .fromSeconds(1),
        },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, "http", server.address(), "/deadline");
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

test "HTTP/2 pool request timeout rejects a non-positive budget" {
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

test "HTTP/2 pool deadline rejects a non-awake clock before URI parsing" {
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

test "HTTP/2 client pool reuses verified TLS connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.close();
            for (0..2) |_| {
                var request = connection.readRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                connection.writeResponse(request.stream_id, .{
                    .body = "secure",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, "https", server.address(), "/one");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, "https", server.address(), "/two");
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("secure", first.body);
    try std.testing.expectEqualStrings("secure", second.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

fn testTlsTicketResumptionAfterRetirement(
    comptime protocol_policy: tls_stream.VersionPolicy,
) !void {
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
    var keyring = try tls_stream.Tls13TicketKeyring.init(.{
        .id = 31,
        .secret = [_]u8{0x31} ** tls_stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .protocol_policy = protocol_policy,
            .tls12_session_tickets = if (protocol_policy == .tls12_only) .{
                .keyring = &keyring,
                .server_id = "127.0.0.1",
                .lifetime_seconds = 3600,
            } else null,
            .tls13_session_tickets = if (protocol_policy == .tls13_only) .{
                .keyring = &keyring,
                .server_id = "127.0.0.1",
                .lifetime_seconds = 3600,
            } else null,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.TlsServer,
        resumed: [2]bool = .{ false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var connection = try self.server.accept();
                defer connection.close();
                self.resumed[index] = connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                var request = try connection.readRequest();
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(request.stream_id, .{
                    .body = if (index == 0) "first" else "second",
                });
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
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .protocol_policy = protocol_policy,
        },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, "https", server.address(), "/ticket");
    defer allocator.free(uri);
    var first = try pool.requestUri(uri, .{});
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.body);
    var second = try pool.requestUri(uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(bool, &.{ false, true }, &shared.resumed);
}

test "HTTP/2 client pool resumes TLS 1.2 ticket after retirement" {
    try testTlsTicketResumptionAfterRetirement(.tls12_only);
}

test "HTTP/2 client pool resumes TLS 1.3 ticket after retirement" {
    try testTlsTicketResumptionAfterRetirement(.tls13_only);
}
