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

test "HTTP/1 client pool discards Connection close responses" {
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
                .headers = &.{.{ .name = "Connection", .value = "close" }},
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
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var response = self.pool.requestUri(self.uri, .{}) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit(self.pool.allocator);
            if (!std.mem.eql(u8, response.response.body, "parallel")) {
                self.err = error.InvalidResponse;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = request_count,
        .max_idle_per_authority = request_count,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/parallel");
    defer allocator.free(uri);
    var requests: [request_count]Requester = undefined;
    var threads: [request_count]std.Thread = undefined;
    for (&requests, 0..) |*request, index| {
        request.* = .{ .pool = &pool, .uri = uri };
        threads[index] = try std.Thread.spawn(.{}, Requester.run, .{request});
    }
    for (&threads) |*thread| thread.join();
    for (requests) |request| if (request.err) |err| return err;
    try std.testing.expectEqual(request_count, pool.idleCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
