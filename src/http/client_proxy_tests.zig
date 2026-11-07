//! Unified HTTP client and pool proxy routing regressions.
const std = @import("std");
const http = @import("mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2 = @import("../http2/mod.zig");
const http2_runtime = @import("../http2/runtime.zig");
const tls_testing = @import("../tls/testing.zig");
const net = std.Io.net;
const gpa = std.testing.allocator;

test "unified HTTP client rejects incompatible proxy routes" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(gpa, io, .{
        .http_proxy = .{ .uri = "https://proxy.example" },
    }));
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(gpa, io, .{
        .http_proxy = .{ .uri = "http://user@proxy.example" },
    }));
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(gpa, io, .{
        .http_proxy = .{ .uri = "http://proxy.example/path" },
    }));
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(gpa, io, .{
        .http_proxy = .{ .uri = "http://proxy.example" },
        .socks5_proxy = .{ .host = "socks.example" },
    }));
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(gpa, io, .{
        .http_proxy = .{ .uri = "http://proxy.example" },
        .cleartext_protocol = .http2_prior_knowledge,
    }));
}

test "unified HTTP pool reuses one cleartext forward-proxy connection" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try http1_runtime.Server.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer proxy.deinit();

    const Shared = struct {
        proxy: *http1_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.proxy.accept();
            defer connection.close();
            const targets = [_][]const u8{
                "http://example.com:8080/one?q=1",
                "http://example.com:8080/two",
            };
            for (targets, 0..) |expected, index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.proxy.allocator);
                try std.testing.expectEqualStrings(expected, request.request.target);
                try std.testing.expectEqualStrings(
                    "example.com:8080",
                    request.request.header("host").?,
                );
                try std.testing.expectEqualStrings(
                    "Basic cHJveHk=",
                    request.request.header("proxy-authorization").?,
                );
                try std.testing.expectEqualStrings(
                    if (index == 0) "one" else "two",
                    request.request.header("x-origin").?,
                );
                try connection.writeResponse(.{
                    .status = 200,
                    .body = if (index == 0) "proxy-one" else "proxy-two",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var shared = Shared{ .proxy = &proxy };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{proxy.address().getPort()},
    );
    var pool = try http.Pool.init(gpa, io, .{
        .max_connections = 4,
        .client = .{
            .protocol_policy = .http1_only,
            .cleartext_protocol = .http1,
            .http_proxy = .{
                .uri = proxy_uri,
                .headers = &.{.{
                    .name = "Proxy-Authorization",
                    .value = "Basic cHJveHk=",
                }},
            },
        },
    });
    defer pool.deinit();

    var first = try pool.requestUri("http://example.com:8080/one?q=1#ignored", .{
        .headers = &.{.{ .name = "X-Origin", .value = "one" }},
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status());
    try std.testing.expectEqualStrings("proxy-one", first.body());

    var second = try pool.requestUri("http://example.com:8080/two", .{
        .headers = &.{.{ .name = "X-Origin", .value = "two" }},
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status());
    try std.testing.expectEqualStrings("proxy-two", second.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "unified HTTP client CONNECTs through an HTTP proxy before origin TLS" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var origin = try http1_runtime.TlsServer.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer origin.deinit();

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        origin: *http1_runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var owned = true;
            defer if (owned) stream.close(self.io);
            var connect = try http1_runtime.readRequestFromStream(
                gpa,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer connect.deinit(gpa);
            try std.testing.expect(connect.request.method == .CONNECT);
            const expected_authority = try std.fmt.allocPrint(
                gpa,
                "localhost:{d}",
                .{self.origin.address().getPort()},
            );
            defer gpa.free(expected_authority);
            try std.testing.expectEqualStrings(
                expected_authority,
                connect.request.target,
            );
            try std.testing.expectEqualStrings(
                "Basic dHVubmVs",
                connect.request.header("proxy-authorization").?,
            );
            try http1_runtime.writeResponseToStream(
                gpa,
                self.io,
                stream,
                .{ .status = 200, .request_method = .CONNECT },
            );

            var connection = try self.origin.acceptStream(stream);
            owned = false;
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(gpa);
            try std.testing.expectEqualStrings("/secure?q=1", request.request.target);
            try std.testing.expect(
                request.request.header("proxy-authorization") == null,
            );
            try std.testing.expectEqualStrings(
                "origin-only",
                request.request.header("x-origin").?,
            );
            try connection.writeResponse(.{
                .status = 200,
                .body = "secure-through-proxy",
                .request_method = request.request.method,
            });
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .origin = &origin,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{listener.socket.address.getPort()},
    );
    var client = try http.Client.init(gpa, io, .{
        .protocol_policy = .http1_only,
        .http_proxy = .{
            .uri = proxy_uri,
            .headers = &.{.{
                .name = "Proxy-Authorization",
                .value = "Basic dHVubmVs",
            }},
        },
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
        } },
    });
    defer client.deinit();
    const secure_uri = try std.fmt.allocPrint(
        gpa,
        "https://localhost:{d}/secure?q=1#ignored",
        .{origin.address().getPort()},
    );
    defer gpa.free(secure_uri);
    var response = try client.requestUri(secure_uri, .{
        .headers = &.{.{ .name = "X-Origin", .value = "origin-only" }},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status());
    try std.testing.expectEqualStrings("secure-through-proxy", response.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "unified HTTP pool reuses one h2 connection through CONNECT" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const limits = http2_runtime.Limits{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var origin = try http2_runtime.TlsServer.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .protocol_policy = .tls13_only,
            .limits = limits,
        },
    );
    defer origin.deinit();

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        origin: *http2_runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var owned = true;
            defer if (owned) stream.close(self.io);
            var connect = try http1_runtime.readRequestFromStream(
                gpa,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer connect.deinit(gpa);
            try std.testing.expect(connect.request.method == .CONNECT);
            const expected_authority = try std.fmt.allocPrint(
                gpa,
                "localhost:{d}",
                .{self.origin.address().getPort()},
            );
            defer gpa.free(expected_authority);
            try std.testing.expectEqualStrings(
                expected_authority,
                connect.request.target,
            );
            try std.testing.expectEqualStrings(
                "Basic cHJveHk=",
                connect.request.header("proxy-authorization").?,
            );
            try http1_runtime.writeResponseToStream(
                gpa,
                self.io,
                stream,
                .{ .status = 200, .request_method = .CONNECT },
            );

            var connection = try self.origin.acceptStreamWithTimeout(
                stream,
                .fromSeconds(3),
            );
            owned = false;
            defer connection.close();
            const paths = [_][]const u8{ "/one", "/two" };
            for (paths, 0..) |path, index| {
                var request = try connection.readRequest();
                defer request.deinit(gpa);
                try std.testing.expectEqualStrings(path, request.path);
                try std.testing.expectEqualStrings("https", request.scheme);
                try std.testing.expectEqualStrings(
                    expected_authority,
                    request.authority.?,
                );
                try std.testing.expect(
                    headerValue(request.headers, "proxy-authorization") == null,
                );
                try connection.writeResponse(request.stream_id, .{
                    .status = 200,
                    .body = if (index == 0) "h2-one" else "h2-two",
                    .request_method = request.method,
                });
            }
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .origin = &origin,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{listener.socket.address.getPort()},
    );
    var pool = try http.Pool.init(gpa, io, .{
        .max_connections = 4,
        .client = .{
            .protocol_policy = .http2_only,
            .http_proxy = .{
                .uri = proxy_uri,
                .headers = &.{.{
                    .name = "Proxy-Authorization",
                    .value = "Basic cHJveHk=",
                }},
            },
            .tls = .{
                .protocol_policy = .tls13_only,
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
                },
            },
        },
    });
    defer pool.deinit();

    const first_uri = try std.fmt.allocPrint(
        gpa,
        "https://localhost:{d}/one",
        .{origin.address().getPort()},
    );
    defer gpa.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        gpa,
        "https://localhost:{d}/two",
        .{origin.address().getPort()},
    );
    defer gpa.free(second_uri);

    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit();
    try std.testing.expectEqual(http.Protocol.http2, first.protocol());
    try std.testing.expectEqual(@as(u16, 200), first.status());
    try std.testing.expectEqualStrings("h2-one", first.body());

    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit();
    try std.testing.expectEqual(http.Protocol.http2, second.protocol());
    try std.testing.expectEqual(@as(u16, 200), second.status());
    try std.testing.expectEqualStrings("h2-two", second.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn headerValue(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}
