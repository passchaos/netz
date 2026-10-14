const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

fn findHeader(
    headers: []const http1.Header,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn uri(
    buffer: []u8,
    address: net.IpAddress,
    path: []const u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "http://127.0.0.1:{d}{s}",
        .{ address.getPort(), path },
    );
}

test "HTTP URI redirect rewrites POST 303 to credential-preserving GET" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const first_stream = try self.listener.accept(self.io);
            defer first_stream.close(self.io);
            var first = try runtime.readRequestFromStream(
                allocator,
                self.io,
                first_stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer first.deinit(allocator);
            try std.testing.expect(first.request.method == .POST);
            try std.testing.expectEqualStrings("/a/start", first.request.target);
            try std.testing.expectEqualStrings("payload", first.request.body);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                first.request.header("authorization").?,
            );
            try runtime.writeResponseToStream(
                allocator,
                self.io,
                first_stream,
                .{
                    .status = 303,
                    .reason = "See Other",
                    .headers = &.{.{
                        .name = "Location",
                        .value = "../final?q=1#not-on-wire",
                    }},
                    .body = "redirect",
                    .request_method = .POST,
                },
            );

            const second_stream = try self.listener.accept(self.io);
            defer second_stream.close(self.io);
            var second = try runtime.readRequestFromStream(
                allocator,
                self.io,
                second_stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer second.deinit(allocator);
            try std.testing.expect(second.request.method == .GET);
            try std.testing.expectEqualStrings("/final?q=1", second.request.target);
            try std.testing.expectEqual(@as(usize, 0), second.request.body.len);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                second.request.header("authorization").?,
            );
            try std.testing.expect(second.request.header("content-type") == null);
            try std.testing.expect(second.request.header("content-digest") == null);
            try std.testing.expect(second.request.header("content-length") == null);
            try runtime.writeResponseToStream(
                allocator,
                self.io,
                second_stream,
                .{ .status = 200, .body = "accepted", .request_method = .GET },
            );
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var uri_buffer: [96]u8 = undefined;
    var result = try runtime.Client.requestUriFollowingRedirectsDetailedWithTimeout(
        allocator,
        io,
        try uri(&uri_buffer, listener.socket.address, "/a/start#initial"),
        .{
            .method = .POST,
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer same-origin" },
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "Content-Digest", .value = "sha-256=:AAAA:" },
            },
            .body = "payload",
        },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqualStrings("accepted", result.response.response.body);
    var expected_buffer: [96]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buffer,
        "http://127.0.0.1:{d}/final?q=1",
        .{listener.socket.address.getPort()},
    );
    try std.testing.expectEqualStrings(expected, result.final_uri);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP cross-origin redirect strips credentials and preserves representation headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer redirector.deinit(io);
    var destination = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer destination.deinit(io);
    var destination_uri_buffer: [96]u8 = undefined;
    const destination_uri = try uri(
        &destination_uri_buffer,
        destination.socket.address,
        "/final",
    );

    const Shared = struct {
        io: std.Io,
        redirector: *net.Server,
        destination: *net.Server,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const first_stream = try self.redirector.accept(self.io);
            defer first_stream.close(self.io);
            var first = try runtime.readRequestFromStream(
                allocator,
                self.io,
                first_stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer first.deinit(allocator);
            try std.testing.expectEqualStrings(
                "Bearer secret",
                first.request.header("authorization").?,
            );
            try std.testing.expectEqualStrings(
                "session=secret",
                first.request.header("cookie").?,
            );
            try std.testing.expectEqualStrings(
                "trailer-secret",
                findHeader(first.request.trailers, "x-secret").?,
            );
            try runtime.writeResponseToStream(
                allocator,
                self.io,
                first_stream,
                .{
                    .status = 307,
                    .reason = "Temporary Redirect",
                    .headers = &.{.{
                        .name = "Location",
                        .value = self.destination_uri,
                    }},
                    .request_method = .POST,
                },
            );

            const second_stream = try self.destination.accept(self.io);
            defer second_stream.close(self.io);
            var second = try runtime.readRequestFromStream(
                allocator,
                self.io,
                second_stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer second.deinit(allocator);
            try std.testing.expect(second.request.method == .POST);
            try std.testing.expectEqualStrings("payload", second.request.body);
            try std.testing.expect(second.request.header("authorization") == null);
            try std.testing.expect(second.request.header("cookie") == null);
            try std.testing.expect(second.request.header("trailer") == null);
            try std.testing.expectEqual(@as(usize, 0), second.request.trailers.len);
            try std.testing.expectEqualStrings(
                "application/json",
                second.request.header("accept").?,
            );
            try runtime.writeResponseToStream(
                allocator,
                self.io,
                second_stream,
                .{ .status = 200, .body = "done", .request_method = .POST },
            );
        }
    };
    var shared = Shared{
        .io = io,
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var initial_uri_buffer: [96]u8 = undefined;
    var response = try runtime.Client.requestUriFollowingRedirects(
        allocator,
        io,
        try uri(&initial_uri_buffer, redirector.socket.address, "/start"),
        .{
            .method = .POST,
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer secret" },
                .{ .name = "Cookie", .value = "session=secret" },
                .{ .name = "Accept", .value = "application/json" },
                .{ .name = "Trailer", .value = "X-Secret" },
            },
            .body = "payload",
            .trailers = &.{.{
                .name = "X-Secret",
                .value = "trailer-secret",
            }},
        },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("done", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP 307 redirect preserves method body and content headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                const stream = try self.listener.accept(self.io);
                defer stream.close(self.io);
                var request = try runtime.readRequestFromStream(
                    allocator,
                    self.io,
                    stream,
                    .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                    .{},
                );
                defer request.deinit(allocator);
                try std.testing.expect(request.request.method == .POST);
                try std.testing.expectEqualStrings("replay", request.request.body);
                try std.testing.expectEqualStrings(
                    "application/octet-stream",
                    request.request.header("content-type").?,
                );
                if (index == 0) {
                    try runtime.writeResponseToStream(
                        allocator,
                        self.io,
                        stream,
                        .{
                            .status = 307,
                            .reason = "Temporary Redirect",
                            .headers = &.{.{
                                .name = "Location",
                                .value = "/replayed",
                            }},
                            .request_method = .POST,
                        },
                    );
                } else {
                    try std.testing.expectEqualStrings(
                        "/replayed",
                        request.request.target,
                    );
                    try runtime.writeResponseToStream(
                        allocator,
                        self.io,
                        stream,
                        .{
                            .status = 200,
                            .body = "preserved",
                            .request_method = .POST,
                        },
                    );
                }
            }
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var uri_buffer: [96]u8 = undefined;
    var response = try runtime.Client.requestUriFollowingRedirects(
        allocator,
        io,
        try uri(&uri_buffer, listener.socket.address, "/upload"),
        .{
            .method = .POST,
            .headers = &.{.{
                .name = "Content-Type",
                .value = "application/octet-stream",
            }},
            .body = "replay",
        },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("preserved", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
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

test "HTTPS redirect authenticates every origin" {
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
    const listen_options: runtime.TlsListenOptions = .{ .identity = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    } };
    var redirector = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        listen_options,
    );
    defer redirector.deinit();
    var destination = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        listen_options,
    );
    defer destination.deinit();
    const destination_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/secure",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        redirector: *runtime.TlsServer,
        destination: *runtime.TlsServer,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.redirector.accept();
            defer first.close();
            var first_request = try first.readRequest(.{});
            defer first_request.deinit(allocator);
            try first.writeResponse(.{
                .status = 308,
                .reason = "Permanent Redirect",
                .headers = &.{.{
                    .name = "Location",
                    .value = self.destination_uri,
                }},
                .request_method = first_request.request.method,
            });

            var second = try self.destination.accept();
            defer second.close();
            var second_request = try second.readRequest(.{});
            defer second_request.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/secure",
                second_request.request.target,
            );
            try second.writeResponse(.{
                .status = 200,
                .body = "secure-final",
                .request_method = second_request.request.method,
            });
        }
    };
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_uri);
    var response = try runtime.Client.requestUriFollowingRedirectsWithTimeout(
        allocator,
        io,
        initial_uri,
        .{},
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{ .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } } },
        .fromSeconds(5),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("secure-final", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP redirects retain forward proxy and isolate credentials" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                const stream = try self.proxy.accept(self.io);
                defer stream.close(self.io);
                var request = try runtime.readRequestFromStream(
                    allocator,
                    self.io,
                    stream,
                    .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                    .{},
                );
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(
                    "Basic cHJveHk=",
                    request.request.header("proxy-authorization").?,
                );
                if (index == 0) {
                    try std.testing.expectEqualStrings(
                        "http://initial.example/start",
                        request.request.target,
                    );
                    try std.testing.expectEqualStrings(
                        "Bearer origin",
                        request.request.header("authorization").?,
                    );
                    try runtime.writeResponseToStream(
                        allocator,
                        self.io,
                        stream,
                        .{
                            .status = 302,
                            .reason = "Found",
                            .headers = &.{.{
                                .name = "Location",
                                .value = "http://final.example/end",
                            }},
                            .request_method = .GET,
                        },
                    );
                } else {
                    try std.testing.expectEqualStrings(
                        "http://final.example:80/end",
                        request.request.target,
                    );
                    try std.testing.expect(
                        request.request.header("authorization") == null,
                    );
                    try runtime.writeResponseToStream(
                        allocator,
                        self.io,
                        stream,
                        .{ .status = 200, .body = "proxied", .request_method = .GET },
                    );
                }
            }
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [96]u8 = undefined;
    var response = try runtime.Client.requestUriFollowingRedirects(
        allocator,
        io,
        "http://initial.example/start",
        .{ .headers = &.{.{
            .name = "Authorization",
            .value = "Bearer origin",
        }} },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{ .proxy = .{
            .uri = try uri(&proxy_uri_buffer, proxy.socket.address, ""),
            .options = .{ .headers = &.{.{
                .name = "Proxy-Authorization",
                .value = "Basic cHJveHk=",
            }} },
        } },
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("proxied", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP redirect timeout rejects zero budget before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://127.0.0.1:1/",
            .{},
            .{},
            .{},
            .zero,
        ),
    );
}
