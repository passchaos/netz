const std = @import("std");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

test "WebSocket URI follows relative redirect under one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer server.deinit();
    var jar = try @import("../../http/cookies/mod.zig").Jar.init(
        allocator,
        .{},
    );
    defer jar.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/a/start", first.target());
            try std.testing.expectEqualStrings(
                "Bearer redirect-origin",
                first.header("authorization").?,
            );
            try first.reject(
                307,
                "Temporary Redirect",
                &.{
                    .{
                        .name = "Location",
                        .value = "../final?q=1#not-on-wire",
                    },
                    .{
                        .name = "Set-Cookie",
                        .value = "redirect=one; Path=/",
                    },
                },
                "redirecting",
            );

            var second = try self.server.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/final?q=1", second.target());
            try std.testing.expectEqualStrings(
                "Bearer redirect-origin",
                second.header("authorization").?,
            );
            try std.testing.expectEqualStrings(
                "redirect=one",
                second.header("cookie").?,
            );
            var connection = try second.acceptWithHeaders(&.{.{
                .name = "Set-Cookie",
                .value = "accepted=two; Path=/",
            }});
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("redirected", message.payload);
            try connection.sendText("accepted");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/a/start#initial-fragment",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.CookieHeaderConflict,
        runtime.Client.connectUriFollowingRedirects(
            allocator,
            io,
            uri,
            .{ .extra_headers = &.{.{
                .name = "Cookie",
                .value = "caller=ambiguous",
            }} },
            .{ .cookies = .{ .jar = &jar } },
        ),
    );
    var connection = try runtime.Client.connectUriFollowingRedirectsWithTimeout(
        allocator,
        io,
        uri,
        .{ .extra_headers = &.{.{
            .name = "Authorization",
            .value = "Bearer redirect-origin",
        }} },
        .{ .cookies = .{ .jar = &jar } },
        .fromSeconds(3),
    );
    defer connection.close();
    try connection.sendText("redirected");
    var response = try connection.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("accepted", response.payload);
    const cookies = try jar.cookieHeaderValueAlloc(
        allocator,
        uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(cookies);
    try std.testing.expectEqualStrings(
        "redirect=one; accepted=two",
        cookies,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket cross-origin redirect strips custom headers and Host override" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer redirector.deinit();
    var destination = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer destination.deinit();
    var jar = try @import("../../http/cookies/mod.zig").Jar.init(
        allocator,
        .{},
    );
    defer jar.deinit();

    const Shared = struct {
        redirector: *runtime.Server,
        destination: *runtime.Server,
        destination_uri: []const u8,
        destination_host: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.redirector.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings(
                "Bearer do-not-forward",
                first.header("authorization").?,
            );
            try first.reject(
                302,
                "Found",
                &.{
                    .{ .name = "Location", .value = self.destination_uri },
                    .{
                        .name = "Set-Cookie",
                        .value = "origin_a=one; Path=/",
                    },
                },
                &.{},
            );

            var second = try self.destination.receiveUpgradeRequest(.{});
            try std.testing.expect(second.header("authorization") == null);
            try std.testing.expect(second.header("cookie") == null);
            try std.testing.expectEqualStrings(
                self.destination_host,
                second.header("host").?,
            );
            var connection = try second.acceptWithHeaders(&.{.{
                .name = "Set-Cookie",
                .value = "origin_b=two; Path=/",
            }});
            defer connection.close();
        }
    };
    const destination_uri = try std.fmt.allocPrint(
        allocator,
        "ws://localhost:{d}/final",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_uri);
    const destination_host = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_host);
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
        .destination_host = destination_host,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_uri);
    const initial_host = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_host);
    var connection = try runtime.Client.connectUriFollowingRedirects(
        allocator,
        io,
        initial_uri,
        .{
            .host = initial_host,
            .extra_headers = &.{.{
                .name = "Authorization",
                .value = "Bearer do-not-forward",
            }},
        },
        .{ .cookies = .{
            .jar = &jar,
            .request_context = .{ .top_level_navigation = true },
            .store_context = .{ .top_level_navigation = true },
        } },
    );
    connection.close();

    const first_cookie = try jar.cookieHeaderValueAlloc(
        allocator,
        initial_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(first_cookie);
    try std.testing.expectEqualStrings("origin_a=one", first_cookie);
    const second_cookie = try jar.cookieHeaderValueAlloc(
        allocator,
        destination_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(second_cookie);
    try std.testing.expectEqualStrings("origin_b=two", second_cookie);

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

test "WebSocket WSS redirect authenticates every origin" {
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
    var jar = try @import("../../http/cookies/mod.zig").Jar.init(
        allocator,
        .{},
    );
    defer jar.deinit();

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
            var first = try self.redirector.receiveUpgradeRequest(.{});
            try first.reject(
                308,
                "Permanent Redirect",
                &.{
                    .{ .name = "Location", .value = self.destination_uri },
                    .{
                        .name = "Set-Cookie",
                        .value = "secure=one; Secure; SameSite=None; Path=/",
                    },
                },
                &.{},
            );
            var second = try self.destination.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/secure", second.target());
            try std.testing.expectEqualStrings(
                "secure=one",
                second.header("cookie").?,
            );
            var connection = try second.accept();
            defer connection.close();
        }
    };
    const destination_uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/secure",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_uri);
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_uri);
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var connection = try runtime.Client.connectUriFollowingRedirectsWithTimeout(
        allocator,
        io,
        initial_uri,
        .{},
        .{
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .cookies = .{ .jar = &jar },
        },
        .fromSeconds(5),
    );
    connection.close();

    const secure_cookie = try jar.cookieHeaderValueAlloc(
        allocator,
        initial_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(secure_cookie);
    try std.testing.expectEqualStrings("secure=one", secure_cookie);
    const clear_uri = try std.fmt.allocPrint(
        allocator,
        "ws://localhost:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(clear_uri);
    const clear_cookie = try jar.cookieHeaderValueAlloc(
        allocator,
        clear_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(clear_cookie);
    try std.testing.expectEqualStrings("", clear_cookie);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket redirect attempt preserves final rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.receiveUpgradeRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            pending.reject(
                401,
                "Unauthorized",
                &.{.{ .name = "WWW-Authenticate", .value = "Bearer" }},
                "denied",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/denied",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var attempt = try runtime.Client.connectUriFollowingRedirectsAttempt(
        allocator,
        io,
        uri,
        .{},
        .{},
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings("denied", attempt.body());
    try std.testing.expectEqualStrings(
        "Bearer",
        attempt.responseHeader("www-authenticate").?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn acceptProxyTunnel(
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: *net.Server,
    expected_target: []const u8,
) !net.Stream {
    const stream = try listener.accept(io);
    var owned = true;
    errdefer if (owned) stream.close(io);
    var connect = try http1_runtime.readRequestFromStream(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
        .{},
    );
    defer connect.deinit(allocator);
    try std.testing.expect(connect.request.method == .CONNECT);
    try std.testing.expectEqualStrings(expected_target, connect.request.target);
    try std.testing.expectEqualStrings(
        "Basic cmVkaXJlY3QtcHJveHk=",
        connect.request.header("proxy-authorization").?,
    );
    try std.testing.expect(connect.request.header("authorization") == null);
    try http1_runtime.writeResponseToStream(
        allocator,
        io,
        stream,
        .{ .status = 200, .request_method = .CONNECT },
    );
    owned = false;
    return stream;
}

test "WebSocket redirects retain HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const first_stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "initial.example:80",
            );
            var first = try self.server.receiveStreamUpgradeRequest(
                first_stream,
                .{},
            );
            try std.testing.expectEqualStrings(
                "Bearer redirect-origin",
                first.header("authorization").?,
            );
            try first.reject(
                302,
                "Found",
                &.{.{
                    .name = "Location",
                    .value = "ws://final.example/end",
                }},
                &.{},
            );

            const second_stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "final.example:80",
            );
            var second = try self.server.receiveStreamUpgradeRequest(
                second_stream,
                .{},
            );
            try std.testing.expect(second.header("authorization") == null);
            try std.testing.expect(second.header("proxy-authorization") == null);
            try std.testing.expectEqualStrings(
                "final.example:80",
                second.header("host").?,
            );
            var connection = try second.accept();
            defer connection.close();
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{proxy.socket.address.getPort()},
    );
    var connection = try runtime.Client.connectUriFollowingRedirectsWithTimeout(
        allocator,
        io,
        "ws://initial.example/start",
        .{ .extra_headers = &.{.{
            .name = "Authorization",
            .value = "Bearer redirect-origin",
        }} },
        .{ .proxy = .{
            .uri = proxy_uri,
            .options = .{ .headers = &.{.{
                .name = "Proxy-Authorization",
                .value = "Basic cmVkaXJlY3QtcHJveHk=",
            }} },
        } },
        .fromSeconds(3),
    );
    connection.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket redirect timeout rejects zero budget before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectUriFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "ws://127.0.0.1:1/start",
            .{},
            .{},
            .zero,
        ),
    );
}
