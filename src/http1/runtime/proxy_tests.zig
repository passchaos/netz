const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

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

test "HTTP1 forward proxy sends strict absolute-form requests persistently" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer proxy.deinit();

    const Shared = struct {
        proxy: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.proxy.accept();
            defer connection.close();
            const expected_targets = [_][]const u8{
                "http://example.com:8080/one?q=1",
                "http://other.example/two",
            };
            const expected_hosts = [_][]const u8{
                "example.com:8080",
                "other.example",
            };
            for (expected_targets, expected_hosts, 0..) |
                expected_target,
                expected_host,
                index,
            | {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.proxy.allocator);
                try std.testing.expectEqualStrings(
                    expected_target,
                    request.request.target,
                );
                try std.testing.expectEqualStrings(
                    expected_host,
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

    var client = try runtime.Client.connect(
        allocator,
        io,
        proxy.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const proxy_options = runtime.ProxyOptions{ .headers = &.{.{
        .name = "Proxy-Authorization",
        .value = "Basic cHJveHk=",
    }} };
    var first = try client.requestForwardProxyUri(
        "http://example.com:8080/one?q=1#not-on-wire",
        .{ .headers = &.{.{ .name = "X-Origin", .value = "one" }} },
        proxy_options,
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("proxy-one", first.response.body);
    var second = try client.requestForwardProxyUriWithTimeout(
        "http://other.example/two",
        .{ .headers = &.{.{ .name = "X-Origin", .value = "two" }} },
        proxy_options,
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("proxy-two", second.response.body);
    try std.testing.expectError(
        error.UnsupportedScheme,
        client.requestForwardProxyUri(
            "https://example.com/secure",
            .{},
            proxy_options,
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        client.requestForwardProxyUri(
            "http://user@example.com/private",
            .{},
            proxy_options,
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 HTTPS proxy CONNECT isolates headers and authenticates origin TLS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    var tls_server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer tls_server.deinit();

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        tls_server: *runtime.TlsServer,
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
            var connect = try runtime.readRequestFromStream(
                allocator,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer connect.deinit(allocator);
            try std.testing.expect(connect.request.method == .CONNECT);
            try std.testing.expectEqualStrings(
                "localhost:443",
                connect.request.target,
            );
            try std.testing.expectEqualStrings(
                "Basic dHVubmVs",
                connect.request.header("proxy-authorization").?,
            );
            try runtime.writeResponseToStream(
                allocator,
                self.io,
                stream,
                .{ .status = 200, .request_method = .CONNECT },
            );

            var origin = try self.tls_server.acceptStream(stream);
            owned = false;
            defer origin.close();
            var request = try origin.readRequest(.{});
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/secure?q=1",
                request.request.target,
            );
            try std.testing.expectEqualStrings(
                "localhost",
                request.request.header("host").?,
            );
            try std.testing.expect(
                request.request.header("proxy-authorization") == null,
            );
            try std.testing.expectEqualStrings(
                "origin-only",
                request.request.header("x-origin").?,
            );
            try origin.writeResponse(.{
                .status = 200,
                .body = "secure-through-proxy",
                .request_method = request.request.method,
            });
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .tls_server = &tls_server,
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
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var response = try runtime.Client.requestUriViaProxyWithTimeout(
        allocator,
        io,
        proxy_uri,
        "https://localhost/secure?q=1#not-on-wire",
        .{ .headers = &.{.{
            .name = "X-Origin",
            .value = "origin-only",
        }} },
        .{ .headers = &.{.{
            .name = "Proxy-Authorization",
            .value = "Basic dHVubmVs",
        }} },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
        .fromSeconds(3),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "secure-through-proxy",
        response.response.body,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 proxy helpers reject invalid endpoints and budgets before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriViaProxyWithTimeout(
            std.testing.allocator,
            io,
            "http://127.0.0.1:1",
            "http://example.com/",
            .{},
            .{},
            .{},
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedScheme,
        runtime.Client.requestUriViaProxy(
            std.testing.allocator,
            io,
            "https://proxy.example/",
            "http://example.com/",
            .{},
            .{},
            .{},
            .{},
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        runtime.Client.requestUriViaProxy(
            std.testing.allocator,
            io,
            "http://proxy.example/path",
            "http://example.com/",
            .{},
            .{},
            .{},
            .{},
        ),
    );
}
