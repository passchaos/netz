const std = @import("std");
const http = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2 = @import("../http2/mod.zig");
const http2_runtime = @import("../http2/runtime.zig");
const http3 = @import("../http3/mod.zig");
const http3_runtime = @import("../http3/runtime.zig");
const tls_testing = @import("../tls/testing.zig");
const vort = @import("vort");

fn findHeader(headers: anytype, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "unified HTTP responses iterate repeated headers and trailers" {
    const allocator = std.testing.allocator;
    var empty_bytes: [0]u8 = .{};
    var empty_body: [0]u8 = .{};

    var h1_headers = [_]http1.Header{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Link", .value = "</one>; rel=preload" },
        .{ .name = "set-cookie", .value = "b=2" },
    };
    var h1_trailers = [_]http1.Header{
        .{ .name = "X-Checksum", .value = "one" },
        .{ .name = "x-checksum", .value = "two" },
    };
    const h1 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http1 = .{
            .bytes = &empty_bytes,
            .response = .{
                .version = .http_1_1,
                .status = 200,
                .reason = "OK",
                .headers = &h1_headers,
                .body = &.{},
                .trailers = &h1_trailers,
                .consumed = 0,
            },
        } },
    };
    try expectUnifiedFields(
        h1,
        &.{ "Set-Cookie", "Link", "set-cookie" },
        &.{ false, false, false },
        &.{ "X-Checksum", "x-checksum" },
        &.{ false, false },
    );

    var h2_headers = [_]http2.Hpack.HeaderField{
        .{ .name = "set-cookie", .value = "a=1", .never_index = true },
        .{ .name = "link", .value = "</one>; rel=preload" },
        .{ .name = "set-cookie", .value = "b=2" },
    };
    var h2_trailers = [_]http2.Hpack.HeaderField{
        .{ .name = "x-checksum", .value = "one" },
        .{ .name = "x-checksum", .value = "two", .never_index = true },
    };
    const h2 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http2 = .{
            .headers = &h2_headers,
            .status = 200,
            .body = &empty_body,
            .trailers = &h2_trailers,
        } },
    };
    try expectUnifiedFields(
        h2,
        &.{ "set-cookie", "link", "set-cookie" },
        &.{ true, false, false },
        &.{ "x-checksum", "x-checksum" },
        &.{ false, true },
    );

    var h3_headers = [_]http3.Qpack.HeaderField{
        .{ .name = "set-cookie", .value = "a=1" },
        .{ .name = "link", .value = "</one>; rel=preload" },
        .{ .name = "set-cookie", .value = "b=2", .never_indexed = true },
    };
    var h3_trailers = [_]http3.Qpack.HeaderField{
        .{ .name = "x-checksum", .value = "one", .never_indexed = true },
        .{ .name = "x-checksum", .value = "two" },
    };
    const h3 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http3 = .{
            .stream_bytes = &empty_bytes,
            .response = .{
                .status = 200,
                .headers = &h3_headers,
                .body = &.{},
                .trailers = &h3_trailers,
                .consumed = 0,
            },
        } },
    };
    try expectUnifiedFields(
        h3,
        &.{ "set-cookie", "link", "set-cookie" },
        &.{ false, false, true },
        &.{ "x-checksum", "x-checksum" },
        &.{ true, false },
    );

    var empty_uri: [0]u8 = .{};
    const redirected = http.RedirectedResponse{
        .allocator = allocator,
        .response = h3,
        .final_uri = &empty_uri,
        .redirect_count = 1,
    };
    try std.testing.expectEqualStrings(
        "b=2",
        (blk: {
            var values = redirected.headerValues("SET-cookie");
            _ = values.next().?;
            break :blk values.next().?.value;
        }),
    );
    try std.testing.expectEqualStrings(
        "one",
        redirected.trailer("X-CHECKSUM").?,
    );
}

fn expectUnifiedFields(
    response: http.OwnedResponse,
    expected_header_names: []const []const u8,
    expected_header_never_indexed: []const bool,
    expected_trailer_names: []const []const u8,
    expected_trailer_never_indexed: []const bool,
) !void {
    const header_values = [_][]const u8{
        "a=1",
        "</one>; rel=preload",
        "b=2",
    };
    var headers = response.headers();
    for (
        expected_header_names,
        header_values,
        expected_header_never_indexed,
    ) |name, value, never_indexed| {
        const field = headers.next().?;
        try std.testing.expectEqualStrings(name, field.name);
        try std.testing.expectEqualStrings(value, field.value);
        try std.testing.expectEqual(never_indexed, field.never_indexed);
    }
    try std.testing.expect(headers.next() == null);
    try std.testing.expect(headers.next() == null);

    try std.testing.expectEqualStrings("a=1", response.header("SET-cookie").?);
    try std.testing.expect(response.header("missing") == null);
    var cookies = response.headerValues("SET-cookie");
    try std.testing.expectEqualStrings("a=1", cookies.next().?.value);
    try std.testing.expectEqualStrings("b=2", cookies.next().?.value);
    try std.testing.expect(cookies.next() == null);

    const trailer_values = [_][]const u8{ "one", "two" };
    var trailers = response.trailers();
    for (
        expected_trailer_names,
        trailer_values,
        expected_trailer_never_indexed,
    ) |name, value, never_indexed| {
        const field = trailers.next().?;
        try std.testing.expectEqualStrings(name, field.name);
        try std.testing.expectEqualStrings(value, field.value);
        try std.testing.expectEqual(never_indexed, field.never_indexed);
    }
    try std.testing.expect(trailers.next() == null);

    try std.testing.expectEqualStrings(
        "one",
        response.trailer("X-CHECKSUM").?,
    );
    try std.testing.expect(response.trailer("missing") == null);
    var checksums = response.trailerValues("X-CHECKSUM");
    try std.testing.expectEqualStrings("one", checksums.next().?.value);
    try std.testing.expectEqualStrings("two", checksums.next().?.value);
    try std.testing.expect(checksums.next() == null);
}

test "unified HTTP responses preserve bounded content decoding across protocols" {
    const allocator = std.testing.allocator;
    const payload = "unified stacked response decoding " ** 16;
    const deflate = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(deflate);
    const encoded = try vort.encodeGzipStoredAlloc(allocator, deflate);
    defer allocator.free(encoded);
    const max_layer_bytes = @max(payload.len, deflate.len);

    var h1_headers = [_]http1.Header{.{
        .name = "Content-Encoding",
        .value = "deflate, gzip",
    }};
    var empty_h1_bytes: [0]u8 = .{};
    const h1 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http1 = .{
            .bytes = &empty_h1_bytes,
            .response = .{
                .version = .http_1_1,
                .status = 200,
                .reason = "OK",
                .headers = &h1_headers,
                .body = encoded,
                .consumed = 0,
            },
        } },
    };
    try expectUnifiedDecoded(h1, payload, max_layer_bytes);

    var h2_headers = [_]http2.Hpack.HeaderField{.{
        .name = "content-encoding",
        .value = "deflate, gzip",
    }};
    const h2 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http2 = .{
            .headers = &h2_headers,
            .status = 200,
            .body = encoded,
        } },
    };
    try expectUnifiedDecoded(h2, payload, max_layer_bytes);

    var h3_headers = [_]http3.Qpack.HeaderField{.{
        .name = "content-encoding",
        .value = "deflate, gzip",
    }};
    var empty_h3_bytes: [0]u8 = .{};
    const h3 = http.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http3 = http3_runtime.OwnedHandshakeResponse{
            .stream_bytes = &empty_h3_bytes,
            .response = .{
                .status = 200,
                .headers = &h3_headers,
                .body = encoded,
                .consumed = 0,
            },
        } },
    };
    try expectUnifiedDecoded(h3, payload, max_layer_bytes);

    var empty_uri: [0]u8 = .{};
    const redirected = http.RedirectedResponse{
        .allocator = allocator,
        .response = h3,
        .final_uri = &empty_uri,
        .redirect_count = 1,
    };
    var redirected_decoded = try redirected.decodeContentAlloc(
        allocator,
        max_layer_bytes,
    );
    defer redirected_decoded.deinit(allocator);
    try std.testing.expectEqualStrings(payload, redirected_decoded.bytes);
}

fn expectUnifiedDecoded(
    response: http.OwnedResponse,
    expected: []const u8,
    max_layer_bytes: usize,
) !void {
    const chain = try response.contentEncoding();
    try std.testing.expectEqualSlices(
        http.ContentCoding,
        &.{ .deflate, .gzip },
        chain.items(),
    );

    var decoded = try response.decodeContentAlloc(
        std.testing.allocator,
        max_layer_bytes,
    );
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(expected, decoded.bytes);
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        response.decodeContentAlloc(
            std.testing.allocator,
            max_layer_bytes - 1,
        ),
    );

    var output: [4096]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(
        expected,
        try response.decodeContentInto(&output, &scratch),
    );
}

test "unified HTTP client follows redirect from negotiated h1 to h2" {
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
    const h2_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/final?from=h2",
        .{h2_server.address().ip4.port},
    );
    defer allocator.free(h2_uri);

    const H1Worker = struct {
        server: *http1_runtime.TlsServer,
        location: []const u8,
        release: *std.Io.Event,
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
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqualStrings("payload", request.request.body);
            try std.testing.expectEqualStrings(
                "Bearer first-origin",
                findHeader(request.request.headers, "authorization").?,
            );
            try connection.writeResponse(.{
                .status = 303,
                .reason = "See Other",
                .headers = &.{.{ .name = "Location", .value = self.location }},
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    const H2Worker = struct {
        server: *http2_runtime.TlsServer,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("GET", request.method);
            try std.testing.expectEqualStrings("/final?from=h2", request.path);
            try std.testing.expectEqual(@as(usize, 0), request.body.len);
            try std.testing.expect(
                findHeader(request.headers, "authorization") == null,
            );
            try std.testing.expect(
                findHeader(request.headers, "content-type") == null,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "x-selected-protocol", .value = "h2" }},
                .body = "negotiated-h2-final",
                .request_method = request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var h1_worker = H1Worker{
        .server = &h1_server,
        .location = h2_uri,
        .release = &release,
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

    var client = try http.Client.init(allocator, io, .{
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    });
    defer client.deinit();
    const h1_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{h1_server.address().ip4.port},
    );
    defer allocator.free(h1_uri);
    var result = try client.requestUriFollowingRedirectsDetailedWithTimeout(
        h1_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer first-origin" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = "payload",
        },
        .{},
        .fromSeconds(5),
    );
    defer result.deinit();
    try std.testing.expectEqual(http.Protocol.http2, result.response.protocol());
    try std.testing.expectEqual(@as(u16, 200), result.response.status());
    try std.testing.expectEqualStrings("negotiated-h2-final", result.response.body());
    try std.testing.expectEqualStrings(
        "h2",
        result.response.header("x-selected-protocol").?,
    );
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);

    release.set(io);
    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (h1_worker.err) |err| return err;
    if (h2_worker.err) |err| return err;
}

test "unified HTTP connection reuses negotiated h2 transport" {
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
    var server = try http2_runtime.TlsServer.listen(
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
        server: *http2_runtime.TlsServer,
        release: std.Io.Event = .unset,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for (0..2) |index| {
                var request = try connection.readRequest();
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/one" else "/two",
                    request.path,
                );
                try connection.writeResponse(request.stream_id, .{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.method,
                });
                self.requests += 1;
            }
            try self.release.wait(self.server.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try http.Client.init(allocator, io, .{
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    });
    defer client.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var connection = try client.connectUriWithTimeout(uri, .fromSeconds(5));
    defer connection.close();
    try std.testing.expectEqual(http.Protocol.http2, connection.protocol());
    var first = try connection.requestWithTimeout(
        "/one",
        .{},
        .fromSeconds(3),
    );
    defer first.deinit();
    var second = try connection.requestWithTimeout(
        "/two",
        .{},
        .fromSeconds(3),
    );
    defer second.deinit();
    try std.testing.expectEqualStrings("one", first.body());
    try std.testing.expectEqualStrings("two", second.body());
    try std.testing.expect(connection.isReusable());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.requests);
}

test "unified HTTP client selects explicit cleartext protocol" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var h1_server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer h1_server.deinit();
    var h2_server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer h2_server.deinit();

    const H1Worker = struct {
        server: *http1_runtime.Server,
        release: *std.Io.Event,
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
            try std.testing.expectEqualStrings("/h1", request.request.target);
            try connection.writeResponse(.{
                .body = "cleartext-h1",
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    const H2Worker = struct {
        server: *http2_runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/h2", request.path);
            try connection.writeResponse(request.stream_id, .{
                .body = "cleartext-h2",
                .request_method = request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var h1_worker = H1Worker{ .server = &h1_server, .release = &release };
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

    const h1_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/h1",
        .{h1_server.address().getPort()},
    );
    defer allocator.free(h1_uri);
    const h2_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/h2",
        .{h2_server.address().getPort()},
    );
    defer allocator.free(h2_uri);
    var h1_client = try http.Client.init(allocator, io, .{});
    defer h1_client.deinit();
    var h1_response = try h1_client.requestUriWithTimeout(
        h1_uri,
        .{},
        .fromSeconds(3),
    );
    defer h1_response.deinit();
    try std.testing.expectEqual(http.Protocol.http1, h1_response.protocol());
    try std.testing.expectEqualStrings("cleartext-h1", h1_response.body());

    var h2_client = try http.Client.init(allocator, io, .{
        .cleartext_protocol = .http2_prior_knowledge,
    });
    defer h2_client.deinit();
    var h2_response = try h2_client.requestUriWithTimeout(
        h2_uri,
        .{},
        .fromSeconds(3),
    );
    defer h2_response.deinit();
    try std.testing.expectEqual(http.Protocol.http2, h2_response.protocol());
    try std.testing.expectEqualStrings("cleartext-h2", h2_response.body());

    release.set(io);
    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (h1_worker.err) |err| return err;
    if (h2_worker.err) |err| return err;
}

test "unified HTTP client rejects zero timeout before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var client = try http.Client.init(allocator, threaded.io(), .{});
    defer client.deinit();
    try std.testing.expectError(
        error.Timeout,
        client.requestUriWithTimeout(
            "https://127.0.0.1:1/",
            .{},
            .zero,
        ),
    );
}
