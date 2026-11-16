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

test {
    _ = @import("client_tests/duplex.zig");
}

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

    const Resolver = struct {
        h1_address: std.Io.net.IpAddress,
        h2_address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "localhost") or deadline == null) {
                return error.UnknownHostName;
            }
            const address = if (self.h1_address.getPort() == port)
                self.h1_address
            else if (self.h2_address.getPort() == port)
                self.h2_address
            else
                return error.UnknownHostName;
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                1,
            );
            addresses[0] = address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .h1_address = h1_server.address(),
        .h2_address = h2_server.address(),
    };

    var client = try http.Client.init(allocator, io, .{
        .address_resolver = .{
            .context = &resolver,
            .resolve = Resolver.resolve,
        },
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
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));

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
    const BypassResolver = struct {
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.calls.fetchAdd(1, .acq_rel);
            return error.UnknownHostName;
        }
    };
    var bypass_resolver = BypassResolver{};
    var h1_client = try http.Client.init(allocator, io, .{
        .address_resolver = .{
            .context = &bypass_resolver,
            .resolve = BypassResolver.resolve,
        },
    });
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
        .address_resolver = .{
            .context = &bypass_resolver,
            .resolve = BypassResolver.resolve,
        },
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
    try std.testing.expectEqual(
        @as(u8, 0),
        bypass_resolver.calls.load(.acquire),
    );

    release.set(io);
    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (h1_worker.err) |err| return err;
    if (h2_worker.err) |err| return err;
}

test "unified HTTP client streams reader request bodies" {
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
            try std.testing.expectEqualStrings(
                "streamed-h1",
                request.request.body,
            );
            try std.testing.expect(request.request.body_framing == .chunked);
            try connection.writeResponse(.{
                .body = "ok-h1",
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
            try std.testing.expectEqualStrings("streamed-h2", request.body);
            try connection.writeResponse(request.stream_id, .{
                .body = "ok-h2",
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
        "http://127.0.0.1:{d}/upload",
        .{h1_server.address().getPort()},
    );
    defer allocator.free(h1_uri);
    const h2_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{h2_server.address().getPort()},
    );
    defer allocator.free(h2_uri);

    var h1_client = try http.Client.init(allocator, io, .{});
    defer h1_client.deinit();
    var h1_reader = std.Io.Reader.fixed("streamed-h1");
    var h1_response = try h1_client.requestUriWithTimeout(
        h1_uri,
        .{
            .method = "POST",
            .body_source = .{ .reader = .{ .reader = &h1_reader } },
        },
        .fromSeconds(3),
    );
    defer h1_response.deinit();
    try std.testing.expectEqualStrings("ok-h1", h1_response.body());

    var h2_client = try http.Client.init(allocator, io, .{
        .cleartext_protocol = .http2_prior_knowledge,
    });
    defer h2_client.deinit();
    var h2_reader = std.Io.Reader.fixed("streamed-h2");
    var h2_response = try h2_client.requestUriWithTimeout(
        h2_uri,
        .{
            .method = "POST",
            .body_source = .{ .reader = .{ .reader = &h2_reader } },
        },
        .fromSeconds(3),
    );
    defer h2_response.deinit();
    try std.testing.expectEqualStrings("ok-h2", h2_response.body());

    release.set(io);
    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (h1_worker.err) |err| return err;
    if (h2_worker.err) |err| return err;
}

test "redirect following rejects reader-backed bodies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var client = try http.Client.init(allocator, threaded.io(), .{});
    defer client.deinit();
    var reader = std.Io.Reader.fixed("body");
    try std.testing.expectError(
        error.StreamingBodyUnsupported,
        client.requestUriFollowingRedirects(
            "http://127.0.0.1:1/",
            .{
                .method = "POST",
                .body_source = .{ .reader = .{ .reader = &reader } },
            },
            .{},
        ),
    );
}

test "unified HTTP client sends a streaming multipart form" {
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
            try std.testing.expect(request.request.body_framing == .chunked);
            try std.testing.expect(std.mem.indexOf(
                u8,
                request.request.body,
                "Content-Disposition: form-data; name=\"field\"",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                request.request.body,
                "value",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                request.request.body,
                "filename=\"a.txt\"",
            ) != null);
            try std.testing.expect(std.mem.indexOf(
                u8,
                request.request.body,
                "hello",
            ) != null);
            try connection.writeResponse(.{
                .body = "ok-multipart",
                .request_method = request.request.method,
            });
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

    const boundary = "----netz-e2e";
    const parts = [_]http.multipart.Part{
        .{ .name = "field", .body = .{ .slice = "value" } },
        .{
            .name = "upload",
            .filename = "a.txt",
            .content_type = "text/plain",
            .body = .{ .slice = "hello" },
        },
    };
    var form_reader = try http.multipart.Reader.init(&parts, boundary);
    var content_type_buf: [128]u8 = undefined;
    const content_type = try http.multipart.contentType(
        &content_type_buf,
        boundary,
    );

    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{.{
                .name = "content-type",
                .value = content_type,
            }},
            .body_source = .{ .reader = .{
                .reader = &form_reader.reader,
            } },
        },
        .fromSeconds(3),
    );
    defer response.deinit();
    try std.testing.expectEqualStrings("ok-multipart", response.body());

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "unified HTTP client uses one resolver contract for h1 and h2" {
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

    const Worker = struct {
        h1: *http1_runtime.Server,
        h2: *http2_runtime.Server,
        h1_err: ?anyerror = null,
        h2_err: ?anyerror = null,

        fn runH1(self: *@This()) void {
            self.runH1Fallible() catch |err| {
                self.h1_err = err;
            };
        }

        fn runH1Fallible(self: *@This()) !void {
            var connection = try self.h1.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.h1.allocator);
            try std.testing.expectEqualStrings("/resolved-h1", request.request.target);
            try connection.writeResponse(.{
                .body = "resolved-h1",
                .request_method = request.request.method,
            });
        }

        fn runH2(self: *@This()) void {
            self.runH2Fallible() catch |err| {
                self.h2_err = err;
            };
        }

        fn runH2Fallible(self: *@This()) !void {
            var connection = try self.h2.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.h2.allocator);
            try std.testing.expectEqualStrings("/resolved-h2", request.path);
            try connection.writeResponse(request.stream_id, .{
                .body = "resolved-h2",
                .request_method = request.method,
            });
        }
    };
    var worker = Worker{ .h1 = &h1_server, .h2 = &h2_server };
    const h1_thread = try std.Thread.spawn(.{}, Worker.runH1, .{&worker});
    var h1_joined = false;
    defer if (!h1_joined) h1_thread.join();
    const h2_thread = try std.Thread.spawn(.{}, Worker.runH2, .{&worker});
    var h2_joined = false;
    defer if (!h2_joined) h2_thread.join();

    const Resolver = struct {
        h1_address: std.Io.net.IpAddress,
        h2_address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (deadline == null) return error.Timeout;
            const expected = if (std.mem.eql(u8, host, "h1.resolver.test"))
                self.h1_address
            else if (std.mem.eql(u8, host, "h2.resolver.test"))
                self.h2_address
            else
                return error.UnknownHostName;
            if (expected.getPort() != port) return error.UnknownHostName;
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                2,
            );
            addresses[0] = .{ .ip4 = .loopback(0) };
            addresses[1] = expected;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .h1_address = h1_server.address(),
        .h2_address = h2_server.address(),
    };
    const h1_uri = try std.fmt.allocPrint(
        allocator,
        "http://h1.resolver.test:{d}/resolved-h1",
        .{h1_server.address().getPort()},
    );
    defer allocator.free(h1_uri);
    const h2_uri = try std.fmt.allocPrint(
        allocator,
        "http://h2.resolver.test:{d}/resolved-h2",
        .{h2_server.address().getPort()},
    );
    defer allocator.free(h2_uri);

    var h1_client = try http.Client.init(allocator, io, .{
        .address_resolver = .{
            .context = &resolver,
            .resolve = Resolver.resolve,
        },
    });
    defer h1_client.deinit();
    var h1_response = try h1_client.requestUriWithTimeout(
        h1_uri,
        .{},
        .fromSeconds(3),
    );
    defer h1_response.deinit();
    try std.testing.expectEqual(http.Protocol.http1, h1_response.protocol());
    try std.testing.expectEqualStrings("resolved-h1", h1_response.body());

    var h2_client = try http.Client.init(allocator, io, .{
        .cleartext_protocol = .http2_prior_knowledge,
        .address_resolver = .{
            .context = &resolver,
            .resolve = Resolver.resolve,
        },
    });
    defer h2_client.deinit();
    var h2_response = try h2_client.requestUriWithTimeout(
        h2_uri,
        .{},
        .fromSeconds(3),
    );
    defer h2_response.deinit();
    try std.testing.expectEqual(http.Protocol.http2, h2_response.protocol());
    try std.testing.expectEqualStrings("resolved-h2", h2_response.body());
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));

    h1_thread.join();
    h1_joined = true;
    h2_thread.join();
    h2_joined = true;
    if (worker.h1_err) |err| return err;
    if (worker.h2_err) |err| return err;
}

test "unified HTTP client applies Happy Eyeballs to system resolution" {
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
            try std.testing.expectEqualStrings(
                "/happy-eyeballs",
                request.request.target,
            );
            try connection.writeResponse(.{
                .body = "happy",
                .request_method = request.request.method,
            });
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/happy-eyeballs",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var client = try http.Client.init(allocator, io, .{
        .address_connect_policy = .{ .happy_eyeballs = .{
            .attempt_delay = .fromMilliseconds(10),
        } },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{},
        .fromSeconds(3),
    );
    defer response.deinit();
    try std.testing.expectEqualStrings("happy", response.body());

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "unified HTTP client rejects zero timeout before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var client = try http.Client.init(allocator, threaded.io(), .{});
    defer client.deinit();
    try std.testing.expectError(
        error.InvalidAddressConnectPolicy,
        http.Client.init(allocator, threaded.io(), .{
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .zero,
            } },
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.requestUriWithTimeout(
            "https://127.0.0.1:1/",
            .{},
            .zero,
        ),
    );
}

test "unified HTTP resolver inherits the caller deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Resolver = struct {
        never: std.Io.Event = .unset,
        saw_deadline: std.atomic.Value(bool) = .init(false),

        fn resolve(
            context: *anyopaque,
            _: std.mem.Allocator,
            resolve_io: std.Io,
            host: []const u8,
            _: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "deadline.resolver.test")) {
                return error.UnknownHostName;
            }
            const absolute = deadline orelse return error.Timeout;
            self.saw_deadline.store(true, .release);
            self.never.waitTimeout(
                resolve_io,
                .{ .deadline = absolute },
            ) catch |err| return err;
            return error.UnknownHostName;
        }
    };
    var resolver = Resolver{};
    var client = try http.Client.init(allocator, io, .{
        .address_resolver = .{
            .context = &resolver,
            .resolve = Resolver.resolve,
        },
    });
    defer client.deinit();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        client.requestUriWithTimeout(
            "http://deadline.resolver.test/",
            .{},
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expect(resolver.saw_deadline.load(.acquire));
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
}

test "HTTP server streams a multipart request body through the parser" {
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
        parts: usize = 0,
        seen: std.ArrayList(u8) = .empty,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var body_reader = try connection.readRequestBody(.{});
            defer body_reader.deinit();
            const head = try body_reader.head();
            const content_type = head.header("content-type") orelse
                return error.MissingContentType;
            var std_reader = http1_runtime.RequestBodyReader.StdReader.init(
                body_reader,
            );
            try http.multipart.parseStream(
                self.server.allocator,
                &std_reader.reader,
                content_type,
                .{ .buffer_bytes = 16 },
                .{
                    .context = self,
                    .begin = Self.begin,
                    .data = Self.data,
                    .end = Self.end,
                },
            );
            while (try body_reader.next()) |_| {}
            var request = try body_reader.takeRequest();
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                .body = "ok-stream-parser",
                .request_method = request.method,
            });
            try self.release.wait(self.server.io);
        }

        fn begin(context: *anyopaque, head: http.multipart.StreamPartHead) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.parts += 1;
            try self.seen.appendSlice(self.server.allocator, head.name);
            try self.seen.append(self.server.allocator, 0);
            if (head.filename) |filename| {
                try self.seen.appendSlice(self.server.allocator, filename);
            }
            try self.seen.append(self.server.allocator, 0);
            if (head.content_type) |value| {
                try self.seen.appendSlice(self.server.allocator, value);
            }
            try self.seen.append(self.server.allocator, 1);
        }

        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.seen.appendSlice(self.server.allocator, bytes);
        }

        fn end(context: *anyopaque) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.seen.append(self.server.allocator, 2);
        }

        fn deinit(self: *Self) void {
            self.seen.deinit(self.server.allocator);
        }
    };

    var release: std.Io.Event = .unset;
    var worker = Worker{ .server = &server, .release = &release };
    defer worker.deinit();
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

    const boundary = "----netz-server-stream";
    const parts = [_]http.multipart.Part{
        .{ .name = "field", .body = .{ .slice = "value" } },
        .{
            .name = "upload",
            .filename = "a.txt",
            .content_type = "text/plain",
            .body = .{ .slice = "hello" },
        },
    };
    var form_reader = try http.multipart.Reader.init(&parts, boundary);
    var content_type_buffer: [128]u8 = undefined;
    const content_type = try http.multipart.contentType(
        &content_type_buffer,
        boundary,
    );

    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{.{
                .name = "content-type",
                .value = content_type,
            }},
            .body_source = .{ .reader = .{
                .reader = &form_reader.reader,
            } },
        },
        .fromSeconds(3),
    );
    defer response.deinit();
    try std.testing.expectEqualStrings("ok-stream-parser", response.body());

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), worker.parts);
    try std.testing.expect(std.mem.indexOf(
        u8,
        worker.seen.items,
        "field\x00\x00\x01value\x02",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        worker.seen.items,
        "upload\x00a.txt\x00text/plain\x01hello\x02",
    ) != null);
}
