//! HTTP/1 URI parsing, serve-loop, and extension-method tests.
//! Tests moved out of the module runtime root.

const std = @import("std");
const http1 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const CertificateBundle = runtime.CertificateBundle;
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const IdleSocketState = runtime.IdleSocketState;
const InformationalResponseHead = runtime.InformationalResponseHead;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const Server = runtime.Server;
const StapledOcspPolicy = runtime.StapledOcspPolicy;
const TlsServer = runtime.TlsServer;
const Tunnel = runtime.Tunnel;
const WriteScratch = runtime.WriteScratch;
const WriteStrategy = runtime.WriteStrategy;
const adjustResponseForServeLoop = runtime.adjustResponseForServeLoop;
const body_writer = runtime.body_writer;
const builtin = runtime.builtin;
const close_delimited = runtime.close_delimited;
const localTestCaBundle = runtime.localTestCaBundle;
const probeIdleSocket = runtime.probeIdleSocket;
const readExactForTest = runtime.readExactForTest;
const readMessageBytesBufferedWithContext = runtime.readMessageBytesBufferedWithContext;
const readRequestFromStream = runtime.readRequestFromStream;
const readResponseFromStreamBuffered = runtime.readResponseFromStreamBuffered;
const readResponseFromStreamBufferedForRequest = runtime.readResponseFromStreamBufferedForRequest;
const readResponseFromStreamForRequest = runtime.readResponseFromStreamForRequest;
const readSome = runtime.readSome;
const requestShouldSendContinue = runtime.requestShouldSendContinue;
const responseBatchWriteStrategy = runtime.responseBatchWriteStrategy;
const responseOptionsKeepAlive = runtime.responseOptionsKeepAlive;
const response_batch_borrow_threshold = runtime.response_batch_borrow_threshold;
const runtime_write = runtime.runtime_write;
const shutdownAfterTlsCloseNotify = runtime.shutdownAfterTlsCloseNotify;
const stream_io = runtime.stream_io;
const tls = runtime.tls;
const tls_stream = runtime.tls_stream;
const uriEndpoint = runtime.uriEndpoint;
const vail = runtime.vail;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const wire = runtime.wire;
const writeAllToStream = runtime.writeAllToStream;
const writeRequestToStream = runtime.writeRequestToStream;
const writeResponseToStream = runtime.writeResponseToStream;
const writeResponsesToTransportScratch = runtime.writeResponsesToTransportScratch;

test "HTTP/1 connections keep optional write scratch compact" {
    if (@sizeOf(usize) == 8) {
        // Connection policy storage grows with supported socket/resolver
        // options; the non-policy owner budgets and scratch stay fixed.
        try std.testing.expectEqual(@as(usize, 304), @sizeOf(Client) - @sizeOf(runtime.Limits));
        try std.testing.expectEqual(@as(usize, 240), @sizeOf(Connection) - @sizeOf(runtime.Limits));
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(WriteScratch));
    }
}

test "URI endpoint handles bracketed IPv6 literals" {
    const allocator = std.testing.allocator;
    const uri = try std.Uri.parse("http://[::1]:8080/ipv6?x=1");
    var endpoint = try uriEndpoint(allocator, uri, 80);
    defer endpoint.deinit();

    try std.testing.expectEqualStrings("[::1]:8080", endpoint.authority);
    try std.testing.expectEqualStrings("::1", endpoint.tls_host);
    switch (endpoint.target) {
        .ip => |address| switch (address) {
            .ip6 => |ip6| try std.testing.expectEqual(@as(u16, 8080), ip6.port),
            .ip4 => return error.InvalidUri,
        },
        .host => return error.InvalidUri,
    }

    const default_port_uri = try std.Uri.parse("http://example.com/path");
    var default_endpoint = try uriEndpoint(allocator, default_port_uri, 80);
    defer default_endpoint.deinit();
    try std.testing.expectEqualStrings("example.com", default_endpoint.authority);
    try std.testing.expectEqual(@as(u16, 80), default_endpoint.port);
}

test "URI endpoint retains host and authority in one allocation" {
    const allocator = std.testing.allocator;

    var implicit_one_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    const implicit = try std.Uri.parse("http://example.com/path");
    var implicit_endpoint = try uriEndpoint(
        implicit_one_alloc.allocator(),
        implicit,
        80,
    );
    defer implicit_endpoint.deinit();
    try std.testing.expect(!implicit_one_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @intFromPtr(implicit_endpoint.host_storage.ptr),
        @intFromPtr(implicit_endpoint.authority.ptr),
    );

    var explicit_one_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    const explicit = try std.Uri.parse("https://[::1]:8443/path");
    var explicit_endpoint = try uriEndpoint(
        explicit_one_alloc.allocator(),
        explicit,
        443,
    );
    defer explicit_endpoint.deinit();
    try std.testing.expect(!explicit_one_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("[::1]", explicit_endpoint.host_storage);
    try std.testing.expectEqualStrings("[::1]:8443", explicit_endpoint.authority);
    try std.testing.expectEqualStrings("::1", explicit_endpoint.tls_host);
    try std.testing.expectEqual(
        @intFromPtr(explicit_endpoint.host_storage.ptr),
        @intFromPtr(explicit_endpoint.authority.ptr),
    );
}

test "HTTP/1 serve response derives trailer capability from request" {
    const allocator = std.testing.allocator;
    var accepted_headers = [_]http1.Header{
        .{ .name = "Host", .value = "example.test" },
        .{ .name = "TE", .value = "gzip" },
        .{ .name = "te", .value = "Trailers" },
        .{ .name = "Connection", .value = "TE" },
    };
    var accepted = try adjustResponseForServeLoop(
        allocator,
        .{
            .method = .GET,
            .target = "/",
            .version = .http_1_1,
            .headers = &accepted_headers,
            .body = &.{},
            .consumed = 0,
        },
        .{},
        false,
    );
    defer accepted.deinit(allocator);
    try std.testing.expect(accepted.response.request_accepts_trailers);

    var refused_headers = [_]http1.Header{
        .{ .name = "Host", .value = "example.test" },
    };
    var refused = try adjustResponseForServeLoop(
        allocator,
        .{
            .method = .GET,
            .target = "/",
            .version = .http_1_1,
            .headers = &refused_headers,
            .body = &.{},
            .consumed = 0,
        },
        .{ .request_accepts_trailers = true },
        false,
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.response.request_accepts_trailers);
}

test "HTTP/1 serve loop preserves hop-by-hop Connection options" {
    const allocator = std.testing.allocator;
    const extension_headers = [_]http1.Header{
        .{ .name = "Connection", .value = "x-hop" },
        .{ .name = "X-Hop", .value = "private" },
    };

    var close_headers = [_]http1.Header{.{
        .name = "Connection",
        .value = "close",
    }};
    var close = try adjustResponseForServeLoop(
        allocator,
        .{
            .method = .GET,
            .target = "/",
            .version = .http_1_1,
            .headers = &close_headers,
            .body = &.{},
            .consumed = 0,
        },
        .{ .headers = &extension_headers },
        false,
    );
    defer close.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), close.response.headers.len);
    try std.testing.expect(wire.anyHeaderContainsToken(
        close.response.headers,
        "connection",
        "x-hop",
    ));
    try std.testing.expect(wire.anyHeaderContainsToken(
        close.response.headers,
        "connection",
        "close",
    ));
    try std.testing.expect(close.response.headers[1].eqlName("x-hop"));
    try std.testing.expectEqualStrings(
        "private",
        close.response.headers[1].value,
    );
    try std.testing.expect(!responseOptionsKeepAlive(close.response));
}

test "HTTP/1 runtime accepts matching absolute-form target" {
    const allocator = std.testing.allocator;

    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("http://example.com:8080/absolute?x=1", request.request.target);
            try std.testing.expectEqualStrings("example.com:8080", request.request.header("host").?);
            try connection.writeResponse(.{ .body = "absolute-ok", .request_method = request.request.method });
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .target = "http://example.com:8080/absolute?x=1",
        .headers = &.{.{ .name = "Connection", .value = "close" }},
    });
    var response = try readResponseFromStreamForRequest(allocator, io, stream, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    }, .{}, .GET);
    defer response.deinit(allocator);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("absolute-ok", response.response.body);
}

test "HTTP/1 runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expect(request.request.method == .POST);
            try std.testing.expectEqualStrings("/echo", request.request.target);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.header("host").?);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 201,
                .reason = "Created",
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/echo",
        .host = "127.0.0.1",
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 201), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expectEqualStrings("text/plain", response.response.header("content-type").?);
}

test "HTTP/1 runtime preserves extension methods end to end" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "PURGE",
                request.request.method.string(),
            );
            switch (request.request.method) {
                .extension => {},
                else => return error.TestUnexpectedResult,
            }
            try connection.writeResponse(.{
                .body = "purged",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.request(.{
        .method = try http1.Method.parse("PURGE"),
        .target = "/cache",
        .host = "127.0.0.1",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("purged", response.response.body);
}
