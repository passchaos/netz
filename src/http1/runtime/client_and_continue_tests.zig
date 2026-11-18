//! HTTP/1 client URI, 100-continue, and informational-response tests.

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

test "HTTP/1 client connects by host name" {
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
            var expected_host: [32]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "dns-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{});
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("dns-ok", response.response.body);
}

test "HTTP/1 client sends request to URI" {
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
            try std.testing.expectEqualStrings("/uri?x=1", request.request.target);
            var expected_host: [32]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("uri-ok", response.response.body);

    try std.testing.expectError(error.UnsupportedScheme, Client.requestUri(allocator, io, "ftp://localhost/", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http:///missing-host", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http://user:pass@localhost/", .{}, .{}));
}

test "HTTP/1 client sends request to bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
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
            try std.testing.expectEqualStrings("/ipv6?x=1", request.request.target);
            var expected_host: [64]u8 = undefined;
            const rendered_host = try std.fmt.bufPrint(&expected_host, "[::1]:{d}", .{server_ptr.address().ip6.port});
            try std.testing.expectEqualStrings(rendered_host, request.request.header("host").?);
            try connection.writeResponse(.{ .body = "ipv6-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://[::1]:{d}/ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("ipv6-uri-ok", response.response.body);
}

test "HTTP/1 server sends 100 Continue before reading expected body" {
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
            try std.testing.expectEqualStrings("/expect", request.request.target);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 200,
                .reason = "OK",
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    // Send only the head first.  A Hyper-compatible HTTP/1 server must emit
    // 100 Continue after seeing a valid HTTP/1.1 request with a body so the
    // client can safely stream a large payload without deadlocking.
    try writeAllToStream(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-Continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    try writeAllToStream(io, client.stream, "ping");
    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 server suppresses 100 Continue for invalid request head" {
    const bad_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: http://example.com\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(bad_host));

    const duplicate_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Host: other.example\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(duplicate_host));

    const mixed_expect = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Expect: 100-continue, custom\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(mixed_expect));
}

test "HTTP/1 unbuffered server validates full head before 100 Continue" {
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
        const Expected = struct { request: []const u8, err: anyerror };
        const cases = [_]Expected{
            .{
                .request = "POST /malformed HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Malformed Header\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4\r\n\r\n",
                .err = error.MalformedHeader,
            },
            .{
                .request = "POST /conflict HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Content-Length: 5\r\n\r\n",
                .err = error.ConflictingContentLength,
            },
            .{
                .request = "POST /duplicate-chunked HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Transfer-Encoding: chunked, chunked\r\n\r\n",
                .err = error.InvalidTransferEncoding,
            },
            .{
                .request = "POST /oversized HTTP/1.1\r\n" ++
                    "Host: localhost\r\n" ++
                    "Expect: 100-continue\r\n" ++
                    "Content-Length: 4097\r\n\r\n",
                .err = error.BodyTooLarge,
            },
        };

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (@This().cases) |case| {
                const stream = try self.server.listener.accept(self.server.io);
                defer stream.close(self.server.io);
                const result = readRequestFromStream(
                    self.server.allocator,
                    self.server.io,
                    stream,
                    self.server.limits,
                    .{},
                );
                try std.testing.expectError(case.err, result);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (Shared.cases) |case| {
        const stream = try server.address().connect(io, .{ .mode = .stream });
        defer stream.close(io);
        try writeAllToStream(io, stream, case.request);
        var received: [25]u8 = undefined;
        try std.testing.expectEqual(
            @as(usize, 0),
            try readSome(io, stream, &received),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 server sends 100 Continue even when body was pre-read" {
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
            try std.testing.expectEqualStrings("ping", request.request.body);
            try connection.writeResponse(.{ .body = "accepted" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    try writeAllToStream(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "ping");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client skips interim responses before final response" {
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
            try std.testing.expectEqualStrings("/interim", request.request.target);

            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 100 Continue\r\n\r\n" ++
                "HTTP/1.1 102 Processing\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/interim",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 client observes informational response heads in order" {
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
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\n" ++
                    "Link: </style.css>; rel=preload\r\n\r\n" ++
                    "HTTP/1.1 102 Processing\r\n" ++
                    "X-Progress: indexed\r\n\r\n" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\nConnection: close\r\n\r\nfinal",
            );
        }
    };

    const Observer = struct {
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn onResponse(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.count >= self.statuses.len) @panic(
                "too many informational callbacks",
            );
            self.statuses[self.count] = head.status;
            if (head.status == 103) {
                if (!std.mem.eql(
                    u8,
                    head.header("link") orelse @panic("missing Link"),
                    "</style.css>; rel=preload",
                )) @panic("unexpected Link");
            } else if (head.status == 102) {
                if (!std.mem.eql(
                    u8,
                    head.header("x-progress") orelse
                        @panic("missing X-Progress"),
                    "indexed",
                )) @panic("unexpected X-Progress");
            }
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var observer = Observer{};
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.requestWithInformational(
        .{
            .method = .GET,
            .target = "/informational",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        },
        .{
            .context = &observer,
            .on_response = Observer.onResponse,
        },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), observer.count);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        &observer.statuses,
    );
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 aggregate request rejects informational callback reentry" {
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
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest(.{});
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/first",
                first.request.target,
            );
            try writeAllToStream(
                shared.server.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\n" ++
                    "Link: </next>; rel=preload\r\n\r\n" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\n\r\nfirst",
            );

            var second = try connection.readRequest(.{});
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/after",
                second.request.target,
            );
            try writeAllToStream(
                shared.server.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 5\r\n" ++
                    "Connection: close\r\n\r\nafter",
            );
        }
    };

    const Observer = struct {
        client: *Client,
        error_seen: ?anyerror = null,
        unexpectedly_started: bool = false,

        fn onResponse(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (head.status != 103) @panic("unexpected interim status");
            var nested = self.client.startRequest(.{
                .method = .GET,
                .target = "/nested",
                .host = "localhost",
                .body_length = 0,
            }) catch |err| {
                self.error_seen = err;
                return;
            };
            self.unexpectedly_started = true;
            nested.deinit();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var observer = Observer{ .client = &client };
    var first = try client.requestWithInformational(
        .{
            .method = .GET,
            .target = "/first",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        },
        .{ .context = &observer, .on_response = Observer.onResponse },
    );
    defer first.deinit(allocator);
    try std.testing.expect(!observer.unexpectedly_started);
    switch (observer.error_seen orelse
        return error.TestUnexpectedResult) {
        error.ConnectionBusy => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("first", first.response.body);
    try std.testing.expect(client.isReusable());

    var second = try client.request(.{
        .method = .GET,
        .target = "/after",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("after", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client bounds informational response chains" {
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
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 102 Processing\r\n\r\n" ** 3 ++
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
            .max_informational_responses = 2,
        },
    );
    defer client.close();
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .method = .GET,
            .target = "/informational-limit",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        }),
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = .GET,
            .target = "/must-not-reuse",
            .headers = &.{.{ .name = "Host", .value = "localhost" }},
        }),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming client waits for 100 Continue before body" {
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

            var head: [256]u8 = undefined;
            var used: usize = 0;
            while (std.mem.indexOf(u8, head[0..used], "\r\n\r\n") == null) {
                if (used == head.len) return error.HeadersTooLarge;
                const count = try readSome(
                    server_ptr.io,
                    connection.stream,
                    head[used..],
                );
                if (count == 0) return error.ConnectionClosed;
                used += count;
            }
            const head_end = std.mem.indexOf(
                u8,
                head[0..used],
                "\r\n\r\n",
            ).? + 4;
            try std.testing.expectEqual(head_end, used);
            try std.testing.expect(std.mem.indexOf(
                u8,
                head[0..head_end],
                "Expect: 100-continue\r\n",
            ) != null);

            // Send an unrelated hint first to prove waitForContinue consumes
            // multiple informational heads rather than accepting any 1xx.
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n" ++
                    "HTTP/1.1 100 Continue\r\n\r\n",
            );
            var body: [4]u8 = undefined;
            try readExactForTest(
                server_ptr.io,
                connection.stream,
                &body,
            );
            try std.testing.expectEqualStrings("ping", &body);
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
            );
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
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/expect-client",
        .host = "localhost",
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
        .body_length = 4,
    });
    defer writer.deinit();
    const Observer = struct {
        count: usize = 0,

        fn observe(
            raw: *anyopaque,
            head: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const expected_status: u16 = switch (self.count) {
                0 => 103,
                1 => 100,
                else => @panic("too many informational responses"),
            };
            if (head.status != expected_status) {
                @panic("unexpected informational status");
            }
            self.count += 1;
        }
    };
    var observer = Observer{};
    try std.testing.expect((try writer.waitForContinueWithInformational(.{
        .context = &observer,
        .on_response = Observer.observe,
    })) == .proceed);
    try std.testing.expectEqual(@as(usize, 2), observer.count);
    try std.testing.expectError(
        error.InvalidWriterState,
        writer.waitForContinue(),
    );
    try writer.write("ping");
    try writer.finish();
    var response = try writer.readResponseWithInformational(.{
        .context = &observer,
        .on_response = Observer.observe,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(usize, 2), observer.count);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming client returns final response before expected body" {
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

            var head: [256]u8 = undefined;
            var used: usize = 0;
            while (std.mem.indexOf(u8, head[0..used], "\r\n\r\n") == null) {
                if (used == head.len) return error.HeadersTooLarge;
                const count = try readSome(
                    server_ptr.io,
                    connection.stream,
                    head[used..],
                );
                if (count == 0) return error.ConnectionClosed;
                used += count;
            }
            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 417 Expectation Failed\r\n" ++
                    "Content-Length: 8\r\nConnection: close\r\n\r\nrejected",
            );
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
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/expect-reject",
        .host = "localhost",
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
        .body_length = 4,
    });
    defer writer.deinit();
    switch (try writer.waitForContinue()) {
        .proceed => return error.TestUnexpectedResult,
        .final_response => |value| {
            var response = value;
            defer response.deinit(allocator);
            try std.testing.expectEqual(
                @as(u16, 417),
                response.response.status,
            );
            try std.testing.expectEqualStrings(
                "rejected",
                response.response.body,
            );
        },
    }
    try std.testing.expectError(error.InvalidWriterState, writer.write("ping"));
    try std.testing.expectError(
        error.InvalidWriterState,
        writer.readResponse(),
    );

    thread.join();
    if (shared.err) |err| return err;
}
