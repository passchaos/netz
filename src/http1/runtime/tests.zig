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
        try std.testing.expectEqual(@as(usize, 448), @sizeOf(Client));
        try std.testing.expectEqual(@as(usize, 384), @sizeOf(Connection));
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

test "HTTP/1 buffered reader transfers exact message buffer ownership" {
    const allocator = std.testing.allocator;
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    var inbuf: std.ArrayList(u8) = .fromOwnedSlice(try allocator.dupe(u8, raw));
    const original_ptr = inbuf.items.ptr;

    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        .{ .tcp = .{ .io = undefined, .stream = undefined } },
        .{},
        .{},
        &inbuf,
        null,
        false,
        true,
        null,
        null,
        null,
        null,
    );
    defer allocator.free(bytes);

    try std.testing.expectEqual(original_ptr, bytes.ptr);
    try std.testing.expectEqual(@as(usize, 0), inbuf.items.len);
    try std.testing.expectEqualStrings(raw, bytes);
}

test "HTTP/1 borrowed pipeline batch preserves bodies until consume" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    const pipeline =
        "GET /one HTTP/1.1\r\nHost: example\r\n\r\n" ++
        "POST /two HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 3\r\n\r\nabc" ++
        "GET /next HTTP/1.1\r\nHost: example\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, pipeline);

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    const consumed = try connection.readRequestBatchInto(
        &heads,
        &headers,
        &bodies,
        .{ .max_headers = 4 },
    );
    try std.testing.expect(heads[0].method == .GET);
    try std.testing.expectEqualStrings("/one", heads[0].target);
    try std.testing.expect(heads[1].method == .POST);
    try std.testing.expectEqualStrings("abc", bodies[1]);
    try std.testing.expectEqualStrings(
        pipeline[0..consumed],
        connection.inbuf.items[0..consumed],
    );

    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqualStrings(
        "GET /next HTTP/1.1\r\nHost: example\r\n\r\n",
        connection.inbuf.items,
    );
    try std.testing.expectError(
        error.InvalidResponse,
        connection.consumeRequestBatch(
            connection.inbuf.items.len + 1,
        ),
    );
}

test "HTTP/1 borrowed pipeline batch decodes chunked bodies in place" {
    const allocator = std.testing.allocator;
    const chunked_head =
        "POST /chunked HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    const empty_head =
        "POST /empty HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    const fixed =
        "POST /fixed HTTP/1.1\r\n" ++
        "Host: example\r\n" ++
        "Content-Length: 3\r\n\r\nabc";
    const suffix = "GET /next HTTP/1.1\r\nHost: example\r\n\r\n";
    const pipeline = chunked_head ++
        "2;foo=bar\r\nhe\r\n3\r\nllo\r\n" ++
        "0\r\nDigest: sha-256=demo\r\n\r\n" ++
        empty_head ++ "0\r\n\r\n" ++ fixed ++ suffix;
    const compacted = chunked_head ++ "hello" ++ empty_head ++ fixed;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    try connection.inbuf.appendSlice(allocator, pipeline);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = no_alloc.allocator();

    var heads: [3]http1.RequestHead = undefined;
    var headers: [12]http1.Header = undefined;
    var bodies: [3][]const u8 = undefined;
    const consumed = try connection.readRequestBatchInto(
        &heads,
        &headers,
        &bodies,
        .{ .max_headers = 4 },
    );

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("/chunked", heads[0].target);
    try std.testing.expectEqual(http1.BodyFraming.chunked, heads[0].body_framing);
    try std.testing.expect(!heads[0].must_close);
    try std.testing.expect(heads[0].header("content-length") == null);
    try std.testing.expectEqualStrings("hello", bodies[0]);
    try std.testing.expectEqualStrings("/empty", heads[1].target);
    try std.testing.expectEqual(http1.BodyFraming.chunked, heads[1].body_framing);
    try std.testing.expectEqual(@as(usize, 0), bodies[1].len);
    try std.testing.expectEqualStrings("/fixed", heads[2].target);
    try std.testing.expectEqual(http1.BodyFraming.content_length, heads[2].body_framing);
    try std.testing.expectEqualStrings("abc", bodies[2]);
    try std.testing.expectEqual(compacted.len, consumed);
    try std.testing.expectEqualStrings(
        compacted ++ suffix,
        connection.inbuf.items,
    );

    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqualStrings(suffix, connection.inbuf.items);
}

test "HTTP/1 borrowed chunked batch validation is transactional" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }
    const invalid =
        "POST /first HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nx\r\n0\r\n\r\n" ++
        "POST /second HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\ny\r\n0\r\nContent-Length: 1\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, invalid);

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    try std.testing.expectError(
        error.InvalidTrailer,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectEqualStrings(invalid, connection.inbuf.items);

    connection.inbuf.clearRetainingCapacity();
    const ambiguous =
        "POST /first HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nx\r\n0\r\n\r\n" ++
        "GET /second HTTP/1.1\r\nHost: example\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, ambiguous);
    try std.testing.expectError(
        error.InvalidResponse,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectEqualStrings(ambiguous, connection.inbuf.items);

    connection.inbuf.clearRetainingCapacity();
    const terminal_ambiguous =
        "POST /terminal HTTP/1.1\r\nHost: example\r\n" ++
        "Content-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nz\r\n0\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, terminal_ambiguous);
    const terminal_consumed = try connection.readRequestBatchInto(
        heads[0..1],
        headers[0..4],
        bodies[0..1],
        .{ .max_headers = 4 },
    );
    try std.testing.expect(heads[0].must_close);
    try std.testing.expect(heads[0].header("content-length") == null);
    try std.testing.expectEqualStrings("z", bodies[0]);
    try connection.consumeRequestBatch(terminal_consumed);

    connection.inbuf.clearRetainingCapacity();
    const folded =
        "POST /folded HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "0\r\nX-Trace: one\r\n two\r\n\r\n";
    try connection.inbuf.appendSlice(allocator, folded);
    try std.testing.expectError(
        error.MalformedHeader,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );
    const consumed = try connection.readRequestBatchInto(
        heads[0..1],
        headers[0..4],
        bodies[0..1],
        .{ .max_headers = 4, .allow_obs_fold = true },
    );
    try std.testing.expectEqualStrings("", bodies[0]);
    try connection.consumeRequestBatch(consumed);
    try std.testing.expectEqual(@as(usize, 0), connection.inbuf.items.len);
}

test "HTTP/1 borrowed chunked batch reads fragmented transport" {
    const allocator = std.testing.allocator;
    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var heads: [2]http1.RequestHead = undefined;
            var headers: [8]http1.Header = undefined;
            var bodies: [2][]const u8 = undefined;
            const consumed = try connection.readRequestBatchInto(
                &heads,
                &headers,
                &bodies,
                .{ .max_headers = 4 },
            );
            try std.testing.expectEqualStrings("/chunked", heads[0].target);
            try std.testing.expectEqualStrings("hello", bodies[0]);
            try std.testing.expectEqualStrings("/fixed", heads[1].target);
            try std.testing.expectEqualStrings("x", bodies[1]);
            try connection.consumeRequestBatch(consumed);

            var suffix = try connection.readRequest(.{});
            defer suffix.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/suffix", suffix.request.target);
        }
    };
    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAllToStream(
        io,
        client,
        "POST /chunked HTTP/1.1\r\nHost: example\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n2\r\nh",
    );
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try writeAllToStream(
        io,
        client,
        "e\r\n3\r\nllo\r\n0\r\nDigest: ok\r\n\r\n" ++
            "POST /fixed HTTP/1.1\r\nHost: example\r\n" ++
            "Content-Length: 1\r\n\r\nx" ++
            "GET /suffix HTTP/1.1\r\nHost: example\r\n\r\n",
    );

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "HTTP/1 borrowed pipeline batch enforces limits before I/O" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .max_head_bytes = 24, .max_body_bytes = 2 },
    };
    defer {
        connection.inbuf.deinit(allocator);
        connection.write_scratch.deinit(allocator);
    }

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    try connection.inbuf.appendSlice(
        allocator,
        "GET /long HTTP/1.1\r\nHost: example\r\n\r\n",
    );
    try std.testing.expectError(
        error.HeadersTooLarge,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );

    connection.inbuf.clearRetainingCapacity();
    connection.limits.max_head_bytes = 1024;
    try connection.inbuf.appendSlice(
        allocator,
        "POST / HTTP/1.1\r\nHost: example\r\n" ++
            "Content-Length: 3\r\n\r\nabc",
    );
    try std.testing.expectError(
        error.BodyTooLarge,
        connection.readRequestBatchInto(
            heads[0..1],
            headers[0..4],
            bodies[0..1],
            .{ .max_headers = 4 },
        ),
    );

    connection.inbuf.clearRetainingCapacity();
    connection.limits = .{
        .max_head_bytes = std.math.maxInt(usize),
        .max_body_bytes = 0,
    };
    try std.testing.expectError(
        error.BodyTooLarge,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = 4 },
        ),
    );
    try std.testing.expectError(
        error.TooManyHeaders,
        connection.readRequestBatchInto(
            &heads,
            &headers,
            &bodies,
            .{ .max_headers = std.math.maxInt(usize) },
        ),
    );
}

test "HTTP/1 response batch validation is transactional" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    const responses = [_]ResponseOptions{
        .{ .body = "ok" },
        .{ .status = 204, .body = "forbidden" },
    };
    try std.testing.expectError(
        error.InvalidContentLength,
        writeResponsesToTransportScratch(
            allocator,
            .{ .tcp = .{ .io = undefined, .stream = undefined } },
            &responses,
            null,
            &scratch,
        ),
    );
    // The invalid batch never reaches the transport. Scratch content itself is
    // internal and may be reused/partially encoded for the next attempt.
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

test "HTTP/1 runtime opens CONNECT tunnel" {
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
            try std.testing.expect(request.request.method == .CONNECT);
            try std.testing.expectEqualStrings("example.com:443", request.request.target);
            try std.testing.expectEqualStrings("example.com:443", request.request.header("host").?);

            var tunnel = try connection.acceptConnectTunnel(request.request, &.{});
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.writeResponse(.{ .status = 204 }),
            );
            var buf: [64]u8 = undefined;
            const n = try tunnel.read(&buf);
            try std.testing.expectEqualStrings("client tunnel bytes", buf[0..n]);
            try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));
            try tunnel.writeParts("server tunnel ", "bytes");
            try tunnel.closeWrite();
            try std.testing.expectError(
                error.ConnectionClosed,
                tunnel.write("late server bytes"),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var tunnel = try client.openConnectTunnelWithTimeout(
        "example.com:443",
        &.{},
        .fromSeconds(2),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = .GET,
            .target = "/after-connect",
            .host = "example.com",
        }),
    );
    try tunnel.writeSlices(&.{ "client ", "", "tunnel ", "bytes" });
    try tunnel.closeWrite();
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.closeWrite(),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("late client bytes"),
    );
    var buf: [64]u8 = undefined;
    const n = try tunnel.read(&buf);
    try std.testing.expectEqualStrings("server tunnel bytes", buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(
        error.ConnectionUnusable,
        client.openConnectTunnel("/not-authority", &.{}),
    );
}

test "HTTP/1 TLS tunnels close the write half and retain reads" {
    const allocator = std.testing.allocator;
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    inline for (.{ false, true }) |use_vail_client| {
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try TlsServer.listen(
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
        defer server.deinit();

        const Shared = struct {
            server: *TlsServer,
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
                defer request.deinit(allocator);
                var tunnel = try connection.acceptConnectTunnel(
                    request.request,
                    &.{},
                );
                var received: [12]u8 = undefined;
                var offset: usize = 0;
                while (true) {
                    const count = try tunnel.read(received[offset..]);
                    if (count == 0) break;
                    offset += count;
                }
                try std.testing.expectEqualStrings(
                    "client bytes",
                    received[0..offset],
                );
                try tunnel.writeParts("server ", "bytes");
                try tunnel.closeWrite();
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.write("late server bytes"),
                );
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.updateTrafficKeys(false),
                );
            }
        };
        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();

        var ca: ?struct { CertificateBundle, std.Io.RwLock } = null;
        defer if (ca) |*value| value[0].deinit(allocator);
        var client = if (use_vail_client)
            try Client.connectVailTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                } },
            )
        else client: {
            ca = try localTestCaBundle(allocator, io);
            break :client try Client.connectTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .ca_bundle = .{
                    .bundle = &ca.?[0],
                    .lock = &ca.?[1],
                } },
            );
        };
        defer client.close();
        var tunnel = try client.openConnectTunnelWithTimeout(
            "example.com:443",
            &.{},
            .fromSeconds(2),
        );
        try tunnel.writeSlices(&.{ "client", "", " ", "bytes" });
        try tunnel.closeWrite();
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.closeWrite(),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.write("late client bytes"),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.updateTrafficKeys(false),
        );
        var received: [12]u8 = undefined;
        var offset: usize = 0;
        while (true) {
            const count = try tunnel.read(received[offset..]);
            if (count == 0) break;
            offset += count;
        }
        try std.testing.expectEqualStrings(
            "server bytes",
            received[0..offset],
        );

        thread.join();
        joined = true;
        if (shared.err) |err| return err;
    }
}

test "HTTP/1 tunnel write-half close failure is terminal" {
    const PartialFailWriter = struct {
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    const FailingIo = struct {
        shutdown_calls: usize = 0,
        write_calls: usize = 0,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.shutdown_calls += 1;
            return error.NetworkDown;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.write_calls += 1;
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var write_failure: FailingIo = .{};
    var write_failure_vtable = threaded.io().vtable.*;
    write_failure_vtable.netWrite = FailingIo.write;
    var write_failure_inbuf: std.ArrayList(u8) = .empty;
    defer write_failure_inbuf.deinit(std.testing.allocator);
    var write_failure_tunnel = Tunnel{
        .io = .{
            .userdata = &write_failure,
            .vtable = &write_failure_vtable,
        },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &write_failure_inbuf,
    };
    try std.testing.expectError(
        error.NetworkDown,
        write_failure_tunnel.write("first-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        write_failure_tunnel.write("must-not-write"),
    );
    try std.testing.expectEqual(@as(usize, 1), write_failure.write_calls);

    var partial: PartialFailWriter = .{};
    var partial_vtable = threaded.io().vtable.*;
    partial_vtable.netWrite = PartialFailWriter.write;
    var partial_inbuf: std.ArrayList(u8) = .empty;
    defer partial_inbuf.deinit(std.testing.allocator);
    var partial_tunnel = Tunnel{
        .io = .{ .userdata = &partial, .vtable = &partial_vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &partial_inbuf,
    };

    try std.testing.expectError(
        error.NetworkDown,
        partial_tunnel.writeParts("head", "payload"),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeParts("must", "not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeSlices(&.{ "must", "not", "write" }),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);

    var failing: FailingIo = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netShutdown = FailingIo.shutdown;
    vtable.netWrite = FailingIo.write;
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(std.testing.allocator);
    var tunnel = Tunnel{
        .io = .{ .userdata = &failing, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &inbuf,
    };

    try std.testing.expectError(error.NetworkDown, tunnel.closeWrite());
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectError(error.ConnectionClosed, tunnel.closeWrite());
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.updateTrafficKeys(false),
    );
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectEqual(@as(usize, 0), failing.write_calls);
}

test "HTTP/1 TLS post-close-notify shutdown treats disconnected peer as complete" {
    const ShutdownIo = struct {
        calls: usize = 0,
        result: enum { disconnected, failed } = .disconnected,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            return switch (self.result) {
                .disconnected => error.SocketUnconnected,
                .failed => error.NetworkDown,
            };
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state: ShutdownIo = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netShutdown = ShutdownIo.shutdown;
    const io = std.Io{ .userdata = &state, .vtable = &vtable };
    const stream: net.Stream = undefined;

    try shutdownAfterTlsCloseNotify(io, stream);
    try std.testing.expectEqual(@as(usize, 1), state.calls);

    state.result = .failed;
    try std.testing.expectError(
        error.NetworkDown,
        shutdownAfterTlsCloseNotify(io, stream),
    );
    try std.testing.expectEqual(@as(usize, 2), state.calls);
}

test "HTTP/1 tunnel deadline preserves buffered bytes and recovers after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
        io: std.Io,
        buffered_read: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.buffered_read.set(self.io);
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-timeout",
                &.{},
            );

            var buffer: [16]u8 = undefined;
            const buffered = try tunnel.readWithTimeout(
                &buffer,
                .fromNanoseconds(0),
            );
            try std.testing.expectEqualStrings(
                "buffered",
                buffer[0..buffered],
            );
            self.buffered_read.set(self.io);

            try std.testing.expectError(
                error.Timeout,
                tunnel.readWithTimeout(
                    &buffer,
                    .fromMilliseconds(20),
                ),
            );
            self.timed_out.set(self.io);

            const resumed = try tunnel.readWithDeadline(
                &buffer,
                .fromNow(
                    self.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            );
            try std.testing.expectEqualStrings(
                "after-timeout",
                buffer[0..resumed],
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: netz-timeout\r\n\r\nbuffered",
    );
    var tunnel = try client.finishUpgradeWithTimeout(
        "netz-timeout",
        .fromSeconds(2),
    );
    try shared.buffered_read.wait(io);
    try shared.timed_out.wait(io);
    try tunnel.write("after-timeout");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime hands off generic Upgrade with buffered bytes" {
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
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-test",
                &.{},
            );
            try tunnel.write("server-preface");
            var payload: [14]u8 = undefined;
            var read: usize = 0;
            while (read < payload.len) {
                const count = try tunnel.read(payload[read..]);
                if (count == 0) return error.ConnectionClosed;
                read += count;
            }
            try std.testing.expectEqualStrings(
                "client-preface",
                &payload,
            );
            try tunnel.closeWrite();
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: keep-alive, Upgrade\r\n" ++
            "Upgrade: netz-test\r\n\r\nclient-preface",
    );
    var tunnel = try client.finishUpgradeWithTimeout(
        "netz-test",
        .fromSeconds(2),
    );
    try tunnel.closeWrite();
    var preface: [14]u8 = undefined;
    var read: usize = 0;
    while (read < preface.len) {
        const count = try tunnel.read(preface[read..]);
        if (count == 0) return error.ConnectionClosed;
        read += count;
    }
    try std.testing.expectEqualStrings("server-preface", &preface);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&preface));

    thread.join();
    if (shared.err) |err| return err;
}

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

test "HTTP/1 async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: http1.Request) Error!ResponseOptions {
            if (request.method != .POST) return error.InvalidMethod;
            if (std.mem.eql(u8, request.target, "/one")) {
                return .{ .status = 200, .body = "handled-one" };
            }
            if (std.mem.eql(u8, request.target, "/two")) {
                return .{ .status = 200, .body = "handled-two" };
            }
            return .{ .status = 404, .reason = "Not Found", .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        target: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
            defer client.close();
            var response = try client.request(.{
                .method = .POST,
                .target = task.target,
                .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(task.expected, response.response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/one", .expected = "handled-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/two", .expected = "handled-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/1 serveConnection handles keep-alive requests" {
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

    const Context = struct {
        count: usize = 0,

        fn handle(ctx: *@This(), request: http1.Request) Error!ResponseOptions {
            ctx.count += 1;
            if (std.mem.eql(u8, request.target, "/first")) {
                return .{
                    .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                    .body = "one",
                };
            }
            if (std.mem.eql(u8, request.target, "/second")) {
                return .{
                    .headers = &.{.{ .name = "Connection", .value = "close" }},
                    .body = "two",
                };
            }
            return .{ .status = 404, .reason = "Not Found", .headers = &.{.{ .name = "Connection", .value = "close" }} };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(&shared.context, Context.handle, 8) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    var first = try client.request(.{ .target = "/first", .headers = &keep_alive });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
}

test "HTTP/1 serveConnection can disable keep-alive without consuming pipeline suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
            .keep_alive = false,
        },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,

        fn handle(ctx: *@This(), request: http1.Request) Error!ResponseOptions {
            ctx.count += 1;
            if (!std.mem.eql(u8, "/first", request.target)) {
                return error.InvalidResponse;
            }
            return .{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "keep-alive",
                }},
                .body = "one",
            };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.served = try self.server.serveConnection(
                &self.context,
                Context.handle,
                8,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .target = "/first",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    // Queue a second complete request before reading the first response. The
    // disabled serve policy must not dispatch this buffered suffix.
    try writeRequestToStream(allocator, io, stream, .{
        .target = "/second",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });

    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var first = try readResponseFromStreamBuffered(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
        &inbuf,
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expect(!first.response.keepAlive());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
    try std.testing.expectEqual(@as(usize, 1), shared.context.count);
}

test "HTTP/1 serveConnection adds close for request close" {
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

    const Context = struct {
        fn handle(_: *@This(), _: http1.Request) Error!ResponseOptions {
            return .{ .body = "closing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            _ = shared.server.serveConnection(&shared.context, Context.handle, 4) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const close_header = [_]http1.Header{.{ .name = "Connection", .value = "close" }};
    var response = try client.request(.{ .target = "/close", .headers = &close_header });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("closing", response.response.body);
    try std.testing.expectEqualStrings("close", response.response.header("connection").?);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "HTTP/1 serveConnection retires TE plus CL requests before pipeline suffix" {
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

    const Context = struct {
        count: usize = 0,

        fn handle(self: *@This(), request: http1.Request) Error!ResponseOptions {
            self.count += 1;
            if (!request.must_close or request.keepAlive() or
                !std.mem.eql(u8, "payload", request.body) or
                request.header("content-length") != null)
            {
                return error.InvalidResponse;
            }
            return .{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "keep-alive",
                }},
                .body = "handled",
            };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(
                &shared.context,
                Context.handle,
                4,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(
        io,
        stream,
        "POST /ambiguous HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Content-Length: 1\r\n\r\n" ++
            "7\r\npayload\r\n0\r\n\r\n" ++
            "GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    var response = try readResponseFromStreamForRequest(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
        .POST,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("handled", response.response.body);
    try std.testing.expectEqualStrings(
        "keep-alive",
        response.response.header("connection").?,
    );
    try std.testing.expect(!response.response.keepAlive());
    try std.testing.expect(wire.anyHeaderContainsToken(
        response.response.headers,
        "connection",
        "close",
    ));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
    try std.testing.expectEqual(@as(usize, 1), shared.context.count);
}

test "HTTP/1 runtime reuses persistent connection and preserves pipelined bytes" {
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/one", first.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                .body = "first",
            });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/two", second.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "close" }},
                .body = "second",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/one",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/two",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings("first", first_response.response.body);
    try std.testing.expect(first_response.response.keepAlive());

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("second", second_response.response.body);
    try std.testing.expect(!second_response.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client reuses default HTTP/1.1 persistent connection" {
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-one", first.request.target);
            try std.testing.expect(first.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "first" });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-two", second.request.target);
            try std.testing.expect(second.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "second" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var first = try client.request(.{
        .target = "/default-one",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    try std.testing.expect(first.response.keepAlive());

    var second = try client.request(.{
        .target = "/default-two",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.response.body);
    try std.testing.expect(second.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client keeps pipelined response after HEAD response headers" {
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expect(first.request.method == .HEAD);

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expect(second.request.method == .GET);

            // A HEAD response can advertise the Content-Length a GET would have
            // returned, but no body bytes follow.  Send the next response
            // immediately to prove the client does not consume it as a HEAD
            // body.
            const raw =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
            try writeAllToStream(server_ptr.io, connection.stream, raw);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .HEAD,
        .target = "/head",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/next",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var head_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .HEAD);
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.none, head_response.response.body_framing);
    try std.testing.expectEqualStrings("", head_response.response.body);

    var get_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .GET);
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.response.status);
    try std.testing.expectEqualStrings("pong", get_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime writes duplicate request trailers with chunked framing" {
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
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("upload", request.request.body);
            try std.testing.expectEqualStrings("chunked", request.request.header("transfer-encoding").?);
            try std.testing.expectEqualStrings("Digest, X-Upload-Complete", request.request.header("trailer").?);
            try std.testing.expectEqual(@as(usize, 3), request.request.trailers.len);
            try std.testing.expectEqualStrings("Digest", request.request.trailers[0].name);
            try std.testing.expectEqualStrings("sha-256=demo", request.request.trailers[0].value);
            try std.testing.expectEqualStrings("digest", request.request.trailers[1].name);
            try std.testing.expectEqualStrings("sha-256=second", request.request.trailers[1].value);
            try std.testing.expectEqualStrings("X-Upload-Complete", request.request.trailers[2].name);
            try std.testing.expectEqualStrings("yes", request.request.trailers[2].value);

            try connection.writeResponse(.{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/upload",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        .body = "upload",
        .trailers = &.{
            .{ .name = "Digest", .value = "sha-256=demo" },
            .{ .name = "digest", .value = "sha-256=second" },
            .{ .name = "X-Upload-Complete", .value = "yes" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
}

test "HTTP/1 runtime writes duplicate response trailers with chunked framing" {
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
            try std.testing.expectEqualStrings("/download", request.request.target);
            try std.testing.expectEqualStrings("trailers", request.request.header("te").?);

            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "download",
                .request_accepts_trailers = request.request.acceptsTrailers(),
                .trailers = &.{
                    .{ .name = "Digest", .value = "sha-256=response" },
                    .{ .name = "digest", .value = "sha-256=second" },
                },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/download",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "TE", .value = "trailers" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("download", response.response.body);
    try std.testing.expectEqualStrings("chunked", response.response.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("Digest", response.response.header("trailer").?);
    try std.testing.expectEqual(@as(usize, 2), response.response.trailers.len);
    try std.testing.expectEqualStrings("Digest", response.response.trailers[0].name);
    try std.testing.expectEqualStrings("sha-256=response", response.response.trailers[0].value);
    try std.testing.expectEqualStrings("digest", response.response.trailers[1].name);
    try std.testing.expectEqualStrings("sha-256=second", response.response.trailers[1].value);
}

test "HTTP/1 runtime honors explicit transfer-encoding chunked writes" {
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
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("streamed", request.request.body);
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("content-length"));
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("trailer"));

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/explicit-chunked",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Content-Length", .value = "999" },
        },
        .body = "streamed",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(?[]const u8, null), response.response.header("content-length"));
    try std.testing.expectEqual(@as(usize, 0), response.response.trailers.len);
}

test "HTTP/1 client reads close-delimited response body" {
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
            try std.testing.expectEqualStrings("/close-delimited", request.request.target);

            // No Content-Length or Transfer-Encoding: the response body is
            // delimited by closing the connection, which remains common for
            // simple origin/proxy responses.
            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 client treats non-chunked response transfer coding as close-delimited" {
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
            try std.testing.expectEqualStrings("/te-close-delimited", request.request.target);

            // Hyper treats a response with a non-chunked transfer coding as
            // close-delimited.  Requests remain strict because accepting
            // unsupported request transfer codings is a smuggling risk.
            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: yolo\r\nContent-Length: 999\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/te-close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("yolo", response.response.header("transfer-encoding").?);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 status-forbidden body preserves pipelined response without request context" {
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);

            try writeAllToStream(server_ptr.io, connection.stream, "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/no-content", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/next", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), first_response.response.status);
    try std.testing.expectEqualStrings("", first_response.response.body);

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), second_response.response.status);
    try std.testing.expectEqualStrings("pong", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client consumes framed 205 content before next response" {
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
            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);

            try writeAllToStream(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 205 Reset Content\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Connection: keep-alive\r\n\r\nbody" ++
                    "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: 4\r\n" ++
                    "Connection: close\r\n\r\npong",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const headers = [_]http1.Header{
        .{ .name = "Connection", .value = "keep-alive" },
        .{ .name = "Host", .value = "localhost" },
    };
    try writeRequestToStream(allocator, io, client.stream, .{
        .target = "/reset",
        .headers = &headers,
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .target = "/next",
        .headers = &headers,
    });

    var first_response = try readResponseFromStreamBuffered(
        allocator,
        io,
        client.stream,
        client.limits,
        .{},
        &client.inbuf,
    );
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), first_response.response.status);
    try std.testing.expectEqualStrings("body", first_response.response.body);

    var second_response = try readResponseFromStreamBuffered(
        allocator,
        io,
        client.stream,
        client.limits,
        .{},
        &client.inbuf,
    );
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("pong", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime does not default Content-Length for status-forbidden responses" {
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
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            connection.writeResponse(.{ .status = 204, .reason = "No Content" }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var response = try client.request(.{
        .target = "/no-content",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("", response.response.body);
}

test "HTTP/1 runtime does not default Connection close on writes" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    const defaulted = try runtime_write.prepareResponse(
        allocator,
        .{},
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, defaulted.header, "Connection:") == null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            defaulted.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const explicit_close = try runtime_write.prepareResponse(
        allocator,
        .{ .headers = &.{.{
            .name = "Connection",
            .value = "close",
        }} },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            explicit_close.header,
            "Connection: close\r\n",
        ) != null,
    );
}

test "HTTP/1 request writers default Content-Length by method" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    inline for (.{ http1.Method.GET, .HEAD, .CONNECT }) |method| {
        const safe = try runtime_write.prepareRequest(
            allocator,
            .{
                .method = method,
                .target = if (method == .CONNECT)
                    "example.com:443"
                else
                    "/",
                .host = if (method == .CONNECT)
                    "example.com:443"
                else
                    "example.com",
            },
            &scratch,
        );
        try std.testing.expect(
            std.mem.indexOf(u8, safe.header, "Content-Length:") == null,
        );
    }

    const post = try runtime_write.prepareRequest(
        allocator,
        .{ .method = .POST, .host = "example.com" },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            post.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const get_body = try runtime_write.prepareRequest(
        allocator,
        .{ .host = "example.com", .body = "x" },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            get_body.header,
            "Content-Length: 1\r\n",
        ) != null,
    );
}

test "HTTP/1 request writer omits zero Content-Length for bodyless safe methods" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expect(first.request.method == .GET);
            try std.testing.expect(first.request.header("content-length") == null);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expect(second.request.method == .POST);
            try std.testing.expectEqualStrings("0", second.request.header("content-length").?);

            var third = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer third.deinit(shared.allocator);
            try std.testing.expect(third.request.method == .GET);
            try std.testing.expectEqualStrings("/cache/http://example.com/object", third.request.target);
            try std.testing.expectEqualStrings("proxy.local", third.request.header("host").?);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/safe",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });
    try writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/entity",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });
    try writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/cache/http://example.com/object",
        .headers = &.{.{ .name = "Host", .value = "proxy.local" }},
    });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime validates outbound request and response framing before writing" {
    const allocator = std.testing.allocator;
    const io: std.Io = undefined;
    const stream: net.Stream = undefined;

    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/missing-host",
    }));
    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http://example.com/absolute",
        .headers = &.{.{ .name = "Host", .value = "other.example" }},
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http:///absolute",
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "http://?q=1",
    }));
    try std.testing.expectError(error.MalformedStartLine, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "1http://example.com/absolute",
        .headers = &.{.{ .name = "Host", .value = "example.com" }},
    }));
    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{.{ .name = "Host", .value = "other.example:443" }},
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/bad-length",
        .headers = &.{
            .{ .name = "Host", .value = "example" },
            .{ .name = "Content-Length", .value = "5" },
        },
        .body = "ping",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{.{ .name = "Host", .value = "example.com:443" }},
        .body = "not allowed",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{
            .{ .name = "Host", .value = "example.com:443" },
            .{ .name = "Content-Length", .value = "0" },
        },
    }));
    try std.testing.expectError(error.InvalidTransferEncoding, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{
            .{ .name = "Host", .value = "example.com:443" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
        },
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "5" }},
        .body = "pong",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "0" }},
        .request_method = .CONNECT,
    }));

    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    const connect = try runtime_write.prepareResponse(
        allocator,
        .{ .request_method = .CONNECT },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, connect.header, "Content-Length:") == null,
    );

    const connect_error = try runtime_write.prepareResponse(
        allocator,
        .{ .status = 400, .request_method = .CONNECT },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            connect_error.header,
            "Content-Length: 0\r\n",
        ) != null,
    );

    const no_content = try runtime_write.prepareResponse(
        allocator,
        .{ .status = 204 },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, no_content.header, "Content-Length:") == null,
    );
}

test "HTTP/1 buffered aggregate chunk limit ignores pipeline suffix" {
    const allocator = std.testing.allocator;
    const first = "POST /first HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const second = "GET /second HTTP/1.1\r\nHost: example\r\n\r\n";
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(allocator, first ++ second);

    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        .{ .tcp = .{ .io = undefined, .stream = undefined } },
        .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
        .{},
        &inbuf,
        null,
        true,
        false,
        null,
        null,
        null,
        null,
    );
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings(first, bytes);
    try std.testing.expectEqualStrings(second, inbuf.items);
}

test "HTTP/1 non-buffered request reader preserves pipelined bytes on socket" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/first", first.request.target);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(io, stream, "POST /first HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nhello" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 non-buffered chunked reader preserves pipelined bytes on socket" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/chunked", first.request.target);
            try std.testing.expectEqual(http1.BodyFraming.chunked, first.request.body_framing);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(io, stream, "POST /chunked HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nDigest: ok\r\n\r\n" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 non-buffered chunked reader accepts exact and zero body limits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            var exact = try readRequestFromStream(
                shared.allocator,
                shared.io,
                stream,
                .{ .max_head_bytes = 1024, .max_body_bytes = 5 },
                .{},
            );
            defer exact.deinit(shared.allocator);
            try std.testing.expectEqualStrings("hello", exact.request.body);

            var empty = try readRequestFromStream(
                shared.allocator,
                shared.io,
                stream,
                .{ .max_head_bytes = 1024, .max_body_bytes = 0 },
                .{},
            );
            defer empty.deinit(shared.allocator);
            try std.testing.expectEqual(@as(usize, 0), empty.request.body.len);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAllToStream(
        io,
        stream,
        "POST /exact HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n" ++
            "POST /empty HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 native nonblocking peek distinguishes idle data and EOF" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    try std.testing.expectEqual(IdleSocketState.clean, probeIdleSocket(client));

    const write_parts = [_][]const u8{""};
    _ = try io.vtable.netWrite(
        io.userdata,
        server.socket.handle,
        "x",
        &write_parts,
        0,
    );
    var attempts: usize = 0;
    while (probeIdleSocket(client) == .clean and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(IdleSocketState.data, probeIdleSocket(client));
    var read_byte: [1]u8 = undefined;
    var read_parts = [_][]u8{&read_byte};
    try std.testing.expectEqual(
        @as(usize, 1),
        try io.vtable.netRead(
            io.userdata,
            client.socket.handle,
            &read_parts,
        ),
    );
    try std.testing.expectEqual(@as(u8, 'x'), read_byte[0]);

    try server.shutdown(io, .send);
    attempts = 0;
    while (probeIdleSocket(client) == .clean and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(IdleSocketState.eof, probeIdleSocket(client));
}

test {
    _ = @import("tls_tests.zig");
    _ = @import("write_strategy_tests.zig");
    _ = @import("message/continue_retry_tests.zig");
    _ = @import("message/continue_body_retry_tests.zig");
    _ = @import("message/allocation_retry_tests.zig");
    _ = @import("message/tls_allocation_retry_tests.zig");
    _ = @import("message/eof_allocation_tests.zig");
    _ = @import("message/eof_tls_allocation_tests.zig");
    _ = runtime_write;
    _ = @import("message/batch.zig");
    _ = @import("message/tests/framing.zig");
    _ = @import("transfer_encoding_tests.zig");
    _ = @import("header_compatibility_tests.zig");
    _ = close_delimited;
    _ = @import("unix_tests.zig");
    _ = @import("body_reader_tests.zig");
    _ = @import("body_pull_tests.zig");
    _ = @import("close_delimited_limit_tests.zig");
    _ = @import("body_writer_tests.zig");
    _ = @import("header_timeout_tests.zig");
    _ = @import("response_timeout_tests.zig");
    _ = @import("proxy_tests.zig");
    _ = @import("redirect_tests.zig");
    _ = @import("handoff_timeout_tests.zig");
    _ = @import("handoff_tests.zig");
    _ = @import("response_reuse_tests.zig");
    _ = @import("graceful_shutdown_tests.zig");
    _ = @import("tls_client_deadline_tests.zig");
    _ = @import("tls_client/write_retry_tests.zig");
    _ = @import("server_lifecycle_tests.zig");
    _ = @import("half_close_tests.zig");
    _ = @import("tls_close_tests.zig");
    _ = @import("tls_server_api_tests.zig");
    _ = @import("date_tests.zig");
    _ = @import("connect_udp_tests.zig");
    _ = @import("connect_udp_relay_tests.zig");
    _ = @import("connect_ip_tests.zig");
}

test "HTTP/1 drainAndClose delivers an error response before closing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 512 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *Server,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.drainAndClose(.fromNow(self.io, .{
                .raw = .fromMilliseconds(300),
                .clock = .awake,
            }));
            try connection.writeResponse(.{
                .status = 431,
                .headers = &.{},
            });
        }
    };

    var task = ServerTask{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&task});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);

    // A request head well over max_head_bytes, with more bytes still queued
    // when the server responds and closes.
    var request: [2048]u8 = undefined;
    @memset(&request, 'a');
    const prefix = "GET / HTTP/1.1\r\nHost: example\r\nX: ";
    @memcpy(request[0..prefix.len], prefix);
    @memcpy(request[request.len - 4 ..], "\r\n\r\n");
    writeAllToStream(io, stream, &request) catch |err| switch (err) {
        error.ConnectionResetByPeer, error.SocketUnconnected => {},
        else => return err,
    };

    // Let the server finish writing and closing before reading. Otherwise a
    // fast loopback read can observe the response even when close() later
    // destroys it with RST, which would hide the behaviour under test.
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);

    var response: [256]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    var received: usize = 0;
    while (received < response.len) {
        const count = stream_io.readSomeWithDeadline(
            io,
            stream,
            response[received..],
            deadline,
        ) catch |err| switch (err) {
            error.ConnectionResetByPeer => break,
            else => return err,
        };
        if (count == 0) break;
        received += count;
        if (std.mem.indexOf(u8, response[0..received], "\r\n\r\n") != null) break;
    }
    try std.testing.expect(received != 0);
    try std.testing.expect(std.mem.startsWith(u8, response[0..received], "HTTP/1.1 431"));
    thread.join();
    joined = true;
    if (task.err) |err| return err;
}

test "HTTP/1 respondAndClose answers after a failed request read" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 512 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *Server,
        io: std.Io,
        saw_unusable: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            // A head over max_head_bytes fails the read and marks the exchange
            // unusable; writeResponse would now refuse with ConnectionUnusable.
            _ = connection.readRequest(.{}) catch |err| switch (err) {
                error.HeadersTooLarge => {
                    // The streaming request reader retires the exchange with
                    // failRead() when it gives up; reproduce that exact state.
                    connection.writer_state.failRead();
                    self.saw_unusable =
                        connection.writer_state.phase == .unusable;
                    // The ordinary writer refuses once the exchange is
                    // retired; that is the state respondAndClose exists for.
                    try std.testing.expectError(
                        error.ConnectionUnusable,
                        connection.writeResponse(.{ .status = 431 }),
                    );
                    try connection.respondAndClose(.{
                        .status = 431,
                        .reason = "Request Header Fields Too Large",
                    }, .fromNow(self.io, .{
                        .raw = .fromMilliseconds(300),
                        .clock = .awake,
                    }));
                    return;
                },
                else => return err,
            };
            return error.TestUnexpectedResult;
        }
    };

    var task = ServerTask{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&task});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var request: [2048]u8 = undefined;
    @memset(&request, 'a');
    const prefix = "GET / HTTP/1.1\r\nHost: example\r\nX: ";
    @memcpy(request[0..prefix.len], prefix);
    @memcpy(request[request.len - 4 ..], "\r\n\r\n");
    writeAllToStream(io, stream, &request) catch |err| switch (err) {
        error.ConnectionResetByPeer, error.SocketUnconnected => {},
        else => return err,
    };

    var response: [512]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    var received: usize = 0;
    while (received < response.len) {
        const count = stream_io.readSomeWithDeadline(
            io,
            stream,
            response[received..],
            deadline,
        ) catch |err| switch (err) {
            error.ConnectionResetByPeer => break,
            else => return err,
        };
        if (count == 0) break;
        received += count;
        if (std.mem.indexOf(u8, response[0..received], "\r\n\r\n") != null) break;
    }
    try std.testing.expect(received != 0);
    try std.testing.expect(std.mem.startsWith(u8, response[0..received], "HTTP/1.1 431"));
    try std.testing.expect(
        std.mem.indexOf(u8, response[0..received], "Connection: close") != null,
    );

    thread.join();
    joined = true;
    if (task.err) |err| return err;
    try std.testing.expect(task.saw_unusable);
}
