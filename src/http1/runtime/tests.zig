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

test {
    _ = @import("tls_tests.zig");
    _ = @import("client_and_continue_tests.zig");
    _ = @import("tunnel_tests.zig");
    _ = @import("write_strategy_tests.zig");
    _ = @import("keep_alive_and_pipeline_tests.zig");
    _ = @import("writer_framing_and_reader_tests.zig");
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
