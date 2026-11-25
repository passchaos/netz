//! HTTP/1 message buffer ownership, batch, and pipeline validation tests.
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

// Buffered-only reads still expose transport metadata; no socket I/O occurs.
const buffered_stream: net.Stream = .{ .socket = .{ .handle = undefined, .address = .{ .ip4 = .loopback(1234) } } };

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
        .stream = buffered_stream,
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
    try std.testing.expect(heads[0].from != null);
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
        .stream = buffered_stream,
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
        .stream = buffered_stream,
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
        .stream = buffered_stream,
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
