//! HTTP/1 writer framing defaults, buffered readers, and socket-peek tests.
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
