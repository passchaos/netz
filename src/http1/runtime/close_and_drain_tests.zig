//! HTTP/1 drainAndClose and respondAndClose tests.
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
