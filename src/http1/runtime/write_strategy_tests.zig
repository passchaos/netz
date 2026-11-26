//! HTTP/1 write-strategy, batch, and partial-write tests.

const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
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

test "HTTP/1 write strategy controls complete message transport shape" {
    try native_protocol_io.runStream(messageTransportShape);
}

fn messageTransportShape(io: std.Io) !void {
    const Observer = struct {
        delegate: std.Io,
        bytes: [8192]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) {
                for (data[0 .. data.len - 1]) |bytes| {
                    non_empty += @intFromBool(bytes.len != 0);
                    written += self.append(bytes);
                }
                const pattern = data[data.len - 1];
                non_empty += @intFromBool(pattern.len != 0 and splat != 0);
                for (0..splat) |_| written += self.append(pattern);
            }
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            std.debug.assert(self.len + bytes.len <= self.bytes.len);
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    const request_options = RequestOptions{
        .method = .POST,
        .target = "/shape",
        .host = "example.test",
        .body = "request-body",
    };

    var vectored_request: Observer = .{ .delegate = io };
    var vectored_client = Client{
        .io = forwarded_io.observer(&vectored_request, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .vectored },
    };
    defer {
        vectored_client.inbuf.deinit(std.testing.allocator);
        vectored_client.write_scratch.deinit(std.testing.allocator);
    }
    try vectored_client.writeRequestFailClosed(request_options);
    try std.testing.expectEqual(@as(usize, 1), vectored_request.calls);
    try std.testing.expectEqual(@as(usize, 2), vectored_request.max_non_empty_parts);

    var flat_request: Observer = .{ .delegate = io };
    var flat_client = Client{
        .io = forwarded_io.observer(&flat_request, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .flatten },
    };
    defer {
        flat_client.inbuf.deinit(std.testing.allocator);
        flat_client.write_scratch.deinit(std.testing.allocator);
    }
    try flat_client.writeRequestFailClosed(request_options);
    try std.testing.expectEqual(@as(usize, 1), flat_request.calls);
    try std.testing.expectEqual(@as(usize, 1), flat_request.max_non_empty_parts);
    try std.testing.expectEqualStrings(
        vectored_request.bytes[0..vectored_request.len],
        flat_request.bytes[0..flat_request.len],
    );

    const response_options = ResponseOptions{ .body = "response-body" };
    var vectored_response: Observer = .{ .delegate = io };
    var vectored_connection = Connection{
        .io = forwarded_io.observer(&vectored_response, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .vectored,
        },
    };
    defer {
        vectored_connection.inbuf.deinit(std.testing.allocator);
        vectored_connection.write_scratch.deinit(std.testing.allocator);
    }
    try vectored_connection.writeResponse(response_options);
    try std.testing.expectEqual(@as(usize, 2), vectored_response.max_non_empty_parts);

    var flat_response: Observer = .{ .delegate = io };
    var flat_connection = Connection{
        .io = forwarded_io.observer(&flat_response, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        flat_connection.inbuf.deinit(std.testing.allocator);
        flat_connection.write_scratch.deinit(std.testing.allocator);
    }
    try flat_connection.writeResponse(response_options);
    try std.testing.expectEqual(@as(usize, 1), flat_response.max_non_empty_parts);
    try std.testing.expectEqualStrings(
        vectored_response.bytes[0..vectored_response.len],
        flat_response.bytes[0..flat_response.len],
    );
}

test "HTTP/1 flatten strategy applies to streaming chunks" {
    try native_protocol_io.runStream(flattenedStreamingChunks);
}

fn flattenedStreamingChunks(io: std.Io) !void {
    const Observer = struct {
        delegate: std.Io,
        bytes: [1024]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                non_empty += @intFromBool(bytes.len != 0);
                written += self.append(bytes);
            };
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    var observer: Observer = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&observer, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }
    var writer = try connection.startResponse(.{ .body_length = null });
    defer writer.deinit();
    observer.len = 0;
    observer.calls = 0;
    observer.max_non_empty_parts = 0;
    try writer.writeChunks(&.{ "a", "bc" });
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqual(@as(usize, 1), observer.max_non_empty_parts);
    try std.testing.expectEqualStrings("1\r\na\r\n2\r\nbc\r\n", observer.bytes[0..observer.len]);
    try writer.finish();
}

test "HTTP/1 response batch write strategy overrides the automatic threshold" {
    try native_protocol_io.runStream(batchedTransportShape);
}

fn batchedTransportShape(io: std.Io) !void {
    try std.testing.expectEqual(
        WriteStrategy.flatten,
        responseBatchWriteStrategy(.auto, response_batch_borrow_threshold),
    );
    try std.testing.expectEqual(
        WriteStrategy.vectored,
        responseBatchWriteStrategy(
            .auto,
            response_batch_borrow_threshold + 1,
        ),
    );
    try std.testing.expectEqual(
        WriteStrategy.vectored,
        responseBatchWriteStrategy(.vectored, 0),
    );
    try std.testing.expectEqual(
        WriteStrategy.flatten,
        responseBatchWriteStrategy(
            .flatten,
            response_batch_borrow_threshold + 1,
        ),
    );

    const Observer = struct {
        delegate: std.Io,
        bytes: [2048]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_non_empty_parts: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var non_empty: usize = @intFromBool(header.len != 0);
            var written = self.append(header);
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                non_empty += @intFromBool(bytes.len != 0);
                written += self.append(bytes);
            };
            self.max_non_empty_parts = @max(
                self.max_non_empty_parts,
                non_empty,
            );
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            std.debug.assert(self.len + bytes.len <= self.bytes.len);
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    const responses = [_]ResponseOptions{
        .{ .body = "one" },
        .{ .status = 201, .reason = "Created", .body = "two" },
    };

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    var peer = try listener.accept(io);
    defer peer.close(io);
    var vectored = Connection{
        .io = io,
        .allocator = std.testing.allocator,
        .stream = stream,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .vectored,
        },
    };
    defer vectored.close();
    try vectored.writeResponses(&responses);

    var flat_observer: Observer = .{ .delegate = io };
    var flat = Connection{
        .io = forwarded_io.observer(&flat_observer, .{ .netWrite = Observer.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{
            .auto_date_header = false,
            .write_strategy = .flatten,
        },
    };
    defer {
        flat.inbuf.deinit(std.testing.allocator);
        flat.write_scratch.deinit(std.testing.allocator);
    }
    try flat.writeResponses(&responses);
    try std.testing.expectEqual(@as(usize, 1), flat_observer.calls);
    try std.testing.expectEqual(@as(usize, 1), flat_observer.max_non_empty_parts);
    var vectored_bytes: [2048]u8 = undefined;
    try readExactForTest(io, peer, vectored_bytes[0..flat_observer.len]);
    try std.testing.expectEqualStrings(
        flat_observer.bytes[0..flat_observer.len],
        vectored_bytes[0..flat_observer.len],
    );
}

test "HTTP/1 flatten allocation failure is retryable before transport" {
    try native_protocol_io.runStream(flattenAllocationRetry);
}

fn flattenAllocationRetry(io: std.Io) !void {
    const Observer = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            var total = header.len;
            if (data.len != 0) for (data[0 .. data.len - 1]) |bytes| {
                total += bytes.len;
            };
            return total;
        }
    };

    const allocator = std.testing.allocator;
    var observer: Observer = .{ .delegate = io };
    var client = Client{
        .io = forwarded_io.observer(&observer, .{ .netWrite = Observer.write }),
        .allocator = allocator,
        .stream = undefined,
        .limits = .{ .write_strategy = .flatten },
    };
    defer {
        client.inbuf.deinit(allocator);
        client.write_scratch.deinit(allocator);
    }
    const options = RequestOptions{
        .method = .POST,
        .host = "example.test",
        .body = "body",
    };
    _ = try runtime_write.prepareRequest(allocator, options, &client.write_scratch);
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    client.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        client.writeRequestFailClosed(options),
    );
    client.allocator = allocator;
    try std.testing.expect(client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
}

test "HTTP/1 aggregate write failures make connections unusable" {
    try native_protocol_io.runStream(aggregateWriteFailure);
}

fn aggregateWriteFailure(io: std.Io) !void {
    const FailingWriter = struct {
        delegate: std.Io,
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

    var client_writer: FailingWriter = .{ .delegate = io };
    var client = Client{
        .io = forwarded_io.observer(&client_writer, .{ .netWrite = FailingWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
    };
    defer {
        client.inbuf.deinit(std.testing.allocator);
        client.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        client.request(.{
            .method = .POST,
            .target = "/partial-request",
            .host = "example.test",
            .body = "body",
        }),
    );
    try std.testing.expect(!client.isReusable());
    const client_calls = client_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "example.test" }),
    );
    try std.testing.expectEqual(client_calls, client_writer.calls);

    var response_writer: FailingWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&response_writer, .{ .netWrite = FailingWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        connection.writeResponse(.{ .body = "body" }),
    );
    const response_calls = response_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.writeResponse(.{ .body = "must-not-write" }),
    );
    try std.testing.expectEqual(response_calls, response_writer.calls);

    var batch_writer: FailingWriter = .{ .delegate = io };
    var batch_connection = Connection{
        .io = forwarded_io.observer(&batch_writer, .{ .netWrite = FailingWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        batch_connection.inbuf.deinit(std.testing.allocator);
        batch_connection.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.NetworkDown,
        batch_connection.writeResponses(&.{
            .{ .body = "one" },
            .{ .body = "two" },
        }),
    );
    const batch_calls = batch_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        batch_connection.writeResponses(&.{.{ .body = "must-not-write" }}),
    );
    try std.testing.expectEqual(batch_calls, batch_writer.calls);

    var continue_writer: FailingWriter = .{ .delegate = io };
    var continue_connection = Connection{
        .io = forwarded_io.observer(&continue_writer, .{ .netWrite = FailingWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        continue_connection.inbuf.deinit(std.testing.allocator);
        continue_connection.write_scratch.deinit(std.testing.allocator);
    }
    try continue_connection.inbuf.appendSlice(
        std.testing.allocator,
        "POST /continue HTTP/1.1\r\n" ++
            "Host: example.test\r\n" ++
            "Content-Length: 1\r\n" ++
            "Expect: 100-continue\r\n\r\nx",
    );
    try std.testing.expectError(
        error.NetworkDown,
        continue_connection.readRequest(.{}),
    );
    const continue_calls = continue_writer.calls;
    try std.testing.expectError(
        error.ConnectionUnusable,
        continue_connection.readRequest(.{}),
    );
    try std.testing.expectEqual(continue_calls, continue_writer.calls);
}

test "HTTP/1 TLS key updates require an idle HTTP exchange" {
    const fake_client: *tls_stream.ClientConnection = @ptrFromInt(4096);
    var client = Client{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls_vail_conn = fake_client,
    };
    client.writer_state.phase = .writing;
    try std.testing.expectError(
        error.ConnectionBusy,
        client.updateTrafficKeys(false),
    );
    client.writer_state.phase = .unusable;
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.updateTrafficKeys(false),
    );

    const fake_server: *tls_stream.ServerConnection = @ptrFromInt(4096);
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .tls_server_conn = fake_server,
    };
    connection.writer_state.phase = .awaiting_peer;
    try std.testing.expectError(
        error.ConnectionBusy,
        connection.updateTrafficKeys(false),
    );
    connection.writer_state.phase = .unusable;
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.updateTrafficKeys(false),
    );
}

test "HTTP/1 large response batch write failure makes connection unusable" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = try listener.accept(io);
    const abortive: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(
        peer.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.LINGER,
        std.mem.asBytes(&abortive),
    );
    peer.close(io);
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectError(
        error.ConnectionResetByPeer,
        io.vtable.netRead(io.userdata, stream.socket.handle, &buffers),
    );

    var connection = Connection{
        .io = io,
        .allocator = allocator,
        .stream = stream,
        .limits = .{ .auto_date_header = false },
    };
    defer connection.close();
    const large_body = "x" ** (response_batch_borrow_threshold + 1);
    var failed = false;
    connection.writeResponses(&.{.{ .body = large_body }}) catch |err| {
        failed = true;
        try std.testing.expect(err == error.SocketUnconnected or
            err == error.ConnectionResetByPeer);
    };
    try std.testing.expect(failed);
    try std.testing.expectError(
        error.ConnectionUnusable,
        connection.writeResponse(.{ .body = "must-not-write" }),
    );
}

test "HTTP/1 aggregate 100 Continue partial write is terminal" {
    try native_protocol_io.runStream(continuePartialWrite);
}

fn continuePartialWrite(io: std.Io) !void {
    const allocator = std.testing.allocator;
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .auto_date_header = false },
    );
    defer server.deinit();

    const FailingWriter = struct {
        delegate: std.Io,
        calls: usize = 0,

        /// Accept one TCP prefix before the terminal write failure.
        fn write(
            context: ?*anyopaque,
            handle: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls != 1) return error.NetworkDown;
            return self.delegate.vtable.netWrite(
                self.delegate.userdata,
                handle,
                header[0..@min(header.len, 4)],
                &.{""},
                0,
            );
        }
    };

    const Shared = struct {
        server: *Server,
        io: std.Io,
        writer_calls: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var writer = FailingWriter{ .delegate = self.io };
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            });
            connection.io = forwarded_io.observer(&writer, .{ .netWrite = FailingWriter.write });
            defer connection.io = self.io;

            try std.testing.expectError(
                error.NetworkDown,
                connection.readRequestWithDeadline(.{}, deadline),
            );
            const calls = writer.calls;
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.writeResponse(.{ .body = "must-not-write" }),
            );
            try std.testing.expectEqual(calls, writer.calls);
            self.writer_calls = writer.calls;
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAllToStream(
        io,
        client,
        "POST /continue HTTP/1.1\r\n" ++
            "Host: example.test\r\n" ++
            "Content-Length: 4\r\n" ++
            "Expect: 100-continue\r\n\r\n",
    );
    var visible_prefix: [4]u8 = undefined;
    try readExactForTest(io, client, &visible_prefix);
    try std.testing.expectEqualStrings("HTTP", &visible_prefix);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.writer_calls);
}

test "HTTP/1 aggregate write validation errors remain retryable" {
    var client = Client{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
    };
    defer {
        client.inbuf.deinit(std.testing.allocator);
        client.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.InvalidContentLength,
        client.request(.{
            .method = .POST,
            .host = "example.test",
            .headers = &.{.{
                .name = "Content-Length",
                .value = "2",
            }},
            .body = "x",
        }),
    );
    try std.testing.expect(client.isReusable());

    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponse(.{ .status = 204, .body = "forbidden" }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponse(.{ .status = 205, .body = "forbidden" }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponses(&.{
            .{ .body = "ok" },
            .{ .status = 205, .body = "forbidden" },
        }),
    );
    try std.testing.expectEqual(
        body_writer.State.Phase.idle,
        connection.writer_state.phase,
    );
}

test "HTTP/1 response batch borrows fixed bodies after validation" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);

    var first_body = [_]u8{ 'f', 'i', 'r', 's', 't' };
    var second_body = [_]u8{ 's', 'e', 'c', 'o', 'n', 'd' };
    const responses = [_]ResponseOptions{
        .{ .body = &first_body },
        .{ .body = &second_body },
    };
    const parts = try runtime_write.prepareResponseParts(
        allocator,
        &responses,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 4), parts.len);
    try std.testing.expect(parts[1].ptr == first_body[0..].ptr);
    try std.testing.expect(parts[3].ptr == second_body[0..].ptr);
    try std.testing.expect(std.mem.startsWith(
        u8,
        parts[0],
        "HTTP/1.1 200 OK\r\n",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        parts[2],
        "HTTP/1.1 200 OK\r\n",
    ));

    // Borrowing is observable: mutation after validation changes the body
    // slice that would be submitted, while encoded heads remain stable.
    first_body[0] = 'F';
    try std.testing.expectEqualStrings("First", parts[1]);
}

test "HTTP/1 response batch retains chunk framing beside borrowed bodies" {
    const allocator = std.testing.allocator;
    var scratch: WriteScratch = .{};
    defer scratch.deinit(allocator);
    const responses = [_]ResponseOptions{
        .{ .body = "fixed" },
        .{
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
            .body = "chunk",
        },
    };
    const parts = try runtime_write.prepareResponseParts(
        allocator,
        &responses,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 4), parts.len);
    try std.testing.expectEqualStrings("fixed", parts[1]);
    try std.testing.expectEqualStrings(
        "5\r\nchunk\r\n0\r\n\r\n",
        parts[3],
    );
}
