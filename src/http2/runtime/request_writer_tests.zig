const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Limits = runtime.Limits;
const Server = runtime.Server;
const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

test "HTTP/2 request writer streams with flow control and trailers" {
    const allocator = std.testing.allocator;
    const first = "request-writer-first-" ** 2048;
    const second = "request-writer-second-" ** 2048;
    const expected_len = first.len + second.len;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = expected_len,
        .initial_window_size = 24 * 1024,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        bytes: usize = 0,
        checksum: u64 = 0,
        calls: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn consume(shared: *@This(), data: []const u8) !void {
            shared.bytes += data.len;
            shared.calls += 1;
            for (data) |byte| shared.checksum +%= byte;
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequestStreaming(
                shared,
                consume,
            );
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(expected_len, request.body_bytes);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings(
                "complete",
                request.trailers[0].value,
            );
            try connection.writeResponse(request.stream_id, .{
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();

    var writer = try client.startRequest(.{
        .path = "/stream-upload",
        .authority = "localhost",
        .body_length = expected_len,
    });
    defer writer.deinit();
    try writer.write(first);
    try writer.write(second);
    try writer.finishTrailers(&.{.{
        .name = "x-upload-state",
        .value = "complete",
    }});
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (first) |byte| expected_checksum +%= byte;
    for (second) |byte| expected_checksum +%= byte;
    try std.testing.expectEqualStrings("accepted", response.body);
    try std.testing.expectEqual(expected_len, shared.bytes);
    try std.testing.expectEqual(expected_checksum, shared.checksum);
    try std.testing.expect(shared.calls > 2);
    try std.testing.expect(writer.body_finished);
    try std.testing.expect(writer.completed);
}

test "HTTP/2 request writer length errors are transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
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
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("abcde", request.body);
            try connection.writeResponse(request.stream_id, .{});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/length-retry",
        .authority = "localhost",
        .body_length = 5,
    });
    defer writer.deinit();
    try writer.write("ab");
    try std.testing.expectError(
        error.InvalidContentLength,
        writer.finishData("toolong"),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.written);
    try std.testing.expect(!writer.body_finished);
    try writer.finishData("cde");
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer deinit cancels after body FIN" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
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
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            var reset = try connection.readResetStream();
            defer reset.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                request.stream_id,
                reset.reset.stream_id,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/cancel-after-fin",
        .authority = "localhost",
        .body_length = 0,
    });
    try writer.finish();
    writer.deinit();
    try std.testing.expect(writer.completed);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer preserves early response while flow blocked" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = 4096,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        response_consumed: std.Io.Event = .unset,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var connection = try server_ptr.accept();
            defer connection.close();
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.writeHeaders(
                &connection,
                stream_id,
                &.{
                    .{ .name = ":status", .value = "413" },
                    .{ .name = "content-length", .value = "14" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                stream_id,
                "stop uploading",
                true,
            );
            // Closing with unread request DATA can reset TCP before the
            // client consumes the final response. Keep this peer alive until
            // the receive-side assertions have a complete response to inspect.
            try shared.response_consumed.wait(server_ptr.io);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/early-response",
        .authority = "localhost",
    });
    var joined = false;
    defer if (!joined) {
        shared.response_consumed.set(io);
        thread.join();
    };
    defer writer.deinit();

    // Permit exactly the first chunk. The second write must wait for peer
    // input, where it encounters the response HEADERS before WINDOW_UPDATE.
    client.send_connection_window.value = "first".len;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = "first".len;
    try writer.write("first");
    try std.testing.expectError(
        error.ResponseAvailable,
        writer.write("second"),
    );
    try std.testing.expectEqual(@as(usize, "first".len), writer.written);
    try std.testing.expect(writer.body_finished);
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    shared.response_consumed.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 413), response.status);
    try std.testing.expectEqualStrings("stop uploading", response.body);
    try std.testing.expect(writer.completed);
}

test "HTTP/2 early response ignores trailing NO_ERROR reset before reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = 4096,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
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
            const first_stream = try readRequestHeadersStreamId(&connection);
            try runtime.testing.writeHeaders(
                &connection,
                first_stream,
                &.{.{ .name = ":status", .value = "413" }},
                false,
            );
            try runtime.testing.writeData(
                &connection,
                first_stream,
                "early",
                false,
            );
            try runtime.testing.writeHeaders(
                &connection,
                first_stream,
                &.{.{ .name = "x-early", .value = "complete" }},
                true,
            );
            try runtime.testing.writeRawFrame(
                &connection,
                .rst_stream,
                0,
                first_stream,
                &.{ 0, 0, 0, 0 },
            );

            // RequestWriter closes its request half after observing the early
            // response. Consume the already-sent prefix through its zero-length
            // DATA FIN before the next request, preserving exact frame order.
            while (true) {
                var frame = try runtime.testing.readOwnedFrame(&connection);
                defer frame.deinit(server_ptr.allocator);
                if (try runtime.testing.handleConnectionFrame(
                    &connection,
                    frame.frame,
                )) continue;
                if (frame.frame.header.stream_id == first_stream) {
                    try std.testing.expectEqual(
                        http2.FrameType.data,
                        frame.frame.header.frame_type,
                    );
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        runtime.testing.releasePeerStream(
                            &connection,
                            first_stream,
                        );
                    }
                    continue;
                }
                try std.testing.expectEqual(
                    http2.FrameType.headers,
                    frame.frame.header.frame_type,
                );
                try runtime.testing.writeHeaders(
                    &connection,
                    frame.frame.header.stream_id,
                    &.{.{ .name = ":status", .value = "200" }},
                    false,
                );
                try runtime.testing.writeData(
                    &connection,
                    frame.frame.header.stream_id,
                    "reused",
                    true,
                );
                runtime.testing.releasePeerStream(
                    &connection,
                    frame.frame.header.stream_id,
                );
                return;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();

    var writer = try client.startRequest(.{
        .path = "/early-reset",
        .authority = "localhost",
        .body_length = "firstsecond".len,
    });
    defer writer.deinit();
    client.send_connection_window.value = "first".len;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = "first".len;
    try writer.write("first");
    try std.testing.expectError(
        error.ResponseAvailable,
        writer.write("second"),
    );
    var first_response = try writer.readResponse();
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 413), first_response.status);
    try std.testing.expectEqualStrings("early", first_response.body);
    try std.testing.expectEqual(@as(usize, 1), first_response.trailers.len);
    try std.testing.expectEqualStrings(
        "complete",
        first_response.trailers[0].value,
    );

    const second_result = client.request(.{
        .path = "/after-early-reset",
        .authority = "localhost",
    });
    thread.join();
    if (shared.err) |err| return err;
    var second_response = try second_result;
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("reused", second_response.body);
}

test "HTTP/2 request writer reports peer reset while flow blocked" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = 4096,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
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
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.addActivePeerStream(
                &connection,
                stream_id,
            );
            try connection.sendResetStream(
                stream_id,
                .cancel,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/early-reset",
        .authority = "localhost",
    });
    defer writer.deinit();
    client.send_connection_window.value = "first".len;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = "first".len;
    try writer.write("first");
    try std.testing.expectError(
        error.StreamReset,
        writer.write("second"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer streams response preserved during upload" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = 4096,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
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
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.writeHeaders(
                &connection,
                stream_id,
                &.{
                    .{ .name = ":status", .value = "422" },
                    .{ .name = "content-length", .value = "5" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                stream_id,
                "early",
                true,
            );
        }
    };

    const Consumer = struct {
        storage: [5]u8 = undefined,
        len: usize = 0,

        fn consume(self: *@This(), data: []const u8) !void {
            @memcpy(self.storage[self.len..][0..data.len], data);
            self.len += data.len;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/early-stream-response",
        .authority = "localhost",
    });
    defer writer.deinit();
    client.send_connection_window.value = 0;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = 0;
    try std.testing.expectError(
        error.ResponseAvailable,
        writer.write("never-sent"),
    );
    var consumer: Consumer = .{};
    var response = try writer.readResponseStreaming(
        &consumer,
        Consumer.consume,
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 422), response.status);
    try std.testing.expectEqualStrings(
        "early",
        consumer.storage[0..consumer.len],
    );
}

fn readRequestHeadersStreamId(
    connection: *runtime.Connection,
) !u31 {
    while (true) {
        var frame = try runtime.testing.readOwnedFrame(connection);
        defer frame.deinit(connection.allocator);
        if (try runtime.testing.handleConnectionFrame(
            connection,
            frame.frame,
        )) continue;
        try std.testing.expectEqual(
            http2.FrameType.headers,
            frame.frame.header.frame_type,
        );
        return frame.frame.header.stream_id;
    }
}

test "HTTP/2 duplex stream interleaves both halves and releases after both FINs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
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
            var stream = try connection.acceptDuplexRequest();
            defer stream.deinit();
            try std.testing.expectEqualStrings("/duplex", stream.path);
            try stream.startResponse(.{});
            _ = try stream.writeResponse("response-one");

            var request_data = try stream.readRequestEvent();
            defer request_data.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "request-one",
                request_data.data.data,
            );
            _ = try stream.writeResponseParts("response-", "two");

            var request_two = try stream.readRequestEvent();
            defer request_two.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "request-two",
                request_two.data.data,
            );
            // The final request bytes carry END_STREAM, so the DATA event is
            // followed by the explicit terminal event.
            if (!stream.requestFinished()) {
                var request_finished = try stream.readRequestEvent();
                defer request_finished.deinit(self.server.allocator);
                try std.testing.expect(request_finished == .finished);
            }
            try stream.finishResponseTrailers(&.{.{
                .name = "x-duplex",
                .value = "done",
            }});

            var next = try connection.readRequest();
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-duplex", next.path);
            try connection.writeResponse(next.stream_id, .{ .body = "reused" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/duplex",
        .authority = "localhost",
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    const first_write = try stream.write("request-one");
    try std.testing.expectEqual(@as(usize, "request-one".len), first_write.written);

    var head = try stream.readResponseEvent();
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    var first_response = try stream.readResponseEvent();
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings("response-one", first_response.data.data);

    const second_write = try stream.finishRequestParts("request-two", "");
    try std.testing.expectEqual(@as(usize, "request-two".len), second_write.written);
    try std.testing.expect(stream.requestFinished());
    var second_response = try stream.readResponseEvent();
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("response-", second_response.data.data);
    var second_response_tail = try stream.readResponseEvent();
    defer second_response_tail.deinit(allocator);
    try std.testing.expectEqualStrings(
        "two",
        second_response_tail.data.data,
    );
    var trailers = try stream.readResponseEvent();
    defer trailers.deinit(allocator);
    try std.testing.expectEqualStrings(
        "done",
        runtime.testing.findHeader(trailers.trailers, "x-duplex").?,
    );
    var finished = try stream.readResponseEvent();
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    var reused = try connection.request(.{
        .path = "/after-duplex",
        .authority = "localhost",
    });
    defer reused.deinit(allocator);
    try std.testing.expectEqualStrings("reused", reused.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 duplex response HEADERS timeout resumes CONTINUATION" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        first_sent: std.Io.Event = .unset,
        retrying: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_sent.set(self.server.io);
                self.retrying.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const stream_id = try readRequestHeadersStreamId(&connection);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(self.server.allocator);
            try connection.hpack_encoder.encodeBlock(
                &block,
                self.server.allocator,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "x-resumed", .value = "yes" },
                },
            );
            const split = @max(@as(usize, 1), block.items.len / 2);
            try runtime.testing.writeRawFrame(
                &connection,
                .headers,
                flag_end_stream,
                stream_id,
                block.items[0..split],
            );
            self.first_sent.set(self.server.io);
            try self.retrying.wait(self.server.io);
            try runtime.testing.writeRawFrame(
                &connection,
                .continuation,
                flag_end_headers,
                stream_id,
                block.items[split..],
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/resume-head",
        .authority = "localhost",
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    try shared.first_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        stream.readResponseEventWithTimeout(.fromMilliseconds(20)),
    );
    shared.retrying.set(io);
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    try std.testing.expectEqualStrings(
        "yes",
        runtime.testing.findHeader(head.head.headers, "x-resumed").?,
    );
    var finished = try stream.readResponseEvent();
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    try stream.closeRequestAfterResponse();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 duplex response can finish before request drains" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
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
            var stream = try connection.acceptDuplexRequest();
            defer stream.deinit();
            try stream.finishResponseHeaders(.{
                .headers = &.{.{ .name = "x-early", .value = "done" }},
            });
            try std.testing.expect(stream.responseFinished());
            try std.testing.expect(!stream.requestFinished());
            var data = try stream.readRequestEvent();
            defer data.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("late-upload", data.data.data);
            var finished = try stream.readRequestEvent();
            defer finished.deinit(self.server.allocator);
            try std.testing.expect(finished == .finished);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/early-duplex",
        .authority = "localhost",
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    var head = try stream.readResponseEvent();
    defer head.deinit(allocator);
    try std.testing.expectEqualStrings(
        "done",
        runtime.testing.findHeader(head.head.headers, "x-early").?,
    );
    try std.testing.expect(stream.responseFinished());
    const sent = try stream.finishRequestParts("late-upload", "");
    try std.testing.expectEqual(@as(usize, "late-upload".len), sent.written);
    var finished = try stream.readResponseEvent();
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 duplex flow-control writes report exact resumable progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .initial_window_size = 4,
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
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
            var stream = try connection.acceptDuplexRequest();
            defer stream.deinit();
            try stream.startResponse(.{});
            const first = try stream.writeResponse("ABCDEFGH");
            try std.testing.expectEqual(@as(usize, 4), first.written);
            try std.testing.expect(first.response_available);

            var request_one = try stream.readRequestEvent();
            defer request_one.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("abcd", request_one.data.data);
            const second = try stream.writeResponse("EFGH");
            try std.testing.expectEqual(@as(usize, 4), second.written);
            try std.testing.expect(!second.response_available);

            var request_two = try stream.readRequestEvent();
            defer request_two.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("efgh", request_two.data.data);
            if (!stream.requestFinished()) {
                var request_done = try stream.readRequestEvent();
                defer request_done.deinit(self.server.allocator);
                try std.testing.expect(request_done == .finished);
            }
            try stream.finishResponseTrailers(&.{.{
                .name = "x-flow",
                .value = "done",
            }});
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/duplex-flow",
        .authority = "localhost",
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    const first = try stream.write("abcdefgh");
    try std.testing.expectEqual(@as(usize, 4), first.written);
    try std.testing.expect(first.response_available);

    var head = try stream.readResponseEvent();
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    var response_one = try stream.readResponseEvent();
    defer response_one.deinit(allocator);
    try std.testing.expectEqualStrings("ABCD", response_one.data.data);
    const second = try stream.finishRequestParts("efgh", "");
    try std.testing.expectEqual(@as(usize, 4), second.written);
    try std.testing.expect(!second.response_available);

    var response_two = try stream.readResponseEvent();
    defer response_two.deinit(allocator);
    try std.testing.expectEqualStrings("EFGH", response_two.data.data);
    var trailers = try stream.readResponseEvent();
    defer trailers.deinit(allocator);
    try std.testing.expectEqualStrings(
        "done",
        runtime.testing.findHeader(trailers.trailers, "x-flow").?,
    );
    var done = try stream.readResponseEvent();
    defer done.deinit(allocator);
    try std.testing.expect(done == .finished);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client duplex deadline resumes request slices after flow control" {
    const allocator = std.testing.allocator;
    const payload = "abcdefgh";
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .initial_window_size = 4,
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        accepted: std.Io.Event = .unset,
        timeout_done: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try connection.acceptDuplexRequest();
            defer stream.deinit();
            self.accepted.set(self.server.io);
            try self.timeout_done.wait(self.server.io);

            var prefix: [4]u8 = undefined;
            var prefix_len: usize = 0;
            while (prefix_len < prefix.len) {
                var event = try stream.readRequestEventWithTimeout(
                    .fromSeconds(2),
                );
                defer event.deinit(self.server.allocator);
                try std.testing.expect(event == .data);
                const data = event.data.data;
                try std.testing.expect(data.len <= prefix.len - prefix_len);
                @memcpy(prefix[prefix_len..][0..data.len], data);
                prefix_len += data.len;
            }
            try std.testing.expectEqualStrings("abcd", &prefix);
            try connection.releaseReceivedCapacity(
                stream.stream_id,
                prefix.len,
            );
            self.credit_sent.set(self.server.io);

            var second = try stream.readRequestEventWithTimeout(
                .fromSeconds(2),
            );
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("efgh", second.data.data);
            if (!stream.requestFinished()) {
                var finished = try stream.readRequestEventWithTimeout(
                    .fromSeconds(2),
                );
                defer finished.deinit(self.server.allocator);
                try std.testing.expect(finished == .finished);
            }
            try stream.finishResponseHeaders(.{});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timeout_done.set(io);
        thread.join();
    };

    var connection = try Client.connect(allocator, io, server.address(), limits);
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/duplex-request-deadline",
        .authority = "localhost",
        .body_length = payload.len,
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    try shared.accepted.wait(io);
    connection.send_connection_window.value = 4;
    (try runtime.testing.sendStreamWindow(
        &connection,
        stream.stream_id,
    )).value = 4;

    try std.testing.expectError(
        error.Timeout,
        stream.finishRequestDataWithDeadline(payload, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), stream.requestCommittedBytes());

    try std.testing.expectError(
        error.Timeout,
        stream.writeRequestSlicesWithTimeout(
            &.{ "ab", "cdefgh" },
            false,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 4), stream.requestCommittedBytes());
    shared.timeout_done.set(io);
    try shared.credit_sent.wait(io);

    const suffix = payload[stream.requestCommittedBytes()..];
    const resumed = try stream.finishRequestDataWithTimeout(
        suffix,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(suffix.len, resumed.written);
    try std.testing.expect(stream.requestFinished());
    try std.testing.expectEqual(payload.len, stream.requestCommittedBytes());

    var head = try stream.readResponseEventWithTimeout(.fromSeconds(2));
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    var finished = try stream.readResponseEventWithTimeout(.fromSeconds(2));
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 server duplex deadline resumes response slices after flow control" {
    const allocator = std.testing.allocator;
    const payload = "ABCDEFGH";
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        timeout_done: std.Io.Event = .unset,
        allow_retry: std.Io.Event = .unset,
        committed: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timeout_done.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try connection.acceptDuplexRequest();
            defer stream.deinit();
            try stream.startResponse(.{
                .headers = &.{.{
                    .name = "content-length",
                    .value = "8",
                }},
            });
            connection.send_connection_window.value = 4;
            (try runtime.testing.sendStreamWindow(
                &connection,
                stream.stream_id,
            )).value = 4;

            try std.testing.expectError(
                error.Timeout,
                stream.finishResponseDataWithDeadline(payload, .{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                stream.responseCommittedBytes(),
            );

            try std.testing.expectError(
                error.Timeout,
                stream.writeResponseSlicesWithTimeout(
                    &.{ "AB", "CDEFGH" },
                    false,
                    .fromMilliseconds(80),
                ),
            );
            self.committed = stream.responseCommittedBytes();
            self.timeout_done.set(self.server.io);
            try self.allow_retry.wait(self.server.io);

            const suffix = payload[stream.responseCommittedBytes()..];
            const resumed = try stream.finishResponseDataWithTimeout(
                suffix,
                .fromSeconds(2),
            );
            try std.testing.expectEqual(suffix.len, resumed.written);
            try std.testing.expect(stream.responseFinished());
            try std.testing.expectEqual(
                payload.len,
                stream.responseCommittedBytes(),
            );

            var request_done = try stream.readRequestEventWithTimeout(
                .fromSeconds(2),
            );
            defer request_done.deinit(self.server.allocator);
            try std.testing.expect(request_done == .finished);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_retry.set(io);
        thread.join();
    };

    var connection = try Client.connect(allocator, io, server.address(), limits);
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/duplex-response-deadline",
        .authority = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    var stream = try writer.beginDuplex();
    defer stream.deinit();

    try shared.timeout_done.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 4), shared.committed);

    var head = try stream.readResponseEventWithTimeout(.fromSeconds(2));
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    var prefix: [4]u8 = undefined;
    var prefix_len: usize = 0;
    while (prefix_len < prefix.len) {
        var event = try stream.readResponseEventWithTimeout(.fromSeconds(2));
        defer event.deinit(allocator);
        try std.testing.expect(event == .data);
        const data = event.data.data;
        try std.testing.expect(data.len <= prefix.len - prefix_len);
        @memcpy(prefix[prefix_len..][0..data.len], data);
        prefix_len += data.len;
    }
    try std.testing.expectEqualStrings("ABCD", &prefix);
    try connection.releaseReceivedCapacity(
        stream.stream_id,
        prefix.len,
    );
    shared.allow_retry.set(io);

    var second = try stream.readResponseEventWithTimeout(.fromSeconds(2));
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("EFGH", second.data.data);
    var response_done = try stream.readResponseEventWithTimeout(
        .fromSeconds(2),
    );
    defer response_done.deinit(allocator);
    try std.testing.expect(response_done == .finished);
    const request_done = try stream.finishRequestWithTimeout(.fromSeconds(2));
    try std.testing.expectEqual(@as(usize, 0), request_done.written);
    try std.testing.expect(stream.requestFinished());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 tunnel deadline resumes exact bidirectional slice prefixes" {
    const allocator = std.testing.allocator;
    const client_payload = "abcdefgh";
    const server_payload = "ABCDEFGH";
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        accepted: std.Io.Event = .unset,
        client_timeout_done: std.Io.Event = .unset,
        client_credit_sent: std.Io.Event = .unset,
        server_timeout_done: std.Io.Event = .unset,
        server_credit_sent: std.Io.Event = .unset,
        server_progress: runtime.TunnelWriteProgress = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                self.client_credit_sent.set(self.server.io);
                self.server_timeout_done.set(self.server.io);
            };
        }

        fn readExactTunnel(
            tunnel: *runtime.Tunnel,
            allocator_value: std.mem.Allocator,
            out: []u8,
            expect_fin: bool,
        ) !void {
            var offset: usize = 0;
            var saw_fin = false;
            while (offset < out.len or (expect_fin and !saw_fin)) {
                var event = try tunnel.readWithTimeout(.fromSeconds(2));
                defer event.deinit(allocator_value);
                try std.testing.expect(event.data.len <= out.len - offset);
                @memcpy(out[offset..][0..event.data.len], event.data);
                offset += event.data.len;
                saw_fin = event.end_stream;
            }
            try std.testing.expectEqual(expect_fin, saw_fin);
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            var tunnel = try connection.acceptConnectTunnel(request, &.{});
            self.accepted.set(self.server.io);

            try self.client_timeout_done.wait(self.server.io);
            var client_prefix: [4]u8 = undefined;
            try readExactTunnel(
                &tunnel,
                self.server.allocator,
                &client_prefix,
                false,
            );
            try std.testing.expectEqualStrings("abcd", &client_prefix);
            try connection.releaseReceivedCapacity(
                tunnel.stream_id,
                client_prefix.len,
            );
            self.client_credit_sent.set(self.server.io);

            var client_suffix: [4]u8 = undefined;
            try readExactTunnel(
                &tunnel,
                self.server.allocator,
                &client_suffix,
                true,
            );
            try std.testing.expectEqualStrings("efgh", &client_suffix);

            connection.send_connection_window.value = 4;
            (try runtime.testing.sendStreamWindow(
                &connection,
                tunnel.stream_id,
            )).value = 4;
            var writer = try tunnel.beginWriteSequence();
            self.server_progress = .{
                .committed_bytes = 99,
                .fin_committed = true,
            };
            try std.testing.expectError(
                error.Timeout,
                writer.writeWithDeadline(
                    server_payload,
                    true,
                    &self.server_progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                self.server_progress.committed_bytes,
            );
            try std.testing.expect(!self.server_progress.fin_committed);

            try std.testing.expectError(
                error.Timeout,
                writer.writePartsWithTimeout(
                    "AB",
                    "CDEFGH",
                    false,
                    &self.server_progress,
                    .fromMilliseconds(80),
                ),
            );
            self.server_timeout_done.set(self.server.io);
            try self.server_credit_sent.wait(self.server.io);

            var resumed: runtime.TunnelWriteProgress = .{};
            try writer.writeWithTimeout(
                server_payload[self.server_progress.committed_bytes..],
                true,
                &resumed,
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                server_payload.len - self.server_progress.committed_bytes,
                resumed.committed_bytes,
            );
            try std.testing.expect(resumed.fin_committed);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.client_timeout_done.set(io);
        shared.server_credit_sent.set(io);
        thread.join();
    };

    var connection = try Client.connect(allocator, io, server.address(), limits);
    defer connection.close();
    var response = try connection.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);
    var tunnel = response.tunnel;
    try shared.accepted.wait(io);
    connection.send_connection_window.value = 4;
    (try runtime.testing.sendStreamWindow(
        &connection,
        tunnel.stream_id,
    )).value = 4;

    var client_progress: runtime.TunnelWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        tunnel.writeSlicesWithDeadline(
            &.{ "ab", "cdefgh" },
            true,
            &client_progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), client_progress.committed_bytes);
    try std.testing.expect(!client_progress.fin_committed);

    try std.testing.expectError(
        error.Timeout,
        tunnel.writePartsWithTimeout(
            "ab",
            "cdefgh",
            false,
            &client_progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 4), client_progress.committed_bytes);
    try std.testing.expect(!client_progress.fin_committed);
    shared.client_timeout_done.set(io);
    try shared.client_credit_sent.wait(io);

    var client_resumed: runtime.TunnelWriteProgress = .{};
    try tunnel.writeWithTimeout(
        client_payload[client_progress.committed_bytes..],
        true,
        &client_resumed,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(@as(usize, 4), client_resumed.committed_bytes);
    try std.testing.expect(client_resumed.fin_committed);

    try shared.server_timeout_done.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 4),
        shared.server_progress.committed_bytes,
    );
    try std.testing.expect(!shared.server_progress.fin_committed);
    var server_prefix: [4]u8 = undefined;
    try Shared.readExactTunnel(&tunnel, allocator, &server_prefix, false);
    try std.testing.expectEqualStrings("ABCD", &server_prefix);
    try connection.releaseReceivedCapacity(
        tunnel.stream_id,
        server_prefix.len,
    );
    shared.server_credit_sent.set(io);

    var server_suffix: [4]u8 = undefined;
    try Shared.readExactTunnel(&tunnel, allocator, &server_suffix, true);
    try std.testing.expectEqualStrings("EFGH", &server_suffix);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 duplex request HEADERS timeout resumes CONTINUATION" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        first_seen: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_seen.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.first_seen.set(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.acceptDuplexRequestWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            try std.testing.expectError(
                error.UnexpectedFrame,
                connection.readRequestWithTimeout(.fromMilliseconds(20)),
            );
            self.timed_out.set(self.server.io);
            var stream = try connection.acceptDuplexRequestWithTimeout(
                .fromSeconds(1),
            );
            defer stream.deinit();
            try std.testing.expectEqualStrings("/request-resume", stream.path);
            try stream.finishResponseHeaders(.{});
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    try shared.first_seen.wait(io);
    const stream_id = try runtime.testing.reserveNextClientStreamId(&connection);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try connection.hpack_encoder.encodeBlock(
        &block,
        allocator,
        &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/request-resume" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" },
        },
    );
    const split = @max(@as(usize, 1), block.items.len / 2);
    try runtime.testing.writeRawFrame(
        &connection,
        .headers,
        flag_end_stream,
        stream_id,
        block.items[0..split],
    );
    try shared.timed_out.wait(io);
    try runtime.testing.writeRawFrame(
        &connection,
        .continuation,
        flag_end_headers,
        stream_id,
        block.items[split..],
    );
    var response = try connection.readResponseWithTimeout(
        stream_id,
        "POST",
        false,
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client duplex queues sibling response without livelock" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
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
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            var batch: std.ArrayList(u8) = .empty;
            defer batch.deinit(self.server.allocator);
            const sibling_block = try connection.hpack_encoder
                .encodeBlockRetained(self.server.allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "7" },
                .{ .name = "x-shared", .value = "sibling-value" },
            });
            const split = @max(@as(usize, 1), sibling_block.len / 2);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .headers,
                    .flags = 0,
                    .stream_id = second.stream_id,
                },
                .payload = sibling_block[0..split],
            }).write(&batch, self.server.allocator);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .continuation,
                    .flags = flag_end_headers,
                    .stream_id = second.stream_id,
                },
                .payload = sibling_block[split..],
            }).write(&batch, self.server.allocator);
            const active_block = try connection.hpack_encoder
                .encodeBlockRetained(self.server.allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "6" },
                .{ .name = "x-shared", .value = "sibling-value" },
            });
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = first.stream_id,
                },
                .payload = active_block,
            }).write(&batch, self.server.allocator);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .data,
                    .flags = flag_end_stream,
                    .stream_id = second.stream_id,
                },
                .payload = "sibling",
            }).write(&batch, self.server.allocator);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .data,
                    .flags = flag_end_stream,
                    .stream_id = first.stream_id,
                },
                .payload = "active",
            }).write(&batch, self.server.allocator);
            try writeAll(
                self.server.io,
                connection.stream,
                batch.items,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    var first_writer = try connection.startRequest(.{
        .path = "/active",
        .authority = "localhost",
    });
    defer first_writer.deinit();
    var stream = try first_writer.beginDuplex();
    defer stream.deinit();
    _ = try stream.finishRequest();
    const sibling = try runtime.testing.sendCompleteRequest(&connection, .{
        .path = "/sibling",
        .authority = "localhost",
    });
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    var data = try stream.readResponseEvent();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("active", data.data.data);
    var done = try stream.readResponseEvent();
    defer done.deinit(allocator);
    try std.testing.expect(done == .finished);

    var sibling_response = try connection.readResponseWithTimeout(
        sibling.stream_id,
        sibling.request_method,
        sibling.extended_connect,
        .fromSeconds(1),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings("sibling", sibling_response.body);
    try std.testing.expectEqual(@as(u16, 200), sibling_response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request body prefix stays borrowed and ordered" {
    const allocator = std.testing.allocator;
    const prefix = "request-prefix";
    const body = "request-body-" ** 4096;
    const total_len = prefix.len + body.len;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = total_len, .max_frame_payload = 4096 },
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
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);

            var expected: [total_len]u8 = undefined;
            @memcpy(expected[0..prefix.len], prefix);
            @memcpy(expected[prefix.len..], body);
            try std.testing.expectEqualStrings(&expected, request.body);

            var length_buffer: [32]u8 = undefined;
            const length = try std.fmt.bufPrint(&length_buffer, "{}", .{total_len});
            try std.testing.expectEqualStrings(
                length,
                runtime.testing.findHeader(request.headers, "content-length").?,
            );
            try connection.writeResponse(request.stream_id, .{
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = total_len, .max_frame_payload = 4096 },
    );
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/prefixed-request",
        .authority = "localhost",
        .body_prefix = prefix,
        .body = body,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("accepted", response.body);

    thread.join();
    if (shared.err) |err| return err;
}
