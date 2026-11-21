const std = @import("std");
const builtin = @import("builtin");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const flag_ack: u8 = 0x1;
const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
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

fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        },
        .payload = payload,
    }).write(&encoded, allocator);
    try writeAll(io, stream, encoded.items);
}

fn readPeerPing(connection: *runtime.Connection) ![8]u8 {
    while (true) {
        var frame = try runtime.testing.readOwnedFrame(connection);
        defer frame.deinit(connection.allocator);
        if (frame.frame.header.frame_type == .ping) {
            if ((frame.frame.header.flags & flag_ack) != 0) continue;
            return (try http2.PingPayload.parse(frame.frame)).data;
        }
        if (try runtime.testing.handleConnectionFrame(
            connection,
            frame.frame,
        )) continue;
        return error.UnexpectedFrame;
    }
}

test "HTTP/2 bounded PING times out when the peer stays silent" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            // Keep TCP open without pumping frames. The probe must expire
            // independently rather than relying on peer closure.
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(200),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(
            .{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .fromMilliseconds(75),
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded inbound PING preserves a partial frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const payload = [8]u8{ 2, 7, 1, 8, 2, 8, 1, 8 };
    const Shared = struct {
        server: *runtime.Server,
        payload: [8]u8,
        prefix_sent: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_sent.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(self.server.allocator);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .ping,
                    .flags = 0,
                    .stream_id = 0,
                },
                .payload = &self.payload,
            }).write(&encoded, self.server.allocator);
            const split = http2.FrameHeader.encoded_len + 3;
            try writeAll(
                self.server.io,
                connection.stream,
                encoded.items[0..split],
            );
            self.prefix_sent.set(self.server.io);
            try self.timed_out.wait(self.server.io);
            try writeAll(
                self.server.io,
                connection.stream,
                encoded.items[split..],
            );

            while (true) {
                var ack = try runtime.testing.readOwnedFrame(&connection);
                defer ack.deinit(self.server.allocator);
                if (ack.frame.header.frame_type == .ping) {
                    try std.testing.expect(
                        (ack.frame.header.flags & flag_ack) != 0,
                    );
                    try std.testing.expectEqualSlices(
                        u8,
                        &self.payload,
                        &(try http2.PingPayload.parse(ack.frame)).data,
                    );
                    break;
                }
                if (try runtime.testing.handleConnectionFrame(
                    &connection,
                    ack.frame,
                )) continue;
                return error.UnexpectedFrame;
            }
        }
    };
    var shared = Shared{ .server = &server, .payload = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try shared.prefix_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.readPingWithTimeout(.fromMilliseconds(20)),
    );
    shared.timed_out.set(io);
    try std.testing.expectEqualSlices(
        u8,
        &payload,
        &(try client.readPingWithDeadline(.fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ))),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate request timeout preserves a pre-admission frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        prefix_sent: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.prefix_sent.wait(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestWithTimeout(.fromMilliseconds(20)),
            );
            self.timed_out.set(self.server.io);
            var request = try connection.readRequestWithDeadline(.fromNow(
                self.server.io,
                .{ .raw = .fromSeconds(1), .clock = .awake },
            ));
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), request.stream_id);
            try std.testing.expectEqualStrings("GET", request.method);
            try std.testing.expectEqualStrings("/", request.path);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    // All three request pseudo-fields use HPACK static-table indexes. Keeping
    // the final two payload bytes back forces the first read to time out after
    // its frame header and a partial field block are already buffered.
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = .headers,
            .flags = flag_end_headers | flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{ 0x82, 0x86, 0x84 },
    }).write(&encoded, allocator);
    const split = http2.FrameHeader.encoded_len + 1;
    try writeAll(io, client.stream, encoded.items[0..split]);
    shared.prefix_sent.set(io);
    try shared.timed_out.wait(io);
    try writeAll(io, client.stream, encoded.items[split..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate request deadline cancels admitted stream and fails closed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .terminal_cleanup_timeout = .fromSeconds(1) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        request_prefix_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.request_prefix_sent.wait(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestWithDeadline(.fromNow(
                    self.server.io,
                    .{ .raw = .fromMilliseconds(20), .clock = .awake },
                )),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.readRequestWithTimeout(.fromSeconds(1)),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/aggregate-timeout",
        .authority = "localhost",
        .body_length = 4,
    });
    defer writer.deinit();
    try writer.write("a");
    shared.request_prefix_sent.set(io);
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(writer.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate request timeout cancels fragmented sibling and active stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        request_frames_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.request_frames_sent.wait(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestWithTimeout(.fromMilliseconds(20)),
            );
            // The incomplete sibling header block poisons the shared HPACK
            // state, so retry must fail locally rather than touch transport.
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.readRequestWithTimeout(.fromSeconds(1)),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    // Stream 1 becomes the active aggregate request and remains open. Stream 3
    // is a complete sibling request at the HTTP message layer, but its HEADERS
    // block deliberately omits END_HEADERS and the required CONTINUATION.
    const request_block = [_]u8{ 0x82, 0x86, 0x84 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_headers,
        1,
        &request_block,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_stream,
        3,
        request_block[0..1],
    );
    shared.request_frames_sent.set(io);

    var saw_active = false;
    var saw_sibling = false;
    for (0..2) |_| {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(
            http2.ErrorCode.cancel,
            reset.reset.error_code,
        );
        switch (reset.reset.stream_id) {
            1 => {
                try std.testing.expect(!saw_active);
                saw_active = true;
            },
            3 => {
                try std.testing.expect(!saw_sibling);
                saw_sibling = true;
            },
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expect(saw_active);
    try std.testing.expect(saw_sibling);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming request timeout covers body and fails closed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        request_prefix_sent: std.Io.Event = .unset,
        head_count: usize = 0,
        body_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn begin(self: *@This(), head: runtime.StreamingRequestHead) !void {
            try std.testing.expectEqualStrings(
                "/streaming-timeout",
                head.path,
            );
            self.head_count += 1;
        }

        fn consume(self: *@This(), data: []const u8) !void {
            self.body_bytes += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.request_prefix_sent.wait(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestStreamingWithHeadAndTimeout(
                    .fromMilliseconds(20),
                    self,
                    begin,
                    consume,
                ),
            );
            try std.testing.expectEqual(@as(usize, 1), self.head_count);
            try std.testing.expectEqual(@as(usize, 1), self.body_bytes);
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.readRequestStreamingWithDeadline(
                    .fromNow(self.server.io, .{
                        .raw = .fromSeconds(1),
                        .clock = .awake,
                    }),
                    self,
                    consume,
                ),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/streaming-timeout",
        .authority = "localhost",
        .body_length = 4,
    });
    defer writer.deinit();
    try writer.write("a");
    shared.request_prefix_sent.set(io);
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(writer.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded streaming request callback errors cancel once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .terminal_cleanup_timeout = .fromSeconds(1) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        body_calls: usize = 0,
        timeout_head_calls: usize = 0,
        timeout_head_path_ok: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn rejectBody(
            self: *@This(),
            data: []const u8,
        ) error{ConsumerRejected}!void {
            self.body_calls += 1;
            _ = data;
            return error.ConsumerRejected;
        }

        fn rejectHeadWithTimeout(
            self: *@This(),
            head: runtime.StreamingRequestHead,
        ) error{Timeout}!void {
            self.timeout_head_calls += 1;
            self.timeout_head_path_ok =
                std.mem.eql(u8, "/callback-timeout", head.path);
            return error.Timeout;
        }

        fn ignoreBody(_: *@This(), _: []const u8) !void {}

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            try std.testing.expectError(
                error.ConsumerRejected,
                connection.readRequestStreamingWithTimeout(
                    .fromSeconds(1),
                    self,
                    rejectBody,
                ),
            );
            try std.testing.expectEqual(@as(usize, 1), self.body_calls);

            // A callback is allowed to use the same error name as the I/O
            // deadline. It is still an application rejection, not evidence
            // that a deadline-bearing read expired.
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestStreamingWithHeadAndDeadline(
                    .fromNow(self.server.io, .{
                        .raw = .fromSeconds(1),
                        .clock = .awake,
                    }),
                    self,
                    rejectHeadWithTimeout,
                    ignoreBody,
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                self.timeout_head_calls,
            );
            try std.testing.expect(self.timeout_head_path_ok);

            // Reading and answering a later stream proves neither callback
            // error poisoned this connection. On the client, the successful
            // response also proves no duplicate old-stream reset preceded it.
            var request = try connection.readRequestWithTimeout(
                .fromSeconds(1),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-callback", request.path);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();

    var body_rejected = try client.startRequest(.{
        .path = "/callback-error",
        .authority = "localhost",
        .body_length = 1,
    });
    try body_rejected.finishData("x");
    {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(
            body_rejected.stream_id,
            reset.reset.stream_id,
        );
        try std.testing.expectEqual(
            http2.ErrorCode.cancel,
            reset.reset.error_code,
        );
    }
    body_rejected.deinit();
    try std.testing.expect(client.isReusable());

    var timeout_rejected = try client.startRequest(.{
        .path = "/callback-timeout",
        .authority = "localhost",
        .body_length = 0,
    });
    try timeout_rejected.finish();
    {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(
            timeout_rejected.stream_id,
            reset.reset.stream_id,
        );
        try std.testing.expectEqual(
            http2.ErrorCode.cancel,
            reset.reset.error_code,
        );
    }
    timeout_rejected.deinit();
    try std.testing.expect(client.isReusable());

    var response = try client.requestWithTimeout(
        .{ .path = "/after-callback", .authority = "localhost" },
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request readers reject invalid budgets before transport I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var connection = runtime.Connection{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };

    const Callbacks = struct {
        fn begin(_: *@This(), _: runtime.StreamingRequestHead) !void {}
        fn consume(_: *@This(), _: []const u8) !void {}
        fn consumeBatch(_: *@This(), _: u31, _: []const u8) !void {}
    };
    var callbacks: Callbacks = .{};
    var batch_requests: [1]runtime.StreamingRequest = undefined;
    const wrong_clock = std.Io.Clock.Timestamp{
        .clock = .real,
        .raw = .zero,
    };

    try std.testing.expectError(
        error.Timeout,
        connection.readRequestWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestWithDeadline(wrong_clock),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestStreamingWithTimeout(
            .zero,
            &callbacks,
            Callbacks.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestStreamingWithDeadline(
            wrong_clock,
            &callbacks,
            Callbacks.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestStreamingWithHeadAndTimeout(
            .zero,
            &callbacks,
            Callbacks.begin,
            Callbacks.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestStreamingWithHeadAndDeadline(
            wrong_clock,
            &callbacks,
            Callbacks.begin,
            Callbacks.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestBatchStreamingIntoWithTimeout(
            &batch_requests,
            .zero,
            &callbacks,
            Callbacks.consumeBatch,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestBatchStreamingIntoWithDeadline(
            &batch_requests,
            wrong_clock,
            &callbacks,
            Callbacks.consumeBatch,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readOwnedFrameWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readOwnedFrameForDuplexWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readOwnedClientDuplexFrameWithTimeout(1, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readOwnedServerDuplexFrameWithTimeout(1, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.sendCompleteRequestWithTimeout(.{}, .zero),
    );
}

test "HTTP/2 streaming request batch timeout preserves pre-admission frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        prefix_sent: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.server.io);
            };
        }

        fn consume(_: *@This(), _: u31, _: []const u8) !void {}

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.prefix_sent.wait(self.server.io);
            var requests: [1]runtime.StreamingRequest = undefined;
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromMilliseconds(20),
                    self,
                    consume,
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            self.timed_out.set(self.server.io);
            try connection.readRequestBatchStreamingIntoWithDeadline(
                &requests,
                .fromNow(self.server.io, .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                }),
                self,
                consume,
            );
            defer requests[0].deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), requests[0].stream_id);
            try std.testing.expectEqualStrings("/", requests[0].path);
            try connection.writeResponse(requests[0].stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = .headers,
            .flags = flag_end_headers | flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{ 0x82, 0x86, 0x84 },
    }).write(&encoded, allocator);
    const split = http2.FrameHeader.encoded_len + 1;
    try writeAll(io, client.stream, encoded.items[0..split]);
    shared.prefix_sent.set(io);
    try shared.timed_out.wait(io);
    try writeAll(io, client.stream, encoded.items[split..]);

    var response = try client.readResponseWithTimeout(
        1,
        "GET",
        false,
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming request batch timeout after admission fails closed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        request_prefix_sent: std.Io.Event = .unset,
        body_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(
            self: *@This(),
            _: u31,
            data: []const u8,
        ) !void {
            self.body_bytes += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.request_prefix_sent.wait(self.server.io);
            var requests: [2]runtime.StreamingRequest = undefined;
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromMilliseconds(20),
                    self,
                    consume,
                ),
            );
            try std.testing.expectEqual(@as(usize, 1), self.body_bytes);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromSeconds(1),
                    self,
                    consume,
                ),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/batch-timeout",
        .authority = "localhost",
        .body_length = 4,
    });
    defer writer.deinit();
    try writer.write("a");
    shared.request_prefix_sent.set(io);
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(writer.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming request batch deadline is not renewed by completion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .terminal_cleanup_timeout = .fromSeconds(1) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        timed_out: std.Io.Event = .unset,
        resets_observed: std.Io.Event = .unset,
        first_body_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.server.io);
                self.resets_observed.set(self.server.io);
            };
        }

        fn consume(
            self: *@This(),
            stream_id: u31,
            data: []const u8,
        ) !void {
            if (stream_id == 1) self.first_body_bytes += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var requests: [2]runtime.StreamingRequest = undefined;
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromMilliseconds(400),
                    self,
                    consume,
                ),
            );
            try std.testing.expectEqual(@as(usize, 1), self.first_body_bytes);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            self.timed_out.set(self.server.io);
            try self.resets_observed.wait(self.server.io);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.resets_observed.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var first = try client.startRequest(.{
        .path = "/first",
        .authority = "localhost",
        .body_length = 1,
    });
    defer first.deinit();
    var second = try client.startRequest(.{
        .path = "/second",
        .authority = "localhost",
        .body_length = 1,
    });
    defer second.deinit();
    try std.Io.sleep(io, .fromMilliseconds(150), .awake);
    try first.finishData("a");
    try std.Io.sleep(io, .fromMilliseconds(350), .awake);
    try std.testing.expect(shared.timed_out.isSet());

    var saw_first = false;
    var saw_second = false;
    for (0..2) |_| {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(
            http2.ErrorCode.cancel,
            reset.reset.error_code,
        );
        if (reset.reset.stream_id == first.stream_id) {
            saw_first = true;
        } else if (reset.reset.stream_id == second.stream_id) {
            saw_second = true;
        } else {
            return error.UnexpectedFrame;
        }
    }
    try std.testing.expect(saw_first);
    try std.testing.expect(saw_second);
    shared.resets_observed.set(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming request batch deadline covers continuation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        prefix_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(_: *@This(), _: u31, _: []const u8) !void {}

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try self.prefix_sent.wait(self.server.io);
            var requests: [1]runtime.StreamingRequest = undefined;
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromMilliseconds(20),
                    self,
                    consume,
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromSeconds(1),
                    self,
                    consume,
                ),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_stream,
        1,
        &.{0x82},
    );
    shared.prefix_sent.set(io);
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded request batch callback Timeout remains reusable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        callback_calls: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn reject(
            self: *@This(),
            _: u31,
            _: []const u8,
        ) error{Timeout}!void {
            self.callback_calls += 1;
            return error.Timeout;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var requests: [1]runtime.StreamingRequest = undefined;
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestBatchStreamingIntoWithTimeout(
                    &requests,
                    .fromSeconds(1),
                    self,
                    reject,
                ),
            );
            try std.testing.expectEqual(@as(usize, 1), self.callback_calls);

            var next = try connection.readRequestWithTimeout(
                .fromSeconds(1),
            );
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-callback", next.path);
            try connection.writeResponse(next.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var rejected = try client.startRequest(.{
        .path = "/callback-timeout",
        .authority = "localhost",
        .body_length = 1,
    });
    try rejected.finishData("x");
    {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(1));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(rejected.stream_id, reset.reset.stream_id);
        try std.testing.expectEqual(
            http2.ErrorCode.cancel,
            reset.reset.error_code,
        );
    }
    rejected.deinit();
    try std.testing.expect(client.isReusable());

    var response = try client.requestWithTimeout(
        .{ .path = "/after-callback", .authority = "localhost" },
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate response timeout cancels stream and fails closed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        request_seen: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.request_seen.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            self.request_seen.set(self.server.io);
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(
            .{ .path = "/silent", .authority = "localhost" },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        client.request(.{ .path = "/after-timeout" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate response deadline is not renewed by control frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try std.Io.sleep(self.server.io, .fromMilliseconds(15), .awake);
            try connection.sendWindowUpdate(0, 11);
            try std.Io.sleep(self.server.io, .fromMilliseconds(15), .awake);
            try connection.sendWindowUpdate(0, 13);
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(
            .{ .path = "/control-pressure", .authority = "localhost" },
            .fromMilliseconds(25),
        ),
    );
    try std.testing.expectEqual(
        @as(i64, 65_535 + 11),
        client.send_connection_window.value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 informational response shares aggregate deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeInformationalResponse(
                request.stream_id,
                103,
                &.{.{ .name = "link", .value = "</deadline.css>" }},
            );
            try std.Io.sleep(self.server.io, .fromMilliseconds(75), .awake);
            connection.writeResponse(request.stream_id, .{
                .body = "late",
                .request_method = request.method,
            }) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    const Observer = struct {
        count: usize = 0,

        fn observe(context: *anyopaque, head: runtime.StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (head.status != 103) @panic("unexpected informational status");
            self.count += 1;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var observer: Observer = .{};

    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndTimeout(
            .{ .path = "/informational-deadline", .authority = "localhost" },
            .{
                .context = &observer,
                .on_response = Observer.observe,
            },
            .fromMilliseconds(25),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), observer.count);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 URI deadline spans connection bootstrap and response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/deadline",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriWithDeadline(
            allocator,
            io,
            uri,
            .{},
            .{
                .connect_timeout = .fromSeconds(1),
                .handshake_timeout = .fromSeconds(1),
            },
            .fromNow(io, .{
                .raw = .fromMilliseconds(40),
                .clock = .awake,
            }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 URI timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://localhost/",
            .{},
            .{},
            .zero,
        ),
    );
}

test "HTTP/2 response deadline rejects a non-awake clock before writing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var connection = runtime.Connection{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };

    try std.testing.expectError(
        error.Timeout,
        connection.requestWithDeadline(
            .{ .path = "/wrong-clock", .authority = "localhost" },
            std.Io.Clock.Timestamp.fromNow(
                threaded.io(),
                .{ .raw = .fromSeconds(1), .clock = .real },
            ),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestWithInformationalAndDeadline(
            .{ .path = "/wrong-clock-observed", .authority = "localhost" },
            null,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestWithInformationalAndTimeout(
            .{ .path = "/zero-observed", .authority = "localhost" },
            null,
            .zero,
        ),
    );
    const Callback = struct {
        fn begin(_: void, _: runtime.StreamingResponseHead) !void {}
        fn consume(_: void, _: []const u8) !void {}
    };
    try std.testing.expectError(
        error.Timeout,
        connection.requestStreamingWithHeadAndTimeout(
            .{ .path = "/zero-streaming-head", .authority = "localhost" },
            .zero,
            {},
            Callback.begin,
            Callback.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestStreamingWithInformationalAndHeadAndDeadline(
            .{
                .path = "/wrong-clock-streaming-head",
                .authority = "localhost",
            },
            null,
            .{ .clock = .real, .raw = .zero },
            {},
            Callback.begin,
            Callback.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readResponseWithInformationalAndDeadline(
            1,
            "GET",
            false,
            null,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readResponseWithInformationalAndTimeout(
            1,
            "GET",
            false,
            null,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readResponseStreamingWithHeadAndDeadline(
            1,
            "GET",
            false,
            .{ .clock = .real, .raw = .zero },
            {},
            Callback.begin,
            Callback.consume,
        ),
    );
    var writer = runtime.RequestWriter{
        .connection = &connection,
        .stream_id = 1,
        .expected_length = 0,
        .head_request = false,
        .body_finished = true,
    };
    defer writer.completed = true;
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseWithInformationalAndDeadline(
            null,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseWithInformationalAndTimeout(null, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseStreamingWithInformationalAndHeadAndTimeout(
            null,
            .zero,
            {},
            Callback.begin,
            Callback.consume,
        ),
    );
    try std.testing.expect(connection.isReusable());
}

test "HTTP/2 aggregate response deadline covers header continuations" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            // Begin an HPACK block but withhold its CONTINUATION. The timeout
            // must reach the nested header-block reader rather than applying
            // only to the first response frame.
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .headers,
                0x1, // END_STREAM without END_HEADERS.
                request.stream_id,
                &.{},
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(
            .{ .path = "/partial-head", .authority = "localhost" },
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer exposes final head within response timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try std.testing.expectEqualStrings("/writer-timeout", request.path);
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "4",
                }} },
            );
            defer response.deinit();
            try response.write("a");
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    const Sink = struct {
        head_calls: usize = 0,
        body_bytes: usize = 0,

        fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqual(@as(usize, 0), self.body_bytes);
            self.head_calls += 1;
        }

        fn consume(self: *@This(), data: []const u8) !void {
            try std.testing.expectEqual(@as(usize, 1), self.head_calls);
            self.body_bytes += data.len;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/writer-timeout",
        .authority = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    var sink: Sink = .{};
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseStreamingWithHeadAndTimeout(
            .fromMilliseconds(20),
            &sink,
            Sink.begin,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.head_calls);
    try std.testing.expectEqual(@as(usize, 1), sink.body_bytes);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 split response reader honors an absolute deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const pending = try runtime.testing.sendCompleteRequest(&client, .{
        .path = "/split-deadline",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.Timeout,
        client.readResponseWithDeadline(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming response deadline covers a partial body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "4",
                }} },
            );
            defer response.deinit();
            try response.write("a");
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    const Sink = struct {
        bytes: usize = 0,

        fn consume(self: *@This(), part: []const u8) !void {
            self.bytes += part.len;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var sink: Sink = .{};
    try std.testing.expectError(
        error.Timeout,
        client.requestStreamingWithTimeout(
            .{ .path = "/stream-timeout", .authority = "localhost" },
            .fromMilliseconds(20),
            &sink,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.bytes);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming informational and final heads share body deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeInformationalResponse(
                request.stream_id,
                103,
                &.{},
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(5),
                .awake,
            );
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "4",
                }} },
            );
            defer response.deinit();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(5),
                .awake,
            );
            try response.write("b");
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        }
    };
    const Sink = struct {
        informationals: usize = 0,
        final_heads: usize = 0,
        body_bytes: usize = 0,
        phase: enum { initial, informational, final_head, body } = .initial,

        fn observe(context: *anyopaque, head: runtime.StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (head.status != 103) @panic("unexpected informational status");
            if (self.phase != .initial) @panic("informational ordering");
            self.informationals += 1;
            self.phase = .informational;
        }

        fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqual(.informational, self.phase);
            self.final_heads += 1;
            self.phase = .final_head;
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try std.testing.expect(
                self.phase == .final_head or self.phase == .body,
            );
            self.phase = .body;
            self.body_bytes += bytes.len;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var sink: Sink = .{};

    try std.testing.expectError(
        error.Timeout,
        client.requestStreamingWithInformationalAndHeadAndTimeout(
            .{ .path = "/streaming-informational", .authority = "localhost" },
            .{
                .context = &sink,
                .on_response = Sink.observe,
            },
            .fromMilliseconds(25),
            &sink,
            Sink.begin,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.informationals);
    try std.testing.expectEqual(@as(usize, 1), sink.final_heads);
    try std.testing.expectEqual(@as(usize, 1), sink.body_bytes);
    try std.testing.expectEqual(.body, sink.phase);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded response head callback Timeout stays stream-local" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var rejected = try connection.readRequest();
            defer rejected.deinit(self.server.allocator);
            var response = try connection.startResponse(
                rejected.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "1",
                }} },
            );
            defer response.deinit();
            try response.write("x");
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(
                rejected.stream_id,
                reset.reset.stream_id,
            );

            var next = try connection.readRequestWithTimeout(
                .fromSeconds(1),
            );
            defer next.deinit(self.server.allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "ok" });
        }
    };
    const Sink = struct {
        calls: usize = 0,

        fn reject(
            self: *@This(),
            head: runtime.StreamingResponseHead,
        ) error{Timeout}!void {
            self.calls += 1;
            if (head.status != 200) @panic("unexpected final status");
            return error.Timeout;
        }

        fn consume(_: *@This(), _: []const u8) !void {}
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var sink: Sink = .{};

    try std.testing.expectError(
        error.Timeout,
        client.requestStreamingWithHeadAndTimeout(
            .{ .path = "/reject-head", .authority = "localhost" },
            .fromSeconds(1),
            &sink,
            Sink.reject,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expect(client.isReusable());

    var response = try client.requestWithTimeout(
        .{ .path = "/after-head-rejection", .authority = "localhost" },
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded control reads keep one absolute deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(30),
                .awake,
            );
            try connection.sendWindowUpdate(0, 11);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(30),
                .awake,
            );
            try connection.sendWindowUpdate(0, 13);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(30),
                .awake,
            );
            try connection.sendGoAway(0, .no_error, "done");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.readGoAwayWithTimeout(.fromMilliseconds(70)),
    );
    try std.testing.expectEqual(@as(i64, 65_535 + 11 + 13), client.send_connection_window.value);
    var goaway = try client.readGoAwayWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), goaway.goaway.last_stream_id);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded tunnel read resumes after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            var tunnel = try connection.acceptConnectTunnel(request, &.{});
            self.accepted.set(self.server.io);
            try self.timed_out.wait(self.server.io);
            try tunnel.write("after-timeout", true);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);
    try shared.accepted.wait(io);
    try std.testing.expectError(
        error.Timeout,
        response.tunnel.readWithTimeout(.fromMilliseconds(20)),
    );
    shared.timed_out.set(io);
    var data = try response.tunnel.readWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("after-timeout", data.data);
    try std.testing.expect(data.end_stream);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING uses one deadline across control frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const payload = [8]u8{ 1, 3, 3, 7, 9, 9, 4, 2 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.testing.expectEqualSlices(
                u8,
                &self.expected,
                &(try readPeerPing(&connection)),
            );

            // Neither a stale ACK nor useful connection credit extends the
            // caller's original 150 ms budget. A relative timeout restarted
            // after each frame would incorrectly accept the final ACK.
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                &.{ 8, 8, 8, 8, 8, 8, 8, 8 },
            );
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .settings,
                0,
                0,
                &.{},
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            );
            try connection.sendWindowUpdate(0, 17);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            );
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                &self.expected,
            );
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(payload, .fromMilliseconds(150)),
    );
    try std.testing.expectEqual(
        @as(i64, 65_535 + 17),
        client.send_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING preserves interleaved response frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const payload = [8]u8{ 4, 8, 15, 16, 23, 42, 0, 1 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
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
            try connection.writeResponse(request.stream_id, .{
                .body = "response-before-pong",
            });
            try std.testing.expectEqualSlices(
                u8,
                &self.expected,
                &(try connection.readPing()),
            );
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = "GET",
        .path = "/before-pong",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();

    const ack = try client.pingWithTimeout(
        payload,
        .fromSeconds(1),
    );
    try std.testing.expectEqualSlices(u8, &payload, &ack);
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings(
        "response-before-pong",
        response.body,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING preserves interleaved request frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const payload = [8]u8{ 9, 2, 6, 5, 3, 5, 8, 9 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.ready.set(self.server.io);
            const ack = try connection.pingWithTimeout(
                self.expected,
                .fromSeconds(1),
            );
            try std.testing.expectEqualSlices(u8, &self.expected, &ack);
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/during-ping", request.path);
            try std.testing.expectEqualStrings("request-body", request.body);
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try shared.ready.wait(io);
    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/during-ping",
        .body_length = "request-body".len,
    });
    defer writer.deinit();
    try writer.finishData("request-body");
    const observed = try client.readPing();
    try std.testing.expectEqualSlices(u8, &payload, &observed);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 keep-alive skips an idle client unless opted in" {
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectEqual(
        runtime.KeepAliveResult.skipped_idle,
        try connection.keepAlive(.{0} ** 8, .{
            .interval = .fromMilliseconds(1),
        }),
    );
}

test "HTTP/2 keep-alive waits for receive inactivity before probing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const payload = [8]u8{ 8, 6, 7, 5, 3, 0, 9, 0 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(50),
                .awake,
            );
            try connection.sendWindowUpdate(0, 29);
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &self.expected, &observed);
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectEqual(
        runtime.KeepAliveResult.acknowledged,
        try client.keepAlive(payload, .{
            .interval = .fromMilliseconds(100),
            .timeout = .fromSeconds(1),
            .while_idle = true,
        }),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds >=
        std.Io.Duration.fromMilliseconds(130).nanoseconds);
    try std.testing.expectEqual(
        @as(i64, 65_535 + 29),
        client.send_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 keep-alive timeout preserves active response frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            try connection.writeResponse(request.stream_id, .{
                .body = "alive-before-timeout",
            });
            // Do not pump the keep-alive PING. The server remains open beyond
            // the client's interval plus ACK timeout.
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(250),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = "GET",
        .path = "/keep-alive",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    try std.testing.expectError(
        error.Timeout,
        client.keepAlive(.{ 1, 1, 2, 3, 5, 8, 13, 21 }, .{
            .interval = .fromMilliseconds(50),
            .timeout = .fromMilliseconds(75),
        }),
    );
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("alive-before-timeout", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 keep-alive rejects non-positive timing budgets" {
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.keepAlive(.{0} ** 8, .{
            .interval = .zero,
            .while_idle = true,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.keepAlive(.{0} ** 8, .{
            .interval = .fromSeconds(1),
            .timeout = .zero,
            .while_idle = true,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        runtime.KeepAlive.init(.{ .interval = .zero }),
    );
}

test "HTTP/2 keep-alive driver advances payload only after ACK" {
    var driver = try runtime.KeepAlive.init(.{
        .interval = .fromSeconds(1),
    });
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectEqual(
        runtime.KeepAliveResult.skipped_idle,
        try driver.run(&connection),
    );
    try std.testing.expectEqual(@as(u64, 0), driver.next_payload);
}

test "HTTP/2 idle keep-alive succeeds over TLS when enabled" {
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
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        },
    );
    defer server.deinit();

    const payload = [_]u8{0} ** 8;
    const Shared = struct {
        server: *runtime.TlsServer,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            const observed = connection.readPing() catch |err| {
                self.err = err;
                return;
            };
            if (!std.mem.eql(u8, &observed, &self.expected)) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();
    var keep_alive = try runtime.KeepAlive.init(.{
        .interval = .fromMilliseconds(25),
        .timeout = .fromSeconds(1),
        .while_idle = true,
    });
    try std.testing.expectEqual(
        runtime.KeepAliveResult.acknowledged,
        try keep_alive.run(&client),
    );
    try std.testing.expectEqual(@as(u64, 1), keep_alive.next_payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING rejects non-positive durations before writing" {
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithTimeout(.{0} ** 8, .zero),
    );
}

test "HTTP/2 PING deadline validates before writing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(20),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var connection = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer connection.close();
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithDeadline(
            .{0} ** 8,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real }),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithDeadline(
            .{0} ** 8,
            .{ .raw = .zero, .clock = .awake },
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 PING deadline bounds a stalled probe write" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const delegate = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        delegate,
        .{ .reuse_address = true },
    );
    defer listener.deinit(delegate);
    const sender = try listener.socket.address.connect(
        delegate,
        .{ .mode = .stream },
    );
    const peer = try listener.accept(delegate);
    defer peer.close(delegate);

    // A real full send queue cannot force a 17-byte PING frame to sleep: hosts
    // differ in how much slack they accept past EAGAIN. Stall the transport
    // instead so the deadline contract is exercised deterministically.
    const StalledWrite = struct {
        var active: *@This() = undefined;
        delegate: std.Io,
        begun: std.Io.Event = .unset,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active;
            self.begun.set(self.delegate);
            std.Io.sleep(self.delegate, .fromSeconds(30), .awake) catch |err| return err;
            return error.Canceled;
        }
    };
    var stalled = StalledWrite{ .delegate = delegate };
    StalledWrite.active = &stalled;
    var vtable = delegate.vtable.*;
    vtable.netWrite = StalledWrite.write;
    const io = std.Io{ .userdata = delegate.userdata, .vtable = &vtable };

    var connection = runtime.Connection{
        .io = io,
        .allocator = allocator,
        .stream = sender,
        .role = .client,
    };
    defer connection.close();
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithTimeout(
            .{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.ping(.{ 8, 7, 6, 5, 4, 3, 2, 1 }),
    );
}

test "HTTP/2 PING queue overflow preserves the consumed frame" {
    const allocator = std.testing.allocator;
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_pending_ping_frames = 1 },
    };
    defer runtime.testing.deinitPendingApplicationFrames(&connection);

    var first = runtime.OwnedFrame{
        .bytes = try allocator.dupe(u8, "first"),
        .frame = .{
            .header = .{
                .length = 5,
                .frame_type = .data,
                .flags = 0,
                .stream_id = 1,
            },
            .payload = undefined,
        },
    };
    first.frame.payload = first.bytes;
    try runtime.testing.queuePendingApplicationFrame(&connection, first);

    var overflow = runtime.OwnedFrame{
        .bytes = try allocator.dupe(u8, "second"),
        .frame = .{
            .header = .{
                .length = 6,
                .frame_type = .data,
                .flags = 0,
                .stream_id = 3,
            },
            .payload = undefined,
        },
    };
    overflow.frame.payload = overflow.bytes;
    try std.testing.expectError(
        error.MessageTooLarge,
        runtime.testing.queuePendingApplicationFrame(&connection, overflow),
    );
    runtime.testing.recoverPendingApplicationFrameAfterQueueFailure(
        &connection,
        overflow,
    );

    var observed_first = try runtime.testing.readOwnedFrame(&connection);
    defer observed_first.deinit(allocator);
    try std.testing.expectEqualStrings("first", observed_first.frame.payload);
    var observed_second = try runtime.testing.readOwnedFrame(&connection);
    defer observed_second.deinit(allocator);
    try std.testing.expectEqualStrings("second", observed_second.frame.payload);
}

test "HTTP/2 bounded PING succeeds over TLS" {
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
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        },
    );
    defer server.deinit();

    const payload = [8]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
    const Shared = struct {
        server: *runtime.TlsServer,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            const observed = connection.readPing() catch |err| {
                self.err = err;
                return;
            };
            if (!std.mem.eql(u8, &observed, &self.expected)) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();
    const ack = try client.pingWithTimeout(
        payload,
        .fromSeconds(1),
    );
    try std.testing.expectEqualSlices(u8, &payload, &ack);

    thread.join();
    if (shared.err) |err| return err;
}
