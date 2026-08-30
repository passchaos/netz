const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const flag_ack: u8 = 0x1;

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

test "HTTP/2 request writer bounds its response" {
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
    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/writer-timeout",
        .authority = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseWithTimeout(.fromMilliseconds(20)),
    );

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

test "HTTP/2 streaming informational response shares body deadline" {
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
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "4",
                }} },
            );
            defer response.deinit();
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
        body_bytes: usize = 0,

        fn observe(context: *anyopaque, head: runtime.StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (head.status != 103) @panic("unexpected informational status");
            self.informationals += 1;
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
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
        client.requestStreamingWithInformationalAndTimeout(
            .{ .path = "/streaming-informational", .authority = "localhost" },
            .{
                .context = &sink,
                .on_response = Sink.observe,
            },
            .fromMilliseconds(25),
            &sink,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.informationals);
    try std.testing.expectEqual(@as(usize, 1), sink.body_bytes);
    try std.testing.expect(!client.isReusable());

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
