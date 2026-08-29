const std = @import("std");
const websocket = @import("../mod.zig");
const h3 = @import("h3.zig");
const http3 = @import("../../http3/mod.zig");

test "WebSocket HTTP3 server deadline spans QUIC TLS and CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x55} ** 32,
            .x25519_secret_key = [_]u8{0x56} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        handshake_complete: std.Io.Event = .unset,
        send_connect: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.handshake_complete.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h3_client = try http3.runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.server.address(),
                limits,
                .{
                    .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0x57} ** 32,
                        .x25519_secret_key = [_]u8{0x58} ** 32,
                    },
                    .session = .{ .local_settings = .{
                        .enable_connect_protocol = true,
                    } },
                },
            );
            defer h3_client.deinit();
            self.handshake_complete.set(self.io);
            try self.send_connect.wait(self.io);
            _ = try h3_client.startRequest(.{
                .method = "CONNECT",
                .path = "/late-websocket",
                .scheme = "https",
                .authority = "localhost",
                .headers = &.{
                    .{ .name = ":protocol", .value = "websocket" },
                    .{ .name = "sec-websocket-version", .value = "13" },
                },
            }, null);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_connect.set(io);
        client_thread.join();
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(300), .clock = .awake },
    );
    const AcceptResult = h3.Error!h3.ServerConnection;
    const Wake = union(enum) {
        server: AcceptResult,
        client_handshake: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .server => |result| if (result) |connection_value| {
            var connection = connection_value;
            connection.deinit();
        } else |_| {},
        .client_handshake => {},
    };
    select.async(
        .server,
        h3.Server.acceptWithDeadline,
        .{ &server, h3.AcceptOptions{}, deadline },
    );
    select.async(
        .client_handshake,
        std.Io.Event.wait,
        .{ &shared.handshake_complete, io },
    );
    switch (try select.await()) {
        .server => |result| {
            if (result) |connection_value| {
                var connection = connection_value;
                connection.deinit();
                return error.TestUnexpectedResult;
            } else |err| return err;
        },
        .client_handshake => |result| try result,
    }

    // The client deliberately withholds CONNECT until the original absolute
    // deadline has expired. Restarting a phase-local timeout would accept it.
    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining > 0) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
            .awake,
        );
    }
    shared.send_connect.set(io);
    try std.testing.expectError(
        error.Timeout,
        switch (try select.await()) {
            .server => |result| result,
            .client_handshake => return error.TestUnexpectedResult,
        },
    );

    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 client deadline includes CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x85} ** 32,
            .x25519_secret_key = [_]u8{0x86} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        received_connect: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const guard_deadline = std.Io.Clock.Timestamp.fromNow(
                self.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            );
            var session = try self.server.transport.acceptWithDeadline(
                guard_deadline,
            );
            defer session.deinit();
            try session.ensureSettingsSent();
            while (true) {
                var event = try session.receiveRequestEventWithDeadline(
                    guard_deadline,
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (head != .request or
                                !std.mem.eql(u8, head.request.method, "CONNECT") or
                                !std.mem.eql(u8, head.request.path, "/slow-response"))
                            {
                                return error.TestUnexpectedResult;
                            }
                            self.received_connect = true;
                            break;
                        },
                        else => return error.TestUnexpectedResult,
                    },
                }
            }
            const remaining = self.deadline.durationFromNow(self.io)
                .raw.nanoseconds;
            if (remaining > 0) {
                try std.Io.sleep(
                    self.io,
                    .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
                    .awake,
                );
            }
            // Intentionally omit the response. The client must reach its
            // original caller deadline rather than beginning a new wait after
            // QUIC/TLS and peer SETTINGS have completed.
        }
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(300), .clock = .awake },
    );
    var shared = Shared{
        .server = &server,
        .io = io,
        .deadline = deadline,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x87} ** 32,
                .x25519_secret_key = [_]u8{0x88} ** 32,
            } },
            .{
                .authority = "localhost",
                .path = "/slow-response",
            },
            deadline,
        ),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.received_connect);
}

test "WebSocket HTTP3 deadline APIs reject invalid budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client: http3.runtime.HandshakeClient = undefined;
    var server_session: http3.runtime.HandshakeServerSession = undefined;

    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectSessionWithTimeout(
            std.testing.allocator,
            &client,
            .{ .authority = "localhost" },
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        h3.Server.acceptSessionWithTimeout(
            std.testing.allocator,
            &server_session,
            .{},
            .zero,
        ),
    );
    _ = io;
}

test "WebSocket HTTP3 URI derives authority path query and SNI" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x35} ** 32,
            .x25519_secret_key = [_]u8{0x36} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        expected_authority: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.transport.acceptWithTimeout(
                .fromSeconds(2),
            );
            defer session.deinit();
            try session.ensureSettingsSent();
            while (true) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(2),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqualStrings(
                                "/chat/room?token=a%2Fb",
                                head.request.path,
                            );
                            try std.testing.expectEqualStrings(
                                self.expected_authority,
                                head.request.authority.?,
                            );
                            try session.startResponse(
                                message.stream_id,
                                .{
                                    .status = 200,
                                    .request_method = "CONNECT",
                                    .extended_connect = true,
                                },
                                null,
                            );
                            return;
                        },
                        else => return error.TestUnexpectedResult,
                    },
                }
            }
        }
    };

    const port = server.address().getPort();
    const authority = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{port},
    );
    defer allocator.free(authority);
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://{s}/chat/room?token=a%2Fb",
        .{authority},
    );
    defer allocator.free(uri);
    var shared = Shared{
        .server = &server,
        .expected_authority = authority,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connectUriWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .h3_limits = limits,
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x37} ** 32,
                .x25519_secret_key = [_]u8{0x38} ** 32,
            } },
        },
        .fromSeconds(2),
    );
    defer client.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 URI rejects non-HTTPS and userinfo before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const options = h3.UriConnectOptions{
        .h3 = .{ .handshake = .{
            .original_destination_connection_id = "original",
            .local_connection_id = "local",
        } },
    };
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectUri(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "http://example.com/chat",
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectUri(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://user@example.com/chat",
            options,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectUriWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://localhost/chat",
            options,
            .zero,
        ),
    );
}

test "WebSocket over HTTP3 extended CONNECT exchanges frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const request_text = "hello over h3 hello over h3 hello over h3 hello over h3";
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc4} ** 32,
                .x25519_secret_key = [_]u8{0xc5} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .protocols = &.{"chat"},
                .allowed_origins = &.{"https://example.test"},
                .enable_permessage_deflate = true,
                .compression_threshold = 1,
            });
            defer connection.deinit();
            try std.testing.expectEqualStrings(
                "chat",
                connection.selectedProtocol().?,
            );
            try std.testing.expectEqualStrings(
                "h3",
                connection.negotiatedAlpn(),
            );
            try std.testing.expect(connection.permessage_deflate);

            var text = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer text.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.text, text.opcode);
            try std.testing.expectEqualStrings(request_text, text.payload);
            try std.testing.expect(text.was_compressed);
            try connection.sendText("hello client");

            var ping = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer ping.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("probe", ping.payload);

            var close = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            const parsed = (try websocket.parseClosePayload(close.payload)).?;
            try std.testing.expectEqual(websocket.CloseCode.normal_closure, parsed.code);
            try std.testing.expectEqualStrings("done", parsed.reason);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/chat",
            .origin = "https://example.test",
            .protocols = &.{"chat"},
            .enable_permessage_deflate = true,
            .compression_threshold = 1,
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings("chat", client.selectedProtocol().?);
    try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
    try std.testing.expect(client.permessage_deflate);

    try client.sendFragmented(.text, &.{
        request_text[0..20],
        request_text[20..],
    });
    var reply = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, reply.header.opcode);
    try std.testing.expectEqualStrings("hello client", reply.payload);
    try client.sendPing("probe");
    var pong = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("probe", pong.payload);
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP3 validates reserved handshake metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xf4} ** 32,
            .x25519_secret_key = [_]u8{0xf5} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.transport.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.ensureSettingsSent() catch |err| {
                self.err = err;
            };
            connection.deinit();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.InvalidHandshake,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xf2} ** 32,
                .x25519_secret_key = [_]u8{0xf3} ** 32,
            } },
            .{
                .authority = "localhost",
                .extra_headers = &.{.{
                    .name = "sec-websocket-version",
                    .value = "12",
                }},
            },
        ),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP3 rejects peer without extended CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x85} ** 32,
            .x25519_secret_key = [_]u8{0x86} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            session.ensureSettingsSent() catch |err| {
                self.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.ExtendedConnectDisabled,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x83} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            } },
            .{ .authority = "localhost" },
        ),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP3 peer SETTINGS wait rejects an expired budget" {
    var client: http3.runtime.HandshakeClient = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receivePeerSettingsWithTimeout(.zero),
    );
}

test "WebSocket HTTP3 fragmented compression has no plaintext join" {
    const allocator = std.testing.allocator;
    const payload = "h3-fragmented-payload-h3-fragmented-payload-" ** 64;
    const fragments = [_][]const u8{
        payload[0..777],
        payload[777..1555],
        payload[1555..],
    };
    const total = payload.len;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var scratch: @import("compression_scratch.zig").SendScratch = .{};
    defer scratch.deinit(failing.allocator());

    try scratch.prepare(failing.allocator(), total);
    _ = try websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
        &scratch.encoder.?,
        &scratch.payload,
        &fragments,
        15,
    );
    failing.fail_index = failing.alloc_index;
    try scratch.prepare(failing.allocator(), total);
    const compressed = try websocket
        .compressMessageFragmentsVortIntoWindowWithEncoder(
        &scratch.encoder.?,
        &scratch.payload,
        &fragments,
        15,
    );
    try std.testing.expect(compressed.len < total);
    try std.testing.expect(!failing.has_induced_failure);

    const valid_prefix = [_]u8{ 'v', 'a', 'l', 'i', 'd', ' ', 0xe2 };
    const valid_middle = [_]u8{0x82};
    const valid_suffix = [_]u8{ 0xac, ' ', 't', 'e', 'x', 't' };
    const invalid_prefix = [_]u8{ 'i', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 0xe2 };
    const invalid_suffix = [_]u8{'('};
    const split_utf8 = [_][]const u8{
        &valid_prefix,
        &valid_middle,
        &valid_suffix,
    };
    const invalid_utf8 = [_][]const u8{ &invalid_prefix, &invalid_suffix };
    try std.testing.expect(h3.testing.fragmentedTextIsValid(&split_utf8));
    try std.testing.expect(!h3.testing.fragmentedTextIsValid(&invalid_utf8));
    const first = h3.testing.compressedFragmentRangeForTest(10, 3, 0);
    const second = h3.testing.compressedFragmentRangeForTest(10, 3, 1);
    const third = h3.testing.compressedFragmentRangeForTest(10, 3, 2);
    try std.testing.expectEqual(@as(usize, 0), first.start);
    try std.testing.expectEqual(first.end, second.start);
    try std.testing.expectEqual(second.end, third.start);
    try std.testing.expectEqual(@as(usize, 10), third.end);
}
