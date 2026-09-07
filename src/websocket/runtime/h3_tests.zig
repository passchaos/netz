const std = @import("std");
const websocket = @import("../mod.zig");
const h3 = @import("h3.zig");
const http3 = @import("../../http3/mod.zig");
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn countHeaders(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, name));
    }
    return count;
}

test "WebSocket HTTP3 carries 80 request and response headers at 1200 MTU" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 1200,
        .max_frames_per_datagram = 16,
    } };
    var request_headers: [80]http3.Qpack.HeaderField = undefined;
    var response_headers: [80]http3.Qpack.HeaderField = undefined;
    for (&request_headers) |*header| {
        header.* = .{
            .name = "x-many-request",
            .value = large_header_value,
            .never_indexed = true,
        };
    }
    for (&response_headers) |*header| {
        header.* = .{
            .name = "x-many-response",
            .value = large_header_value,
            .never_indexed = true,
        };
    }

    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe2} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{ .allowed_origins = &.{"https://example.test"} },
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/many-headers",
                pending.target(),
            );
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqual(
                @as(usize, 80),
                countHeaders(pending.headers(), "x-many-request"),
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.header("origin") orelse
                    return error.TestUnexpectedResult,
            );
            var connection = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer connection.deinit();
            try connection.h3.waitForRecoveryIdleWithTimeout(
                .fromSeconds(2),
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/many-headers",
            .origin = "https://example.test",
            .extra_headers = &request_headers,
        },
        .fromSeconds(3),
    );
    try std.testing.expect(attempt.accepted());
    try std.testing.expectEqual(
        @as(usize, 80),
        countHeaders(attempt.response.headers, "x-many-response"),
    );
    var connection = try attempt.requireAccepted();
    defer connection.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

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

test "WebSocket HTTP3 pending decision keeps the original deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };
    const client_cid = [_]u8{ 0x72, 0x73, 0x74, 0x75 };
    const server_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x89} ** 32,
            .x25519_secret_key = [_]u8{0x8a} ** 32,
        } },
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
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(1),
            );
            defer pending.deinit();
            try std.Io.sleep(
                self.server.transport.quic_server.endpoint.io,
                .fromMilliseconds(1100),
                .awake,
            );
            try std.testing.expectError(error.Timeout, pending.accept());
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    try std.testing.expectError(
        error.RequestRejected,
        h3.Client.connectWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x8b} ** 32,
                .x25519_secret_key = [_]u8{0x8c} ** 32,
            } },
            .{ .authority = "localhost", .path = "/decision-timeout" },
            .fromSeconds(3),
        ),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
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

test "WebSocket HTTP3 connect attempt preserves rejection metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        } },
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
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{ .allowed_origins = &.{"https://example.test"} },
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings("/private", pending.target());
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "Bearer bad-token",
                pending.header("authorization") orelse
                    return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.header("origin") orelse
                    return error.TestUnexpectedResult,
            );
            try pending.rejectWithBody(
                401,
                &.{.{
                    .name = "www-authenticate",
                    .value = "Bearer realm=chat",
                }},
                "token expired",
                &.{.{
                    .name = "x-rejection-code",
                    .value = "expired",
                }},
            );
            pending_owned = false;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/private",
            .origin = "https://example.test",
            .extra_headers = &.{.{
                .name = "authorization",
                .value = "Bearer bad-token",
            }},
        },
        .fromSeconds(2),
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer realm=chat",
        attempt.responseHeader("WWW-Authenticate").?,
    );
    try std.testing.expectEqualStrings("13", attempt.responseHeader(
        "content-length",
    ).?);
    try std.testing.expectEqualStrings("token expired", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-rejection-code",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "expired",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(error.InvalidResponse, attempt.requireAccepted());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller session attempt restores after rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };
    const client_cid = [_]u8{ 0x22, 0x23, 0x24, 0x25 };
    const server_cid = [_]u8{ 0x32, 0x33, 0x34, 0x35 };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x36} ** 32,
                .x25519_secret_key = [_]u8{0x37} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.ensureSettingsSent();
            var oversized_stream_ids: [2]?u62 = .{ null, null };
            var reset_seen = [_]bool{false} ** 2;
            var reset_count: usize = 0;
            for (0..5) |attempt_index| {
                while (true) {
                    var connect_event = try session
                        .receiveRequestEventWithTimeout(.fromSeconds(3));
                    defer connect_event.deinit(allocator);
                    switch (connect_event) {
                        .reset => |reset| {
                            var matched: ?usize = null;
                            for (oversized_stream_ids, 0..) |candidate, index| {
                                if (candidate == reset.stream_id) {
                                    matched = index;
                                    break;
                                }
                            }
                            const index = matched orelse
                                return error.TestUnexpectedResult;
                            if (reset_seen[index]) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqual(
                                @as(
                                    u64,
                                    http3.ApplicationErrorCode.request_cancelled,
                                ),
                                reset.application_error_code,
                            );
                            reset_seen[index] = true;
                            reset_count += 1;
                            if (reset_count > 2) {
                                return error.TestUnexpectedResult;
                            }
                        },
                        .message => |message| switch (message.value) {
                            .head => |head| {
                                if (head != .request) {
                                    return error.TestUnexpectedResult;
                                }
                                try std.testing.expectEqualStrings(
                                    "CONNECT",
                                    head.request.method,
                                );
                                try std.testing.expectEqualStrings(
                                    switch (attempt_index) {
                                        0 => "/private",
                                        1 => "/legacy",
                                        2 => "/declared-oversized",
                                        3 => "/streamed-oversized",
                                        else => "/trailers-only",
                                    },
                                    head.request.path,
                                );
                                if (attempt_index == 2 or attempt_index == 3) {
                                    oversized_stream_ids[attempt_index - 2] =
                                        message.stream_id;
                                }
                                const response_headers: []const http3.Qpack.HeaderField =
                                    if (attempt_index == 4)
                                        &.{
                                            .{
                                                .name = "www-authenticate",
                                                .value = "Bearer realm=session",
                                            },
                                            .{
                                                .name = "content-length",
                                                .value = "0",
                                            },
                                        }
                                    else
                                        &.{.{
                                            .name = "www-authenticate",
                                            .value = "Bearer realm=session",
                                        }};
                                const response: http3.Response = .{
                                    .status = 401,
                                    .headers = response_headers,
                                    .body = switch (attempt_index) {
                                        0 => "session expired",
                                        1 => "legacy expired",
                                        2 => "oversized",
                                        else => "",
                                    },
                                    .trailers = &.{.{
                                        .name = "x-rejection-code",
                                        .value = "expired",
                                    }},
                                    .request_method = "CONNECT",
                                    .extended_connect = true,
                                };
                                if (attempt_index == 0) {
                                    try session.sendResponseWithInformational(
                                        message.stream_id,
                                        &.{.{
                                            .status = 103,
                                            .headers = &.{.{
                                                .name = "link",
                                                .value = "</auth>; rel=preload",
                                            }},
                                        }},
                                        response,
                                    );
                                } else if (attempt_index == 1 or
                                    attempt_index == 3)
                                {
                                    try session.startResponse(
                                        message.stream_id,
                                        .{
                                            .status = response.status,
                                            .headers = response.headers,
                                            .request_method = "CONNECT",
                                            .extended_connect = true,
                                        },
                                        null,
                                    );
                                    try session.sendResponseBodyPaced(
                                        message.stream_id,
                                        if (attempt_index == 1)
                                            "legacy "
                                        else
                                            "over",
                                        false,
                                    );
                                    try session.sendResponseBodyPaced(
                                        message.stream_id,
                                        if (attempt_index == 1)
                                            "expired"
                                        else
                                            "sized",
                                        false,
                                    );
                                    try session.finishResponseTrailersPaced(
                                        message.stream_id,
                                        response.trailers,
                                    );
                                } else {
                                    try session.sendResponsePaced(
                                        message.stream_id,
                                        response,
                                    );
                                }
                                break;
                            },
                            .finished => {},
                            .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                        },
                    }
                }
            }

            var sibling_sent = false;
            while (!sibling_sent or reset_count != 2) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(3),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => |reset| {
                        var matched: ?usize = null;
                        for (oversized_stream_ids, 0..) |candidate, index| {
                            if (candidate == reset.stream_id) {
                                matched = index;
                                break;
                            }
                        }
                        const index = matched orelse
                            return error.TestUnexpectedResult;
                        if (reset_seen[index]) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqual(
                            @as(
                                u64,
                                http3.ApplicationErrorCode.request_cancelled,
                            ),
                            reset.application_error_code,
                        );
                        reset_seen[index] = true;
                        reset_count += 1;
                        if (reset_count > 2) {
                            return error.TestUnexpectedResult;
                        }
                    },
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (sibling_sent) {
                                return error.TestUnexpectedResult;
                            }
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqualStrings(
                                "/sibling",
                                head.request.path,
                            );
                            try session.sendResponsePaced(message.stream_id, .{
                                .status = 204,
                                .request_method = head.request.method,
                            });
                            sibling_sent = true;
                        },
                        .finished => {},
                        .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                    },
                }
            }
            try std.testing.expectEqual(@as(usize, 2), reset_count);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x38} ** 32,
                .x25519_secret_key = [_]u8{0x39} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer client.deinit();
    var attempt = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/private" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer realm=session",
        attempt.responseHeader("www-authenticate").?,
    );
    try std.testing.expectEqualStrings("session expired", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "expired",
        attempt.trailers()[0].value,
    );
    attempt.deinit();
    try std.testing.expectError(
        error.InvalidResponse,
        h3.Client.connectSessionWithTimeout(
            allocator,
            &client,
            .{ .authority = "localhost", .path = "/legacy" },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{
                .authority = "localhost",
                .path = "/declared-oversized",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{
                .authority = "localhost",
                .path = "/streamed-oversized",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
            .fromSeconds(3),
        ),
    );
    var trailers_only = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/trailers-only" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 401), trailers_only.status());
    try std.testing.expectEqual(@as(usize, 0), trailers_only.body().len);
    try std.testing.expectEqualStrings(
        "0",
        trailers_only.responseHeader("content-length").?,
    );
    try std.testing.expectEqual(@as(usize, 1), trailers_only.trailers().len);
    try std.testing.expectEqualStrings(
        "expired",
        trailers_only.trailers()[0].value,
    );
    trailers_only.deinit();

    var sibling = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller server session restores after rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 };
    const client_cid = [_]u8{ 0x52, 0x53, 0x54, 0x55 };
    const server_cid = [_]u8{ 0x62, 0x63, 0x64, 0x65 };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x66} ** 32,
                .x25519_secret_key = [_]u8{0x67} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();

            var rejected = try h3.Server.receiveSessionUpgradeRequestWithTimeout(
                allocator,
                &session,
                .{},
                .fromSeconds(3),
            );
            try std.testing.expectEqualStrings(
                "/rejected",
                rejected.target(),
            );
            try rejected.rejectWithBody(
                403,
                &.{.{ .name = "x-admission", .value = "denied" }},
                "not allowed",
                &.{.{ .name = "x-final", .value = "true" }},
            );

            var dropped = try h3.Server.receiveSessionUpgradeRequestWithTimeout(
                allocator,
                &session,
                .{},
                .fromSeconds(3),
            );
            try std.testing.expectEqualStrings(
                "/dropped",
                dropped.target(),
            );
            dropped.deinit();

            var sibling = try session.receiveRequestWithTimeout(
                .fromSeconds(3),
            );
            defer sibling.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/sibling",
                sibling.request.path,
            );
            try session.sendResponsePaced(sibling.stream_id, .{
                .status = 204,
                .request_method = sibling.request.method,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x68} ** 32,
                .x25519_secret_key = [_]u8{0x69} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer client.deinit();

    var rejected = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/rejected" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 403), rejected.status());
    try std.testing.expectEqualStrings("denied", rejected.responseHeader(
        "x-admission",
    ).?);
    try std.testing.expectEqualStrings("not allowed", rejected.body());
    try std.testing.expectEqualStrings(
        "true",
        rejected.trailers()[0].value,
    );
    rejected.deinit();

    try std.testing.expectError(
        error.RequestRejected,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{ .authority = "localhost", .path = "/dropped" },
            .fromSeconds(3),
        ),
    );

    var sibling = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const H3Utf8ReceiveMode = enum {
    caller_buffer,
    owned_message,
    frame,
    fragmented_frames,
};

fn expectH3InvalidUtf8RejectedBeforeFrameCompletion(
    receive_mode: H3Utf8ReceiveMode,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const transport_limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const websocket_limits: @import("common.zig").Limits = .{
        .max_frame_bytes = 1024,
        .max_message_bytes = 1024,
    };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        transport_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb5} ** 32,
                .x25519_secret_key = [_]u8{0xb6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        receive_mode: H3Utf8ReceiveMode,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .limits = websocket_limits,
            });
            defer connection.deinit();
            switch (self.receive_mode) {
                .caller_buffer => {
                    var storage: [websocket_limits.max_message_bytes]u8 =
                        undefined;
                    try std.testing.expectError(
                        error.InvalidUtf8,
                        connection.receiveMessageIntoWithTimeout(
                            &storage,
                            .fromSeconds(5),
                        ),
                    );
                },
                .owned_message => try std.testing.expectError(
                    error.InvalidUtf8,
                    connection.receiveMessageWithTimeout(.fromSeconds(5)),
                ),
                .frame => try std.testing.expectError(
                    error.InvalidUtf8,
                    connection.receiveFrameWithTimeout(.fromSeconds(5)),
                ),
                .fragmented_frames => {
                    var first = try connection.receiveFrameWithTimeout(
                        .fromSeconds(5),
                    );
                    defer first.deinit(allocator);
                    try std.testing.expectEqual(
                        websocket.Opcode.text,
                        first.header.opcode,
                    );
                    try std.testing.expect(!first.header.fin);
                    try std.testing.expectEqualSlices(
                        u8,
                        &.{0xf4},
                        first.payload,
                    );
                    try std.testing.expectError(
                        error.InvalidUtf8,
                        connection.receiveFrameWithTimeout(.fromSeconds(5)),
                    );
                },
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .receive_mode = receive_mode,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        transport_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb7} ** 32,
                .x25519_secret_key = [_]u8{0xb8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/utf8-fail-fast",
            .limits = websocket_limits,
        },
    );
    defer client.deinit();

    // Advertise a 1024-byte masked text frame, then send only the header and
    // the two bytes that prove F4 90 cannot encode a Unicode scalar. With
    // five-byte QUIC STREAM chunks, the receiver must reject this prefix
    // rather than wait forever for the other 1022 payload bytes.
    const mask_key = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    if (receive_mode == .fragmented_frames) {
        var first_header_storage: [websocket.max_frame_header_len]u8 =
            undefined;
        const first_header = try websocket.writeFrameHeaderForLengthInto(
            &first_header_storage,
            .text,
            1,
            .{ .fin = false, .mask_key = mask_key },
        );
        var second_header_storage: [websocket.max_frame_header_len]u8 =
            undefined;
        const second_header = try websocket.writeFrameHeaderForLengthInto(
            &second_header_storage,
            .continuation,
            websocket_limits.max_frame_bytes,
            .{ .mask_key = mask_key },
        );
        var wire_prefix: [2 * websocket.max_frame_header_len + 2]u8 =
            undefined;
        var wire_len: usize = 0;
        @memcpy(wire_prefix[wire_len..][0..first_header.len], first_header);
        wire_len += first_header.len;
        wire_prefix[wire_len] = 0xf4 ^ mask_key[0];
        wire_len += 1;
        @memcpy(wire_prefix[wire_len..][0..second_header.len], second_header);
        wire_len += second_header.len;
        wire_prefix[wire_len] = 0x90 ^ mask_key[0];
        wire_len += 1;
        try client.h3.sendRequestBodyPaced(
            client.stream_id,
            wire_prefix[0..wire_len],
            false,
        );
    } else {
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .text,
            websocket_limits.max_frame_bytes,
            .{ .mask_key = mask_key },
        );
        var wire_prefix: [websocket.max_frame_header_len + 2]u8 = undefined;
        @memcpy(wire_prefix[0..header.len], header);
        wire_prefix[header.len] = 0xf4 ^ mask_key[0];
        wire_prefix[header.len + 1] = 0x90 ^ mask_key[1];
        try client.h3.sendRequestBodyPaced(
            client.stream_id,
            wire_prefix[0 .. header.len + 2],
            false,
        );
    }

    var close = (try client.receiveCloseFrameWithTimeout(
        .fromSeconds(5),
    )).?;
    defer close.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.invalid_payload_data,
        close.code,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller-buffer rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.caller_buffer);
}

test "WebSocket HTTP3 owned message rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.owned_message);
}

test "WebSocket HTTP3 frame rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.frame);
}

test "WebSocket HTTP3 frame validation spans fragmented receive calls" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.fragmented_frames);
}

test "WebSocket HTTP3 caller-buffer resumes a partially streamed frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const payload = "0123456789abcdef" ** 64;
    const prefix_len = 37;
    const transport_limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const websocket_limits: @import("common.zig").Limits = .{
        .max_frame_bytes = payload.len,
        .max_message_bytes = payload.len,
    };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        transport_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe5} ** 32,
                .x25519_secret_key = [_]u8{0xe6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 256 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        prefix_sent: std.Io.Event = .unset,
        resume_send: std.Io.Event = .unset,
        receive_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_sent.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .limits = websocket_limits,
            });
            defer connection.deinit();
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .text,
                payload.len,
                .{},
            );
            var prefix: [websocket.max_frame_header_len + prefix_len]u8 =
                undefined;
            @memcpy(prefix[0..header.len], header);
            @memcpy(
                prefix[header.len..][0..prefix_len],
                payload[0..prefix_len],
            );
            try connection.h3.sendResponseBodyPaced(
                connection.stream_id,
                prefix[0 .. header.len + prefix_len],
                false,
            );
            self.prefix_sent.set(self.io);
            try self.resume_send.wait(self.io);
            try connection.h3.sendResponseBodyPaced(
                connection.stream_id,
                payload[prefix_len..],
                false,
            );
            try self.receive_done.wait(self.io);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.resume_send.set(io);
        shared.receive_done.set(io);
        thread.join();
    };

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        transport_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xe7} ** 32,
                .x25519_secret_key = [_]u8{0xe8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 256 },
        },
        .{
            .authority = "localhost",
            .path = "/stream-into-resume",
            .limits = websocket_limits,
        },
    );
    defer client.deinit();

    try shared.prefix_sent.wait(io);
    var storage: [payload.len]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithTimeout(
            &storage,
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expect(client.message_into.active());
    try std.testing.expectEqual(
        @as(usize, prefix_len),
        client.message_frame_receive.payload_written,
    );
    var other_storage: [payload.len]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        client.message_into.validateOutput(&other_storage),
    );
    try std.testing.expect(client.inbuf.capacity < payload.len);

    shared.resume_send.set(io);
    const message = client.receiveMessageIntoWithTimeout(
        &storage,
        .fromSeconds(5),
    ) catch |err| {
        shared.receive_done.set(io);
        thread.join();
        joined = true;
        if (shared.err) |send_err| return send_err;
        return err;
    };
    try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
    try std.testing.expectEqualStrings(payload, message.payload);
    try std.testing.expect(client.inbuf.capacity < payload.len);

    shared.receive_done.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
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
    const compressed_first = "h3-borrowed-prefix-";
    const compressed_second = "compressible-application-payload-" ** 32;
    const compressed_parts = compressed_first ++ compressed_second;
    const concurrent_a = "concurrent-a-" ** 32;
    const concurrent_b = "concurrent-b-" ** 32;
    const fallback_fragments = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7", "8",
        "9", "a", "b", "c", "d", "e", "f", "g",
    };
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
        io: std.Io,
        sibling_stream_id: u62 = 4,
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
                .limits = .{
                    .max_frame_bytes = compressed_parts.len,
                    .max_message_bytes = compressed_parts.len,
                },
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

            var receive_storage: [compressed_parts.len]u8 = undefined;
            const text = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.text, text.opcode);
            try std.testing.expectEqualStrings(request_text, text.payload);

            // A sibling request is deliberately sent before the WebSocket
            // DATA. The targeted CONNECT reader must leave that sibling
            // buffered instead of consuming it as an invalid WS event.
            var sibling_head = try connection.h3
                .receiveRequestEventForWithTimeout(
                self.sibling_stream_id,
                .fromSeconds(5),
            );
            defer sibling_head.deinit(allocator);
            try std.testing.expect(sibling_head == .message);
            try std.testing.expect(sibling_head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/sibling-while-websocket",
                sibling_head.message.value.head.request.path,
            );
            var sibling_finished = try connection.h3
                .receiveRequestEventForWithTimeout(
                self.sibling_stream_id,
                .fromSeconds(5),
            );
            defer sibling_finished.deinit(allocator);
            try std.testing.expect(sibling_finished == .message);
            try std.testing.expect(
                sibling_finished.message.value == .finished,
            );
            try connection.h3.sendResponse(
                self.sibling_stream_id,
                .{ .status = 204 },
            );

            const plain_parts = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, plain_parts.opcode);
            try std.testing.expectEqualStrings("ab", plain_parts.payload);

            const in_place = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, in_place.opcode);
            try std.testing.expectEqualStrings("mutable-h3", in_place.payload);
            const fallback = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, fallback.opcode);
            try std.testing.expectEqualStrings(
                "0123456789abcdefg",
                fallback.payload,
            );
            try connection.sendText("in-place-received");

            for (0..2) |_| {
                const compressed = try connection.receiveMessageIntoWithTimeout(
                    &receive_storage,
                    .fromSeconds(5),
                );
                try std.testing.expectEqual(
                    websocket.Opcode.binary,
                    compressed.opcode,
                );
                try std.testing.expectEqualStrings(
                    compressed_parts,
                    compressed.payload,
                );
            }
            try connection.sendBinaryParts("a", "b");
            try connection.sendBinaryParts(
                compressed_first,
                compressed_second,
            );
            const compressed_ptr = connection.compression_send.payload
                .allocatedSlice().ptr;
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            connection.allocator = failing.allocator();
            {
                defer connection.allocator = allocator;
                failing.fail_index = failing.alloc_index;
                try connection.sendBinaryParts(
                    compressed_first,
                    compressed_second,
                );
                try std.testing.expect(!failing.has_induced_failure);
                try std.testing.expectEqual(
                    compressed_ptr,
                    connection.compression_send.payload.allocatedSlice().ptr,
                );
            }
            try h3.testing.writeFrame(&connection, .binary, "split-", false);
            try connection.sendPing("between-fragments");
            try h3.testing.writeFrame(
                &connection,
                .continuation,
                "message",
                true,
            );
            try connection.sendText("hello client");

            const Sender = struct {
                connection: *h3.ServerConnection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            var start: std.Io.Event = .unset;
            var senders = [_]Sender{
                .{
                    .connection = &connection,
                    .io = self.io,
                    .start = &start,
                    .payload = concurrent_a,
                },
                .{
                    .connection = &connection,
                    .io = self.io,
                    .start = &start,
                    .payload = concurrent_b,
                },
            };
            const sender_a = try std.Thread.spawn(.{}, Sender.run, .{&senders[0]});
            const sender_b = std.Thread.spawn(.{}, Sender.run, .{&senders[1]}) catch |err| {
                start.set(self.io);
                sender_a.join();
                return err;
            };
            start.set(self.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            var interleaved_pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer interleaved_pong.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.pong,
                interleaved_pong.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "between-fragments",
                interleaved_pong.payload,
            );

            var ping = try connection.pingWithTimeout(
                "server-probe",
                .fromSeconds(5),
            );
            defer ping.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.text,
                ping.application.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "client in flight",
                ping.application.payload,
            );
            var pong = try connection.continuePingWithTimeout(
                "server-probe",
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expect(pong == .pong);

            var close = try connection.closeWithTimeout(
                .{ .code = .normal_closure, .reason = "server-done" },
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.text,
                close.application.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "before close",
                close.application.payload,
            );
            var closed = try connection.continueCloseWithTimeout(
                .fromSeconds(5),
            );
            defer closed.deinit(allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                closed.closed.?.code,
            );
            try std.testing.expectEqualStrings(
                "server-done",
                closed.closed.?.reason,
            );
        }
    };

    var shared = Shared{ .server = &server, .io = io };
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
            .limits = .{
                .max_frame_bytes = compressed_parts.len,
                .max_message_bytes = compressed_parts.len,
            },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings("chat", client.selectedProtocol().?);
    try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
    try std.testing.expect(client.permessage_deflate);

    const sibling_stream_id = try client.h3.sendRequest(.{
        .method = "GET",
        .path = "/sibling-while-websocket",
        .authority = "localhost",
    });
    try std.testing.expectEqual(shared.sibling_stream_id, sibling_stream_id);
    try client.sendFragmented(.text, &.{
        request_text[0..20],
        request_text[20..],
    });
    var sibling_response = try client.h3.receiveResponseWithTimeout(
        sibling_stream_id,
        .fromSeconds(5),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 204),
        sibling_response.response.status,
    );
    try client.sendBinaryParts("a", "b");
    // Compression is negotiated for later messages, but an individual frame
    // may remain uncompressed. Temporarily select that legal path to exercise
    // the mutable-buffer masking contract on this established H3 connection.
    client.permessage_deflate = false;
    var mutable_payload = [_]u8{ 'm', 'u', 't', 'a', 'b', 'l', 'e', '-', 'h', '3' };
    const original_payload = mutable_payload;
    try client.sendBinaryInPlace(&mutable_payload);
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_payload,
        &mutable_payload,
    ));
    try client.sendFragmented(.binary, &fallback_fragments);
    client.permessage_deflate = true;
    var in_place_ack = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer in_place_ack.deinit(allocator);
    try std.testing.expectEqualStrings("in-place-received", in_place_ack.payload);
    try client.sendBinaryParts(compressed_first, compressed_second);
    const compressed_ptr = client.compression_send.payload.allocatedSlice().ptr;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    client.allocator = failing.allocator();
    {
        defer client.allocator = allocator;
        failing.fail_index = failing.alloc_index;
        try client.sendBinaryParts(compressed_first, compressed_second);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(
            compressed_ptr,
            client.compression_send.payload.allocatedSlice().ptr,
        );
    }
    var receive_storage: [compressed_parts.len]u8 = undefined;
    const plain_parts = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, plain_parts.opcode);
    try std.testing.expect(!plain_parts.was_compressed);
    try std.testing.expectEqualStrings("ab", plain_parts.payload);
    for (0..2) |_| {
        const compressed = try client.receiveMessageIntoWithTimeout(
            &receive_storage,
            .fromSeconds(5),
        );
        try std.testing.expectEqual(websocket.Opcode.binary, compressed.opcode);
        try std.testing.expect(compressed.was_compressed);
        try std.testing.expectEqualStrings(compressed_parts, compressed.payload);
    }
    const fragmented = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, fragmented.opcode);
    try std.testing.expect(!fragmented.was_compressed);
    try std.testing.expectEqualStrings("split-message", fragmented.payload);
    var reply = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, reply.header.opcode);
    try std.testing.expectEqualStrings("hello client", reply.payload);
    var concurrent_first = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendText("client in flight");
    var server_ping = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer server_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, server_ping.header.opcode);
    try std.testing.expectEqualStrings("server-probe", server_ping.payload);
    try client.sendText("before close");
    var server_close = (try client.receiveCloseFrameWithTimeout(
        .fromSeconds(5),
    )).?;
    defer server_close.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        server_close.code,
    );
    try std.testing.expectEqualStrings("server-done", server_close.reason);
    // Receiving Close automatically echoes its exact payload. The server's
    // typed progress event therefore owns the same code and reason inspected
    // above rather than requiring an otherwise-invalid second Close frame.

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
    client.dispatcher_bound = false;
    try std.testing.expectError(
        error.Timeout,
        client.receivePeerSettingsWithTimeout(.zero),
    );
}

test "WebSocket HTTP3 control progress APIs reject expired budgets" {
    var client: h3.ClientConnection = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout("probe", .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.continuePingWithTimeout("probe", .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(null, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveCloseFrameWithTimeout(.zero),
    );
    var message_storage: [1]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithTimeout(&message_storage, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.continueCloseWithTimeout(.zero),
    );

    // Empty Close is represented by an absent typed payload. This checks the
    // API contract independently of transport framing; the end-to-end test
    // above covers owned non-empty metadata and automatic echo.
    try std.testing.expect(
        (try websocket.parseClosePayloadOwned(
            std.testing.allocator,
            &.{},
        )) == null,
    );
}

test "WebSocket HTTP3 in-place binary send rejects unsupported modes" {
    var server: h3.ServerConnection = undefined;
    server.permessage_deflate = false;
    server.close_sent = .init(false);
    server.close_received = .init(false);
    server.limits = .{};
    const payload = [_]u8{1};
    try std.testing.expectError(
        error.InvalidFrame,
        h3.testing.validateBinaryInPlace(&server, payload.len),
    );

    var client: h3.ClientConnection = undefined;
    client.permessage_deflate = true;
    client.close_sent = .init(false);
    client.close_received = .init(false);
    client.limits = .{};
    try std.testing.expectError(
        error.InvalidFrame,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
    client.permessage_deflate = false;
    client.close_sent.store(true, .release);
    try std.testing.expectError(
        error.ConnectionClosed,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
    client.close_sent.store(false, .release);
    client.limits.max_frame_bytes = 0;
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
}

test "WebSocket HTTP3 sends enforce configured outbound limits before IO" {
    var client: h3.ClientConnection = undefined;
    client.close_sent = .init(false);
    client.close_received = .init(false);
    client.permessage_deflate = true;
    client.limits = .{
        .max_frame_bytes = 4,
        .max_message_bytes = 6,
    };

    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendText("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinary("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinaryParts("abc", "de"),
    );
    client.permessage_deflate = false;
    var in_place_payload = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinaryInPlace(&in_place_payload),
    );
    client.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendPing("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendClose(.normal_closure, "abc"),
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
