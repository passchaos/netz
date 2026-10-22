const std = @import("std");
const websocket = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../../http2/mod.zig");
const http2_runtime = http2.runtime;

test "WebSocket RFC 8441 pending admission exposes metadata before 200" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        io: std.Io,
        pending_ready: std.Io.Event = .unset,
        allow_accept: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.pending_ready.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var pending = try runtime.H2Server.receiveUpgradeRequest(
                self.server.allocator,
                &h2,
                .{
                    .protocols = &.{"chat.v1"},
                    .require_subprotocol = true,
                },
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();

            try std.testing.expectEqualStrings("/admission?room=1", pending.target());
            try std.testing.expectEqualStrings("http", pending.scheme());
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "Bearer secret",
                pending.header("authorization") orelse
                    return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "session=abc",
                pending.header("cookie") orelse
                    return error.TestUnexpectedResult,
            );
            try std.testing.expect(pending.headers().len >= 8);
            self.pending_ready.set(self.io);
            try self.allow_accept.wait(self.io);

            var ws = try pending.acceptWithHeaders(&.{.{
                .name = "x-admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer ws.close();
            try ws.sendText("welcome");
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_accept.set(io);
        server_thread.join();
    };

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        client: *http2_runtime.Connection,
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.runFallible() catch |err| {
                self.err = err;
            };
            self.finished.set(self.io);
        }

        fn runFallible(self: *@This()) !void {
            var response = try self.client.openExtendedConnect(.{
                .method = "CONNECT",
                .path = "/admission?room=1",
                .authority = "localhost",
                .protocol = "websocket",
                .headers = &.{
                    .{ .name = "sec-websocket-version", .value = "13" },
                    .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
                    .{ .name = "authorization", .value = "Bearer secret" },
                    .{ .name = "cookie", .value = "session=abc" },
                },
            });
            defer response.deinit(self.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings(
                "accepted",
                http2_runtime.testing.findHeader(
                    response.headers,
                    "x-admission",
                ) orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "chat.v1",
                http2_runtime.testing.findHeader(
                    response.headers,
                    "sec-websocket-protocol",
                ) orelse return error.TestUnexpectedResult,
            );
            var data = try response.tunnel.readWithTimeout(.fromSeconds(1));
            defer data.deinit(self.allocator);
            var frame = try websocket.parseFrame(self.allocator, data.data);
            defer frame.deinit(self.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expectEqualStrings("welcome", frame.payload);
        }
    };
    var client_task = ClientTask{
        .allocator = allocator,
        .io = io,
        .client = &client,
    };
    const client_thread = try std.Thread.spawn(
        .{},
        ClientTask.run,
        .{&client_task},
    );
    var client_joined = false;
    defer if (!client_joined) {
        shared.allow_accept.set(io);
        client_thread.join();
    };
    try client_task.started.wait(io);
    try shared.pending_ready.wait(io);
    if (shared.err) |err| return err;
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    try std.testing.expect(!client_task.finished.isSet());
    shared.allow_accept.set(io);
    client_thread.join();
    client_joined = true;
    if (client_task.err) |err| return err;

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 rejection preserves body trailers and shared H2 connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            for (0..2) |index| {
                var pending = try runtime.H2Server.receiveUpgradeRequest(
                    self.server.allocator,
                    &h2,
                    .{},
                );
                var pending_owned = true;
                defer if (pending_owned) pending.deinit();
                try std.testing.expectEqualStrings(
                    "bad-token",
                    pending.header("authorization") orelse
                        return error.TestUnexpectedResult,
                );
                if (index == 0) {
                    try pending.rejectWithBody(
                        401,
                        &.{
                            .{
                                .name = "www-authenticate",
                                .value = "Bearer",
                            },
                            .{
                                .name = "content-type",
                                .value = "text/plain",
                            },
                        },
                        "denied\n",
                        &.{.{
                            .name = "x-rejection-complete",
                            .value = "yes",
                        }},
                    );
                } else {
                    try pending.rejectWithBody(
                        401,
                        &.{.{
                            .name = "www-authenticate",
                            .value = "Bearer",
                        }},
                        "legacy denied\n",
                        &.{.{
                            .name = "x-legacy-complete",
                            .value = "yes",
                        }},
                    );
                }
                pending_owned = false;
            }

            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/sibling", sibling.path);
            try h2.writeResponse(sibling.stream_id, .{
                .status = 204,
                .headers = &.{.{ .name = "x-sibling", .value = "ok" }},
            });
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var attempt = try runtime.H2Client.openAttempt(
        allocator,
        &client,
        .{
            .path = "/private",
            .authority = "localhost",
            .extra_headers = &.{
                .{ .name = "authorization", .value = "bad-token" },
            },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer",
        attempt.responseHeader("www-authenticate") orelse
            return error.TestUnexpectedResult,
    );
    try std.testing.expectEqualStrings("denied\n", attempt.body());
    try std.testing.expectEqualStrings(
        "7",
        attempt.responseHeader("content-length") orelse
            return error.TestUnexpectedResult,
    );
    try std.testing.expectEqualStrings(
        "yes",
        http2_runtime.testing.findHeader(
            attempt.trailers(),
            "x-rejection-complete",
        ) orelse return error.TestUnexpectedResult,
    );

    try std.testing.expectError(
        error.InvalidStatus,
        runtime.H2Client.open(allocator, &client, .{
            .path = "/legacy-rejection",
            .authority = "localhost",
            .extra_headers = &.{.{
                .name = "authorization",
                .value = "bad-token",
            }},
        }),
    );
    var sibling = try client.request(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);
    try std.testing.expectEqualStrings(
        "ok",
        http2_runtime.testing.findHeader(
            sibling.headers,
            "x-sibling",
        ) orelse return error.TestUnexpectedResult,
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 rejection body limit resets only its stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequest(
                "websocket",
            );
            defer request.deinit(self.server.allocator);
            var response = try h2.startResponse(
                request.stream_id,
                .{
                    .status = 429,
                    .headers = &.{.{
                        .name = "retry-after",
                        .value = "1",
                    }},
                    .request_method = "CONNECT",
                    .extended_connect = true,
                },
            );
            defer response.deinit();
            try response.write("1234");
            try response.write("5");
            try response.finishTrailers(&.{.{
                .name = "x-end",
                .value = "yes",
            }});

            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/after-large-rejection",
                sibling.path,
            );
            try h2.writeResponse(sibling.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4 },
    );
    defer client.close();
    try std.testing.expectError(
        error.MessageTooLarge,
        runtime.H2Client.openAttempt(allocator, &client, .{
            .path = "/limited",
            .authority = "localhost",
        }),
    );

    var sibling = try client.request(.{
        .method = "GET",
        .path = "/after-large-rejection",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 attempt collects split END_STREAM rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequest("websocket");
            defer request.deinit(self.server.allocator);

            var response = try h2.startResponse(request.stream_id, .{
                .status = 403,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .request_method = "CONNECT",
                .extended_connect = true,
            });
            defer response.deinit();
            try response.write("split ");
            try response.write("rejection");
            try response.finishTrailers(&.{.{
                .name = "x-rejection-complete",
                .value = "yes",
            }});
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var attempt = try runtime.H2Client.openAttempt(allocator, &client, .{
        .path = "/split-rejection",
        .authority = "localhost",
    });
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 403), attempt.status());
    try std.testing.expectEqualStrings("split rejection", attempt.body());
    try std.testing.expect(attempt.responseHeader("content-length") == null);
    try std.testing.expectEqualStrings(
        "yes",
        http2_runtime.testing.findHeader(
            attempt.trailers(),
            "x-rejection-complete",
        ) orelse return error.TestUnexpectedResult,
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 pending decision keeps the original deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var pending = try runtime.H2Server
                .receiveUpgradeRequestWithTimeout(
                self.server.allocator,
                &h2,
                .{},
                .fromMilliseconds(40),
            );
            defer pending.deinit();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(80),
                .awake,
            );
            try std.testing.expectError(error.Timeout, pending.accept());
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.StreamReset,
        client.openExtendedConnectWithTimeout(
            .{
                .method = "CONNECT",
                .path = "/deadline",
                .authority = "localhost",
                .protocol = "websocket",
                .headers = &.{.{
                    .name = "sec-websocket-version",
                    .value = "13",
                }},
            },
            .fromSeconds(1),
        ),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 pending deinit resets only its stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var pending = try runtime.H2Server.receiveUpgradeRequest(
                self.server.allocator,
                &h2,
                .{},
            );
            pending.deinit();

            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-reset", sibling.path);
            try h2.writeResponse(sibling.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.StreamReset,
        client.openExtendedConnect(.{
            .method = "CONNECT",
            .path = "/drop",
            .authority = "localhost",
            .protocol = "websocket",
            .headers = &.{.{
                .name = "sec-websocket-version",
                .value = "13",
            }},
        }),
    );
    var sibling = try client.request(.{
        .method = "GET",
        .path = "/after-reset",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 advertises version 13 and reuses H2 connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            try std.testing.expectError(
                error.UnsupportedVersion,
                runtime.H2Server.receiveUpgradeRequest(
                    self.server.allocator,
                    &h2,
                    .{},
                ),
            );

            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/after-version-rejection",
                sibling.path,
            );
            try h2.writeResponse(sibling.stream_id, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var rejected = try client.openExtendedConnectAttempt(.{
        .method = "CONNECT",
        .path = "/unsupported-version",
        .authority = "localhost",
        .protocol = "websocket",
        .headers = &.{.{
            .name = "sec-websocket-version",
            .value = "12",
        }},
    });
    defer rejected.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 426), rejected.status);
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqualStrings(
        "13",
        rejected.responseHeader("sec-websocket-version") orelse
            return error.TestUnexpectedResult,
    );

    var sibling = try client.request(.{
        .method = "GET",
        .path = "/after-version-rejection",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 client rejects unoffered compression window" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequest("websocket");
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
                http2_runtime.testing.findHeader(
                    request.headers,
                    "sec-websocket-extensions",
                ) orelse return error.TestUnexpectedResult,
            );
            _ = try h2.acceptExtendedConnect(request, &.{.{
                .name = "sec-websocket-extensions",
                .value = "permessage-deflate; " ++
                    "server_no_context_takeover; " ++
                    "client_no_context_takeover; " ++
                    "client_max_window_bits=15",
            }});

            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-invalid-extension", sibling.path);
            try h2.writeResponse(sibling.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.InvalidExtension,
        runtime.H2Client.open(allocator, &client, .{
            .authority = "localhost",
            .path = "/invalid-takeover",
            .enable_permessage_deflate = true,
        }),
    );
    var sibling = try client.request(.{
        .method = "GET",
        .path = "/after-invalid-extension",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 rejection headers cannot negotiate or override framing" {
    try std.testing.expectError(
        error.InvalidHandshake,
        runtime.testing.validateH2RejectionHeaders(&.{.{
            .name = "sec-websocket-protocol",
            .value = "chat.v1",
        }}),
    );
    try std.testing.expectError(
        error.InvalidHandshake,
        runtime.testing.validateH2RejectionHeaders(&.{.{
            .name = "content-length",
            .value = "1",
        }}),
    );
}
