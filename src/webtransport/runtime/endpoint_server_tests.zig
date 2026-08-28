const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../runtime.zig");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "WebTransport endpoint server exposes stable session API" {
    try std.testing.expect(@hasDecl(runtime, "EndpointServer"));
    try std.testing.expect(@hasDecl(runtime, "EndpointServerEvent"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "receive"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "accept"));
    try std.testing.expect(@hasDecl(runtime.EndpointServer, "reject"));
    try std.testing.expect(@hasDecl(
        http3.runtime.EndpointServer,
        "promotedSession",
    ));
}

test "WebTransport URI connect forwards HTTP3 total handshake timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectUri(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{ .h3 = .{
                .connect_timeout = .fromMilliseconds(20),
                .handshake = .{
                    .original_destination_connection_id = "wt-timeout-origin",
                    .local_connection_id = "wt-timeout-client",
                    .handshake_recovery = .{
                        .initial_pto_ms = 1_000,
                        .max_pto_ms = 4_000,
                        .max_retries = 3,
                    },
                },
            } },
        ),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
}

test "WebTransport URI connect exposes an absolute handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClientSession.connectUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            "https://localhost/",
            .{ .h3 = .{ .handshake = .{
                .original_destination_connection_id = "wt-deadline-origin",
                .local_connection_id = "wt-deadline-client",
            } } },
            .fromNow(io, .{ .raw = .zero, .clock = .awake }),
        ),
    );
}

test "WebTransport endpoint server rotates ready sessions fairly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "wt-fair-server" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    // The scheduler only passes these stable addresses to the synthetic
    // readiness callback. Clearing the map before EndpointServer.deinit keeps
    // the intentionally uninitialized protocol objects out of ownership code.
    var accepted_storage: [3]runtime.EndpointAcceptedSession = undefined;
    defer endpoint.sessions.clearRetainingCapacity();
    const handles = [_]quic.endpoint_dispatcher.ConnectionHandle{ 11, 22, 33 };
    for (handles, 0..) |handle, index| {
        try endpoint.sessions.put(
            allocator,
            handle,
            &accepted_storage[index],
        );
    }

    var order: [handles.len]quic.endpoint_dispatcher.ConnectionHandle =
        undefined;
    for (&order) |*handle| {
        handle.* = (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    }
    for (order, 0..) |handle, index| {
        for (order[0..index]) |earlier| {
            try std.testing.expect(handle != earlier);
        }
    }
    try std.testing.expectEqual(
        order[0],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )).?,
    );

    // Skipping idle entries must still advance from the actual producer.
    const only_middle = [_]quic.endpoint_dispatcher.ConnectionHandle{
        order[1],
    };
    try std.testing.expectEqual(
        order[1],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &only_middle,
        )).?,
    );
    try std.testing.expectEqual(
        order[2],
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )).?,
    );

    // A cursor invalidated by removal falls back to a complete scan rather
    // than suppressing ready sessions until another insertion reshuffles the
    // hash table.
    const stale = order[2];
    try std.testing.expect(endpoint.sessions.remove(stale));
    endpoint.last_session_event_handle = stale;
    const after_removal =
        (try runtime.EndpointServer.testing.pollReadySessionHandle(
            &endpoint,
            &handles,
        )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(after_removal != stale);
}

test "WebTransport endpoint server owns concurrent real sessions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-endpoint-template",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();
    const dispatcher_address = @intFromPtr(endpoint.h3.dispatcher);

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        datagram: []const u8,
        response_datagram: []const u8,
        settings: http3.Settings,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClientSession = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            self.client = try runtime.HandshakeClientSession.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{
                    .authority = "localhost",
                    .path = self.path,
                    .limits = .{ .http3 = .{ .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 16,
                    } } },
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = self.original_dcid,
                            .local_connection_id = self.local_cid,
                            .server_name = "localhost",
                            .random = self.random,
                            .x25519_secret_key = self.secret,
                            .handshake_recovery = .{
                                .initial_pto_ms = 20,
                                .max_pto_ms = 40,
                                .max_duration_ms = 2_000,
                            },
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            );
            try self.client.?.sendDatagram(self.datagram);
            var response = try self.client.?.receiveDatagram();
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings(
                self.response_datagram,
                response.datagram.payload,
            );
            const stream_id = try self.client.?.openBidirectionalStream();
            try self.client.?.sendStream(
                stream_id,
                self.datagram,
                true,
            );
            var stream_response = try self.client.?.receiveStream();
            defer stream_response.deinit();
            try std.testing.expectEqualStrings(
                self.response_datagram,
                stream_response.payload,
            );
            try self.client.?.close(77, self.datagram);
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-endpoint-one",
            .local_cid = "wt-client-one",
            .path = "/one",
            .datagram = "one",
            .response_datagram = "echo-one",
            .settings = settings,
            .random = [_]u8{0xe3} ** 32,
            .secret = [_]u8{0xe4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-endpoint-two",
            .local_cid = "wt-client-two",
            .path = "/two",
            .datagram = "two",
            .response_datagram = "echo-two",
            .settings = settings,
            .random = [_]u8{0xe5} ** 32,
            .secret = [_]u8{0xe6} ** 32,
        },
    };
    const first_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const second_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        first_thread.join();
        second_thread.join();
        for (&clients) |*client| if (client.client) |*value| value.deinit();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var accepted_handles: [2]quic.endpoint_dispatcher.ConnectionHandle = undefined;
    var accepted_count: usize = 0;
    var received_datagrams: usize = 0;
    var received_streams: usize = 0;
    var received_closes: usize = 0;
    var stream_one_bytes: usize = 0;
    var stream_two_bytes: usize = 0;
    var stream_buffer: [128]u8 = undefined;
    while (accepted_count < clients.len or
        received_datagrams < clients.len or
        received_streams < clients.len or
        received_closes < clients.len)
    {
        var event = try endpoint.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
            &stream_buffer,
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                const path = pending.path();
                if (!std.mem.eql(u8, path, "/one") and
                    !std.mem.eql(u8, path, "/two"))
                {
                    return error.TestUnexpectedResult;
                }
                const accepted = try endpoint.accept(handle);
                try std.testing.expectEqual(
                    handle,
                    accepted.handle,
                );
                try std.testing.expectEqual(
                    dispatcher_address,
                    @intFromPtr(accepted.dispatcher),
                );
                try std.testing.expectEqual(
                    @intFromPtr(endpoint.h3.session(handle).?),
                    @intFromPtr(accepted.h3),
                );
                accepted_handles[accepted_count] = handle;
                accepted_count += 1;
            },
            .session_event => |*value| switch (value.event) {
                .datagram => |datagram| {
                    const accepted = endpoint.session(value.handle) orelse
                        return error.TestUnexpectedResult;
                    const expected = if (std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    )) "one" else "two";
                    try std.testing.expectEqualStrings(
                        expected,
                        datagram.datagram.payload,
                    );
                    try accepted.sendDatagram(if (std.mem.eql(
                        u8,
                        expected,
                        "one",
                    )) "echo-one" else "echo-two");
                    received_datagrams += 1;
                },
                .stream => |stream| {
                    if (stream != .data) {
                        return error.TestUnexpectedResult;
                    }
                    const accepted = endpoint.session(value.handle) orelse
                        return error.TestUnexpectedResult;
                    const is_one = std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    );
                    const expected = if (is_one) "one" else "two";
                    const received = if (is_one)
                        &stream_one_bytes
                    else
                        &stream_two_bytes;
                    try std.testing.expectEqualStrings(
                        expected[received.*..][0..stream.data.bytes],
                        stream_buffer[0..stream.data.bytes],
                    );
                    received.* += stream.data.bytes;
                    if (stream.data.fin) {
                        try std.testing.expectEqual(expected.len, received.*);
                        try accepted.sendStream(
                            stream.data.stream_id,
                            if (is_one) "echo-one" else "echo-two",
                            true,
                        );
                        received_streams += 1;
                    }
                },
                .session => |session_event| {
                    if (session_event != .closed or
                        session_event.closed.code != 77)
                    {
                        return error.TestUnexpectedResult;
                    }
                    const accepted = endpoint.session(value.handle) orelse
                        return error.TestUnexpectedResult;
                    const expected = if (std.mem.eql(
                        u8,
                        accepted.request.request.path,
                        "/one",
                    )) "one" else "two";
                    try std.testing.expectEqualStrings(
                        expected,
                        session_event.closed.reason,
                    );
                    received_closes += 1;
                },
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }

    first_thread.join();
    second_thread.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        if (client.client) |*value| value.deinit();
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 2), endpoint.sessionCount());
    try std.testing.expectEqual(@as(usize, 2), endpoint.connectionCount());
    for (accepted_handles) |handle| {
        try std.testing.expect(endpoint.removeConnection(handle));
    }
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
}

test "WebTransport endpoint serve loop shuts down from a session event" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-serve-template",
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .inbox_capacity = 8,
    });
    defer endpoint.deinit();

    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        accepted: bool = false,
        received: bool = false,

        fn handle(
            self: *@This(),
            endpoint_server: *runtime.EndpointServer,
            event: runtime.ServeEvent,
        ) !void {
            switch (event) {
                .connected => {},
                .closed => return error.TestUnexpectedResult,
                .session_request => |pending| {
                    _ = try endpoint_server.accept(pending.handle);
                    self.accepted = true;
                },
                .session_event => |value| switch (value.event.*) {
                    .datagram => |datagram| {
                        try std.testing.expectEqualStrings(
                            "serve-loop",
                            datagram.datagram.payload,
                        );
                        self.received = true;
                        self.shutdown.set(self.io);
                    },
                    .stream, .session => return error.TestUnexpectedResult,
                },
            }
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        context: Context,
        err: ?anyerror = null,

        fn init(
            endpoint_ptr: *runtime.EndpointServer,
            io_value: std.Io,
            shutdown: *std.Io.Event,
        ) @This() {
            return .{
                .endpoint = endpoint_ptr,
                .context = .{ .io = io_value, .shutdown = shutdown },
            };
        }

        fn run(self: *@This()) void {
            self.endpoint.serveUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.context.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                        quic.Version.version_2.wireValue(),
                    },
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(2),
                    },
                    .stream_buffer_size = 128,
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared.init(&endpoint, io, &shutdown);
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        server_thread.join();
    };

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/serve",
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = "wt-serve-origin",
                    .local_connection_id = "wt-serve-client",
                    .server_name = "localhost",
                    .random = [_]u8{0xf3} ** 32,
                    .x25519_secret_key = [_]u8{0xf4} ** 32,
                },
                .session = .{ .local_settings = settings },
            },
        },
    );
    defer client.deinit();
    try client.sendDatagram("serve-loop");

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.context.accepted);
    try std.testing.expect(shared.context.received);
}

test "WebTransport endpoint isolates accepted and rejected connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = webtransport.defaultSettings(.{});
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-policy-template",
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .inbox_capacity = 8,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    const ClientTask = struct {
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        expected_status: u16,
        settings: http3.Settings,
        random: [32]u8,
        secret: [32]u8,
        client: ?runtime.HandshakeClientSession = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var attempt = try runtime.HandshakeClientSession.connectAttempt(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{
                    .authority = "localhost",
                    .path = self.path,
                    .h3 = .{
                        .handshake = .{
                            .original_destination_connection_id = self.original_dcid,
                            .local_connection_id = self.local_cid,
                            .server_name = "localhost",
                            .random = self.random,
                            .x25519_secret_key = self.secret,
                        },
                        .session = .{ .local_settings = self.settings },
                    },
                },
            );
            if (attempt.status() != self.expected_status) {
                attempt.deinit();
                return error.TestUnexpectedResult;
            }
            if (attempt.accepted()) {
                self.client = try attempt.requireAccepted();
                try self.client.?.sendDatagram("accepted");
            } else {
                attempt.deinit();
            }
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-policy-accept",
            .local_cid = "wt-client-accept",
            .path = "/accept",
            .expected_status = 200,
            .settings = settings,
            .random = [_]u8{0xa3} ** 32,
            .secret = [_]u8{0xa4} ** 32,
        },
        .{
            .io = io,
            .address = server.address(),
            .original_dcid = "wt-policy-reject",
            .local_cid = "wt-client-reject",
            .path = "/reject",
            .expected_status = 403,
            .settings = settings,
            .random = [_]u8{0xa5} ** 32,
            .secret = [_]u8{0xa6} ** 32,
        },
    };
    const first_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const second_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        first_thread.join();
        second_thread.join();
        for (&clients) |*client| if (client.client) |*value| value.deinit();
    };

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var handles: [2]quic.endpoint_dispatcher.ConnectionHandle = undefined;
    var request_count: usize = 0;
    var received_datagram = false;
    var stream_buffer: [64]u8 = undefined;
    while (request_count < clients.len or !received_datagram) {
        var event = try endpoint.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
            &stream_buffer,
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.TestUnexpectedResult,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.TestUnexpectedResult;
                handles[request_count] = handle;
                request_count += 1;
                if (std.mem.eql(u8, pending.path(), "/accept")) {
                    _ = try endpoint.accept(handle);
                } else if (std.mem.eql(u8, pending.path(), "/reject")) {
                    try endpoint.reject(handle, 403, &.{});
                } else return error.TestUnexpectedResult;
            },
            .session_event => |value| switch (value.event) {
                .datagram => |datagram| {
                    try std.testing.expectEqualStrings(
                        "accepted",
                        datagram.datagram.payload,
                    );
                    received_datagram = true;
                },
                .stream, .session => return error.TestUnexpectedResult,
            },
            .unrouted => return error.TestUnexpectedResult,
        }
    }

    first_thread.join();
    second_thread.join();
    joined = true;
    for (&clients) |*client| {
        if (client.err) |err| return err;
        if (client.client) |*value| value.deinit();
        client.client = null;
    }
    try std.testing.expectEqual(@as(usize, 1), endpoint.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.rejectedSessionCount());
    for (handles) |handle| {
        try std.testing.expect(endpoint.removeConnection(handle));
    }
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint.rejectedSessionCount());
}
