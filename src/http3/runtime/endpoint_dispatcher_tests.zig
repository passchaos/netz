const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const FixedClockIo = @import("../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");

test "HTTP/3 client handshakes through one endpoint socket owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits = runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "h3-source-server",
            .random = [_]u8{0xc1} ** 32,
            .x25519_secret_key = [_]u8{0xc2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{"h3-source-client"},
        server.address(),
        64,
    );
    defer inbox.deinit();

    const ServerTask = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequestWithTimeout(
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(allocator);
            if (!std.mem.eql(u8, request.request.path, "/source")) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "source-response",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    const ClientTask = struct {
        endpoint: *quic.runtime.Endpoint,
        inbox: *quic.handshake_inbox.Inbox,
        server: std.Io.net.IpAddress,
        done: std.atomic.Value(bool) = .init(false),
        client: ?runtime.HandshakeClient = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.client = runtime.HandshakeClient.connectFrom(
                self.endpoint,
                self.inbox.datagramSource(),
                self.server,
                .{
                    .handshake = .{
                        .original_destination_connection_id = "h3-source-dispatch",
                        .local_connection_id = "h3-source-client",
                        .server_name = "localhost",
                        .random = [_]u8{0xc3} ** 32,
                        .x25519_secret_key = [_]u8{0xc4} ** 32,
                        .handshake_recovery = .{
                            .initial_pto_ms = 20,
                            .max_pto_ms = 40,
                            .max_duration_ms = 2_000,
                        },
                    },
                    .session = .{ .max_stream_frame_data = 1024 },
                },
            ) catch |err| {
                self.err = err;
                self.done.store(true, .release);
                return;
            };
            self.done.store(true, .release);
        }
    };

    var server_task = ServerTask{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerTask.run,
        .{&server_task},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var client_task = ClientTask{
        .endpoint = &client_endpoint,
        .inbox = &inbox,
        .server = server.address(),
    };
    const client_thread = try std.Thread.spawn(
        .{},
        ClientTask.run,
        .{&client_task},
    );

    var owner_err: ?anyerror = null;
    owner: while (!client_task.done.load(.acquire)) {
        var datagram = client_endpoint.receiveBytesTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(20),
            },
        }) catch |err| switch (err) {
            error.Timeout => continue,
            else => {
                owner_err = err;
                break :owner;
            },
        };
        inbox.push(datagram) catch |err| {
            switch (err) {
                // An already-complete handshake can leave retransmitted
                // long-header packets queued until this owner observes the
                // worker's completion flag. The dispatcher drops overflow in
                // this state too; QUIC recovery covers any packet still needed.
                // A datagram whose destination CID is no longer the handshake
                // CID is equally stale and is dropped by the production
                // dispatcher as well.
                error.Full, error.ConnectionIdMismatch => datagram.deinit(allocator),
                else => {
                    datagram.deinit(allocator);
                    owner_err = err;
                    break :owner;
                },
            }
        };
    }
    if (!client_task.done.load(.acquire)) inbox.close();
    client_thread.join();
    if (owner_err) |err| {
        if (client_task.client) |*client| client.deinit();
        return err;
    }
    if (client_task.err) |err| {
        if (client_task.client) |*client| client.deinit();
        return err;
    }
    var client = client_task.client orelse return error.TestUnexpectedResult;
    defer client.deinit();
    try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &client.established.connection);
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/source",
        .authority = "localhost",
    });
    var status: ?u16 = null;
    var body: ["source-response".len]u8 = undefined;
    var body_len: usize = 0;
    var finished = false;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!finished) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try std.testing.expectEqual(@as(usize, 1), routed.connection_handle);
                try client.processResponsePacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
                while (!finished) {
                    const value = (try client.pollResponseEvent(
                        stream_id,
                    )) orelse break;
                    var response = value;
                    defer response.deinit(allocator);
                    switch (response) {
                        .head => |head| switch (head) {
                            .response => |final| status = final.status,
                            .request => return error.TestUnexpectedResult,
                        },
                        .data_available => {
                            body_len += try client.readResponseData(
                                stream_id,
                                body[body_len..],
                            );
                        },
                        .finished => finished = true,
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(@as(?u16, 200), status);
    try std.testing.expectEqualStrings("source-response", body[0..body_len]);
    try std.testing.expect(try dispatcher.unregisterConnection(1));
    server_thread.join();
    server_joined = true;
    if (server_task.err) |err| return err;
}

test "HTTP/3 source-driven client handshake has a total timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{"h3-timeout-client"},
        silent.address(),
        1,
    );
    defer inbox.deinit();

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectFromWithTimeout(
            &endpoint,
            inbox.datagramSource(),
            silent.address(),
            .{ .handshake = .{
                .original_destination_connection_id = "h3-timeout-origin",
                .local_connection_id = "h3-timeout-client",
                .handshake_recovery = .{
                    .initial_pto_ms = 1_000,
                    .max_pto_ms = 4_000,
                    .max_retries = 3,
                },
            } },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectFromWithTimeout(
            &endpoint,
            inbox.datagramSource(),
            silent.address(),
            .{ .handshake = .{
                .original_destination_connection_id = "h3-timeout-origin",
                .local_connection_id = "h3-timeout-client",
            } },
            .zero,
        ),
    );
}

test "HTTP/3 sessions consume dispatcher packets without socket races" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "h3-client-a";
    const client_b_cid = "h3-client-b";
    const server_a_cid = "h3-server-a";
    const server_b_cid = "h3-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa1} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb1} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb2} ** quic.protection.secret_len,
    );
    const limits = runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    const session_options = runtime.HandshakeSessionOptions{
        .max_stream_frame_data = 1024,
    };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_endpoint.deinit();
    var client_a = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        limits,
        session_options,
        .{
            .receive_keys = server_a_keys,
            .send_keys = client_a_keys,
            .local_connection_id = client_a_cid,
            .peer_connection_id = server_a_cid,
        },
    );
    defer client_a.deinit();
    var client_b = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        limits,
        session_options,
        .{
            .receive_keys = server_b_keys,
            .send_keys = client_b_keys,
            .local_connection_id = client_b_cid,
            .peer_connection_id = server_b_cid,
        },
    );
    defer client_b.deinit();
    var server_a = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_a.address(),
        session_options,
        .{
            .receive_keys = client_a_keys,
            .send_keys = server_a_keys,
            .local_connection_id = server_a_cid,
            .peer_connection_id = client_a_cid,
        },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client_b.address(),
        session_options,
        .{
            .receive_keys = client_b_keys,
            .send_keys = server_b_keys,
            .local_connection_id = server_b_cid,
            .peer_connection_id = client_b_cid,
        },
    );
    defer server_b.deinit();

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &server_a.established.connection);
    try dispatcher.registerConnection(2, &server_b.established.connection);

    try std.testing.expectEqual(@as(?runtime.StreamingRequestEvent, null), try server_a.pollRequestEvent());
    try std.testing.expectEqual(@as(?runtime.StreamingRequestEvent, null), try server_b.pollRequestEvent());
    _ = try client_b.sendRequest(.{
        .method = "POST",
        .path = "/dispatcher-b",
        .authority = "localhost",
        .body = "body-b",
    });
    _ = try client_a.sendRequest(.{
        .method = "POST",
        .path = "/dispatcher-a",
        .authority = "localhost",
        .body = "body-a",
    });

    var seen_a = false;
    var seen_b = false;
    var body_a: [6]u8 = undefined;
    var body_b: [6]u8 = undefined;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!seen_a or !seen_b) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const session = switch (routed.connection_handle) {
                    1 => &server_a,
                    2 => &server_b,
                    else => return error.TestUnexpectedResult,
                };
                try session.processRequestPacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                while (try session.pollRequestEvent()) |request_value| {
                    var request = request_value;
                    defer request.deinit(allocator);
                    if (request != .message) {
                        return error.TestUnexpectedResult;
                    }
                    switch (request.message.value) {
                        .head => |head| {
                            switch (routed.connection_handle) {
                                1 => try std.testing.expectEqualStrings(
                                    "/dispatcher-a",
                                    head.request.path,
                                ),
                                2 => try std.testing.expectEqualStrings(
                                    "/dispatcher-b",
                                    head.request.path,
                                ),
                                else => unreachable,
                            }
                        },
                        .data_available => {
                            const target = if (routed.connection_handle == 1)
                                &body_a
                            else
                                &body_b;
                            const read = try session.readRequestData(
                                request.message.stream_id,
                                target,
                            );
                            try std.testing.expectEqual(target.len, read);
                            if (routed.connection_handle == 1) {
                                try std.testing.expectEqualStrings(
                                    "body-a",
                                    &body_a,
                                );
                                seen_a = true;
                            } else {
                                try std.testing.expectEqualStrings(
                                    "body-b",
                                    &body_b,
                                );
                                seen_b = true;
                            }
                        },
                        .finished => {},
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(server_a.control.settings.received);
    try std.testing.expect(server_b.control.settings.received);
}

test "HTTP/3 clients poll dispatcher-routed responses without socket races" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_a_cid = "h3-response-client-a";
    const client_b_cid = "h3-response-client-b";
    const server_a_cid = "h3-response-server-a";
    const server_b_cid = "h3-response-server-b";
    const client_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    const client_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    const server_a_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
    );
    const server_b_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );
    const limits = runtime.Limits{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    const options = runtime.HandshakeSessionOptions{
        .max_stream_frame_data = 1024,
    };

    var server_a_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_a_endpoint.deinit();
    var server_b_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer server_b_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits.quic,
    );
    defer client_endpoint.deinit();

    var client_a = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_a_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_a_endpoint.address(),
            .client,
            .{
                .receive_keys = server_a_keys,
                .send_keys = client_a_keys,
                .local_connection_id = client_a_cid,
                .peer_connection_id = server_a_cid,
            },
        ),
        options,
    );
    defer client_a.deinit();
    var client_b = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_b_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_b_endpoint.address(),
            .client,
            .{
                .receive_keys = server_b_keys,
                .send_keys = client_b_keys,
                .local_connection_id = client_b_cid,
                .peer_connection_id = server_b_cid,
            },
        ),
        options,
    );
    defer client_b.deinit();

    const stream_a = try client_a.sendRequest(.{
        .method = "GET",
        .path = "/response-a",
        .authority = "localhost",
    });
    const stream_b = try client_b.sendRequest(.{
        .method = "GET",
        .path = "/response-b",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), stream_a);
    try std.testing.expectEqual(@as(u62, 0), stream_b);

    var server_a = try quic.one_rtt.Connection.init(&server_a_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_a_keys,
        .send_keys = server_a_keys,
        .local_connection_id = server_a_cid,
        .peer_connection_id = client_a_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_a.deinit();
    var server_b = try quic.one_rtt.Connection.init(&server_b_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_b_keys,
        .send_keys = server_b_keys,
        .local_connection_id = server_b_cid,
        .peer_connection_id = client_b_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_b.deinit();

    var response_a: std.ArrayList(u8) = .empty;
    defer response_a.deinit(allocator);
    try (http3.Response{ .status = 200, .body = "response-a" }).write(
        &response_a,
        allocator,
    );
    var response_b: std.ArrayList(u8) = .empty;
    defer response_b.deinit(allocator);
    try (http3.Response{ .status = 201, .body = "response-b" }).write(
        &response_b,
        allocator,
    );
    const frames_a = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_a,
        .data = response_a.items,
        .fin = true,
    } }};
    const frames_b = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_b,
        .data = response_b.items,
        .fin = true,
    } }};
    try server_b.send(&frames_b);
    try server_a.send(&frames_a);

    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &client_endpoint,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &client_a.established.connection);
    try dispatcher.registerConnection(2, &client_b.established.connection);

    try std.testing.expect((try client_a.pollNextResponseEvent()) == null);
    try std.testing.expect((try client_b.pollNextResponseEvent()) == null);

    var saw_a = false;
    var saw_b = false;
    var body_a: [10]u8 = undefined;
    var body_b: [10]u8 = undefined;
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    while (!saw_a or !saw_b) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                const client = switch (routed.connection_handle) {
                    1 => &client_a,
                    2 => &client_b,
                    else => return error.TestUnexpectedResult,
                };
                try client.processResponsePacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(
                    routed.connection_handle,
                );
                while (try client.pollNextResponseEvent()) |response_value| {
                    var response = response_value;
                    defer response.deinit(allocator);
                    if (response != .message) {
                        return error.TestUnexpectedResult;
                    }
                    switch (response.message.value) {
                        .head => |head| {
                            if (head != .response) {
                                return error.TestUnexpectedResult;
                            }
                            const expected: u16 =
                                if (routed.connection_handle == 1) 200 else 201;
                            try std.testing.expectEqual(
                                expected,
                                head.response.status,
                            );
                        },
                        .data_available => {
                            const target = if (routed.connection_handle == 1)
                                &body_a
                            else
                                &body_b;
                            const count = try client.readResponseData(
                                response.message.stream_id,
                                target,
                            );
                            const expected = if (routed.connection_handle == 1)
                                "response-a"
                            else
                                "response-b";
                            try std.testing.expectEqualStrings(
                                expected,
                                target[0..count],
                            );
                            if (routed.connection_handle == 1)
                                saw_a = true
                            else
                                saw_b = true;
                        },
                        .finished => {},
                        .push_promise, .trailers => return error.TestUnexpectedResult,
                    }
                }
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }

    // Control traffic remains meaningful after the last response stream has
    // finished. A dispatcher must be able to inject GOAWAY without inventing
    // a dummy outstanding request or falling back to a competing socket read.
    var goaway_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    var server_control = http3.ControlState{};
    const goaway = try server_control.writeGoAwayInto(&goaway_storage, 4);
    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try quic.varint.encode(
        &control_bytes,
        allocator,
        @intFromEnum(http3.StreamType.control),
    );
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});
    try control_bytes.appendSlice(allocator, goaway);
    const goaway_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 3,
        .data = control_bytes.items,
    } }};
    try server_a.send(&goaway_frames);
    while (client_a.peerGoAwayId() == null) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                try std.testing.expectEqual(
                    @as(usize, 1),
                    routed.connection_handle,
                );
                try client_a.processResponsePacket(&routed.packet);
                try dispatcher.refreshConnectionTimer(1);
            },
            .consumed, .timer => {},
            .pending_handshake, .discarded_long_header, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(@as(?u64, 4), client_a.peerGoAwayId());
}

test "HTTP/3 borrowed response packet preserves any-response FIN across pacing" {
    try native_protocol_io.run(borrowedResponsePacketPreservesAnyResponseFinAcrossPacing);
}

fn borrowedResponsePacketPreservesAnyResponseFinAcrossPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const client_cid = "h3-once-client";
    const server_cid = "h3-once-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc6} ** quic.protection.secret_len,
    );
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 512;
    client_transport.initial_max_stream_data_bidi_local = 512;
    const one_rtt = quic.handshake.OneRttConfig{
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
        .receive_window = 512,
        .stream_receive_window = 512,
    };
    var client = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = client_transport,
                .one_rtt = one_rtt,
            },
        ),
        .{},
    );
    defer client.deinit();
    client.established.connection.configureAckPolicy(
        2,
        25_000,
        quic.packet_space.default_packet_threshold,
    );
    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/once",
        .authority = "localhost",
    });
    var padding: [470]u8 = undefined;
    @memset(&padding, 'x');
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{ .status = 204 }).write(
        &response_bytes,
        allocator,
    );
    try (http3.Frame{
        .frame_type = 0x21,
        .payload = &padding,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    try std.testing.expect(response_bytes.items.len > 256);
    try std.testing.expect(response_bytes.items.len <= 512);
    try server.send(&.{.{ .stream = .{
        .stream_id = stream_id,
        .data = response_bytes.items,
        .fin = true,
    } }});
    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = client_endpoint.io,
        .now_ns = .init(1_000_000),
    };
    defer fixed_io.backend.deinit();
    client_endpoint.io = fixed_io.io();
    defer client_endpoint.io = fixed_io.baseIo();

    {
        var packet = try client.established.connection.receivePacket();
        defer packet.deinit(allocator);
        try client.processResponsePacketView(.{
            .from = packet.from,
            .packet_number = packet.packet.packet_number,
            .frames = packet.frames,
            .peer_initiated_key_update = packet.peer_initiated_key_update,
        });
        @memset(packet.packet.payload, 0xaa);
    }
    try std.testing.expect(
        client.established.connection.ackDelayDeadline() != null,
    );
    var head = (try client.pollNextResponseEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expect(head.message.value == .head);
    try std.testing.expectEqual(@as(u16, 204), head.message.value.head.response.status);

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const packet_number = client.established.connection.next_packet_number;
    // Response routing copied and committed the complete stream before this
    // reader was activated. The terminal poll therefore owes only the delayed
    // ACK, which is neither in flight nor paced by QUIC. Publish FIN without
    // waiting for the synthetic data-pacing epoch.
    var finished = (try client.pollNextResponseEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .message);
    try std.testing.expectEqual(stream_id, finished.message.stream_id);
    try std.testing.expect(finished.message.value == .finished);
    try std.testing.expectEqual(@as(usize, 0), client.streaming_responses.entryCount());
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(
        client.established.connection.ackDelayDeadline() == null,
    );
    try std.testing.expectEqual(
        packet_number + 1,
        client.established.connection.next_packet_number,
    );
    try std.testing.expect(
        quic.one_rtt.testing.pacingBlockedUntil(
            &client.established.connection,
        ) == null,
    );
    try std.testing.expect((try client.pollNextResponseEventOnce()) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 push once poll preserves FIN across pacing" {
    try native_protocol_io.run(pushOncePollPreservesFinAcrossPacing);
}

fn pushOncePollPreservesFinAcrossPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const client_cid = "h3-push-once-client";
    const server_cid = "h3-push-once-server";
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd6} ** quic.protection.secret_len,
    );
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 512;
    client_transport.initial_max_stream_data_uni = 512;
    const one_rtt = quic.handshake.OneRttConfig{
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
        .receive_window = 512,
        .stream_receive_window = 512,
    };
    var client = try runtime.HandshakeClient.initEstablished(
        &client_endpoint,
        server_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &client_endpoint,
            server_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = client_cid,
                .peer_connection_id = server_cid,
                .local_transport_parameters = client_transport,
                .one_rtt = one_rtt,
            },
        ),
        .{},
    );
    defer client.deinit();
    client.established.connection.configureAckPolicy(
        2,
        25_000,
        quic.packet_space.default_packet_threshold,
    );
    var server = try quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/push-parent",
        .authority = "localhost",
    });
    client.control.local_max_push_id = 1;
    try client.push_streams.reservePromisesThrough(1);
    try client.push_streams.registerPromise(1, request_stream_id);

    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 1);
    try (http3.Response{ .status = 200 }).write(&push_bytes, allocator);
    var padding: [460]u8 = undefined;
    @memset(&padding, 'p');
    try (http3.Frame{
        .frame_type = 0x21,
        .payload = &padding,
        .consumed = 0,
    }).write(&push_bytes, allocator);
    try std.testing.expect(push_bytes.items.len > 256);
    try std.testing.expect(push_bytes.items.len <= 512);
    const push_stream_id: u62 = 3;
    try server.send(&.{.{ .stream = .{
        .stream_id = push_stream_id,
        .data = push_bytes.items,
        .fin = true,
    } }});
    var packet = try client.established.connection.receivePacket();
    defer packet.deinit(allocator);

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = client_endpoint.io,
        .now_ns = .init(2_000_000),
    };
    defer fixed_io.backend.deinit();
    client_endpoint.io = fixed_io.io();
    defer client_endpoint.io = fixed_io.baseIo();

    try client.processResponsePacket(&packet);
    try std.testing.expect(
        client.established.connection.ackDelayDeadline() != null,
    );
    var head = (try client.pollPushEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head.value == .head);
    try std.testing.expectEqual(@as(u64, 1), head.push_id);
    try std.testing.expectEqual(request_stream_id, head.request_stream_id);
    try std.testing.expectEqual(push_stream_id, head.stream_id);

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const packet_number = client.established.connection.next_packet_number;
    try std.testing.expect((try client.pollPushEventOnce()) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.entryCount());
    try std.testing.expect(client.push_streams.readerForStream(
        push_stream_id,
    ).?.finished());

    const timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pacing, timer.kind);
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;

    var finished = (try client.pollPushEventOnce()) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), finished.push_id);
    try std.testing.expectEqual(push_stream_id, finished.stream_id);
    try std.testing.expect(finished.value == .finished);
    try std.testing.expectEqual(@as(usize, 0), client.push_streams.entryCount());
    try std.testing.expect(
        client.established.connection.ackDelayDeadline() == null,
    );
    try std.testing.expect((try client.pollPushEventOnce()) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 request once send preserves its stream across pacing" {
    try native_protocol_io.run(requestOnceSendPreservesItsStreamAcrossPacing);
}

fn requestOnceSendPreservesItsStreamAcrossPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "once-send-client",
                .peer_connection_id = "once-send-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(3_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    try client.ensureSettingsSentOnce();
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(error.PacingLimited, client.trySendRequest(.{
        .method = "GET",
        .path = "/retry",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));

    const timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pacing, timer.kind);
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), try client.trySendRequest(.{
        .method = "GET",
        .path = "/retry",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 1),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
}

comptime {
    _ = @import("endpoint_dispatcher/control_retry_tests.zig");
}

test "HTTP/3 dispatcher shutdown retries GOAWAY transactionally" {
    try native_protocol_io.run(dispatcherShutdownRetriesGoawayTransactionally);
}

fn dispatcherShutdownRetriesGoawayTransactionally(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    const client_cid = "shutdown-client";
    const server_cid = "shutdown-server";
    const transport_options: quic.handshake.PreconfiguredConnectionOptions = .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
        .one_rtt = .{
            .max_datagram_size = 1200,
            .pacing_max_burst_packets = 1,
        },
    };
    var client = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{},
        transport_options,
    );
    defer client.deinit();
    var server = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer server.deinit();

    // Admission sends all critical stream prefixes before transferring sole
    // socket ownership to the endpoint dispatcher.
    try server.ensureSettingsSent();
    try server.bindDispatcher();

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = server_endpoint.io,
        .now_ns = .init(6_000_000),
    };
    defer fixed_io.backend.deinit();
    server_endpoint.io = fixed_io.io();
    defer server_endpoint.io = fixed_io.baseIo();

    const maximum_goaway_id =
        @as(u64, quic.varint.max_value) & ~@as(u64, 0x3);
    quic.one_rtt.testing.exhaustPacingAt(
        &server.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const initial_offset = server.control_send.next_offset;
    const initial_packet_number =
        server.established.connection.next_packet_number;
    const sends_before_initial = fixed_io.send_calls.load(.acquire);
    try std.testing.expectError(
        error.PacingLimited,
        server.tryInitiateShutdown(),
    );
    try std.testing.expectEqual(
        .active,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(@as(?u64, null), server.control.local_goaway_id);
    try std.testing.expectEqual(initial_offset, server.control_send.next_offset);
    try std.testing.expectEqual(
        initial_packet_number,
        server.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(sends_before_initial, fixed_io.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));

    var timer = server.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pacing, timer.kind);
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try server.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try server.tryInitiateShutdown();
    try std.testing.expectEqual(
        .initial_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(
        @as(?u64, maximum_goaway_id),
        server.control.local_goaway_id,
    );

    while (client.peerGoAwayId() != maximum_goaway_id) {
        try client.pollControlWithTimeout(.fromSeconds(1));
    }

    // A second one-attempt call is independently retryable. The failed final
    // GOAWAY must preserve the already-visible maximum ID and lifecycle.
    quic.one_rtt.testing.exhaustPacingAt(
        &server.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const final_offset = server.control_send.next_offset;
    const final_packet_number = server.established.connection.next_packet_number;
    const sends_before_final = fixed_io.send_calls.load(.acquire);
    try std.testing.expectError(
        error.PacingLimited,
        server.tryCompleteShutdown(),
    );
    try std.testing.expectEqual(
        .initial_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(
        @as(?u64, maximum_goaway_id),
        server.control.local_goaway_id,
    );
    try std.testing.expectEqual(final_offset, server.control_send.next_offset);
    try std.testing.expectEqual(
        final_packet_number,
        server.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(sends_before_final, fixed_io.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));

    timer = server.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pacing, timer.kind);
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try server.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try server.tryCompleteShutdown();
    try std.testing.expectEqual(
        .final_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(@as(?u64, 0), server.control.local_goaway_id);

    while (client.peerGoAwayId() != 0) {
        try client.pollControlWithTimeout(.fromSeconds(1));
    }
    try std.testing.expectEqual(@as(?u64, 0), client.peerGoAwayId());
    try std.testing.expect(server.drainComplete());
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 dispatcher server ORIGIN retries transactionally" {
    try native_protocol_io.run(dispatcherServerOriginRetriesTransactionally);
}

fn dispatcherServerOriginRetriesTransactionally(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    const client_cid = "origin-client";
    const server_cid = "origin-server";
    var client = try runtime.HandshakeClient.initPreconfigured(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = client_cid,
            .peer_connection_id = server_cid,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer client.deinit();
    var server = try runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        client.address(),
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .one_rtt = .{
                .max_datagram_size = 1200,
                .pacing_max_burst_packets = 1,
            },
        },
    );
    defer server.deinit();

    try server.ensureSettingsSent();
    try server.bindDispatcher();

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = server_endpoint.io,
        .now_ns = .init(11_000_000),
    };
    defer fixed_io.backend.deinit();
    server_endpoint.io = fixed_io.io();
    defer server_endpoint.io = fixed_io.baseIo();

    const origins = [_][]const u8{
        "https://example.test",
        "https://api.example.test:8443",
    };
    quic.one_rtt.testing.exhaustPacingAt(
        &server.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const packet_number = server.established.connection.next_packet_number;
    const control_offset = runtime.testing.serverControlSendOffset(&server);
    try std.testing.expectError(
        error.PacingLimited,
        server.trySendOrigins(&origins),
    );
    try std.testing.expect(!runtime.testing.serverHasSentOriginSet(&server));
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.serverControlSendOffset(&server),
    );
    try std.testing.expectEqual(
        packet_number,
        server.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));

    const timer = server.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try server.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try server.trySendOrigins(&origins);
    try std.testing.expect(runtime.testing.serverHasSentOriginSet(&server));

    while (!client.peerOriginSetInitialized()) {
        try client.pollControlWithTimeout(.fromSeconds(1));
    }
    try std.testing.expectEqual(@as(usize, 2), client.peerOrigins().len);
    try std.testing.expect(client.peerOriginKnown(
        try http3.originFromSerialized(origins[0]),
    ));
    try std.testing.expect(client.peerOriginKnown(
        try http3.originFromSerialized(origins[1]),
    ));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 tryStartRequest stream limit is transactional and nonblocking" {
    try native_protocol_io.run(trystartrequestStreamLimitIsTransactionalAndNonblocking);
}

fn trystartrequestStreamLimitIsTransactionalAndNonblocking(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var peer_transport = quic.practical_transport_parameters;
    peer_transport.initial_max_streams_bidi = 0;
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "stream-limit-client",
                .peer_connection_id = "stream-limit-server",
                .peer_transport_parameters = peer_transport,
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();

    try client.ensureSettingsSentOnce();
    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(5_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const packet_number = client.established.connection.next_packet_number;
    try std.testing.expectError(error.PacingLimited, client.tryStartRequest(.{
        .method = "POST",
        .path = "/stream-limit",
        .authority = "localhost",
    }, 1));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientPendingQpackSectionCount(&client),
    );
    try std.testing.expect(client.outbound_bodies.find(0) == null);

    try quic.one_rtt.testing.applyReceivedFrames(
        &client.established.connection,
        0,
        &.{.{ .max_streams_bidi = .{ .maximum_streams = 1 } }},
        @intCast(fixed_io.now_ns.load(.acquire)),
        .not_ect,
    );
    const request_options: http3.Request = .{
        .method = "POST",
        .path = "/stream-limit",
        .authority = "localhost",
    };
    while (true) {
        const stream_id = client.tryStartRequest(
            request_options,
            1,
        ) catch |err| switch (err) {
            error.PacingLimited => {
                const timer = client.established.connection
                    .nextTimerDeadline() orelse
                    return error.TestUnexpectedResult;
                try std.testing.expectEqual(
                    quic.one_rtt.TimerDeadlineKind.pacing,
                    timer.kind,
                );
                fixed_io.setNow(@intCast(timer.deadline_ns));
                _ = (try client.established.connection.serviceNextTimerAt(
                    timer.deadline_ns,
                )) orelse return error.TestUnexpectedResult;
                continue;
            },
            else => return err,
        };
        try std.testing.expectEqual(@as(u62, 0), stream_id);
        break;
    }
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 1),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expect(client.outbound_bodies.find(0) != null);
}

test "HTTP/3 dispatcher-bound abandon never waits for pacing" {
    try native_protocol_io.run(dispatcherBoundAbandonNeverWaitsForPacing);
}

fn dispatcherBoundAbandonNeverWaitsForPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "once-abandon-client",
                .peer_connection_id = "once-abandon-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(5_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/abandon",
        .authority = "localhost",
        .headers = &.{.{
            .name = ":protocol",
            .value = "webtransport",
        }},
    }, null);
    try std.testing.expectEqual(@as(u62, 0), stream_id);
    try client.bindDispatcher();
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );

    client.abandonExtendedConnect(stream_id);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expect(!client.isReusable());
}

test "HTTP/3 request body parts remain transactional across pacing" {
    try native_protocol_io.run(requestBodyPartsRemainTransactionalAcrossPacing);
}

fn requestBodyPartsRemainTransactionalAcrossPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "parts-client",
                .peer_connection_id = "parts-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(7_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/parts",
        .authority = "localhost",
    }, 6);
    const before = client.outbound_bodies.find(stream_id).?.*;
    const sends_before_blocked = fixed_io.send_calls.load(.acquire);
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendRequestBodyParts(
            stream_id,
            &.{ "one", &.{}, "two" },
            true,
        ),
    );
    const after = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expectEqual(before.written, after.written);
    try std.testing.expectEqual(before.send.next_offset, after.send.next_offset);
    try std.testing.expectEqual(before.send.fin_sent, after.send.fin_sent);
    try std.testing.expectEqual(sends_before_blocked, fixed_io.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));

    const timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(quic.one_rtt.TimerDeadlineKind.pacing, timer.kind);
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    const sends_before_retry = fixed_io.send_calls.load(.acquire);
    try client.trySendRequestBodyParts(
        stream_id,
        &.{ "one", &.{}, "two" },
        true,
    );
    try std.testing.expectEqual(
        sends_before_retry + 1,
        fixed_io.send_calls.load(.acquire),
    );
    try std.testing.expect(client.outbound_bodies.find(stream_id) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 request body batch preserves every stream across pacing" {
    try native_protocol_io.run(requestBodyBatchPreservesEveryStreamAcrossPacing);
}

fn requestBodyBatchPreservesEveryStreamAcrossPacing(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "batch-client",
                .peer_connection_id = "batch-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 2,
                },
            },
        ),
        .{},
    );
    defer client.deinit();
    const first = try client.startRequest(.{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
    }, 3);
    const second = try client.startRequest(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
    }, 3);

    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(8_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();
    const first_before = client.outbound_bodies.find(first).?.*;
    const second_before = client.outbound_bodies.find(second).?.*;
    const sends_before = fixed_io.send_calls.load(.acquire);
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    const chunks = [_]runtime.BodyChunk{
        .{ .stream_id = first, .data = "one", .fin = true },
        .{ .stream_id = second, .data = "two", .fin = true },
    };
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendRequestBodyBatch(&chunks),
    );
    const first_after = client.outbound_bodies.find(first).?.*;
    const second_after = client.outbound_bodies.find(second).?.*;
    try std.testing.expectEqual(first_before.written, first_after.written);
    try std.testing.expectEqual(
        first_before.send.next_offset,
        first_after.send.next_offset,
    );
    try std.testing.expectEqual(second_before.written, second_after.written);
    try std.testing.expectEqual(
        second_before.send.next_offset,
        second_after.send.next_offset,
    );
    try std.testing.expectEqual(sends_before, fixed_io.send_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}

test "HTTP/3 flow-blocked request retry retains response semantics" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf6} ** quic.protection.secret_len,
    );
    var peer_transport = quic.practical_transport_parameters;
    peer_transport.initial_max_stream_data_bidi_remote = 0;
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "flow-retry-client",
                .peer_connection_id = "flow-retry-server",
                .peer_transport_parameters = peer_transport,
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .enable_pacing = false,
                },
            },
        ),
        .{},
    );
    defer client.deinit();

    try client.ensureSettingsSentOnce();
    try std.testing.expectError(error.FlowControlBlocked, client.trySendRequest(.{
        .method = "GET",
        .path = "/flow-retry",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 1),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        client.established.connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        client.established.connection.sendStreamStats(0).?.highest_sent_offset,
    );
    try std.testing.expectError(error.UnexpectedStream, client.trySendRequest(.{
        .method = "POST",
        .path = "/flow-retry",
        .authority = "localhost",
    }));

    try quic.one_rtt.testing.applyReceivedFrames(
        &client.established.connection,
        0,
        &.{.{ .max_stream_data = .{
            .stream_id = 0,
            .maximum_stream_data = 1024,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(@as(u62, 0), try client.trySendRequest(.{
        .method = "GET",
        .path = "/flow-retry",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(@as(u62, 4), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 1),
        runtime.testing.clientRequestCount(&client),
    );
}

test "HTTP/3 streaming request once sends retry every stage" {
    try native_protocol_io.run(streamingRequestOnceSendsRetryEveryStage);
}

fn streamingRequestOnceSendsRetryEveryStage(io: std.Io) !void {
    const allocator = std.testing.allocator;

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "stream-once-client",
                .peer_connection_id = "stream-once-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();
    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(4_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    try client.ensureSettingsSentOnce();
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    try std.testing.expectError(error.PacingLimited, client.tryStartRequest(.{
        .method = "POST",
        .path = "/stream",
        .authority = "localhost",
    }, 1));
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientRequestCount(&client),
    );
    try std.testing.expect(client.outbound_bodies.find(0) == null);

    var timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    const stream_id = try client.tryStartRequest(.{
        .method = "POST",
        .path = "/stream",
        .authority = "localhost",
    }, 1);
    try std.testing.expectEqual(@as(u62, 0), stream_id);
    try std.testing.expect(client.outbound_bodies.find(stream_id) != null);

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendRequestBody(stream_id, "x", false),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.find(stream_id).?.written,
    );
    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.trySendRequestBody(stream_id, "x", false);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.outbound_bodies.find(stream_id).?.written,
    );

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    try std.testing.expectError(
        error.PacingLimited,
        client.tryFinishRequestTrailers(stream_id, &.{.{
            .name = "x-upload",
            .value = "complete",
        }}),
    );
    try std.testing.expect(client.outbound_bodies.find(stream_id) != null);
    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.tryFinishRequestTrailers(stream_id, &.{.{
        .name = "x-upload",
        .value = "complete",
    }});
    try std.testing.expect(client.outbound_bodies.find(stream_id) == null);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}
