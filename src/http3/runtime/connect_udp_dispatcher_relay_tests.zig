const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "HTTP/3 dispatcher relay fairly serves two CONNECT-UDP sessions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const settings = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = "relay-endpoint-server",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
            .session = .{
                .local_settings = settings,
                .max_stream_buffer = 64 * 1024,
            },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    defer endpoint.deinit();
    var relays = try runtime.ConnectUdpDispatcherRelay.init(
        allocator,
        io,
        &endpoint,
        .{
            .max_relays = 2,
            .max_queued_target_datagrams = 4,
            .max_queued_target_bytes = 4096,
            .per_relay_turn_budget = 1,
        },
    );
    defer relays.deinit();

    var echo_one = try net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer echo_one.close(io);
    var echo_two = try net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer echo_two.close(io);

    const Echo = struct {
        socket: *net.Socket,
        io: std.Io,
        first: []const u8,
        second: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = if (err == error.Timeout)
                    error.EchoTimeout
                else
                    err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var storage: [128]u8 = undefined;
            var saw_first = false;
            var saw_second = false;
            for (0..2) |_| {
                const message = try self.socket.receiveTimeout(
                    self.io,
                    &storage,
                    .{ .duration = .{
                        .raw = .fromSeconds(5),
                        .clock = .awake,
                    } },
                );
                if (std.mem.eql(u8, message.data, self.first)) {
                    if (saw_first) return error.DuplicatePayload;
                    saw_first = true;
                } else if (std.mem.eql(u8, message.data, self.second)) {
                    if (saw_second) return error.DuplicatePayload;
                    saw_second = true;
                } else {
                    return error.UnexpectedPayload;
                }
                try self.socket.send(self.io, &message.from, message.data);
            }
            try std.testing.expect(saw_first);
            try std.testing.expect(saw_second);
        }
    };
    var echoes = [_]Echo{
        .{
            .socket = &echo_one,
            .io = io,
            .first = "one-a",
            .second = "one-b",
        },
        .{
            .socket = &echo_two,
            .io = io,
            .first = "two-a",
            .second = "two-b",
        },
    };
    const echo_thread_one = try std.Thread.spawn(.{}, Echo.run, .{&echoes[0]});
    const echo_thread_two = try std.Thread.spawn(.{}, Echo.run, .{&echoes[1]});
    var echoes_joined = false;
    defer if (!echoes_joined) {
        echo_thread_one.join();
        echo_thread_two.join();
    };

    const Client = struct {
        io: std.Io,
        address: net.IpAddress,
        stage: std.atomic.Value(u8) = .init(0),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = if (err == error.Timeout)
                    error.ClientTimeout
                else
                    err;
            };
        }

        fn accept(
            client: *runtime.HandshakeClient,
            stream_id: u62,
            deadline: std.Io.Clock.Timestamp,
        ) !runtime.ConnectUdpClientSession {
            var response_head: ?http3.DecodedResponseHead = null;
            while (response_head == null) {
                response_head = try client.pollDetachedResponseHead(stream_id);
                if (response_head == null) {
                    try client.established.connection
                        .servicePacketServicingTimersDeadline(deadline);
                }
            }
            var head = response_head.?;
            defer head.deinit(client.allocator);
            return client.acceptConnectUdpResponse(stream_id, head);
        }

        fn expectPair(
            session: *runtime.ConnectUdpClientSession,
            first: []const u8,
            second: []const u8,
            storage: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            var saw_first = false;
            var saw_second = false;
            for (0..2) |_| {
                const response = try session.receiveIntoWithDeadline(
                    storage,
                    deadline,
                );
                if (std.mem.eql(u8, response.payload, first)) {
                    if (saw_first) return error.DuplicatePayload;
                    saw_first = true;
                } else if (std.mem.eql(u8, response.payload, second)) {
                    if (saw_second) return error.DuplicatePayload;
                    saw_second = true;
                } else {
                    return error.UnexpectedPayload;
                }
            }
            try std.testing.expect(saw_first);
            try std.testing.expect(saw_second);
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                limits,
                .{
                    .handshake = .{
                        .original_destination_connection_id = "relay-origin",
                        .local_connection_id = "relay-client",
                        .server_name = "localhost",
                        .random = [_]u8{0x93} ** 32,
                        .x25519_secret_key = [_]u8{0x94} ** 32,
                        .handshake_recovery = .{
                            .initial_pto_ms = 20,
                            .max_pto_ms = 40,
                            .max_duration_ms = 2_000,
                        },
                    },
                    .session = .{
                        .local_settings = settings,
                        .max_stream_buffer = 64 * 1024,
                    },
                },
            );
            defer client.deinit();
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            });
            try client.ensureSettingsSentOnce();
            _ = try client.receivePeerSettingsWithDeadline(deadline);
            self.stage.store(1, .release);
            var path_one: [192]u8 = undefined;
            var path_two: [192]u8 = undefined;
            const stream_one = try client.startConnectUdp(
                .{ .host = "one.example", .port = 1001 },
                "localhost",
                &path_one,
            );
            const stream_two = try client.startConnectUdp(
                .{ .host = "two.example", .port = 1002 },
                "localhost",
                &path_two,
            );
            var one = try accept(&client, stream_one, deadline);
            defer one.deinit();
            var two = try accept(&client, stream_two, deadline);
            defer two.deinit();
            self.stage.store(2, .release);

            var encoded_storage: [5][32]u8 = undefined;
            var one_payloads: [3][]const u8 = undefined;
            one_payloads[0] = try (http3.connect_udp.ContextDatagram{
                .context_id = 2,
                .payload = "ignored",
            }).writeInto(&encoded_storage[0]);
            one_payloads[1] = try (http3.connect_udp.ContextDatagram{
                .context_id = http3.connect_udp.udp_context_id,
                .payload = "one-a",
            }).writeInto(&encoded_storage[1]);
            one_payloads[2] = try (http3.connect_udp.ContextDatagram{
                .context_id = http3.connect_udp.udp_context_id,
                .payload = "one-b",
            }).writeInto(&encoded_storage[2]);
            var two_payloads: [2][]const u8 = undefined;
            two_payloads[0] = try (http3.connect_udp.ContextDatagram{
                .context_id = http3.connect_udp.udp_context_id,
                .payload = "two-a",
            }).writeInto(&encoded_storage[3]);
            two_payloads[1] = try (http3.connect_udp.ContextDatagram{
                .context_id = http3.connect_udp.udp_context_id,
                .payload = "two-b",
            }).writeInto(&encoded_storage[4]);
            var committed: usize = 0;
            try client.sendConnectDatagramsWithDeadline(
                stream_one,
                &one_payloads,
                &committed,
                deadline,
            );
            try std.testing.expectEqual(@as(usize, 3), committed);
            try client.sendConnectDatagramsWithDeadline(
                stream_two,
                &two_payloads,
                &committed,
                deadline,
            );
            try std.testing.expectEqual(@as(usize, 2), committed);
            self.stage.store(3, .release);

            var response_storage: [64]u8 = undefined;
            // QUIC DATAGRAM is unordered. Read the second association first
            // to prove the first association's backlog cannot starve it, but
            // accept either order within each association.
            try expectPair(
                &two,
                "two-a",
                "two-b",
                &response_storage,
                deadline,
            );
            self.stage.store(4, .release);
            try expectPair(
                &one,
                "one-a",
                "one-b",
                &response_storage,
                deadline,
            );
            self.stage.store(5, .release);
            try client.cancelRequest(
                stream_one,
                http3.ApplicationErrorCode.request_cancelled,
            );
            try client.sendRequestBody(stream_two, &.{}, true);
            self.stage.store(6, .release);
            try std.testing.expectError(
                error.ConnectDatagramAssociationClosed,
                two.receiveIntoWithDeadline(&response_storage, deadline),
            );
            self.stage.store(7, .release);
            try client.closeConnectDatagramAssociation(stream_two);
            self.stage.store(8, .release);
        }
    };
    var client = Client{ .io = io, .address = server.address() };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    var client_joined = false;
    defer if (!client_joined) client_thread.join();

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var registered: usize = 0;
    var closed: usize = 0;
    var one_key: ?runtime.ConnectUdpDispatcherRelay.Key = null;
    var two_key: ?runtime.ConnectUdpDispatcherRelay.Key = null;
    var closed_events: [2]runtime.ConnectUdpDispatcherRelay.RelayClosed = undefined;
    const pump_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(10),
    });
    while (closed < 2) {
        if (pump_deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            if (registered != 2) return error.RelayRegistrationTimeout;
            if (closed == 0) return switch (client.stage.load(.acquire)) {
                0 => error.ClientHandshakeStageTimeout,
                1 => error.ClientAcceptStageTimeout,
                2 => error.ClientSendStageTimeout,
                3 => stage: {
                    const one_stats = relays.relayStats(one_key.?) orelse
                        return error.MissingFirstRelay;
                    const two_stats = relays.relayStats(two_key.?) orelse
                        return error.MissingSecondRelay;
                    if (one_stats.session_to_udp_datagrams != 2) {
                        break :stage error.FirstRelayTargetSendTimeout;
                    }
                    switch (two_stats.session_to_udp_datagrams) {
                        0 => break :stage error.SecondRelayTargetSentZero,
                        1 => break :stage error.SecondRelayTargetSentOne,
                        2 => {},
                        else => break :stage error.SecondRelayTargetSentTooMany,
                    }
                    if (one_stats.udp_to_session_datagrams != 2) {
                        break :stage error.FirstRelaySessionSendTimeout;
                    }
                    if (two_stats.udp_to_session_datagrams != 2) {
                        break :stage error.SecondRelaySessionSendTimeout;
                    }
                    break :stage error.ClientSecondRelayStageTimeout;
                },
                4 => error.ClientFirstRelayStageTimeout,
                5 => error.ClientTerminalSendStageTimeout,
                6 => error.ClientTerminalReceiveStageTimeout,
                7, 8 => error.NoRelayClosedAfterClientDone,
                else => error.InvalidClientStage,
            };
            return switch (closed_events[0].reason) {
                .association_closed => error.StreamResetRelayTimeout,
                .stream_reset => error.AssociationFinRelayTimeout,
                .connection_closed => error.OtherRelayCloseTimeout,
            };
        }
        var event = (try relays.pumpOnce(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .relay_closed => |relay_closed| {
                if (relay_closed.reason == .association_closed) {
                    try relays.tryFinishResponse(relay_closed.key);
                }
                closed_events[closed] = relay_closed;
                closed += 1;
            },
            .endpoint => |*endpoint_event| switch (endpoint_event.*) {
                .connected => {},
                .closed, .handshake_failed, .unrouted => return error.TestUnexpectedResult,
                .request => |*request| switch (request.request) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head_value| switch (head_value) {
                            .response => return error.TestUnexpectedResult,
                            .request => |head| {
                                var host_storage: [128]u8 = undefined;
                                const target = try endpoint.session(
                                    request.connection_handle,
                                ).?.tryAcceptConnectUdp(
                                    message.stream_id,
                                    head,
                                    &host_storage,
                                );
                                const key = runtime.ConnectUdpDispatcherRelay.Key{
                                    .connection_handle = request.connection_handle,
                                    .stream_id = message.stream_id,
                                };
                                const echo = if (std.mem.eql(
                                    u8,
                                    target.host,
                                    "one.example",
                                )) one: {
                                    one_key = key;
                                    break :one echo_one.address;
                                } else if (std.mem.eql(
                                    u8,
                                    target.host,
                                    "two.example",
                                )) two: {
                                    two_key = key;
                                    break :two echo_two.address;
                                } else return error.InvalidTarget;
                                var socket = try net.IpAddress.bind(
                                    &.{ .ip4 = .loopback(0) },
                                    io,
                                    .{ .mode = .dgram, .protocol = .udp },
                                );
                                var socket_owned = true;
                                defer if (socket_owned) socket.close(io);
                                try relays.register(key, socket, echo);
                                socket_owned = false;
                                registered += 1;
                            },
                        },
                        .push_promise,
                        .data_available,
                        .trailers,
                        .finished,
                        => {},
                    },
                },
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 2), registered);
    try std.testing.expectEqual(@as(usize, 0), relays.relayCount());

    client_thread.join();
    client_joined = true;
    echo_thread_one.join();
    echo_thread_two.join();
    echoes_joined = true;
    if (client.err) |err| return err;
    for (echoes) |echo| if (echo.err) |err| return err;
    var saw_reset = false;
    var saw_fin = false;
    for (closed_events) |relay_closed| {
        saw_reset = saw_reset or relay_closed.reason == .stream_reset;
        saw_fin = saw_fin or relay_closed.reason == .association_closed;
        try std.testing.expectEqual(
            @as(u64, 2),
            relay_closed.stats.session_to_udp_datagrams,
        );
        try std.testing.expectEqual(
            @as(u64, 10),
            relay_closed.stats.session_to_udp_bytes,
        );
        try std.testing.expectEqual(
            @as(u64, 2),
            relay_closed.stats.udp_to_session_datagrams,
        );
        try std.testing.expectEqual(
            @as(u64, 10),
            relay_closed.stats.udp_to_session_bytes,
        );
        try std.testing.expectEqual(
            @as(u64, 0),
            relay_closed.stats.dropped_backpressure,
        );
    }
    try std.testing.expect(saw_reset);
    try std.testing.expect(saw_fin);
}
