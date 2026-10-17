const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

test "HTTP/3 typed CONNECT-UDP exchanges Context ID zero payloads" {
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
        .max_frames_per_datagram = 8,
    } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = "connect-udp-server",
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var echo_socket = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer echo_socket.close(io);

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        accepted: *std.Io.Event,
        target: std.Io.net.IpAddress,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            try session.ensureSettingsSent();
            for (0..2) |index| {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(5),
                );
                defer event.deinit(self.server.allocator);
                try std.testing.expect(event == .message);
                try std.testing.expect(event.message.value == .head);
                const request = event.message.value.head.request;
                if (index == 0) {
                    var host_storage: [128]u8 = undefined;
                    const target = try session.acceptConnectUdp(
                        event.message.stream_id,
                        request,
                        &host_storage,
                    );
                    try std.testing.expectEqualStrings(
                        "dns.example",
                        target.host,
                    );
                    try std.testing.expectEqual(@as(u16, 53), target.port);
                } else {
                    try std.testing.expectEqualStrings(
                        "/masque?target_host=dns.example&target_port=5353&token=a%2Fb",
                        request.path,
                    );
                    try session.acceptConnectUdpForTarget(
                        event.message.stream_id,
                        request,
                        .{ .host = "dns.example", .port = 5353 },
                    );
                }
                self.accepted.set(self.server.quic_server.endpoint.io);

                var udp = try session.connectUdpSession(
                    event.message.stream_id,
                );
                defer udp.deinit();
                if (index == 0) {
                    var relay_socket = try std.Io.net.IpAddress.bind(
                        &.{ .ip4 = .loopback(0) },
                        self.server.quic_server.endpoint.io,
                        .{ .mode = .dgram, .protocol = .udp },
                    );
                    defer relay_socket.close(
                        self.server.quic_server.endpoint.io,
                    );
                    var session_storage: [4096]u8 = undefined;
                    var udp_storage: [4096]u8 = undefined;
                    const relayed = try http3.connect_udp.relay.run(
                        runtime.ConnectUdpServerSession,
                        self.server.quic_server.endpoint.io,
                        &udp,
                        &relay_socket,
                        &self.target,
                        &session_storage,
                        &udp_storage,
                        .{
                            .deadline = .fromNow(
                                self.server.quic_server.endpoint.io,
                                .{
                                    .raw = .fromSeconds(2),
                                    .clock = .awake,
                                },
                            ),
                            .max_forwarded_datagrams = 2,
                        },
                    );
                    try std.testing.expectEqual(
                        http3.connect_udp.relay.EndReason.datagram_limit,
                        relayed.reason,
                    );
                    try std.testing.expectEqual(
                        @as(u64, 1),
                        relayed.stats.session_to_udp_datagrams,
                    );
                    try std.testing.expectEqual(
                        @as(u64, 1),
                        relayed.stats.udp_to_session_datagrams,
                    );
                } else {
                    var incoming = try udp.receiveWithTimeout(.fromSeconds(2));
                    defer incoming.deinit(self.server.allocator);
                    try std.testing.expectEqualStrings(
                        "client-custom",
                        incoming.payload,
                    );
                    try udp.sendWithTimeout(
                        "server-custom",
                        .fromSeconds(2),
                    );
                }
            }
        }
    };
    var accepted: std.Io.Event = .unset;
    var worker = ServerWorker{
        .server = &server,
        .accepted = &accepted,
        .target = echo_socket.address,
    };
    const thread = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    const Echo = struct {
        socket: *std.Io.net.Socket,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var storage: [http3.connect_udp.max_udp_payload_size]u8 = undefined;
            const message = try self.socket.receiveTimeout(
                self.io,
                &storage,
                .{ .duration = .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                } },
            );
            try std.testing.expect(message.data.len > 1);
            for (message.data) |byte| {
                try std.testing.expectEqual(@as(u8, 0x5a), byte);
            }
            try self.socket.send(self.io, &message.from, message.data);
        }
    };
    var echo = Echo{ .socket = &echo_socket, .io = io };
    const echo_thread = try std.Thread.spawn(.{}, Echo.run, .{&echo});
    var echo_joined = false;
    defer if (!echo_joined) echo_thread.join();

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = "connect-udp-origin",
                .local_connection_id = "connect-udp-client",
                .server_name = "localhost",
                .random = [_]u8{0x83} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer client.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    try client.ensureSettingsSentOnce();
    _ = try client.receivePeerSettingsWithDeadline(deadline);
    const ClientFlow = struct {
        fn accept(
            client_value: *runtime.HandshakeClient,
            stream_id_value: u62,
            flow_deadline: std.Io.Clock.Timestamp,
        ) !runtime.ConnectUdpClientSession {
            var response_head: ?http3.DecodedResponseHead = null;
            while (response_head == null) {
                response_head = try client_value.pollDetachedResponseHead(
                    stream_id_value,
                );
                if (response_head == null) {
                    try client_value.established.connection
                        .servicePacketServicingTimersDeadline(flow_deadline);
                }
            }
            var head_value = response_head.?;
            defer head_value.deinit(client_value.allocator);
            return client_value.acceptConnectUdpResponse(
                stream_id_value,
                head_value,
            );
        }
    };
    var path_storage: [160]u8 = undefined;
    const next_stream_id = client.next_stream_id;
    try std.testing.expectError(
        error.InvalidTarget,
        client.startConnectUdp(
            .{ .host = "dns.example", .port = 0 },
            "localhost",
            &path_storage,
        ),
    );
    try std.testing.expectEqual(next_stream_id, client.next_stream_id);
    const stream_id = try client.startConnectUdp(
        .{ .host = "dns.example", .port = 53 },
        "localhost",
        &path_storage,
    );
    accepted.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } }) catch |err| {
        thread.join();
        joined = true;
        if (worker.err) |server_err| return server_err;
        return err;
    };
    var udp = ClientFlow.accept(&client, stream_id, deadline) catch |err| {
        thread.join();
        joined = true;
        if (worker.err) |server_err| return server_err;
        return err;
    };
    defer udp.deinit();
    try std.testing.expectEqual(
        client.maxConnectDatagramPayloadSize(stream_id).? - 1,
        udp.maxPayloadSize().?,
    );
    const scratch_len = udp.send_scratch.items.len;
    try std.testing.expectError(
        error.Timeout,
        udp.sendWithTimeout("deadline", .zero),
    );
    try std.testing.expectEqual(scratch_len, udp.send_scratch.items.len);

    var oversized = [_]u8{0} ** (http3.connect_udp.max_udp_payload_size + 1);
    try std.testing.expectError(error.PayloadTooLarge, udp.send(&oversized));

    var extension_storage: [32]u8 = undefined;
    const extension = try (http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "ignored-extension",
    }).writeInto(&extension_storage);
    try client.sendConnectDatagram(stream_id, extension);
    var maximum_payload_storage: [4096]u8 = undefined;
    @memset(&maximum_payload_storage, 0x5a);
    const maximum_payload = maximum_payload_storage[0..udp.maxPayloadSize().?];
    try udp.sendWithDeadline(maximum_payload, deadline);
    var short_incoming: [1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        udp.receiveIntoWithDeadline(&short_incoming, deadline),
    );
    var incoming = try udp.receiveWithDeadline(deadline);
    defer incoming.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        maximum_payload,
        incoming.payload,
    );

    accepted.reset();
    const template = try http3.connect_udp.UriTemplate.compile(
        "https://localhost/masque{?target_host,target_port,token}",
    );
    const custom_stream_id = try client.startConnectUdpWithTemplate(
        template,
        .{ .host = "dns.example", .port = 5353 },
        &.{.{ .name = "token", .value = "a/b" }},
        &path_storage,
    );
    try accepted.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    var custom = try ClientFlow.accept(
        &client,
        custom_stream_id,
        deadline,
    );
    defer custom.deinit();
    try custom.sendWithDeadline("client-custom", deadline);
    var custom_storage: [64]u8 = undefined;
    const custom_incoming = try custom.receiveIntoWithDeadline(
        &custom_storage,
        deadline,
    );
    try std.testing.expectEqualStrings(
        "server-custom",
        custom_incoming.payload,
    );

    thread.join();
    joined = true;
    echo_thread.join();
    echo_joined = true;
    if (worker.err) |err| return err;
    if (echo.err) |err| return err;
}
