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

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        accepted: *std.Io.Event,
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
            var event = try session.receiveRequestEventWithTimeout(
                .fromSeconds(5),
            );
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .message);
            try std.testing.expect(event.message.value == .head);
            var host_storage: [128]u8 = undefined;
            const target = try session.acceptConnectUdp(
                event.message.stream_id,
                event.message.value.head.request,
                &host_storage,
            );
            try std.testing.expectEqualStrings("dns.example", target.host);
            try std.testing.expectEqual(@as(u16, 53), target.port);
            self.accepted.set(self.server.quic_server.endpoint.io);

            var udp = try session.connectUdpSession(event.message.stream_id);
            defer udp.deinit();
            var incoming = try udp.receiveWithTimeout(.fromSeconds(2));
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("client-udp", incoming.payload);
            try udp.sendWithTimeout("server-udp", .fromSeconds(2));
        }
    };
    var accepted: std.Io.Event = .unset;
    var worker = ServerWorker{ .server = &server, .accepted = &accepted };
    const thread = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

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
    var response_head: ?http3.DecodedResponseHead = null;
    while (response_head == null) {
        response_head = try client.pollDetachedResponseHead(stream_id);
        if (response_head == null) {
            client.established.connection
                .servicePacketServicingTimersDeadline(deadline) catch |err| {
                thread.join();
                joined = true;
                if (worker.err) |server_err| return server_err;
                return err;
            };
        }
    }
    var head = response_head.?;
    defer head.deinit(allocator);
    var udp = try client.acceptConnectUdpResponse(stream_id, head);
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
    try udp.sendWithDeadline("client-udp", deadline);
    var incoming = try udp.receiveWithDeadline(deadline);
    defer incoming.deinit(allocator);
    try std.testing.expectEqualStrings("server-udp", incoming.payload);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
