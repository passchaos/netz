const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "HTTP/3 CONNECT-IP keeps Capsules and DATAGRAM packets on one Session" {
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
                .local_connection_id = "connect-ip-server",
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();

    const client_packet = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0x51} ** 16;
    const server_packet = [_]u8{ 0x60, 0, 0, 0 } ++ [_]u8{0x62} ** 36;
    const Worker = struct {
        server: *runtime.HandshakeServer,
        sent: *std.Io.Event,
        delivered: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h3 = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer h3.deinit();
            try h3.ensureSettingsSent();
            var event = try h3.receiveRequestEventWithTimeout(
                .fromSeconds(5),
            );
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .message);
            try std.testing.expect(event.message.value == .head);
            var target_storage: [128]u8 = undefined;
            const scope = try h3.acceptConnectIp(
                event.message.stream_id,
                event.message.value.head.request,
                &target_storage,
            );
            try std.testing.expectEqualStrings("*", scope.target);
            var session = try h3.connectIpSession(event.message.stream_id);
            var configuration = http3.connect_ip.ConfigurationState.init(
                self.server.allocator,
                .{},
            );
            defer configuration.deinit();
            try session.bindConfigurationState(&configuration);
            defer session.deinit();

            // Read the DATAGRAM first even though the Capsule was sent first.
            // Detached progress must retain the attached CONNECT stream bytes.
            var incoming = try session.receiveWithTimeout(.fromSeconds(2));
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualSlices(u8, &client_packet, incoming.payload);
            var address_request = try session.receiveCapsuleWithTimeout(
                .fromSeconds(2),
            );
            defer address_request.deinit(self.server.allocator);
            var requests = try http3.connect_ip.capsules.parseAddressRequest(
                address_request.value,
            );
            try std.testing.expectEqual(
                @as(u62, 13),
                (try requests.next()).?.request_id,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                configuration.peerRequestCount(),
            );

            const assigned = [_]http3.connect_ip.capsules.AddressPrefix{.{
                .request_id = 13,
                .address = .{ .ipv4 = .{ 192, 0, 2, 13 } },
                .prefix_length = 32,
            }};
            var encoded: [64]u8 = undefined;
            const assignment = try http3.connect_ip.capsules
                .writeAddressAssignInto(&encoded, &assigned);
            try session.sendCapsuleWithTimeout(
                assignment,
                .fromSeconds(2),
            );
            try session.sendWithTimeout(&server_packet, .fromSeconds(2));
            self.sent.set(self.server.quic_server.endpoint.io);
            try self.delivered.waitTimeout(
                self.server.quic_server.endpoint.io,
                .{ .duration = .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                } },
            );
            try session.closeWrite();
            try std.testing.expectError(
                error.ConnectDatagramAssociationClosed,
                session.receiveCapsuleWithTimeout(.fromSeconds(2)),
            );
        }
    };
    var sent: std.Io.Event = .unset;
    var delivered: std.Io.Event = .unset;
    var worker = Worker{
        .server = &server,
        .sent = &sent,
        .delivered = &delivered,
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
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
                .original_destination_connection_id = "connect-ip-origin",
                .local_connection_id = "connect-ip-client",
                .server_name = "localhost",
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
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
    const stream_id = try client.startConnectIp(
        .{},
        "localhost",
        &path_storage,
    );

    var session: ?runtime.ConnectIpClientSession = null;
    while (session == null) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .request => return error.TestUnexpectedResult,
                .response => |response| {
                    session = try client.acceptConnectIpResponse(
                        stream_id,
                        response,
                    );
                },
            },
            else => return error.TestUnexpectedResult,
        }
    }
    var ip = session.?;
    var configuration = http3.connect_ip.ConfigurationState.init(
        allocator,
        .{},
    );
    defer configuration.deinit();
    try ip.bindConfigurationState(&configuration);
    defer ip.deinit();

    const requested = [_]http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 13,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    var encoded: [64]u8 = undefined;
    const request = try http3.connect_ip.capsules.writeAddressRequestInto(
        &encoded,
        &requested,
    );
    try ip.sendCapsuleWithDeadline(request, deadline);
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.localRequestCount(),
    );
    try ip.sendWithDeadline(&client_packet, deadline);
    sent.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } }) catch |err| {
        thread.join();
        joined = true;
        if (worker.err) |server_err| return server_err;
        return err;
    };

    // Repeat the reverse ordering to prove both planes preserve each other.
    var incoming = try ip.receiveWithDeadline(deadline);
    defer incoming.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &server_packet, incoming.payload);
    var assignment = try ip.receiveCapsuleWithDeadline(deadline);
    defer assignment.deinit(allocator);
    var assigned = try http3.connect_ip.capsules.parseAddressAssign(
        assignment.value,
    );
    try std.testing.expectEqual(
        @as(u62, 13),
        (try assigned.next()).?.request_id,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.assignedPrefixes().len,
    );
    delivered.set(io);
    try ip.closeWrite();
    const close_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        ip.receiveCapsuleWithDeadline(close_deadline),
    );

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
