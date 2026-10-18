const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

test "HTTP/3 endpoint dispatcher CONNECT-IP polls both planes" {
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
                .local_connection_id = "ip-disp-server",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{ .local_settings = settings },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    defer endpoint.deinit();

    const client_packet = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0x91} ** 16;
    const server_packet = [_]u8{ 0x60, 0, 0, 0 } ++ [_]u8{0xa2} ** 36;
    const Client = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        done: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                std.debug.print(
                    "CONNECT-IP dispatcher client failed: {s}\n",
                    .{@errorName(err)},
                );
                self.err = err;
            };
            self.done.set(self.io);
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
                        .original_destination_connection_id = "ip-disp-origin",
                        .local_connection_id = "ip-disp-client",
                        .server_name = "localhost",
                        .random = [_]u8{0xb3} ** 32,
                        .x25519_secret_key = [_]u8{0xb4} ** 32,
                    },
                    .session = .{ .local_settings = settings },
                },
            );
            defer client.deinit();
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
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
            defer ip.deinit();
            const requested = [_]http3.connect_ip.capsules.AddressPrefix{.{
                .request_id = 31,
                .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
                .prefix_length = 32,
            }};
            var encoded: [64]u8 = undefined;
            const request = try http3.connect_ip.capsules
                .writeAddressRequestInto(&encoded, &requested);
            try ip.sendCapsuleWithDeadline(request, deadline);
            try ip.sendWithDeadline(&client_packet, deadline);
            var incoming = try ip.receiveWithDeadline(deadline);
            defer incoming.deinit(allocator);
            try std.testing.expectEqualSlices(u8, &server_packet, incoming.payload);
            var assignment = try ip.receiveCapsuleWithDeadline(deadline);
            defer assignment.deinit(allocator);
            var assigned = try http3.connect_ip.capsules.parseAddressAssign(
                assignment.value,
            );
            try std.testing.expectEqual(
                @as(u62, 31),
                (try assigned.next()).?.request_id,
            );
            try ip.closeWrite();
            try std.testing.expectError(
                error.ConnectDatagramAssociationClosed,
                ip.receiveCapsuleWithDeadline(deadline),
            );
        }
    };
    var done: std.Io.Event = .unset;
    var client = Client{
        .io = io,
        .address = server.address(),
        .done = &done,
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    var joined = false;
    defer if (!joined) client_thread.join();

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var ip: ?runtime.ConnectIpServerSession = null;
    defer if (ip) |*session| session.deinit();
    var handle: ?@FieldType(
        runtime.EndpointRequestEvent,
        "connection_handle",
    ) = null;
    var saw_capsule = false;
    var saw_packet = false;
    var sent_capsule = false;
    var sent_packet = false;
    var peer_finished = false;
    var response_finished = false;
    var packet_storage: [128]u8 = undefined;
    var assignment_storage: [64]u8 = undefined;
    const assigned = [_]http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 31,
        .address = .{ .ipv4 = .{ 192, 0, 2, 31 } },
        .prefix_length = 32,
    }};
    const assignment = try http3.connect_ip.capsules.writeAddressAssignInto(
        &assignment_storage,
        &assigned,
    );
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(10),
        .clock = .awake,
    });
    while (!done.isSet()) {
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        if (ip) |*session| {
            if (!saw_capsule) {
                if (try session.pollReceiveCapsule()) |capsule_value| {
                    var capsule = capsule_value;
                    defer capsule.deinit(allocator);
                    var requests = try http3.connect_ip.capsules
                        .parseAddressRequest(capsule.value);
                    try std.testing.expectEqual(
                        @as(u62, 31),
                        (try requests.next()).?.request_id,
                    );
                    saw_capsule = true;
                }
            }
            if (!saw_packet) {
                if (try session.pollReceiveInto(&packet_storage)) |packet| {
                    try std.testing.expectEqualSlices(
                        u8,
                        &client_packet,
                        packet.payload,
                    );
                    saw_packet = true;
                }
            }
            if (saw_capsule and !sent_capsule) {
                session.trySendCapsule(assignment) catch |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => {},
                    else => return err,
                };
                sent_capsule = !session.writeInProgress();
            }
            if (saw_packet and !sent_packet) {
                if (session.trySend(&server_packet)) |_| {
                    sent_packet = true;
                } else |err| switch (err) {
                    error.PacingLimited, error.CongestionLimited => {},
                    else => return err,
                }
            }
            if (saw_capsule and saw_packet and !peer_finished) {
                if (session.pollReceiveCapsule()) |maybe_capsule| {
                    if (maybe_capsule) |capsule_value| {
                        var capsule = capsule_value;
                        capsule.deinit(allocator);
                    }
                } else |err| switch (err) {
                    error.ConnectDatagramAssociationClosed => peer_finished = true,
                    else => return err,
                }
            }
            if (peer_finished and sent_capsule and sent_packet and
                !response_finished)
            {
                if (session.tryCloseWrite()) |_| {
                    response_finished = true;
                } else |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => {},
                    else => return err,
                }
            }
        }

        var event = (try endpoint.receiveOnce(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed, .handshake_failed, .unrouted => return error.TestUnexpectedResult,
            .request => |*request| switch (request.request) {
                .reset => return error.TestUnexpectedResult,
                .message => |message| switch (message.value) {
                    .head => |head| switch (head) {
                        .response => return error.TestUnexpectedResult,
                        .request => |request_head| {
                            var target_storage: [64]u8 = undefined;
                            const parent = endpoint.session(
                                request.connection_handle,
                            ) orelse return error.TestUnexpectedResult;
                            _ = try parent.tryAcceptConnectIp(
                                message.stream_id,
                                request_head,
                                &target_storage,
                            );
                            ip = try parent.connectIpSession(message.stream_id);
                            handle = request.connection_handle;
                        },
                    },
                    .finished => if (ip) |*session| {
                        if (session.streamId() == message.stream_id) {
                            session.observePeerFinished();
                            peer_finished = true;
                        }
                    },
                    .data_available, .push_promise, .trailers => {},
                },
            },
        }
        if (handle) |value| {
            try endpoint.dispatcher.refreshConnectionTimer(value);
        }
    }
    client_thread.join();
    joined = true;
    if (client.err) |err| return err;
    try std.testing.expect(saw_capsule);
    try std.testing.expect(saw_packet);
    try std.testing.expect(sent_capsule);
    try std.testing.expect(sent_packet);
    try std.testing.expect(peer_finished);
    try std.testing.expect(response_finished);
}
