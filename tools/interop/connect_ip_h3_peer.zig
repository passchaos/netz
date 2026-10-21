//! Netz half of independent h3/quinn RFC 9484 interoperability.

const std = @import("std");
const netz = @import("netz");

const client_packet = [_]u8{
    0x45, 0, 0, 20, 0,   1, 0,   0,  64, 6, 0, 0,
    192,  0, 2, 21, 203, 0, 113, 42,
};
const server_packet = [_]u8{
    0x45, 0, 0,   20, 0,   2,  0,   0,  64, 17, 0, 0,
    203,  0, 113, 42, 198, 51, 100, 42,
};
const client_route = netz.http3.connect_ip.capsules.Route{ .ipv4 = .{
    .start = .{ 198, 51, 100, 0 },
    .end = .{ 198, 51, 100, 255 },
    .ip_protocol = 17,
} };
const server_route = netz.http3.connect_ip.capsules.Route{ .ipv4 = .{
    .start = .{ 203, 0, 113, 0 },
    .end = .{ 203, 0, 113, 255 },
    .ip_protocol = 6,
} };
const client_scope = netz.http3.connect_ip.Scope{
    .target = "203.0.113.0/24",
    .ip_protocol = 6,
};
const settings = netz.http3.Settings{
    .enable_connect_protocol = true,
    .h3_datagram = true,
};
const limits: netz.http3.runtime.Limits = .{ .quic = .{
    .max_datagram_size = 4096,
    .max_frames_per_datagram = 16,
} };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    const port = try std.fmt.parseUnsigned(u16, args[2], 10);
    if (port == 0) return error.InvalidArguments;
    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    if (std.mem.eql(u8, args[1], "client")) {
        if (!std.Io.Dir.path.isAbsolute(args[3])) {
            return error.InvalidArguments;
        }
        try runClient(allocator, backend.io(), port, args[3]);
    } else if (std.mem.eql(u8, args[1], "server")) {
        try runServer(allocator, backend.io(), port);
    } else {
        return error.InvalidArguments;
    }
}

fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_path: []const u8,
) !void {
    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, ca_path);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .key_exchange_groups = &.{.x25519},
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .local_settings = settings,
                .max_stream_buffer = 64 * 1024,
            },
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
        client_scope,
        "localhost",
        &path_storage,
    );
    var session: ?netz.http3.runtime.ConnectIpClientSession = null;
    while (session == null) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .request => return error.InvalidResponse,
                .response => |response| {
                    session = try client.acceptConnectIpResponse(
                        stream_id,
                        response,
                    );
                },
            },
            else => return error.InvalidResponse,
        }
    }
    var ip = session.?;
    defer ip.deinit();
    var configuration = netz.http3.connect_ip.ConfigurationState.init(
        allocator,
        .{},
    );
    defer configuration.deinit();
    try ip.bindConfigurationState(&configuration);

    const requested = [_]netz.http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 21,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    var encoded: [64]u8 = undefined;
    const request = try netz.http3.connect_ip.capsules
        .writeAddressRequestInto(&encoded, &requested);
    try ip.sendCapsuleWithDeadline(request, deadline);
    const peer_assignment = [_]netz.http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 0,
        .address = .{ .ipv4 = .{ 203, 0, 113, 42 } },
        .prefix_length = 32,
    }};
    const assign_peer = try netz.http3.connect_ip.capsules
        .writeAddressAssignInto(&encoded, &peer_assignment);
    try ip.sendCapsuleWithDeadline(assign_peer, deadline);
    try std.testing.expect(configuration.peerSourceIsAssigned(.{
        .ipv4 = .{ 203, 0, 113, 42 },
    }));
    const route = try netz.http3.connect_ip.capsules
        .writeRouteAdvertisementInto(&encoded, &.{client_route});
    try ip.sendCapsuleWithDeadline(route, deadline);
    try std.testing.expect(configuration.peerRouteAllows(
        .{ .ipv4 = .{ 198, 51, 100, 42 } },
        17,
    ));
    var assignment = try ip.receiveCapsuleWithDeadline(deadline);
    defer assignment.deinit(allocator);
    var assigned = try netz.http3.connect_ip.capsules.parseAddressAssign(
        assignment.value,
    );
    const address = (try assigned.next()).?;
    try std.testing.expectEqual(@as(u62, 21), address.request_id);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 192, 0, 2, 21 },
        address.address.bytes(),
    );
    try std.testing.expect(configuration.sourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 2, 21 },
    }));
    var advertised = try ip.receiveCapsuleWithDeadline(deadline);
    defer advertised.deinit(allocator);
    try std.testing.expectEqual(
        netz.http3.connect_ip.capsules.route_advertisement_type,
        advertised.capsule_type,
    );
    try std.testing.expect(configuration.routeAllows(
        .{ .ipv4 = .{ 203, 0, 113, 42 } },
        6,
    ));
    try std.testing.expect(try configuration.localPacketAllowed(
        &client_packet,
    ));
    try std.testing.expect(try configuration.peerPacketAllowed(
        &server_packet,
    ));
    try std.testing.expectEqual(
        netz.http3.connect_ip.PacketDecision.allowed,
        try client_scope.packetDecision(&client_packet),
    );
    try ip.sendWithDeadline(&client_packet, deadline);
    var incoming = try ip.receiveWithDeadline(deadline);
    defer incoming.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &server_packet, incoming.payload);
    const withdrawn = try netz.http3.connect_ip.capsules
        .writeRouteAdvertisementInto(&encoded, &.{});
    try ip.sendCapsuleWithDeadline(withdrawn, deadline);
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.sentAdvertisedRoutes().len,
    );
    var route_withdrawal = try ip.receiveCapsuleWithDeadline(deadline);
    defer route_withdrawal.deinit(allocator);
    try std.testing.expectEqual(
        netz.http3.connect_ip.capsules.route_advertisement_type,
        route_withdrawal.capsule_type,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.advertisedRoutes().len,
    );
    try ip.sendWithDeadline("netz-ip-ack", deadline);
    try ip.closeWrite();
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        ip.receiveCapsuleWithDeadline(deadline),
    );
    try client.established.connection.closeApplication(
        0,
        "CONNECT-IP complete",
    );
    std.debug.print(
        "netz HTTP/3 CONNECT-IP client interoperated with h3/quinn: address_request=true address_assign=true route_advertisement=true route_withdrawal=true packet_policy=true scope_policy=true sent_ip={} received_ip={} delivery_ack=true request_fin=true response_fin=true client_io=zio-std-io server_io=h3-quinn-tokio\n",
        .{ client_packet.len, server_packet.len },
    );
}

fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
) !void {
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .local_settings = settings,
                .max_stream_buffer = 64 * 1024,
            },
        },
    );
    defer server.deinit();
    std.debug.print("netz HTTP/3 CONNECT-IP server listening\n", .{});
    var h3 = try server.acceptWithTimeout(.fromSeconds(5));
    defer h3.deinit();
    try h3.ensureSettingsSent();
    var event = try h3.receiveRequestEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    if (event != .message or event.message.value != .head) {
        return error.InvalidRequest;
    }
    const stream_id = event.message.stream_id;
    var target_storage: [128]u8 = undefined;
    const scope = try h3.acceptConnectIp(
        stream_id,
        event.message.value.head.request,
        &target_storage,
    );
    try std.testing.expectEqualStrings(client_scope.target, scope.target);
    try std.testing.expectEqual(client_scope.ip_protocol, scope.ip_protocol);
    var ip = try h3.connectIpSession(stream_id);
    defer ip.deinit();
    var configuration = netz.http3.connect_ip.ConfigurationState.init(
        allocator,
        .{},
    );
    defer configuration.deinit();
    try ip.bindConfigurationState(&configuration);
    var address_request = try ip.receiveCapsuleWithTimeout(.fromSeconds(5));
    defer address_request.deinit(allocator);
    var requested = try netz.http3.connect_ip.capsules.parseAddressRequest(
        address_request.value,
    );
    try std.testing.expectEqual(
        @as(u62, 21),
        (try requested.next()).?.request_id,
    );
    var address_assignment = try ip.receiveCapsuleWithTimeout(.fromSeconds(5));
    defer address_assignment.deinit(allocator);
    var peer_assignments = try netz.http3.connect_ip.capsules
        .parseAddressAssign(address_assignment.value);
    const peer_assignment = (try peer_assignments.next()).?;
    try std.testing.expectEqual(@as(u62, 0), peer_assignment.request_id);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 203, 0, 113, 42 },
        peer_assignment.address.bytes(),
    );
    try std.testing.expect(configuration.sourceIsAssigned(.{
        .ipv4 = .{ 203, 0, 113, 42 },
    }));
    var advertised = try ip.receiveCapsuleWithTimeout(.fromSeconds(5));
    defer advertised.deinit(allocator);
    try std.testing.expect(configuration.routeAllows(
        .{ .ipv4 = .{ 198, 51, 100, 42 } },
        17,
    ));
    const assigned = [_]netz.http3.connect_ip.capsules.AddressPrefix{.{
        .request_id = 21,
        .address = .{ .ipv4 = .{ 192, 0, 2, 21 } },
        .prefix_length = 32,
    }};
    var encoded: [64]u8 = undefined;
    const assignment = try netz.http3.connect_ip.capsules
        .writeAddressAssignInto(&encoded, &assigned);
    try ip.sendCapsuleWithTimeout(assignment, .fromSeconds(5));
    try std.testing.expect(configuration.peerSourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 2, 21 },
    }));
    const route = try netz.http3.connect_ip.capsules
        .writeRouteAdvertisementInto(&encoded, &.{server_route});
    try ip.sendCapsuleWithTimeout(route, .fromSeconds(5));
    try std.testing.expect(configuration.peerRouteAllows(
        .{ .ipv4 = .{ 203, 0, 113, 42 } },
        6,
    ));
    try std.testing.expect(try configuration.localPacketAllowed(
        &server_packet,
    ));
    try std.testing.expect(try configuration.peerPacketAllowed(
        &client_packet,
    ));
    try std.testing.expectEqual(
        netz.http3.connect_ip.PacketDecision.allowed,
        try scope.packetDecision(&client_packet),
    );
    var incoming = try ip.receiveWithTimeout(.fromSeconds(5));
    defer incoming.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &client_packet, incoming.payload);
    try ip.sendWithTimeout(&server_packet, .fromSeconds(5));
    var route_withdrawal = try ip.receiveCapsuleWithTimeout(.fromSeconds(5));
    defer route_withdrawal.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.advertisedRoutes().len,
    );
    const withdrawn = try netz.http3.connect_ip.capsules
        .writeRouteAdvertisementInto(&encoded, &.{});
    try ip.sendCapsuleWithTimeout(withdrawn, .fromSeconds(5));
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.sentAdvertisedRoutes().len,
    );
    var ack = try ip.receiveWithTimeout(.fromSeconds(5));
    defer ack.deinit(allocator);
    try std.testing.expectEqualStrings("h3-ip-ack", ack.payload);
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        ip.receiveCapsuleWithTimeout(.fromSeconds(5)),
    );
    try ip.closeWrite();
    std.debug.print(
        "netz HTTP/3 CONNECT-IP server interoperated with h3/quinn: address_request=true address_assign=true route_advertisement=true route_withdrawal=true packet_policy=true scope_policy=true received_ip={} sent_ip={} delivery_ack=true request_fin=true response_fin=true client_io=h3-quinn-tokio server_io=zio-std-io\n",
        .{ client_packet.len, server_packet.len },
    );
}
