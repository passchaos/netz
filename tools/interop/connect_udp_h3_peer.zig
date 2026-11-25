//! Netz half of independent h3/quinn RFC 9298 interoperability.

const std = @import("std");
const netz = @import("netz");

const client_payload = [_]u8{0x5a} ** 513;
const server_payload = [_]u8{0xa5} ** 777;
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
    if (args.len < 3 or args.len > 4) return error.InvalidArguments;
    const port = try std.fmt.parseUnsigned(u16, args[2], 10);
    if (port == 0) return error.InvalidArguments;
    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    if (std.mem.eql(u8, args[1], "client")) {
        if (args.len != 4 or !std.Io.Dir.path.isAbsolute(args[3])) {
            return error.InvalidArguments;
        }
        try runClient(allocator, backend.io(), port, args[3]);
    } else if (std.mem.eql(u8, args[1], "server")) {
        if (args.len != 4) return error.InvalidArguments;
        const target_port = try std.fmt.parseUnsigned(u16, args[3], 10);
        if (target_port == 0) return error.InvalidArguments;
        try runServer(allocator, backend.io(), port, target_port);
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
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        ca_path,
    );
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
                .server_auth = netz.quic.tls.auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()),
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
    var path_storage: [192]u8 = undefined;
    const stream_id = try client.startConnectUdp(
        .{ .host = "dns.example", .port = 53 },
        "localhost",
        &path_storage,
    );
    var response_head: ?netz.http3.DecodedResponseHead = null;
    while (response_head == null) {
        response_head = try client.pollDetachedResponseHead(stream_id);
        if (response_head == null) {
            try client.established.connection
                .servicePacketServicingTimersDeadline(deadline);
        }
    }
    var head = response_head.?;
    defer head.deinit(allocator);
    var session = try client.acceptConnectUdpResponse(stream_id, head);
    defer session.deinit();

    var extension_storage: [64]u8 = undefined;
    const extension = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "unknown-context",
    }).writeInto(&extension_storage);
    try client.sendConnectDatagram(stream_id, extension);
    try session.sendWithDeadline(&client_payload, deadline);
    var response_storage: [server_payload.len]u8 = undefined;
    const response = try session.receiveIntoWithDeadline(
        &response_storage,
        deadline,
    );
    try std.testing.expectEqualSlices(u8, &server_payload, response.payload);
    try session.sendWithDeadline("netz-ack", deadline);
    try std.testing.expectError(
        error.ConnectionClosed,
        session.receiveIntoWithDeadline(&response_storage, deadline),
    );
    try client.closeConnectDatagramAssociation(stream_id);
    std.debug.print(
        "netz HTTP/3 CONNECT-UDP client interoperated with h3/quinn: verified=true sent={} received={} settings_datagram=true settings_extended_connect=true unknown_context=true response_terminal=true client_io=zio-std-io server_io=h3-quinn-tokio\n",
        .{ client_payload.len, response.payload.len },
    );
}

fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    target_port: u16,
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
    std.debug.print("netz HTTP/3 CONNECT-UDP server listening\n", .{});
    var connection = try server.acceptWithTimeout(.fromSeconds(5));
    defer connection.deinit();
    std.debug.print("netz HTTP/3 CONNECT-UDP server accepted QUIC\n", .{});
    try connection.ensureSettingsSent();
    var event = try connection.receiveRequestEventWithTimeout(
        .fromSeconds(5),
    );
    defer event.deinit(allocator);
    if (event != .message or event.message.value != .head) {
        return error.InvalidRequest;
    }
    const stream_id = event.message.stream_id;
    var host_storage: [128]u8 = undefined;
    const target = try connection.acceptConnectUdp(
        stream_id,
        event.message.value.head.request,
        &host_storage,
    );
    std.debug.print("netz HTTP/3 CONNECT-UDP server accepted request\n", .{});
    try std.testing.expectEqualStrings("dns.example", target.host);
    try std.testing.expectEqual(@as(u16, 53), target.port);
    var session = try connection.connectUdpSession(stream_id);
    defer session.deinit();

    var extension_storage: [64]u8 = undefined;
    const extension = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "unknown-context",
    }).writeInto(&extension_storage);
    try connection.sendConnectDatagram(stream_id, extension);

    var relay_socket = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay_socket.close(io);
    var session_storage: [4096]u8 = undefined;
    var udp_storage: [4096]u8 = undefined;
    const udp_target = std.Io.net.IpAddress{ .ip4 = .loopback(target_port) };
    const incoming = try session.receiveIntoWithTimeout(
        &session_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_payload,
        incoming.payload,
    );
    try relay_socket.send(io, &udp_target, incoming.payload);
    const proxied = try relay_socket.receiveTimeout(
        io,
        &udp_storage,
        .{ .duration = .{
            .raw = .fromSeconds(5),
            .clock = .awake,
        } },
    );
    try std.testing.expect(std.Io.net.IpAddress.eql(
        &proxied.from,
        &udp_target,
    ));
    try std.testing.expectEqualSlices(
        u8,
        &server_payload,
        proxied.data,
    );
    try session.sendWithTimeout(proxied.data, .fromSeconds(5));
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        session.receiveIntoWithTimeout(
            &session_storage,
            .fromSeconds(5),
        ),
    );
    try connection.sendResponseBody(stream_id, &.{}, true);
    try connection.closeConnectDatagramAssociation(stream_id);
    std.debug.print(
        "netz HTTP/3 CONNECT-UDP server interoperated with h3/quinn: received={} proxied_udp=true sent={} settings_datagram=true settings_extended_connect=true unknown_context=true request_terminal=true client_io=h3-quinn-tokio server_io=zio-std-io\n",
        .{ client_payload.len, server_payload.len },
    );
}
