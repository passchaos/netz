const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const peer = @import("peer.zig");

const mqtt = netz.mqtt;
const reconnect = mqtt.reconnect;
const runtime = mqtt.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, false);
}

pub fn runTlsSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, true);
}

fn runSequenceWithTransport(
    input: []const u8,
    comptime tls: bool,
) !model.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const Server = if (tls) mqtt.tls_runtime.Server else runtime.Server;
    var server: Server = if (tls)
        try mqtt.tls_runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = .{ .max_packet_size = 4096 },
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"mqtt"},
                .tls_handshake_timeout = model.packet_timeout,
            },
        )
    else
        try runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_packet_size = 4096 },
        );
    var server_open = true;
    defer if (server_open) server.deinit();

    const sequence = input[0..@min(input.len, model.max_operations)];
    const ServerState = peer.ServerState(Server, tls);
    var server_state = ServerState{
        .server = &server,
        .input = sequence,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerState.run,
        .{&server_state},
    );
    var joined = false;
    defer if (!joined) {
        server.deinit();
        server_open = false;
        server_thread.join();
    };

    var shutdown: std.Io.Event = .unset;
    const connect_properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var connector = if (tls) mqtt.tls_runtime.ReconnectConnector{
        .address = server.address(),
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = model.packet_timeout,
        },
    } else {};
    const connect_options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = "fuzz-reconnect",
        .clean_start = false,
        .connect_timeout = model.packet_timeout,
        .properties = &connect_properties,
    };
    const policy: reconnect.ReconnectPolicy = .{
        .initial_delay = .fromMilliseconds(1),
        .max_delay = .fromMilliseconds(1),
        .max_attempts = 1,
    };
    var client = if (tls)
        try reconnect.Client.initConnectorWithOptions(
            allocator,
            io,
            connector.connector(),
            connect_options,
            policy,
            &shutdown,
            .{ .max_subscriptions = model.topics.len },
        )
    else
        try reconnect.Client.initWithOptions(
            allocator,
            io,
            server.address(),
            connect_options,
            policy,
            &shutdown,
            .{ .max_subscriptions = model.topics.len },
        );
    defer client.deinit();
    const initial = try client.connect();
    try std.testing.expect(!initial.session_present);
    if (tls) try validateTls(client.connection().?, &certificate_der);

    var expected_subscriptions: [model.topics.len]bool = .{ false, false };
    for (sequence, 0..) |operation, index| {
        const topic_index: usize = (operation >> 4) & 0x01;
        const retain = operation & 0x20 != 0;
        const subscription_qos: mqtt.QoS = if (operation & 0x40 != 0)
            .at_least_once
        else
            .at_most_once;
        const session_present = operation & 0x08 != 0;
        const payload = model.Payload.init(operation, index);
        switch (operation & 0x07) {
            0 => try publishQoS1(
                &client,
                topic_index,
                retain,
                payload,
                null,
            ),
            1 => try publishQoS1(
                &client,
                topic_index,
                retain,
                payload,
                session_present,
            ),
            2 => try publishQoS2(
                &client,
                topic_index,
                retain,
                payload,
                null,
                false,
            ),
            3 => try publishQoS2(
                &client,
                topic_index,
                retain,
                payload,
                session_present,
                false,
            ),
            4 => try publishQoS2(
                &client,
                topic_index,
                retain,
                payload,
                session_present,
                true,
            ),
            5 => {
                const properties = [_]mqtt.Property{.{ .varint = .{
                    .id = .subscription_identifier,
                    .value = topic_index + 1,
                } }};
                var suback = try client.subscribe(
                    &.{.{
                        .topic_filter = model.topics[topic_index],
                        .qos = subscription_qos,
                    }},
                    .{ .properties = &properties },
                );
                defer suback.deinit(allocator);
                try std.testing.expectEqualSlices(
                    u8,
                    &.{@intFromEnum(subscription_qos)},
                    suback.suback.reason_codes,
                );
                expected_subscriptions[topic_index] = true;
            },
            6 => {
                const existed = expected_subscriptions[topic_index];
                var unsuback = try client.unsubscribe(
                    &.{model.topics[topic_index]},
                    .{},
                );
                defer unsuback.deinit(allocator);
                try std.testing.expectEqualSlices(
                    u8,
                    if (existed) &.{0x00} else &.{0x11},
                    unsuback.unsuback.reason_codes,
                );
                expected_subscriptions[topic_index] = false;
            },
            7 => {
                const connected = try client.reconnect();
                try std.testing.expectEqual(
                    session_present,
                    connected.session_present,
                );
                try client.connection().?.pingWithTimeout(
                    model.packet_timeout,
                );
            },
            else => unreachable,
        }

        try std.testing.expectEqual(
            @as(usize, @intFromBool(expected_subscriptions[0])) +
                @as(usize, @intFromBool(expected_subscriptions[1])),
            client.subscriptionCount(),
        );
        if (tls) try validateTls(client.connection().?, &certificate_der);
    }

    try client.disconnect(0);
    server_thread.join();
    joined = true;
    if (server_state.err) |err| return err;
    return server_state.summary;
}

fn validateTls(
    connection: *runtime.Connection,
    certificate_der: []const u8,
) !void {
    try std.testing.expectEqualStrings(
        "mqtt",
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.CipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
    const chain = connection.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqualSlices(u8, certificate_der, chain[0]);
}

fn publishQoS1(
    client: *reconnect.Client,
    topic_index: usize,
    retain: bool,
    payload: model.Payload,
    reconnect_session: ?bool,
) !void {
    const packet_id = (try client.publish(
        model.topics[topic_index],
        &payload.bytes,
        .{ .qos = .at_least_once, .retain = retain },
    )).?;
    if (reconnect_session == false) {
        try std.testing.expectError(
            error.SessionLost,
            client.completeNextPublish(),
        );
        try expectReleased(client, packet_id);
        try client.connection().?.pingWithTimeout(model.packet_timeout);
        return;
    }
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    try expectReleased(client, packet_id);
}

fn publishQoS2(
    client: *reconnect.Client,
    topic_index: usize,
    retain: bool,
    payload: model.Payload,
    reconnect_session: ?bool,
    disconnect_after_pubrel: bool,
) !void {
    const packet_id = (try client.publish(
        model.topics[topic_index],
        &payload.bytes,
        .{ .qos = .exactly_once, .retain = retain },
    )).?;

    if (disconnect_after_pubrel) {
        try std.testing.expectEqual(packet_id, try client.completeNextPublish());
        try expectState(client, packet_id, .await_pubcomp);
    }

    if (reconnect_session == false) {
        try std.testing.expectError(
            error.SessionLost,
            client.completeNextPublish(),
        );
        try expectReleased(client, packet_id);
        try client.connection().?.pingWithTimeout(model.packet_timeout);
        return;
    }

    if (!disconnect_after_pubrel) {
        try std.testing.expectEqual(packet_id, try client.completeNextPublish());
        try expectState(client, packet_id, .await_pubcomp);
    }
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    try expectReleased(client, packet_id);
}

fn expectState(
    client: *reconnect.Client,
    packet_id: u16,
    expected: mqtt.session.OutgoingQoSState,
) !void {
    try std.testing.expectEqual(
        expected,
        (try client.outgoingQoSState(packet_id)).?,
    );
}

fn expectReleased(client: *reconnect.Client, packet_id: u16) !void {
    try std.testing.expectEqual(
        @as(?mqtt.session.OutgoingQoSState, null),
        try client.outgoingQoSState(packet_id),
    );
}
