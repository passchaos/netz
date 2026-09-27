const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const peer = @import("peer.zig");

const mqtt = netz.mqtt;
const bridge_mod = mqtt.bridge;
const Broker = mqtt.broker.Broker;
const runtime = mqtt.runtime;

const local_subscription_id = 91;

const BrokerRunner = struct {
    broker: *Broker,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = 2,
        }}, .{
            .shutdown = &self.shutdown,
        }) catch |err| {
            self.err = err;
        };
    }

    fn stop(self: *@This(), io: std.Io, thread: std.Thread) !void {
        self.shutdown.set(io);
        thread.join();
        if (self.err) |err| return err;
    }
};

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

    var local = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = model.max_operations,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{ .broker = &local };
    const local_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&local_runner},
    );
    var local_joined = false;
    defer if (!local_joined) {
        local_runner.shutdown.set(io);
        local_thread.join();
    };

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "fuzz-bridge-subscriber",
            .topic_alias_maximum = 0,
        },
        model.packet_timeout,
    );
    defer subscriber.close();
    const subscription_properties = [_]mqtt.Property{.{ .varint = .{
        .id = .subscription_identifier,
        .value = local_subscription_id,
    } }};
    var suback = try subscriber.subscribe(&.{.{
        .topic_filter = "mirror/#",
        .qos = .at_least_once,
        .retain_as_published = true,
    }}, .{ .properties = &subscription_properties });
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x01},
        suback.suback.reason_codes,
    );

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const Server = if (tls) mqtt.tls_runtime.Server else runtime.Server;
    var remote: Server = if (tls)
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
    var remote_open = true;
    defer if (remote_open) remote.deinit();
    const sequence = input[0..@min(input.len, model.max_operations)];
    const PeerState = peer.State(Server, tls);
    var peer_state = PeerState{
        .server = &remote,
        .input = sequence,
    };
    const peer_thread = try std.Thread.spawn(
        .{},
        PeerState.run,
        .{&peer_state},
    );
    var peer_joined = false;

    var bridge_shutdown: std.Io.Event = .unset;
    const connect_properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var connector = if (tls) mqtt.tls_runtime.ReconnectConnector{
        .address = remote.address(),
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
    const options: bridge_mod.MultiOptions = .{
        .connect = .{
            .protocol = .v5,
            .client_id = "fuzz-inbound-bridge",
            .clean_start = false,
            .connect_timeout = model.packet_timeout,
            .properties = &connect_properties,
        },
        .reconnect_policy = .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
            .max_attempts = 1,
        },
        .rules = &.{
            .{
                .filter = model.remote_topics[0],
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
            .{
                .filter = model.remote_topics[1],
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
    };
    var bridge = (if (tls)
        bridge_mod.Bridge.initConnectorMany(
            allocator,
            io,
            &local,
            connector.connector(),
            options,
            &bridge_shutdown,
        )
    else
        bridge_mod.Bridge.initMany(
            allocator,
            io,
            &local,
            remote.address(),
            options,
            &bridge_shutdown,
        )) catch |err| {
        remote.deinit();
        remote_open = false;
        peer_thread.join();
        return err;
    };
    defer bridge.deinit();
    defer if (!peer_joined) {
        remote.deinit();
        remote_open = false;
        peer_thread.join();
    };

    const connected = try bridge.connect();
    try std.testing.expect(!connected.session_present);
    if (tls) try validateTls(bridge.client.connection().?, &certificate_der);
    var expected = model.State{};
    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        const kind = operation & 0x07;
        try std.testing.expect(try bridge.step(.{
            .timeout = model.packet_timeout,
        }));
        if (tls) {
            try validateTls(bridge.client.connection().?, &certificate_der);
        }
        if (kind == 5 or kind == 6) {
            try drainThroughPing(&subscriber, null, &summary);
            continue;
        }
        const delivery = expected.apply(operation, index).?;
        if (kind == 2 or kind == 3) summary.retained_writes += 1;
        if (kind == 4) summary.retained_deletes += 1;
        if (kind == 7) summary.duplicate_inputs += 1;
        try drainThroughPing(&subscriber, delivery, &summary);
    }
    try drainThroughPing(&subscriber, null, &summary);

    try bridge.disconnect(0);
    peer_thread.join();
    peer_joined = true;
    if (peer_state.err) |err| return err;
    summary.qos1_acknowledgements = peer_state.summary
        .qos1_acknowledgements;
    summary.fresh_reconnects = peer_state.summary.fresh_reconnects;
    summary.resumed_reconnects = peer_state.summary.resumed_reconnects;
    summary.subscription_replays = peer_state.summary.subscription_replays;

    try verifyRetainedState(allocator, io, local, expected, &summary);
    try subscriber.disconnect(0);
    try local_runner.stop(io, local_thread);
    local_joined = true;
    return summary;
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

fn drainThroughPing(
    connection: *runtime.Connection,
    expected: ?model.Delivery,
    summary: *model.Summary,
) !void {
    try connection.writePingReq();
    var observed = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |delivery| {
                if (observed) return error.UnexpectedBridgeDelivery;
                try validateDelivery(delivery.publish, expected orelse {
                    return error.UnexpectedBridgeDelivery;
                }, local_subscription_id);
                if (delivery.publish.qos == .at_least_once) {
                    try connection.writePubAck(
                        delivery.publish.packet_id.?,
                        0,
                    );
                }
                observed = true;
                summary.deliveries += 1;
            },
            .pingresp => {
                try std.testing.expectEqual(expected != null, observed);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

fn verifyRetainedState(
    allocator: std.mem.Allocator,
    io: std.Io,
    local: Broker,
    expected: model.State,
    summary: *model.Summary,
) !void {
    var probe = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "fuzz-bridge-retained-probe",
            .topic_alias_maximum = 0,
        },
        model.packet_timeout,
    );
    defer probe.close();

    for (model.local_topics, 0..) |topic, topic_index| {
        const identifier = 101 + topic_index;
        const properties = [_]mqtt.Property{.{ .varint = .{
            .id = .subscription_identifier,
            .value = identifier,
        } }};
        var suback = try probe.subscribe(&.{.{
            .topic_filter = topic,
            .qos = .at_least_once,
            .retain_as_published = true,
        }}, .{ .properties = &properties });
        defer suback.deinit(allocator);
        try std.testing.expectEqualSlices(
            u8,
            &.{0x01},
            suback.suback.reason_codes,
        );
        if (expected.retained[topic_index]) |retained| {
            try drainProbeThroughPing(
                &probe,
                retained,
                identifier,
                summary,
            );
        } else {
            try drainProbeThroughPing(&probe, null, identifier, summary);
        }
    }
    try drainProbeThroughPing(&probe, null, 0, summary);
    try probe.disconnect(0);
}

fn drainProbeThroughPing(
    connection: *runtime.Connection,
    expected: ?model.Delivery,
    subscription_id: usize,
    summary: *model.Summary,
) !void {
    try connection.writePingReq();
    var observed = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |delivery| {
                if (observed) return error.UnexpectedRetainedDelivery;
                const retained = expected orelse
                    return error.UnexpectedRetainedDelivery;
                try validateDelivery(
                    delivery.publish,
                    .{
                        .topic_index = retained.topic_index,
                        .payload = retained.payload,
                        .payload_len = retained.payload_len,
                        .qos = retained.qos,
                        .retain = true,
                    },
                    subscription_id,
                );
                if (delivery.publish.qos == .at_least_once) {
                    try connection.writePubAck(
                        delivery.publish.packet_id.?,
                        0,
                    );
                }
                observed = true;
                summary.retained_probe_deliveries += 1;
            },
            .pingresp => {
                try std.testing.expectEqual(expected != null, observed);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

fn validateDelivery(
    publish: mqtt.Publish,
    expected: model.Delivery,
    subscription_id: usize,
) !void {
    try std.testing.expectEqualStrings(
        model.local_topics[expected.topic_index],
        publish.topic,
    );
    try std.testing.expectEqualSlices(
        u8,
        expected.payload[0..expected.payload_len],
        publish.payload,
    );
    try std.testing.expectEqual(expected.qos, publish.qos);
    try std.testing.expectEqual(expected.retain, publish.retain);
    try std.testing.expect(!publish.dup);
    try expectBridgeProperties(publish.properties, subscription_id);
}

fn expectBridgeProperties(
    properties: []const mqtt.Property,
    subscription_id: usize,
) !void {
    var user_properties: usize = 0;
    var subscription_identifiers: usize = 0;
    for (properties) |property| switch (property) {
        .utf8_pair => |value| if (value.id == .user_property) {
            try std.testing.expectEqualStrings("origin", value.key);
            try std.testing.expectEqualStrings("remote", value.value);
            user_properties += 1;
        },
        .varint => |value| if (value.id == .subscription_identifier) {
            try std.testing.expectEqual(subscription_id, value.value);
            subscription_identifiers += 1;
        },
        .two_byte => |value| if (value.id == .topic_alias) {
            return error.RemoteTopicAliasLeaked;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), user_properties);
    try std.testing.expectEqual(@as(usize, 1), subscription_identifiers);
}
