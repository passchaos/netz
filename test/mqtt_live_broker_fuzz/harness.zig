const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;
const Broker = mqtt.broker.Broker;

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

    const broker_options: mqtt.broker.Options = .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = model.max_operations,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .accept = .{
            .protocol = .v5,
            .max_outgoing_inflight = 16,
        },
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var broker = if (tls)
        try Broker.init(allocator, io, broker_options)
    else
        try Broker.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            broker_options,
        );
    defer broker.deinit();
    var tls_server = if (tls)
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
                .limits = broker_options.limits.runtime,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"mqtt"},
                .tls_handshake_timeout = model.event_timeout,
            },
        )
    else {};
    defer if (tls) tls_server.deinit();

    const ServeState = struct {
        broker: *Broker,
        tls_server: if (tls) *mqtt.tls_runtime.Server else void,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            if (tls) {
                try self.broker.serveListeners(&.{.{
                    .source = self.tls_server.pendingSource(),
                    .connection_count = 3,
                }});
            } else {
                try self.broker.serve(3);
            }
        }
    };
    var serve: ServeState = .{
        .broker = &broker,
        .tls_server = if (tls) &tls_server else {},
    };
    const server_thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) server_thread.join();

    const address = if (tls) tls_server.address() else broker.address();
    var publisher = try connect(
        allocator,
        io,
        address,
        "fuzz-publisher",
        public_key,
        tls,
    );
    defer publisher.close();
    var subscriber_zero = try connect(
        allocator,
        io,
        address,
        "fuzz-sub-zero",
        public_key,
        tls,
    );
    defer subscriber_zero.close();
    var subscriber_one = try connect(
        allocator,
        io,
        address,
        "fuzz-sub-one",
        public_key,
        tls,
    );
    defer subscriber_one.close();
    const subscribers = [2]*runtime.Connection{
        &subscriber_zero,
        &subscriber_one,
    };

    var summary = model.Summary{};
    if (tls) {
        for ([3]*runtime.Connection{
            &publisher,
            &subscriber_zero,
            &subscriber_one,
        }) |connection| {
            try validateTls(connection);
            try connection.updateTrafficKeys(true);
        }
        summary.key_updates = 3;
    }

    var state = model.State{};
    for (input[0..@min(input.len, model.max_operations)], 0..) |operation, index| {
        const subscriber_index: usize = (operation >> 3) & 0x01;
        const topic_index: usize = (operation >> 4) & 0x01;
        const payload = model.Payload.init(operation, index, topic_index);
        switch (operation & 0x07) {
            0 => try subscribe(
                subscribers[subscriber_index],
                &state,
                &summary,
                subscriber_index,
                topic_index,
            ),
            1, 6 => try unsubscribe(
                subscribers[subscriber_index],
                &state,
                &summary,
                subscriber_index,
                topic_index,
            ),
            2 => {
                try publisher.publish(
                    model.topics[topic_index],
                    &payload.bytes,
                    .{},
                );
                try state.enqueueLive(
                    topic_index,
                    model.ExpectedDelivery.message(
                        topic_index,
                        payload,
                        false,
                    ),
                );
                summary.normal_publishes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            3, 7 => {
                if (state.retained[topic_index] != null) {
                    summary.retained_replacements += 1;
                }
                try publisher.publish(
                    model.topics[topic_index],
                    &payload.bytes,
                    .{ .retain = true },
                );
                state.retained[topic_index] = payload;
                try state.enqueueLive(
                    topic_index,
                    model.ExpectedDelivery.message(
                        topic_index,
                        payload,
                        false,
                    ),
                );
                summary.retained_writes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            4 => {
                try publisher.publish(
                    model.topics[topic_index],
                    &.{},
                    .{ .retain = true },
                );
                state.retained[topic_index] = null;
                try state.enqueueLive(
                    topic_index,
                    model.ExpectedDelivery.empty(topic_index),
                );
                summary.retained_deletes += 1;
                try drainThroughPing(&publisher, null, &summary);
            },
            5 => try subscribe(
                subscribers[subscriber_index],
                &state,
                &summary,
                subscriber_index,
                topic_index,
            ),
            else => unreachable,
        }

        for (subscribers, 0..) |subscriber, subscriber_index_value| {
            try drainThroughPing(
                subscriber,
                &state.expected[subscriber_index_value],
                &summary,
            );
        }
    }

    try drainThroughPing(&publisher, null, &summary);
    for (subscribers, 0..) |subscriber, subscriber_index| {
        try drainThroughPing(
            subscriber,
            &state.expected[subscriber_index],
            &summary,
        );
    }
    if (tls) {
        try validateKeyUpdate(&publisher);
        try validateKeyUpdate(&subscriber_zero);
        try validateKeyUpdate(&subscriber_one);
    }

    try subscriber_one.disconnect(0);
    try subscriber_zero.disconnect(0);
    try publisher.disconnect(0);
    server_thread.join();
    joined = true;
    if (serve.err) |err| return err;
    return summary;
}

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    public_key: [65]u8,
    comptime tls: bool,
) !runtime.Connection {
    const options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = client_id,
        .limits = .{ .max_packet_size = 4096 },
    };
    return if (tls)
        mqtt.tls_runtime.Client.connectAddressWithTimeout(
            allocator,
            io,
            address,
            "localhost",
            .{
                .mqtt = options,
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .alpn_protocols = &.{"mqtt"},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls_handshake_timeout = model.event_timeout,
            },
            model.event_timeout,
        )
    else
        runtime.Client.connectWithTimeout(
            allocator,
            io,
            address,
            options,
            model.event_timeout,
        );
}

fn validateTls(connection: *runtime.Connection) !void {
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
}

fn validateKeyUpdate(connection: *runtime.Connection) !void {
    const counts = connection.keyUpdateCounts() orelse
        return error.MissingTlsState;
    try std.testing.expectEqual(@as(u64, 1), counts.sent);
    try std.testing.expectEqual(@as(u64, 1), counts.received);
    try std.testing.expect(!counts.awaiting_peer_response);
}

fn subscribe(
    connection: *runtime.Connection,
    state: *model.State,
    summary: *model.Summary,
    subscriber_index: usize,
    topic_index: usize,
) !void {
    var suback = try connection.subscribe(
        &.{.{
            .topic_filter = model.topics[topic_index],
            .retain_handling = 0,
        }},
        .{},
    );
    defer suback.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x00},
        suback.suback.reason_codes,
    );

    const already_subscribed =
        state.subscribed[subscriber_index][topic_index];
    if (already_subscribed) summary.subscription_replacements += 1;
    state.subscribed[subscriber_index][topic_index] = true;
    if (state.retained[topic_index]) |payload| {
        try state.expected[subscriber_index].append(
            model.ExpectedDelivery.message(topic_index, payload, true),
        );
        summary.retained_replays += 1;
    }
    summary.subscribes += 1;
}

fn unsubscribe(
    connection: *runtime.Connection,
    state: *model.State,
    summary: *model.Summary,
    subscriber_index: usize,
    topic_index: usize,
) !void {
    const existed = state.subscribed[subscriber_index][topic_index];
    var unsuback = try connection.unsubscribe(
        &.{model.topics[topic_index]},
        .{},
    );
    defer unsuback.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        if (existed) &.{0x00} else &.{0x11},
        unsuback.unsuback.reason_codes,
    );
    state.subscribed[subscriber_index][topic_index] = false;
    summary.unsubscribes += 1;
}

fn drainThroughPing(
    connection: *runtime.Connection,
    expected_queue: ?*model.ExpectedQueue,
    summary: *model.Summary,
) !void {
    try connection.writePingReq();
    var observed: usize = 0;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.event_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |delivery| {
                const queue = expected_queue orelse
                    return error.UnexpectedPublisherDelivery;
                if (observed >= queue.len) return error.UnexpectedDelivery;
                const expected = queue.items[observed];
                try std.testing.expectEqualStrings(
                    model.topics[expected.topic_index],
                    delivery.publish.topic,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    expected.payload[0..expected.payload_len],
                    delivery.publish.payload,
                );
                try std.testing.expectEqual(
                    mqtt.QoS.at_most_once,
                    delivery.publish.qos,
                );
                try std.testing.expectEqual(
                    expected.retain,
                    delivery.publish.retain,
                );
                try std.testing.expectEqual(
                    @as(?u16, null),
                    delivery.publish.packet_id,
                );
                observed += 1;
                summary.deliveries += 1;
            },
            .pingresp => {
                if (expected_queue) |queue| {
                    try std.testing.expectEqual(queue.len, observed);
                    queue.clear();
                } else {
                    try std.testing.expectEqual(@as(usize, 0), observed);
                }
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}
