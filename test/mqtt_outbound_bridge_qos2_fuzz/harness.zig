const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const outbound = mqtt.bridge.outbound;
const Broker = mqtt.broker.Broker;
const runtime = mqtt.runtime;

const local_subscription_id = 113;

const BrokerRunner = struct {
    broker: *Broker,
    accept_concurrency: usize,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = self.accept_concurrency,
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
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var source = try listenBroker(allocator, io, 2);
    defer source.deinit();
    var target = try listenBroker(allocator, io, 3);
    defer target.deinit();
    var source_runner = BrokerRunner{
        .broker = &source,
        .accept_concurrency = 2,
    };
    var target_runner = BrokerRunner{
        .broker = &target,
        .accept_concurrency = 3,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&source_runner},
    );
    var source_joined = false;
    defer if (!source_joined) {
        source_runner.shutdown.set(io);
        source_thread.join();
    };
    const target_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&target_runner},
    );
    var target_joined = false;
    defer if (!target_joined) {
        target_runner.shutdown.set(io);
        target_thread.join();
    };

    var subscriber = try connect(
        allocator,
        io,
        target,
        "fuzz-outbound-qos2-subscriber",
    );
    defer subscriber.close();
    const subscription_properties = [_]mqtt.Property{.{ .varint = .{
        .id = .subscription_identifier,
        .value = local_subscription_id,
    } }};
    var suback = try subscriber.subscribe(&.{.{
        .topic_filter = "remote/#",
        .qos = .exactly_once,
        .retain_as_published = true,
    }}, .{ .properties = &subscription_properties });
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x02},
        suback.suback.reason_codes,
    );

    var publisher = try connect(
        allocator,
        io,
        source,
        "fuzz-outbound-qos2-publisher",
    );
    defer publisher.close();

    var shutdown: std.Io.Event = .unset;
    var bridge: ?outbound.Bridge = try initBridge(
        allocator,
        io,
        source.address(),
        target.address(),
        &shutdown,
        tmp.dir,
        .create,
    );
    defer if (bridge) |*value| value.deinit();
    const connected = try bridge.?.connect();
    try std.testing.expect(!connected.source_session_present);
    try std.testing.expect(!connected.target_session_present);

    const sequence = input[0..@min(input.len, model.max_operations)];
    var state = model.State{};
    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        const payload = model.Payload.init(operation, index);
        const properties = [_]mqtt.Property{
            .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
            .{ .utf8_pair = .{
                .id = .user_property,
                .key = "origin",
                .value = "source-broker",
            } },
        };
        try publisher.publish(
            model.source_topics[model.topicIndex(operation)],
            if (model.deletesRetained(operation)) &.{} else &payload.bytes,
            .{
                .qos = .exactly_once,
                .retain = model.retain(operation),
                .properties = &properties,
            },
        );

        if (model.reconnectSource(operation)) {
            bridge.?.source.disconnectTransport();
            const resumed = try bridge.?.connect();
            try std.testing.expect(resumed.source_session_present);
            summary.source_resumes += 1;
        }

        try outbound.testing.stageNextDurableQoS2(&bridge.?, .{
            .timeout = model.packet_timeout,
        });
        try std.testing.expect(bridge.?.hasPendingDurableQoS2());
        switch (model.mode(operation)) {
            0 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                try finishTransaction(&bridge.?);
                summary.ordinary += 1;
            },
            1 => {
                try recreateBridge(
                    allocator,
                    io,
                    &bridge,
                    source.address(),
                    target.address(),
                    &shutdown,
                    tmp.dir,
                );
                try finishTransaction(&bridge.?);
                summary.pre_wire_restores += 1;
            },
            2 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                try outbound.testing.stageTargetPubRec(&bridge.?, .{
                    .timeout = model.packet_timeout,
                });
                try recreateBridge(
                    allocator,
                    io,
                    &bridge,
                    source.address(),
                    target.address(),
                    &shutdown,
                    tmp.dir,
                );
                try finishTransaction(&bridge.?);
                summary.pubrel_restores += 1;
            },
            3 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                bridge.?.target.disconnectTransport();
                try finishTransaction(&bridge.?);
                summary.target_resumes += 1;
            },
        }
        try std.testing.expect(!bridge.?.hasPendingDurableQoS2());
        state.apply(operation, index);
        summary.retained_writes += @intFromBool(model.retain(operation) and
            !model.deletesRetained(operation));
        summary.retained_deletes += @intFromBool(
            model.deletesRetained(operation),
        );
        try drainSubscriber(&subscriber, operation, index);
        summary.delivered += 1;
    }
    try drainNoDelivery(&subscriber);

    try bridge.?.disconnect(0);
    try publisher.disconnect(0);
    try verifyRetainedState(allocator, io, target, state, &summary);
    try subscriber.disconnect(0);
    try source_runner.stop(io, source_thread);
    source_joined = true;
    try target_runner.stop(io, target_thread);
    target_joined = true;
    return summary;
}

fn listenBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
    max_connections: usize,
) !Broker {
    return Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .limits = .{
            .max_connections = max_connections,
            .max_queued_deliveries_per_connection = model.max_operations,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .accept = .{ .protocol = .v5 },
    });
}

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: Broker,
    client_id: []const u8,
) !runtime.Connection {
    return runtime.Client.connectWithTimeout(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = client_id,
            .topic_alias_maximum = 0,
        },
        model.packet_timeout,
    );
}

fn initBridge(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_address: std.Io.net.IpAddress,
    target_address: std.Io.net.IpAddress,
    shutdown: *std.Io.Event,
    dir: std.Io.Dir,
    mode: outbound.CoordinatorMode,
) !outbound.Bridge {
    const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    return outbound.Bridge.initMany(
        allocator,
        io,
        source_address,
        target_address,
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "fuzz-outbound-qos2-source",
                .clean_start = false,
                .connect_timeout = model.packet_timeout,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "fuzz-outbound-qos2-target",
                .clean_start = false,
                .connect_timeout = model.packet_timeout,
                .properties = &session_expiry,
            },
            .source_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(1),
                .max_attempts = 1,
            },
            .target_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(1),
                .max_attempts = 1,
            },
            .rules = &.{
                .{
                    .filter = model.bridge_filters[0],
                    .qos = .exactly_once,
                    .local_prefix = "local/",
                    .remote_prefix = "remote/",
                },
                .{
                    .filter = model.bridge_filters[1],
                    .qos = .exactly_once,
                    .local_prefix = "local/",
                    .remote_prefix = "remote/",
                },
            },
            .coordinator = .{
                .bridge_id = model.bridge_id,
                .dir = dir,
                .sub_path = "outbound-qos2-fuzz.log",
                .mode = mode,
            },
        },
        shutdown,
    );
}

fn recreateBridge(
    allocator: std.mem.Allocator,
    io: std.Io,
    bridge: *?outbound.Bridge,
    source_address: std.Io.net.IpAddress,
    target_address: std.Io.net.IpAddress,
    shutdown: *std.Io.Event,
    dir: std.Io.Dir,
) !void {
    bridge.*.?.deinit();
    bridge.* = null;
    bridge.* = try initBridge(
        allocator,
        io,
        source_address,
        target_address,
        shutdown,
        dir,
        .restore,
    );
    const connected = try bridge.*.?.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expect(connected.target_session_present);
}

fn finishTransaction(bridge: *outbound.Bridge) !void {
    var attempts: usize = 0;
    while (bridge.hasPendingDurableQoS2()) {
        if (attempts == 64) return error.BridgeProgressLimitExceeded;
        _ = try bridge.step(.{
            .timeout = model.packet_timeout,
            .cancellation_check_interval = .fromMilliseconds(5),
        });
        attempts += 1;
    }
}

fn drainSubscriber(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    try connection.writePingReq();
    var pending_id: ?u16 = null;
    var delivered = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |publish| {
                if (pending_id != null or delivered) {
                    return error.UnexpectedTargetDelivery;
                }
                try validateDelivery(publish.publish, operation, index);
                pending_id = publish.publish.packet_id.?;
                try connection.writePubRec(pending_id.?, 0);
            },
            .pubrel => |release| {
                try std.testing.expectEqual(pending_id.?, release.ack.packet_id);
                try connection.writePubComp(release.ack.packet_id, 0);
                pending_id = null;
                delivered = true;
            },
            .pingresp => {
                if (pending_id != null) {
                    try connection.writePingReq();
                    continue;
                }
                try std.testing.expect(delivered);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

fn drainNoDelivery(connection: *runtime.Connection) !void {
    try connection.writePingReq();
    var event = try connection.readClientPacketEventWithTimeout(
        model.packet_timeout,
    );
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .pingresp);
}

fn validateDelivery(
    publish: mqtt.Publish,
    operation: u8,
    index: usize,
) !void {
    const payload = model.Payload.init(operation, index);
    try std.testing.expectEqualStrings(
        model.target_topics[model.topicIndex(operation)],
        publish.topic,
    );
    try std.testing.expectEqualSlices(
        u8,
        if (model.deletesRetained(operation)) &.{} else &payload.bytes,
        publish.payload,
    );
    try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.qos);
    try std.testing.expectEqual(model.retain(operation), publish.retain);
    try std.testing.expect(!publish.dup);
    var user_properties: usize = 0;
    var subscription_identifiers: usize = 0;
    for (publish.properties) |property| switch (property) {
        .utf8_pair => |value| if (value.id == .user_property) {
            try std.testing.expectEqualStrings("origin", value.key);
            try std.testing.expectEqualStrings("source-broker", value.value);
            user_properties += 1;
        },
        .varint => |value| if (value.id == .subscription_identifier) {
            try std.testing.expectEqual(local_subscription_id, value.value);
            subscription_identifiers += 1;
        },
        .two_byte => |value| if (value.id == .topic_alias) {
            return error.SourceTopicAliasLeaked;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), user_properties);
    try std.testing.expectEqual(@as(usize, 1), subscription_identifiers);
}

fn verifyRetainedState(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: Broker,
    state: model.State,
    summary: *model.Summary,
) !void {
    var probe = try connect(
        allocator,
        io,
        target,
        "fuzz-outbound-qos2-retained-probe",
    );
    defer probe.close();
    for (model.target_topics, 0..) |topic, topic_index| {
        var suback = try probe.subscribe(&.{.{
            .topic_filter = topic,
            .qos = .exactly_once,
            .retain_as_published = true,
        }}, .{});
        defer suback.deinit(allocator);
        if (state.retained[topic_index]) |retained| {
            try drainRetained(
                &probe,
                topic_index,
                retained,
            );
            summary.retained_probe_deliveries += 1;
        } else {
            try drainNoDelivery(&probe);
        }
    }
    try probe.disconnect(0);
}

fn drainRetained(
    connection: *runtime.Connection,
    topic_index: usize,
    retained: model.Retained,
) !void {
    try connection.writePingReq();
    var pending_id: ?u16 = null;
    var delivered = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |publish| {
                try std.testing.expectEqualStrings(
                    model.target_topics[topic_index],
                    publish.publish.topic,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    retained.payload[0..retained.payload_len],
                    publish.publish.payload,
                );
                try std.testing.expect(publish.publish.retain);
                pending_id = publish.publish.packet_id.?;
                try connection.writePubRec(pending_id.?, 0);
            },
            .pubrel => |release| {
                try std.testing.expectEqual(pending_id.?, release.ack.packet_id);
                try connection.writePubComp(release.ack.packet_id, 0);
                pending_id = null;
                delivered = true;
            },
            .pingresp => {
                if (pending_id != null) {
                    try connection.writePingReq();
                    continue;
                }
                try std.testing.expect(delivered);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}
