const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

pub fn ServerState(
    comptime Server: type,
    comptime expected_alpn: ?[]const u8,
) type {
    return struct {
        server: *Server,
        input: []const u8,
        assigned_identity: bool = false,
        summary: model.Summary = .{},
        err: ?anyerror = null,

        pub fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var active: ?runtime.AcceptedClient = try self.server.accept(.{
                .protocol = .v5,
                .assigned_client_identifier = if (self.assigned_identity) "fuzz-assigned" else null,
            });
            defer if (active) |*connection| {
                connection.deinit(self.server.allocator);
            };
            try validateConnect(active.?.connect.connect, if (self.assigned_identity) "" else "fuzz-reconnect");
            if (expected_alpn) |alpn| {
                try validateTls(&active.?.connection, alpn);
            }

            var subscriptions = model.SubscriptionModel{};
            for (
                self.input[0..@min(self.input.len, model.max_operations)],
                0..,
            ) |operation, index| {
                const topic_index: usize = (operation >> 4) & 0x01;
                const retain = operation & 0x20 != 0;
                const subscription_qos: mqtt.QoS = if (operation & 0x40 != 0)
                    .at_least_once
                else
                    .at_most_once;
                const session_present = operation & 0x08 != 0;
                const payload = model.Payload.init(operation, index);
                switch (operation & 0x07) {
                    0 => try handleQoS1Success(
                        &active.?.connection,
                        topic_index,
                        retain,
                        payload,
                    ),
                    1 => try self.handleQoS1Reconnect(
                        &active,
                        subscriptions,
                        topic_index,
                        retain,
                        payload,
                        session_present,
                    ),
                    2 => try handleQoS2Success(
                        &active.?.connection,
                        topic_index,
                        retain,
                        payload,
                    ),
                    3 => try self.handleQoS2PublishReconnect(
                        &active,
                        subscriptions,
                        topic_index,
                        retain,
                        payload,
                        session_present,
                    ),
                    4 => try self.handleQoS2PubRelReconnect(
                        &active,
                        subscriptions,
                        topic_index,
                        retain,
                        payload,
                        session_present,
                    ),
                    5 => try handleSubscribe(
                        &active.?.connection,
                        &subscriptions,
                        topic_index,
                        subscription_qos,
                    ),
                    6 => try handleUnsubscribe(
                        &active.?.connection,
                        &subscriptions,
                        topic_index,
                    ),
                    7 => {
                        try self.replaceConnection(
                            &active,
                            &subscriptions,
                            session_present,
                        );
                        try pingBarrier(&active.?.connection);
                        self.summary.empty_reconnect_barriers += 1;
                    },
                    else => unreachable,
                }
            }

            var event = try active.?.connection.readBrokerEventWithTimeout(
                model.packet_timeout,
            );
            defer event.deinit(self.server.allocator);
            switch (event) {
                .disconnect => |disconnect| try std.testing.expectEqual(
                    @as(u8, 0),
                    disconnect.disconnect.reason_code,
                ),
                else => return error.ExpectedDisconnect,
            }
        }

        fn replaceConnection(
            self: *@This(),
            active: *?runtime.AcceptedClient,
            subscriptions: *const model.SubscriptionModel,
            session_present: bool,
        ) !void {
            if (active.*) |*connection| {
                connection.connection.shutdown() catch {};
                connection.deinit(self.server.allocator);
                active.* = null;
            }

            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            errdefer pending.deinit(self.server.allocator);
            active.* = try pending.finish(.{
                .protocol = .v5,
                .session_present = session_present,
            });
            try validateConnect(active.*.?.connect.connect, if (self.assigned_identity) "fuzz-assigned" else "fuzz-reconnect");
            if (expected_alpn) |alpn| {
                try validateTls(&active.*.?.connection, alpn);
            }
            self.summary.reconnects += 1;
            if (session_present) {
                self.summary.resumed_sessions += 1;
            } else {
                self.summary.fresh_sessions += 1;
                try replaySubscriptions(
                    &active.*.?.connection,
                    subscriptions.*,
                    &self.summary,
                );
            }
        }

        fn handleQoS1Reconnect(
            self: *@This(),
            active: *?runtime.AcceptedClient,
            subscriptions: model.SubscriptionModel,
            topic_index: usize,
            retain: bool,
            payload: model.Payload,
            session_present: bool,
        ) !void {
            const packet_id = try expectPublish(
                &active.*.?.connection,
                topic_index,
                retain,
                payload,
                .at_least_once,
                false,
            );
            try self.replaceConnection(active, &subscriptions, session_present);
            if (!session_present) {
                self.summary.session_losses += 1;
                try pingBarrier(&active.*.?.connection);
                return;
            }
            const replay_id = try expectPublish(
                &active.*.?.connection,
                topic_index,
                retain,
                payload,
                .at_least_once,
                true,
            );
            try std.testing.expectEqual(packet_id, replay_id);
            try active.*.?.connection.writePubAck(replay_id, 0);
            self.summary.publish_replays += 1;
        }

        fn handleQoS2PublishReconnect(
            self: *@This(),
            active: *?runtime.AcceptedClient,
            subscriptions: model.SubscriptionModel,
            topic_index: usize,
            retain: bool,
            payload: model.Payload,
            session_present: bool,
        ) !void {
            const packet_id = try expectPublish(
                &active.*.?.connection,
                topic_index,
                retain,
                payload,
                .exactly_once,
                false,
            );
            try self.replaceConnection(active, &subscriptions, session_present);
            if (!session_present) {
                self.summary.session_losses += 1;
                try pingBarrier(&active.*.?.connection);
                return;
            }
            const replay_id = try expectPublish(
                &active.*.?.connection,
                topic_index,
                retain,
                payload,
                .exactly_once,
                true,
            );
            try std.testing.expectEqual(packet_id, replay_id);
            try finishQoS2(&active.*.?.connection, replay_id);
            self.summary.publish_replays += 1;
        }

        fn handleQoS2PubRelReconnect(
            self: *@This(),
            active: *?runtime.AcceptedClient,
            subscriptions: model.SubscriptionModel,
            topic_index: usize,
            retain: bool,
            payload: model.Payload,
            session_present: bool,
        ) !void {
            const packet_id = try expectPublish(
                &active.*.?.connection,
                topic_index,
                retain,
                payload,
                .exactly_once,
                false,
            );
            try active.*.?.connection.writePubRec(packet_id, 0);
            var pubrel = try active.*.?.connection.readPubRel();
            try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
            pubrel.deinit(self.server.allocator);

            try self.replaceConnection(active, &subscriptions, session_present);
            if (!session_present) {
                self.summary.session_losses += 1;
                try pingBarrier(&active.*.?.connection);
                return;
            }
            var replay = try active.*.?.connection.readSessionPubRel();
            defer replay.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, replay.ack.packet_id);
            try active.*.?.connection.writePubComp(packet_id, 0);
            self.summary.pubrel_replays += 1;
        }
    };
}

fn validateTls(connection: *runtime.Connection, expected_alpn: []const u8) !void {
    try std.testing.expectEqualStrings(
        expected_alpn,
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
}

fn validateConnect(connect: mqtt.Connect, expected_identity: []const u8) !void {
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectEqualStrings(expected_identity, connect.client_id);
    try std.testing.expectEqual(
        @as(?u32, 60),
        mqtt.sessionExpiryInterval(connect.properties),
    );
}

fn expectPublish(
    connection: *runtime.Connection,
    topic_index: usize,
    retain: bool,
    payload: model.Payload,
    qos: mqtt.QoS,
    dup: bool,
) !u16 {
    var event = try connection.readBrokerEventWithTimeout(
        model.packet_timeout,
    );
    defer event.deinit(std.testing.allocator);
    const publish = switch (event) {
        .publish => |value| value.publish,
        else => return error.ExpectedPublish,
    };
    try std.testing.expectEqualStrings(model.topics[topic_index], publish.topic);
    try std.testing.expectEqualSlices(u8, &payload.bytes, publish.payload);
    try std.testing.expectEqual(qos, publish.qos);
    try std.testing.expectEqual(retain, publish.retain);
    try std.testing.expectEqual(dup, publish.dup);
    return publish.packet_id orelse error.ExpectedPacketIdentifier;
}

fn handleQoS1Success(
    connection: *runtime.Connection,
    topic_index: usize,
    retain: bool,
    payload: model.Payload,
) !void {
    const packet_id = try expectPublish(
        connection,
        topic_index,
        retain,
        payload,
        .at_least_once,
        false,
    );
    try connection.writePubAck(packet_id, 0);
}

fn handleQoS2Success(
    connection: *runtime.Connection,
    topic_index: usize,
    retain: bool,
    payload: model.Payload,
) !void {
    const packet_id = try expectPublish(
        connection,
        topic_index,
        retain,
        payload,
        .exactly_once,
        false,
    );
    try finishQoS2(connection, packet_id);
}

fn finishQoS2(connection: *runtime.Connection, packet_id: u16) !void {
    try connection.writePubRec(packet_id, 0);
    var pubrel = try connection.readPubRel();
    defer pubrel.deinit(std.testing.allocator);
    try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
    try connection.writePubComp(packet_id, 0);
}

fn handleSubscribe(
    connection: *runtime.Connection,
    subscription_model: *model.SubscriptionModel,
    topic_index: usize,
    qos: mqtt.QoS,
) !void {
    var event = try connection.readBrokerEventWithTimeout(model.packet_timeout);
    defer event.deinit(std.testing.allocator);
    const subscribe = switch (event) {
        .subscribe => |value| value.subscribe,
        else => return error.ExpectedSubscribe,
    };
    try validateSubscription(subscribe, topic_index, qos);
    try connection.writeSubAck(
        subscribe.packet_id,
        &.{@intFromEnum(qos)},
        &.{},
    );
    subscription_model.set(topic_index, qos);
}

fn handleUnsubscribe(
    connection: *runtime.Connection,
    subscription_model: *model.SubscriptionModel,
    topic_index: usize,
) !void {
    var event = try connection.readBrokerEventWithTimeout(model.packet_timeout);
    defer event.deinit(std.testing.allocator);
    const unsubscribe = switch (event) {
        .unsubscribe => |value| value.unsubscribe,
        else => return error.ExpectedUnsubscribe,
    };
    try std.testing.expectEqual(@as(usize, 1), unsubscribe.topic_filters.len);
    try std.testing.expectEqualStrings(
        model.topics[topic_index],
        unsubscribe.topic_filters[0],
    );
    const existed = subscription_model.remove(topic_index);
    try connection.writeUnsubAck(
        unsubscribe.packet_id,
        if (existed) &.{0x00} else &.{0x11},
        &.{},
    );
}

fn replaySubscriptions(
    connection: *runtime.Connection,
    subscriptions: model.SubscriptionModel,
    summary: *model.Summary,
) !void {
    for (subscriptions.order[0..subscriptions.len]) |topic_index| {
        var event = try connection.readBrokerEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        const subscribe = switch (event) {
            .subscribe => |value| value.subscribe,
            else => return error.ExpectedSubscriptionReplay,
        };
        try validateSubscription(
            subscribe,
            topic_index,
            subscriptions.qos[topic_index],
        );
        try connection.writeSubAck(
            subscribe.packet_id,
            &.{@intFromEnum(subscriptions.qos[topic_index])},
            &.{},
        );
        summary.subscription_replays += 1;
    }
}

fn validateSubscription(
    subscribe: mqtt.Subscribe,
    topic_index: usize,
    qos: mqtt.QoS,
) !void {
    try std.testing.expectEqual(@as(usize, 1), subscribe.subscriptions.len);
    try std.testing.expectEqualStrings(
        model.topics[topic_index],
        subscribe.subscriptions[0].topic_filter,
    );
    try std.testing.expectEqual(qos, subscribe.subscriptions[0].qos);
    try std.testing.expectEqual(
        @as(?usize, topic_index + 1),
        mqtt.subscriptionIdentifier(subscribe.properties),
    );
}

fn pingBarrier(connection: *runtime.Connection) !void {
    var event = try connection.readBrokerEventWithTimeout(model.packet_timeout);
    defer event.deinit(std.testing.allocator);
    switch (event) {
        .pingreq => try connection.writePingResp(),
        else => return error.ExpectedPing,
    }
}
