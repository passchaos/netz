const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

const remote_properties = [_]mqtt.Property{
    .{ .utf8_pair = .{
        .id = .user_property,
        .key = "origin",
        .value = "remote",
    } },
    .{ .varint = .{
        .id = .subscription_identifier,
        .value = 77,
    } },
    .{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } },
};

pub fn State(comptime Server: type, comptime tls: bool) type {
    return struct {
        server: *Server,
        input: []const u8,
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
            });
            defer if (active) |*connection| {
                connection.deinit(self.server.allocator);
            };
            try validateConnect(active.?.connect.connect);
            if (tls) try validateTls(&active.?.connection);
            try expectInitialSubscriptions(&active.?.connection);

            for (
                self.input[0..@min(self.input.len, model.max_operations)],
                0..,
            ) |operation, index| {
                const kind = operation & 0x07;
                if (kind == 5 or kind == 6) {
                    const session_present = kind == 6;
                    try self.replaceConnection(&active, session_present);
                    continue;
                }
                try self.sendPublish(&active.?.connection, operation, index);
            }

            var disconnect = try active.?.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(u8, 0),
                disconnect.disconnect.reason_code,
            );
        }

        fn replaceConnection(
            self: *@This(),
            active: *?runtime.AcceptedClient,
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
            try validateConnect(active.*.?.connect.connect);
            if (tls) try validateTls(&active.*.?.connection);
            if (session_present) {
                self.summary.resumed_reconnects += 1;
            } else {
                self.summary.fresh_reconnects += 1;
                try expectReplayedSubscriptions(
                    &active.*.?.connection,
                    &self.summary,
                );
            }
        }

        fn sendPublish(
            self: *@This(),
            connection: *runtime.Connection,
            operation: u8,
            index: usize,
        ) !void {
            const kind = operation & 0x07;
            const topic_index: usize = (operation >> 3) & 0x01;
            const qos: mqtt.QoS = switch (kind) {
                0, 2 => .at_most_once,
                1, 3, 4, 7 => .at_least_once,
                else => unreachable,
            };
            const retain = kind == 2 or kind == 3 or kind == 4;
            const payload = model.Payload.init(operation, index);
            const packet_id = try connection.writePublish(
                model.remote_topics[topic_index],
                if (kind == 4) &.{} else &payload.bytes,
                .{
                    .qos = qos,
                    .retain = retain,
                    .dup = kind == 7,
                    .properties = &remote_properties,
                },
            );
            if (qos == .at_most_once) {
                try std.testing.expect(packet_id == null);
                return;
            }
            var acknowledgement = try connection.readPubAck();
            defer acknowledgement.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id.?, acknowledgement.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0), acknowledgement.ack.reason_code);
            self.summary.qos1_acknowledgements += 1;
        }
    };
}

fn validateTls(connection: *runtime.Connection) !void {
    try std.testing.expectEqualStrings(
        "mqtt",
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

fn validateConnect(connect: mqtt.Connect) !void {
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectEqualStrings("fuzz-inbound-bridge", connect.client_id);
    try std.testing.expectEqual(
        @as(?u32, 60),
        mqtt.sessionExpiryInterval(connect.properties),
    );
}

fn expectInitialSubscriptions(connection: *runtime.Connection) !void {
    var subscribe = try connection.readSubscribe();
    defer subscribe.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(usize, model.remote_topics.len),
        subscribe.subscribe.subscriptions.len,
    );
    for (subscribe.subscribe.subscriptions, 0..) |subscription, index| {
        try validateSubscription(subscription, index);
    }
    try connection.writeSubAck(
        subscribe.subscribe.packet_id,
        &.{ 0x01, 0x01 },
        &.{},
    );
}

fn expectReplayedSubscriptions(
    connection: *runtime.Connection,
    summary: *model.Summary,
) !void {
    for (model.remote_topics, 0..) |_, index| {
        var subscribe = try connection.readSubscribe();
        defer subscribe.deinit(std.testing.allocator);
        try std.testing.expectEqual(
            @as(usize, 1),
            subscribe.subscribe.subscriptions.len,
        );
        try validateSubscription(
            subscribe.subscribe.subscriptions[0],
            index,
        );
        try connection.writeSubAck(
            subscribe.subscribe.packet_id,
            &.{0x01},
            &.{},
        );
        summary.subscription_replays += 1;
    }
}

fn validateSubscription(
    subscription: mqtt.Subscription,
    index: usize,
) !void {
    try std.testing.expectEqualStrings(
        model.remote_topics[index],
        subscription.topic_filter,
    );
    try std.testing.expectEqual(mqtt.QoS.at_least_once, subscription.qos);
    try std.testing.expect(subscription.retain_as_published);
}
