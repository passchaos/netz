const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

const publish_properties = [_]mqtt.Property{
    .{ .two_byte = .{ .id = .topic_alias, .value = 7 } },
    .{ .varint = .{ .id = .subscription_identifier, .value = 13 } },
    .{ .utf8_pair = .{
        .id = .user_property,
        .key = "bridge",
        .value = "outbound-fuzz",
    } },
};

pub const State = struct {
    server: *runtime.Server,
    allocator: std.mem.Allocator,
    io: std.Io,
    input: []const u8,
    signals: *model.Signals,
    summary: model.Summary = .{},
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var active: ?runtime.AcceptedClient = try self.accept(false);
        defer if (active) |*connection| {
            connection.deinit(self.allocator);
        };
        try expectSubscriptions(&active.?.connection, null);

        for (
            self.input[0..@min(self.input.len, model.max_operations)],
            0..,
        ) |operation, index| {
            const kind = operation & 0x07;
            if (kind == 4 or kind == 5) {
                const session_present = kind == 4;
                try replaceConnection(
                    self,
                    &active,
                    session_present,
                    true,
                );
                if (session_present) {
                    self.summary.source_resumed += 1;
                } else {
                    try expectSubscriptions(
                        &active.?.connection,
                        &self.summary,
                    );
                    self.summary.source_fresh += 1;
                }
                self.signals.source_reconnected[index].set(self.io);
                self.signals.source_completed.store(index + 1, .release);
                self.signals.target_done[index].waitUncancelable(
                    self.io,
                );
                continue;
            }
            const payload = model.Payload.init(operation, index);
            const packet_id = try sendPublish(
                &active.?.connection,
                operation,
                payload,
                false,
                @intCast(index + 1),
            );
            if (model.qos(operation) == .at_most_once) {
                self.signals.source_completed.store(index + 1, .release);
                self.signals.target_done[index].waitUncancelable(
                    self.io,
                );
                continue;
            }

            var acknowledgement = try active.?.connection
                .readBrokerEventWithTimeout(model.packet_timeout);
            defer acknowledgement.deinit(self.allocator);
            switch (acknowledgement) {
                .puback => |puback| {
                    try std.testing.expectEqual(
                        packet_id.?,
                        puback.ack.packet_id,
                    );
                    try std.testing.expectEqual(
                        @as(u8, 0),
                        puback.ack.reason_code,
                    );
                },
                else => return error.ExpectedSourcePubAck,
            }
            self.signals.source_completed.store(index + 1, .release);
            self.signals.target_done[index].waitUncancelable(self.io);
        }

        var disconnect = try active.?.connection.readDisconnect();
        defer disconnect.deinit(self.allocator);
    }

    fn accept(self: *@This(), session_present: bool) !runtime.AcceptedClient {
        var pending = try self.server.acceptPending(.{ .protocol = .v5 });
        errdefer pending.deinit(self.allocator);
        const accepted = try pending.finish(.{
            .protocol = .v5,
            .session_present = session_present,
        });
        try validateConnect(accepted.connect.connect);
        return accepted;
    }
};

fn replaceConnection(
    self: *State,
    active: *?runtime.AcceptedClient,
    session_present: bool,
    graceful: bool,
) !void {
    if (graceful) {
        var previous = active.* orelse return error.MissingSourceConnection;
        active.* = null;
        defer previous.deinit(self.allocator);
        try previous.connection.disconnect(0);
        active.* = try self.accept(session_present);
    } else {
        if (active.*) |*connection| {
            connection.connection.shutdown() catch {};
            connection.deinit(self.allocator);
            active.* = null;
        }
        active.* = try self.accept(session_present);
    }
}

fn validateConnect(connect: mqtt.Connect) !void {
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectEqualStrings(
        "fuzz-outbound-source",
        connect.client_id,
    );
}

fn expectSubscriptions(
    connection: *runtime.Connection,
    replay_summary: ?*model.Summary,
) !void {
    for (model.source_topics) |topic| {
        var subscribe = try connection.readSubscribe();
        defer subscribe.deinit(std.testing.allocator);
        try std.testing.expectEqual(
            @as(usize, 1),
            subscribe.subscribe.subscriptions.len,
        );
        const subscription = subscribe.subscribe.subscriptions[0];
        try std.testing.expectEqualStrings(topic, subscription.topic_filter);
        try std.testing.expectEqual(mqtt.QoS.at_least_once, subscription.qos);
        try std.testing.expect(subscription.retain_as_published);
        try connection.writeSubAck(
            subscribe.subscribe.packet_id,
            &.{0x01},
            &.{},
        );
        if (replay_summary) |summary| {
            summary.source_subscription_replays += 1;
        }
    }
}

fn sendPublish(
    connection: *runtime.Connection,
    operation: u8,
    payload: model.Payload,
    retransmission: bool,
    packet_id: u16,
) !?u16 {
    if (model.qos(operation) == .at_most_once) {
        try std.testing.expect(!retransmission);
        try connection.publish(
            model.source_topics[model.topicIndex(operation)],
            &payload.bytes,
            .{
                .retain = model.retain(operation),
                .properties = &publish_properties,
            },
        );
        return null;
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try mqtt.writePublish(
        &encoded,
        std.testing.allocator,
        .v5,
        model.source_topics[model.topicIndex(operation)],
        &payload.bytes,
        .{
            .qos = .at_least_once,
            .retain = model.retain(operation),
            .dup = retransmission or model.sourceDup(operation),
            .packet_id = packet_id,
            .properties = &publish_properties,
        },
    );
    try connection.transport.writePacket(encoded.items);
    return packet_id;
}
