const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

pub const State = struct {
    server: *runtime.Server,
    input: []const u8,
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
            connection.deinit(self.server.allocator);
        };
        try expectSubscriptions(&active.?.connection, null);

        for (
            self.input[0..@min(self.input.len, model.max_operations)],
            0..,
        ) |operation, index| {
            const kind = operation & 0x03;
            const packet_id = try self.sendPublish(
                &active.?.connection,
                operation,
                index,
            );
            var pubrec = try active.?.connection.readPubRec();
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            pubrec.deinit(self.server.allocator);

            switch (kind) {
                0 => {
                    try active.?.connection.writePubRel(packet_id, 0);
                    try expectPubComp(&active.?.connection, packet_id);
                },
                1, 2 => {
                    try replaceConnection(self, &active, true);
                    try active.?.connection.writePubRel(packet_id, 0);
                    try expectPubComp(&active.?.connection, packet_id);
                },
                3 => {
                    try replaceConnection(self, &active, false);
                    try expectSubscriptions(
                        &active.?.connection,
                        &self.summary,
                    );
                },
                else => unreachable,
            }
        }

        var disconnect = try active.?.connection.readDisconnect();
        defer disconnect.deinit(self.server.allocator);
        try std.testing.expectEqual(
            @as(u8, 0),
            disconnect.disconnect.reason_code,
        );
    }

    fn accept(self: *@This(), session_present: bool) !runtime.AcceptedClient {
        var pending = try self.server.acceptPending(.{ .protocol = .v5 });
        errdefer pending.deinit(self.server.allocator);
        const accepted = try pending.finish(.{
            .protocol = .v5,
            .session_present = session_present,
        });
        try validateConnect(accepted.connect.connect);
        return accepted;
    }

    fn sendPublish(
        self: *@This(),
        connection: *runtime.Connection,
        operation: u8,
        index: usize,
    ) !u16 {
        _ = self;
        const topic_index: usize = (operation >> 2) & 0x01;
        const payload = model.Payload.init(operation, index);
        return (try connection.writePublish(
            model.remote_topics[topic_index],
            &payload.bytes,
            .{
                .qos = .exactly_once,
                .retain = operation & 0x08 != 0,
                .dup = operation & 0x10 != 0,
                .properties = &.{.{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "origin",
                    .value = "remote-qos2",
                } }},
            },
        )).?;
    }
};

fn replaceConnection(
    self: *State,
    active: *?runtime.AcceptedClient,
    session_present: bool,
) !void {
    if (active.*) |*connection| {
        connection.connection.shutdown() catch {};
        connection.deinit(self.server.allocator);
        active.* = null;
    }
    active.* = try self.accept(session_present);
}

fn validateConnect(connect: mqtt.Connect) !void {
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectEqualStrings("fuzz-qos2-bridge", connect.client_id);
    try std.testing.expectEqual(
        @as(?u32, 60),
        mqtt.sessionExpiryInterval(connect.properties),
    );
}

fn expectSubscriptions(
    connection: *runtime.Connection,
    replay_summary: ?*model.Summary,
) !void {
    for (model.remote_topics, 0..) |topic, index| {
        var subscribe = try connection.readSubscribe();
        defer subscribe.deinit(std.testing.allocator);
        try std.testing.expectEqual(
            @as(usize, 1),
            subscribe.subscribe.subscriptions.len,
        );
        const subscription = subscribe.subscribe.subscriptions[0];
        try std.testing.expectEqualStrings(topic, subscription.topic_filter);
        try std.testing.expectEqual(mqtt.QoS.exactly_once, subscription.qos);
        try std.testing.expect(subscription.retain_as_published);
        try connection.writeSubAck(
            subscribe.subscribe.packet_id,
            &.{0x02},
            &.{},
        );
        if (replay_summary) |summary| {
            summary.subscription_replays += 1;
        }
        _ = index;
    }
}

fn expectPubComp(connection: *runtime.Connection, packet_id: u16) !void {
    var pubcomp = try connection.readPubComp();
    defer pubcomp.deinit(std.testing.allocator);
    try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
}
