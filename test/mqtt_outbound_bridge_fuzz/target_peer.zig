const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

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

        for (
            self.input[0..@min(self.input.len, model.max_operations)],
            0..,
        ) |operation, index| {
            const kind = operation & 0x07;
            if (kind == 4 or kind == 5) {
                try self.signals.source_reconnected[index].waitTimeout(
                    self.io,
                    .{ .duration = .{
                        .raw = model.packet_timeout,
                        .clock = .awake,
                    } },
                );
                self.signals.target_completed.store(index + 1, .release);
                self.signals.target_done[index].set(self.io);
                continue;
            }
            const first_packet_id = try expectPublish(
                &active.?.connection,
                operation,
                index,
                false,
            );
            if (kind == 2 or kind == 3) {
                const session_present = kind == 2;
                try replaceConnection(self, &active, session_present);
                const replay_packet_id = try expectPublish(
                    &active.?.connection,
                    operation,
                    index,
                    session_present,
                );
                if (session_present) {
                    try std.testing.expectEqual(
                        first_packet_id.?,
                        replay_packet_id.?,
                    );
                    self.summary.target_resumed += 1;
                } else {
                    self.summary.target_fresh += 1;
                }
                self.summary.target_replays += 1;
                try expectSourcePending(self.signals, operation, index);
                try acknowledge(&active.?.connection, replay_packet_id);
            } else {
                try expectSourcePending(self.signals, operation, index);
                try acknowledge(&active.?.connection, first_packet_id);
            }
            self.summary.forwarded += 1;
            self.summary.qos0 += @intFromBool(
                model.qos(operation) == .at_most_once,
            );
            self.summary.qos1 += @intFromBool(
                model.qos(operation) == .at_least_once,
            );
            self.summary.retained += @intFromBool(model.retain(operation));
            self.summary.source_dup_normalized += @intFromBool(
                model.sourceDup(operation),
            );
            self.signals.target_completed.store(index + 1, .release);
            self.signals.target_done[index].set(self.io);
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
            .topic_alias_maximum = 0,
        });
        try std.testing.expectEqualStrings(
            "fuzz-outbound-target",
            accepted.connect.connect.client_id,
        );
        return accepted;
    }
};

fn expectSourcePending(
    signals: *const model.Signals,
    operation: u8,
    index: usize,
) !void {
    if (model.qos(operation) == .at_least_once) {
        try std.testing.expect(signals.source_completed.load(.acquire) <
            index + 1);
    }
}

fn replaceConnection(
    self: *State,
    active: *?runtime.AcceptedClient,
    session_present: bool,
) !void {
    if (active.*) |*connection| {
        connection.connection.shutdown() catch {};
        connection.deinit(self.allocator);
        active.* = null;
    }
    active.* = try self.accept(session_present);
}

fn expectPublish(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
    dup: bool,
) !?u16 {
    var publish = try connection.readPublish();
    defer publish.deinit(std.testing.allocator);
    const payload = model.Payload.init(operation, index);
    try std.testing.expectEqualStrings(
        model.target_topics[model.topicIndex(operation)],
        publish.publish.topic,
    );
    try std.testing.expectEqualSlices(u8, &payload.bytes, publish.publish.payload);
    try std.testing.expectEqual(model.qos(operation), publish.publish.qos);
    try std.testing.expectEqual(model.retain(operation), publish.publish.retain);
    try std.testing.expectEqual(dup, publish.publish.dup);
    try expectForwardProperties(publish.publish.properties);
    return publish.publish.packet_id;
}

fn acknowledge(
    connection: *runtime.Connection,
    packet_id: ?u16,
) !void {
    if (packet_id) |value| try connection.writePubAck(value, 0);
}

fn expectForwardProperties(properties: []const mqtt.Property) !void {
    var user_properties: usize = 0;
    for (properties) |property| switch (property) {
        .utf8_pair => |value| if (value.id == .user_property) {
            try std.testing.expectEqualStrings("bridge", value.key);
            try std.testing.expectEqualStrings("outbound-fuzz", value.value);
            user_properties += 1;
        },
        .two_byte => |value| if (value.id == .topic_alias) {
            return error.SourceTopicAliasLeaked;
        },
        .varint => |value| if (value.id == .subscription_identifier) {
            return error.SourceSubscriptionIdentifierLeaked;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), user_properties);
}
