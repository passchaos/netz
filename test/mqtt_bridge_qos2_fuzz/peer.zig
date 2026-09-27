const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

pub fn State(comptime Server: type, comptime tls: bool) type {
    return struct {
        server: *Server,
        input: []const u8,
        summary: model.Summary = .{},
        err: ?anyerror = null,
        failed: std.atomic.Value(bool) = .init(false),

        pub fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.failed.store(true, .release);
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
                try expectPubRec(
                    &active.?.connection,
                    self.server.allocator,
                    packet_id,
                );

                switch (kind) {
                    0 => {
                        try active.?.connection.writePubRel(packet_id, 0);
                        try expectPubComp(
                            &active.?.connection,
                            self.server.allocator,
                            packet_id,
                        );
                    },
                    1, 2 => {
                        try self.replaceConnection(&active, true);
                        try active.?.connection.writePubRel(packet_id, 0);
                        try expectPubComp(
                            &active.?.connection,
                            self.server.allocator,
                            packet_id,
                        );
                    },
                    3 => {
                        try self.replaceConnection(&active, false);
                        try expectSubscriptions(
                            &active.?.connection,
                            &self.summary,
                        );
                    },
                    else => unreachable,
                }
            }

            try expectDisconnect(
                &active.?.connection,
                self.server.allocator,
            );
        }

        fn accept(
            self: *@This(),
            session_present: bool,
        ) !runtime.AcceptedClient {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            errdefer pending.deinit(self.server.allocator);
            const accepted = try pending.finish(.{
                .protocol = .v5,
                .session_present = session_present,
            });
            try validateConnect(accepted.connect.connect);
            if (tls) try validateTls(&accepted.connection);
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
            active.* = try self.accept(session_present);
        }
    };
}

fn validateTls(connection: *const runtime.Connection) !void {
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
        var event = try connection.readBrokerEventWithTimeout(
            model.coordination_timeout,
        );
        defer event.deinit(std.testing.allocator);
        const subscribe = switch (event) {
            .subscribe => |value| value.subscribe,
            else => return error.ExpectedSubscribe,
        };
        try std.testing.expectEqual(@as(usize, 1), subscribe.subscriptions.len);
        try std.testing.expectEqualStrings(
            topic,
            subscribe.subscriptions[0].topic_filter,
        );
        try std.testing.expectEqual(
            mqtt.QoS.exactly_once,
            subscribe.subscriptions[0].qos,
        );
        try std.testing.expect(subscribe.subscriptions[0].retain_as_published);
        try connection.writeSubAck(subscribe.packet_id, &.{0x02}, &.{});
        if (replay_summary) |summary| summary.subscription_replays += 1;
        _ = index;
    }
}

fn expectPubRec(
    connection: *runtime.Connection,
    allocator: std.mem.Allocator,
    packet_id: u16,
) !void {
    var event = try connection.readBrokerEventWithTimeout(
        model.coordination_timeout,
    );
    defer event.deinit(allocator);
    const pubrec = switch (event) {
        .pubrec => |value| value.ack,
        else => return error.ExpectedPubRec,
    };
    try std.testing.expectEqual(packet_id, pubrec.packet_id);
}

fn expectPubComp(
    connection: *runtime.Connection,
    allocator: std.mem.Allocator,
    packet_id: u16,
) !void {
    var event = try connection.readBrokerEventWithTimeout(
        model.coordination_timeout,
    );
    defer event.deinit(allocator);
    const pubcomp = switch (event) {
        .pubcomp => |value| value.ack,
        else => return error.ExpectedPubComp,
    };
    try std.testing.expectEqual(packet_id, pubcomp.packet_id);
}

fn expectDisconnect(
    connection: *runtime.Connection,
    allocator: std.mem.Allocator,
) !void {
    var event = try connection.readBrokerEventWithTimeout(
        model.coordination_timeout,
    );
    defer event.deinit(allocator);
    switch (event) {
        .disconnect => |value| try std.testing.expectEqual(
            @as(u8, 0),
            value.disconnect.reason_code,
        ),
        else => return error.ExpectedDisconnect,
    }
}
