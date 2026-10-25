//! A resumed broker Session may still have an incomplete subscription replay.
const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");
const Failure = enum { refused, timeout, closed };

test "MQTT reconnect resumes unfinished subscription replay on a preserved Session" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Failure)) |failure| {
            for ([_]bool{ false, true }) |accepted| try exercise(protocol, failure, true, accepted, false);
        }
    }
}

test "MQTT reconnect restarts unfinished subscription replay when the broker Session is lost" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try exercise(protocol, .refused, false, false, false);
        try exercise(protocol, .timeout, false, true, false);
    }
}

test "MQTT reconnect snapshot resumes partial subscription recovery after client reconstruction" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        try exercise(protocol, .refused, true, true, true);
        try exercise(protocol, .timeout, true, false, true);
    }
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try exercise(protocol, .closed, false, true, true);
    }
}

fn subscription(protocol: mqtt.ProtocolVersion, filter: []const u8) mqtt.Subscription {
    return .{ .topic_filter = filter, .qos = .at_least_once, .no_local = protocol == .v5, .retain_as_published = protocol == .v5, .retain_handling = if (protocol == .v5) 1 else 0 };
}

const replay_properties = [_]mqtt.Property{
    .{ .varint = .{ .id = .subscription_identifier, .value = 53 } },
    .{ .utf8_pair = .{ .id = .user_property, .key = "scope", .value = "owned" } },
};

fn properties(protocol: mqtt.ProtocolVersion) []const mqtt.Property {
    return if (protocol == .v5) &replay_properties else &.{};
}

fn readFilter(connection: *runtime.Connection, expected: []const u8) !runtime.OwnedSubscribe {
    var event = try connection.readBrokerEventWithTimeout(.fromSeconds(1));
    errdefer event.deinit(connection.allocator);
    try std.testing.expect(event == .subscribe);
    const packet = event.subscribe.subscribe;
    try std.testing.expectEqual(@as(usize, 1), packet.subscriptions.len);
    const requested = packet.subscriptions[0];
    try std.testing.expectEqualDeep(subscription(connection.protocol, expected), requested);
    try std.testing.expectEqualDeep(properties(connection.protocol), packet.properties);
    return event.subscribe;
}

fn acknowledgeFilter(connection: *runtime.Connection, expected: []const u8) !void {
    var filter = try readFilter(connection, expected);
    defer filter.deinit(connection.allocator);
    // A granted lower QoS must not replace the desired subscription's options.
    try connection.writeSubAck(filter.subscribe.packet_id, &.{0}, &.{});
}

fn pingBarrier(connection: *runtime.Connection) !void {
    var event = try connection.readBrokerEventWithTimeout(.fromSeconds(1));
    defer event.deinit(connection.allocator);
    try std.testing.expect(event == .pingreq);
    try connection.writePingResp();
}

fn exercise(protocol: mqtt.ProtocolVersion, failure: Failure, preserved: bool, accepted: bool, reconstructed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        failure: Failure,
        preserved: bool,
        accepted: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            if (self.accepted) {
                var original = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(2));
                defer original.deinit(self.server.allocator);
                try acknowledgeFilter(&original.connection, "replay/first");
                try acknowledgeFilter(&original.connection, "replay/second");
                var end = try original.connection.readBrokerEventWithTimeout(.fromSeconds(1));
                defer end.deinit(self.server.allocator);
                try std.testing.expect(end == .disconnect);
            }
            {
                var fresh = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(2));
                defer fresh.deinit(self.server.allocator);
                try acknowledgeFilter(&fresh.connection, "replay/first");
                var second = try readFilter(&fresh.connection, "replay/second");
                defer second.deinit(self.server.allocator);
                switch (self.failure) {
                    .refused => try fresh.connection.writeSubAck(second.subscribe.packet_id, &.{if (self.protocol == .v5) 0x87 else 0x80}, &.{}),
                    .closed => {},
                    .timeout => {
                        if (fresh.connection.readBrokerEventWithTimeout(.fromSeconds(1))) |value| {
                            var event = value;
                            event.deinit(self.server.allocator);
                            return error.TestUnexpectedResult;
                        } else |err| switch (err) {
                            error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                            else => return err,
                        }
                    },
                }
            }
            if (self.failure == .refused and self.protocol != .v3_1) {
                // A second refused attempt on a preserved Session must retain
                // the same unconfirmed filter, including its original options.
                var retry = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(2));
                defer retry.deinit(self.server.allocator);
                var second = try readFilter(&retry.connection, "replay/second");
                defer second.deinit(self.server.allocator);
                try retry.connection.writeSubAck(second.subscribe.packet_id, &.{if (self.protocol == .v5) 0x87 else 0x80}, &.{});
            }
            {
                var resumed = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = self.preserved }, .fromSeconds(2));
                defer resumed.deinit(self.server.allocator);
                if (!self.preserved) try acknowledgeFilter(&resumed.connection, "replay/first");
                var second = try readFilter(&resumed.connection, "replay/second");
                defer second.deinit(self.server.allocator);
                // SUBACK completion must preserve unrelated inbound traffic.
                _ = try resumed.connection.writePublish("replay/second", "during recovery", .{});
                try resumed.connection.writeSubAck(second.subscribe.packet_id, &.{0}, &.{});
                if (self.failure == .timeout) try acknowledgeFilter(&resumed.connection, "replay/added");
                try pingBarrier(&resumed.connection);
                var end = try resumed.connection.readBrokerEventWithTimeout(.fromSeconds(1));
                defer end.deinit(self.server.allocator);
                try std.testing.expect(end == .disconnect);
            }
            // Recovery completed: a later preserved Session needs no SUBSCRIBE.
            var confirmed = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(2));
            defer confirmed.deinit(self.server.allocator);
            if (self.protocol == .v3_1) {
                // MQTT 3.1 has no Session Present flag, so recovery restarts.
                try acknowledgeFilter(&confirmed.connection, "replay/first");
                try acknowledgeFilter(&confirmed.connection, "replay/second");
                if (self.failure == .timeout) try acknowledgeFilter(&confirmed.connection, "replay/added");
            }
            try pingBarrier(&confirmed.connection);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .failure = failure, .preserved = preserved, .accepted = accepted };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const connect_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "subscription-replay",
        .clean_start = false,
        .properties = if (protocol == .v5) &connect_properties else &.{},
    }, .{ .initial_delay = .fromMilliseconds(1), .max_delay = .fromMilliseconds(1) }, &shutdown);
    defer client.deinit();
    if (accepted) {
        _ = try client.connectWithTimeout(.fromSeconds(1));
        for ([_][]const u8{ "replay/first", "replay/second" }) |filter| {
            var suback = try client.subscribeWithTimeout(&.{subscription(protocol, filter)}, .{ .properties = properties(protocol) }, .fromSeconds(1));
            suback.deinit(allocator);
        }
        try client.disconnect(0);
    } else {
        try client.seedSubscription(subscription(protocol, "replay/first"), properties(protocol));
        try client.seedSubscription(subscription(protocol, "replay/second"), properties(protocol));
    }
    const result = client.connectWithTimeout(.fromMilliseconds(100));
    if (failure == .closed) {
        if (result) |_| return error.TestUnexpectedResult else |err| switch (err) {
            error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
            else => return err,
        }
    } else try std.testing.expectError(if (failure == .timeout) error.Timeout else error.SubscriptionRefused, result);
    try std.testing.expect(client.connection() == null);
    try std.testing.expectEqual(@as(usize, 2), client.subscriptionCount());
    if (failure == .refused and protocol != .v3_1) {
        try std.testing.expectError(error.SubscriptionRefused, client.connectWithTimeout(.fromSeconds(1)));
        try std.testing.expect(client.connection() == null);
        try std.testing.expectEqual(@as(usize, 2), client.subscriptionCount());
    }
    // Desired filters appended while disconnected join an already pending
    // recovery suffix; confirming earlier filters must not skip the new one.
    if (failure == .timeout) try client.seedSubscription(subscription(protocol, "replay/added"), properties(protocol));
    if (reconstructed) {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try client.writeSessionSnapshot(&encoded);
        var replacement = try reconnect.Client.init(allocator, io, server.address(), .{
            .protocol = protocol,
            .client_id = "subscription-replay",
            .clean_start = false,
            .properties = if (protocol == .v5) &connect_properties else &.{},
        }, .{ .initial_delay = .fromMilliseconds(1), .max_delay = .fromMilliseconds(1) }, &shutdown);
        errdefer replacement.deinit();
        try replacement.restoreSessionSnapshot(encoded.items);
        client.deinit();
        client = replacement;
    }
    const resumed = try client.connectWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(preserved, resumed.session_present);
    try std.testing.expectEqual(@as(usize, if (failure == .timeout) 3 else 2), client.subscriptionCount());
    var queued = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer queued.deinit(allocator);
    try std.testing.expect(queued == .publish);
    try std.testing.expectEqualStrings("during recovery", queued.publish.publish.payload);
    try client.connection().?.pingWithTimeout(.fromSeconds(1));
    try client.disconnect(0);
    try std.testing.expectEqual(protocol != .v3_1, (try client.connectWithTimeout(.fromSeconds(1))).session_present);
    try client.connection().?.pingWithTimeout(.fromSeconds(1));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
