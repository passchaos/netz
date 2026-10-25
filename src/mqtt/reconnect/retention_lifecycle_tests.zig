//! Wire negotiation and local offline time bound reconnect QoS replay.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect retention follows CONNACK and DISCONNECT across client reconstruction" {
    for ([_]?u32{ null, 0, 2, std.math.maxInt(u32) }) |override| {
        for ([_]bool{ false, true }) |reconstructed| {
            try exercise(60, 3, override, override == 0, reconstructed);
            if (override != 0 and override != std.math.maxInt(u32)) try exercise(60, 3, override, true, reconstructed);
        }
    }
    try exercise(0, 3, null, false, true);
    try exercise(60, 0, null, true, true);
}

fn expiry(seconds: u32) mqtt.Property {
    return .{ .four_byte = .{ .id = .session_expiry_interval, .value = seconds } };
}

fn exercise(requested: u32, granted: u32, override: ?u32, expired: bool, reconstructed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        requested: u32,
        granted: u32,
        override: ?u32,
        expired: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn subscription(connection: *runtime.Connection) !void {
            var event = try connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(connection.allocator);
            try std.testing.expect(event == .subscribe);
            try std.testing.expectEqualStrings("desired/#", event.subscribe.subscribe.subscriptions[0].topic_filter);
            try connection.writeSubAck(event.subscribe.subscribe.packet_id, &.{0}, &.{});
        }

        fn serve(self: *@This()) !void {
            {
                var pending = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(3));
                defer pending.deinit(self.server.allocator);
                try std.testing.expectEqual(@as(?u32, self.requested), mqtt.sessionExpiryInterval(pending.connect.connect.properties));
                try pending.connection.writeConnAck(.{ .properties = &.{expiry(self.granted)} });
                try std.testing.expectEqual(self.granted, pending.connection.sessionExpiryInterval());
                try subscription(&pending.connection);
                var disconnect = try pending.connection.readDisconnect();
                defer disconnect.deinit(self.server.allocator);
                try std.testing.expectEqual(self.override, mqtt.sessionExpiryInterval(disconnect.disconnect.properties));
                try std.testing.expectEqual(self.override orelse self.granted, pending.connection.sessionExpiryInterval());
            }
            // Retention must be enforced even if the peer reports a preserved
            // Session after the client knows its previous lifetime elapsed.
            var accepted = try self.server.acceptWithTimeout(.{ .protocol = .v5, .session_present = true }, .fromSeconds(3));
            defer accepted.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(?u32, self.requested), mqtt.sessionExpiryInterval(accepted.connect.connect.properties));
            if (self.expired) try subscription(&accepted.connection) else {
                var event = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
                defer event.deinit(self.server.allocator);
                try std.testing.expect(event == .publish);
                try std.testing.expectEqualStrings("pending", event.publish.publish.topic);
                try std.testing.expectEqualStrings("payload", event.publish.publish.payload);
                try std.testing.expect(event.publish.publish.dup);
                try accepted.connection.writePubAck(event.publish.publish.packet_id.?, 0);
            }
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var peer = Peer{ .server = &server, .requested = requested, .granted = granted, .override = override, .expired = expired };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const options = runtime.ConnectOptions{ .protocol = .v5, .client_id = "retention-wire", .clean_start = false, .properties = &.{expiry(requested)} };
    const client_options = reconnect.ClientOptions{ .manual_acknowledgements = true, .inbound_qos2_release_policy = .deferred };
    var client = try reconnect.Client.initWithOptions(allocator, io, server.address(), options, .{}, &shutdown, client_options);
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "desired/#" }, &.{});
    const first = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(!first.session_present and !first.session_resumed and !client.sessionResumed());
    try std.testing.expectEqual(granted, client.sessionExpiryInterval());
    try std.testing.expectEqual(granted, client.connection().?.sessionExpiryInterval());
    if (requested == 0) {
        try std.testing.expectError(error.InvalidProperty, client.disconnectWithProperties(0, &.{expiry(1)}));
        try std.testing.expectEqual(granted, client.sessionExpiryInterval());
        try std.testing.expect(client.connection() != null);
    }
    const id = try client.stagePublish("pending", "payload", .{ .qos = .at_least_once });
    if (override) |value| try client.disconnectWithProperties(0, &.{expiry(value)}) else try client.disconnect(0);
    try std.testing.expect(!client.sessionResumed());
    const interval = override orelse granted;
    try std.testing.expectEqual(interval, client.sessionExpiryInterval());
    const initial_deadline = client.retention.expires_at;
    client.disconnectTransport();
    try std.testing.expectEqualDeep(initial_deadline, client.retention.expires_at);
    if (expired) client.retention.expires_at = .zero;
    if (reconstructed) {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try client.writeSessionSnapshot(&bytes);
        var replacement = try reconnect.Client.initWithOptions(allocator, io, server.address(), options, .{}, &shutdown, client_options);
        errdefer replacement.deinit();
        try replacement.restoreSessionSnapshot(bytes.items);
        client.deinit();
        client = replacement;
        try std.testing.expectEqual(interval, client.sessionExpiryInterval());
    }
    const connected = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(connected.session_present);
    try std.testing.expectEqual(!expired, connected.session_resumed);
    try std.testing.expectEqual(connected.session_resumed, client.sessionResumed());
    if (expired) {
        try std.testing.expectError(error.SessionLost, client.restoreIncomingQoS2(77, .await_pubrel));
        try std.testing.expectError(error.SessionLost, client.restoreIncomingQoS2(78, .release_pending));
    } else {
        try client.restoreIncomingQoS2(77, .await_pubrel);
        try client.restoreIncomingQoS2(78, .release_pending);
        try client.restoreIncomingQoS2(78, .release_pending);
        try std.testing.expectEqual(@as(usize, 2), (try client.outgoingStats()).incoming_qos2_count);
    }
    if (!expired) try std.testing.expectEqual(id, try client.completeNextPublish());
    try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
    try std.testing.expect(client.hasSubscription("desired/#"));
    try client.connection().?.pingWithTimeout(.fromSeconds(2));
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
