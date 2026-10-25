//! Server-assigned MQTT 5 identities must survive the reconnect owner.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

const persistent_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};

test "MQTT reconnect accepts an empty MQTT5 Client ID for server assignment" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = "",
        .clean_start = false,
        .properties = &persistent_properties,
    }, .{}, &shutdown);
    defer client.deinit();
    try std.testing.expectEqualStrings("", client.clientId());
    try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
    var image: std.ArrayList(u8) = .empty;
    defer image.deinit(std.testing.allocator);
    try image.appendSlice(std.testing.allocator, "outer");
    try std.testing.expectError(error.InvalidClientId, client.writeSessionSnapshotAt(&image, .zero, .zero));
    try std.testing.expectEqualStrings("outer", image.items);
}

test "MQTT reconnect assigned identity survives QoS recovery and client reconstruction" {
    for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
        for ([_]bool{ false, true }) |preserved| {
            for ([_]bool{ false, true }) |reconstructed| try exercise(qos, preserved, reconstructed);
        }
    }
}

test "MQTT reconnect assigned identity stays unassigned after refusal" {
    for ([_]bool{ false, true }) |clean_start| {
        const allocator = std.testing.allocator;
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        defer server.deinit();
        const Peer = struct {
            server: *runtime.Server,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.serve() catch |err| {
                    self.err = err;
                };
            }

            fn serve(self: *@This()) !void {
                {
                    var refused = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(3));
                    defer refused.deinit(self.server.allocator);
                    try refused.connection.writeConnAck(.{ .reason_code = 0x84 });
                }
                var accepted = try self.server.acceptWithTimeout(.{ .protocol = .v5, .assigned_client_identifier = "after-refusal" }, .fromSeconds(3));
                defer accepted.deinit(self.server.allocator);
                try std.testing.expectEqualStrings("", accepted.connect.connect.client_id);
                var disconnect = try accepted.connection.readDisconnect();
                defer disconnect.deinit(self.server.allocator);
            }
        };
        var peer = Peer{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.init(allocator, io, server.address(), .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = clean_start,
            .properties = &persistent_properties,
        }, .{}, &shutdown);
        defer client.deinit();
        try std.testing.expectError(error.ConnectRefused, client.connectWithTimeout(.fromSeconds(2)));
        try std.testing.expectEqualStrings("", client.clientId());
        try std.testing.expectError(error.InvalidClientId, client.adaptProtocolToLastConnectRefusal(.v3_1_1, false));
        try std.testing.expectEqual(mqtt.ProtocolVersion.v5, client.options.value.protocol);
        try std.testing.expectEqual(@as(u8, 0x84), client.lastConnectRefusal().?.reason_code);
        _ = try client.connectWithTimeout(.fromSeconds(2));
        try std.testing.expectEqualStrings("after-refusal", client.clientId());
        try client.disconnect(0);
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
    }
}

fn exercise(qos: mqtt.QoS, preserved: bool, reconstructed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const assigned_id = "server-assigned-identity";
    const properties = [_]mqtt.Property{.{ .varint = .{ .id = .subscription_identifier, .value = 9 } }};
    const subscription = mqtt.Subscription{ .topic_filter = "assigned/#", .qos = .exactly_once, .no_local = true, .retain_as_published = true };
    const Peer = struct {
        server: *runtime.Server,
        qos: mqtt.QoS,
        preserved: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn expectSubscription(connection: *runtime.Connection) !void {
            var request = try connection.readSubscribe();
            defer request.deinit(connection.allocator);
            try std.testing.expectEqualDeep(subscription, request.subscribe.subscriptions[0]);
            try std.testing.expectEqualDeep(@as([]const mqtt.Property, &properties), request.subscribe.properties);
            try connection.writeSubAck(request.subscribe.packet_id, &.{2}, &.{});
        }

        fn serve(self: *@This()) !void {
            var packet_id: u16 = undefined;
            {
                var pending = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(3));
                var pending_owned = true;
                defer if (pending_owned) pending.deinit(self.server.allocator);
                try std.testing.expectEqualStrings("", pending.connect.connect.client_id);
                try std.testing.expect(!pending.connect.connect.clean_start);
                var accepted = try pending.finish(.{ .protocol = .v5, .assigned_client_identifier = assigned_id });
                pending_owned = false;
                defer accepted.deinit(self.server.allocator);
                try expectSubscription(&accepted.connection);
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                packet_id = publish.publish.packet_id.?;
                try std.testing.expectEqualStrings("assigned/pending", publish.publish.topic);
                try std.testing.expectEqualStrings("payload", publish.publish.payload);
                try std.testing.expect(!publish.publish.dup);
                if (self.qos == .exactly_once) {
                    try accepted.connection.writePubRec(packet_id, 0);
                    var release = try accepted.connection.readPubRel();
                    defer release.deinit(self.server.allocator);
                    try std.testing.expectEqual(packet_id, release.ack.packet_id);
                }
                accepted.connection.readPingReq() catch |err| switch (err) {
                    error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                    else => return err,
                };
            }
            var pending = try self.server.acceptPendingWithTimeout(.{ .protocol = .v5 }, .fromSeconds(3));
            var pending_owned = true;
            defer if (pending_owned) pending.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(assigned_id, pending.connect.connect.client_id);
            try std.testing.expect(!pending.connect.connect.clean_start);
            var accepted = try pending.finish(.{ .protocol = .v5, .session_present = self.preserved });
            pending_owned = false;
            defer accepted.deinit(self.server.allocator);
            if (self.preserved) {
                if (self.qos == .exactly_once) {
                    var release = try accepted.connection.readSessionPubRel();
                    defer release.deinit(self.server.allocator);
                    try std.testing.expectEqual(packet_id, release.ack.packet_id);
                    try accepted.connection.writePubComp(packet_id, 0);
                } else {
                    var publish = try accepted.connection.readPublish();
                    defer publish.deinit(self.server.allocator);
                    try std.testing.expectEqual(packet_id, publish.publish.packet_id.?);
                    try std.testing.expect(publish.publish.dup);
                    try std.testing.expectEqualStrings("payload", publish.publish.payload);
                    try accepted.connection.writePubAck(packet_id, 0);
                }
            } else try expectSubscription(&accepted.connection);
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var peer = Peer{ .server = &server, .qos = qos, .preserved = preserved };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const options = runtime.ConnectOptions{ .protocol = .v5, .client_id = "", .clean_start = false, .properties = &persistent_properties };
    var client = try reconnect.Client.init(allocator, io, server.address(), options, .{}, &shutdown);
    defer client.deinit();
    try client.seedSubscription(subscription, &properties);
    try std.testing.expect(!(try client.connectWithTimeout(.fromSeconds(2))).session_present);
    try std.testing.expectEqualStrings(assigned_id, client.clientId());
    try std.testing.expectEqualStrings(assigned_id, try client.outgoing.clientId(client.outgoing_handle));
    const packet_id = (try client.publishOneAttempt("assigned/pending", "payload", .{ .qos = qos })).packet_id.?;
    if (qos == .exactly_once) try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    client.disconnectTransport();
    if (reconstructed) {
        var image: std.ArrayList(u8) = .empty;
        defer image.deinit(allocator);
        try client.writeSessionSnapshot(&image);
        var replacement = try reconnect.Client.init(allocator, io, server.address(), options, .{}, &shutdown);
        errdefer replacement.deinit();
        try replacement.restoreSessionSnapshot(image.items);
        @memset(image.items, 0);
        client.deinit();
        client = replacement;
        try std.testing.expectEqualStrings(assigned_id, client.clientId());
        try std.testing.expect(client.hasSubscription("assigned/#"));
    }
    try std.testing.expectEqual(preserved, (try client.connectWithTimeout(.fromSeconds(2))).session_present);
    try std.testing.expectEqualStrings(assigned_id, client.clientId());
    try std.testing.expect(client.connection().?.assignedClientId() == null);
    if (preserved) try std.testing.expectEqual(packet_id, try client.completeNextPublish()) else try std.testing.expect((try client.outgoingQoSState(packet_id)) == null);
    try client.connection().?.pingWithTimeout(.fromSeconds(2));
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
