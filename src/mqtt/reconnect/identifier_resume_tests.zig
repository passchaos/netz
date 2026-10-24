const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");

test "MQTT reconnect identifiers remain reserved after Session Present and Client move" {
    // MQTT 3.1 CONNACK has no Session Present bit to prove restoration.
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| try exercise(protocol, qos);
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        qos: mqtt.QoS,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            {
                var accepted = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(3));
                defer accepted.deinit(self.server.allocator);
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqual(@as(?u16, 1), publish.publish.packet_id);
                if (self.qos == .exactly_once) {
                    try accepted.connection.writePubRec(1, 0);
                    var release = try accepted.connection.readPubRel();
                    defer release.deinit(self.server.allocator);
                    try std.testing.expectEqual(@as(u16, 1), release.ack.packet_id);
                }
                accepted.connection.readPingReq() catch |err| switch (err) {
                    error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                    else => return err,
                };
            }
            var resumed = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(3));
            defer resumed.deinit(self.server.allocator);
            if (self.qos == .exactly_once) {
                var release = try resumed.connection.readSessionPubRel();
                defer release.deinit(self.server.allocator);
                try std.testing.expectEqual(@as(u16, 1), release.ack.packet_id);
            } else {
                var publish = try resumed.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqual(@as(?u16, 1), publish.publish.packet_id);
                try std.testing.expect(publish.publish.dup);
            }
            var subscription = try resumed.connection.readSubscribe();
            defer subscription.deinit(self.server.allocator);
            try resumed.connection.writeSubAck(subscription.subscribe.packet_id, &.{0}, &.{});
            try std.testing.expectEqual(@as(u16, 2), subscription.subscribe.packet_id);
            if (self.qos == .exactly_once) try resumed.connection.writePubComp(1, 0) else try resumed.connection.writePubAck(1, 0);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .qos = qos };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const properties: []const mqtt.Property = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{};
    var original = try reconnect.Client.init(allocator, io, server.address(), .{ .protocol = protocol, .client_id = "resumed-identifiers", .clean_start = false, .properties = properties }, .{}, &shutdown);
    var moved = false;
    defer if (!moved) original.deinit();
    _ = try original.connectWithTimeout(.fromSeconds(2));
    const id = (try original.publishOneAttempt("ids/pending", "payload", .{ .qos = qos })).packet_id.?;
    if (qos == .exactly_once) try std.testing.expectEqual(id, try original.completeNextPublish());
    original.disconnectTransport();
    const connected = try original.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(connected.session_present);
    // The ownership callback must follow the stable Session map instead of a
    // pointer into the old Client/Store or Connection aggregate address.
    var client = original;
    original = undefined;
    moved = true;
    defer client.deinit();
    try std.testing.expect(client.connection().?.hasOutgoingPacketIdentifier(id));
    var ack = try client.subscribeWithTimeout(&.{.{ .topic_filter = "ids/#" }}, .{}, .fromSeconds(2));
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 2), ack.suback.packet_id);
    try std.testing.expectEqual(id, try client.completeNextPublish());
    try std.testing.expect(!client.connection().?.hasOutgoingPacketIdentifier(id));
    try std.testing.expectEqual(@as(u16, 0), client.connection().?.outgoing_inflight);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
