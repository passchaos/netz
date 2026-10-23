const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const reconnect = @import("../../reconnect.zig");

test "MQTT reconnect accepts pre-SUBACK QoS1 publications during fresh Session replay" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| try replay(protocol);
}

fn replay(protocol: mqtt.ProtocolVersion) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            for ([_][]const u8{ "initial", "replayed" }) |payload| {
                var accepted = try self.server.accept(.{ .protocol = self.protocol, .session_present = false });
                defer accepted.deinit(self.server.allocator);
                var request = try accepted.connection.readSubscribe();
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqual(@as(usize, 1), request.subscribe.subscriptions.len);
                try std.testing.expectEqualStrings("replay/#", request.subscribe.subscriptions[0].topic_filter);
                try std.testing.expectEqual(mqtt.QoS.at_least_once, request.subscribe.subscriptions[0].qos);
                const packet_id = (try accepted.connection.writePublish("replay/retained", payload, .{ .qos = .at_least_once, .retain = true })).?;
                try accepted.connection.writeSubAck(request.subscribe.packet_id, &.{1}, &.{});
                var acknowledgement = try accepted.connection.readPubAck();
                defer acknowledgement.deinit(self.server.allocator);
                try std.testing.expectEqual(packet_id, acknowledgement.ack.packet_id);
                try accepted.connection.readPingReq();
                try accepted.connection.writePingResp();
            }
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const expiry = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "subscribe-replay",
        .clean_start = false,
        .properties = if (protocol == .v5) &expiry else &.{},
    }, .{}, &shutdown);
    defer client.deinit();
    for ([_][]const u8{ "initial", "replayed" }, 0..) |payload, generation| {
        const connected = try client.connect();
        try std.testing.expect(!connected.session_present);
        if (generation == 0) {
            var acknowledgement = try client.subscribe(&.{.{ .topic_filter = "replay/#", .qos = .at_least_once }}, .{});
            defer acknowledgement.deinit(allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
        var event = (try client.pollWithTimeout(.fromSeconds(2))) orelse return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        if (event != .publish) return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("replay/retained", event.publish.publish.topic);
        try std.testing.expectEqualStrings(payload, event.publish.publish.payload);
        try std.testing.expectEqual(mqtt.QoS.at_least_once, event.publish.publish.qos);
        try std.testing.expect(event.publish.publish.retain);
        // The peer requires PUBACK before PINGRESP. This proves queued
        // messages still pass through the reconnect client's normal QoS path.
        try client.connection().?.pingWithTimeout(.fromSeconds(2));
        client.disconnectTransport();
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
