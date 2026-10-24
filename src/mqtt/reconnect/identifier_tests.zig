const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");

const Delivery = enum { immediate, staged, pubrel };
const Operation = enum { subscribe, unsubscribe };
const Publication = enum { immediate, staged, queued };

test "MQTT reconnect controls avoid identifiers held by durable PUBLISH and PUBREL" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Delivery)) |delivery| {
            for (std.enums.values(Operation)) |operation| try exercise(protocol, delivery, operation);
        }
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, delivery: Delivery, operation: Operation) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        delivery: Delivery,
        operation: Operation,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(3));
            defer accepted.deinit(self.server.allocator);
            const connection = &accepted.connection;
            if (self.delivery != .staged) {
                var publish = try connection.readPublish();
                defer publish.deinit(connection.allocator);
                try std.testing.expectEqual(@as(?u16, 1), publish.publish.packet_id);
                if (self.delivery == .pubrel) {
                    try connection.writePubRec(1, 0);
                    var release = try connection.readPubRel();
                    defer release.deinit(connection.allocator);
                    try std.testing.expectEqual(@as(u16, 1), release.ack.packet_id);
                }
            }
            const id = switch (self.operation) {
                .subscribe => blk: {
                    var request = try connection.readSubscribe();
                    defer request.deinit(connection.allocator);
                    try connection.writeSubAck(request.subscribe.packet_id, &.{0}, &.{});
                    break :blk request.subscribe.packet_id;
                },
                .unsubscribe => blk: {
                    var request = try connection.readUnsubscribe();
                    defer request.deinit(connection.allocator);
                    try connection.writeUnsubAck(request.unsubscribe.packet_id, if (self.protocol == .v5) &.{0} else &.{}, &.{});
                    break :blk request.unsubscribe.packet_id;
                },
            };
            try std.testing.expectEqual(@as(u16, 2), id);
            if (self.delivery == .staged) {
                var publish = try connection.readPublish();
                defer publish.deinit(connection.allocator);
                try std.testing.expectEqual(@as(?u16, 1), publish.publish.packet_id);
            }
            if (self.delivery == .pubrel) try connection.writePubComp(1, 0) else try connection.writePubAck(1, 0);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .delivery = delivery, .operation = operation };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, io, server.address(), .{ .protocol = protocol, .client_id = "durable-identifiers", .clean_start = false }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(2));
    const qos: mqtt.QoS = if (delivery == .pubrel) .exactly_once else .at_least_once;
    const id = if (delivery == .staged)
        try client.stagePublish("ids/pending", "payload", .{ .qos = qos })
    else
        (try client.publishOneAttempt("ids/pending", "payload", .{ .qos = qos })).packet_id.?;
    try std.testing.expectEqual(@as(u16, 1), id);
    if (delivery == .pubrel) try std.testing.expectEqual(id, try client.completeNextPublish());
    const control_id = switch (operation) {
        .subscribe => blk: {
            var ack = try client.subscribeWithTimeout(&.{.{ .topic_filter = "ids/#" }}, .{}, .fromSeconds(2));
            defer ack.deinit(allocator);
            break :blk ack.suback.packet_id;
        },
        .unsubscribe => blk: {
            var ack = try client.unsubscribeWithTimeout(&.{"ids/#"}, .{}, .fromSeconds(2));
            defer ack.deinit(allocator);
            break :blk ack.unsuback.packet_id;
        },
    };
    try std.testing.expectEqual(@as(u16, 2), control_id);
    if (delivery == .staged) try client.flushPendingWithTimeout(.fromSeconds(2));
    try std.testing.expectEqual(id, try client.completeNextPublish());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "MQTT reconnect durable allocation avoids pending subscription commands" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Publication)) |publication| try exerciseInverse(protocol, publication);
    }
}

fn exerciseInverse(protocol: mqtt.ProtocolVersion, publication: Publication) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
            var accepted = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(3));
            defer accepted.deinit(self.server.allocator);
            const connection = &accepted.connection;
            var subscription = try connection.readSubscribe();
            defer subscription.deinit(connection.allocator);
            var unsubscription = try connection.readUnsubscribe();
            defer unsubscription.deinit(connection.allocator);
            var publish = try connection.readPublish();
            defer publish.deinit(connection.allocator);
            try std.testing.expectEqual(@as(u16, 1), subscription.subscribe.packet_id);
            try std.testing.expectEqual(@as(u16, 2), unsubscription.unsubscribe.packet_id);
            try std.testing.expectEqual(@as(?u16, 3), publish.publish.packet_id);
            // Release controls in reverse order while PUBLISH remains owned
            // by the durable Store. The next PUBLISH must remain distinct.
            try connection.writeUnsubAck(2, if (self.protocol == .v5) &.{0} else &.{}, &.{});
            try connection.writeSubAck(1, &.{0}, &.{});
            try connection.writePubAck(3, 0);
            var following = try connection.readPublish();
            defer following.deinit(connection.allocator);
            try std.testing.expectEqual(@as(?u16, 4), following.publish.packet_id);
            try connection.writePubAck(4, 0);
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, io, server.address(), .{ .protocol = protocol, .client_id = "inverse-identifiers", .clean_start = false }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(2));
    const active = client.connection().?;
    const subscribe_id = try active.writeSubscribe(&.{.{ .topic_filter = "ids/#" }}, .{});
    const unsubscribe_id = try active.writeUnsubscribe(&.{"ids/#"}, .{});
    const now = std.Io.Clock.awake.now(io);
    const publish_id: u16 = switch (publication) {
        .immediate => (try client.publishOneAttempt("ids/pending", "payload", .{ .qos = .at_least_once })).packet_id.?,
        .staged => blk: {
            const id = try client.stagePublish("ids/pending", "payload", .{ .qos = .at_least_once });
            try client.flushPendingWithTimeout(.fromSeconds(2));
            break :blk id;
        },
        .queued => blk: {
            _ = try client.outgoing.enqueuePublish(client.outgoing_handle, "ids/pending", "payload", .{ .qos = .at_least_once, .now = now });
            try client.flushPendingWithTimeout(.fromSeconds(2));
            break :blk 3;
        },
    };
    try std.testing.expectEqual(@as(u16, 3), publish_id);
    try std.testing.expectEqual(@as(u16, 0), active.outgoing_inflight);
    try std.testing.expect(active.hasOutgoingPacketIdentifier(publish_id));
    var subscribe_ack = try active.completeSubscribeWithTimeout(subscribe_id, .fromSeconds(2));
    defer subscribe_ack.deinit(allocator);
    var unsubscribe_ack = try active.completeUnsubscribeWithTimeout(unsubscribe_id, .fromSeconds(2));
    defer unsubscribe_ack.deinit(allocator);
    try std.testing.expectEqual(publish_id, try client.completeNextPublish());
    try std.testing.expect(!active.hasOutgoingPacketIdentifier(publish_id));
    try std.testing.expect(!active.hasOutgoingPacketIdentifier(subscribe_id));
    try std.testing.expect(!active.hasOutgoingPacketIdentifier(unsubscribe_id));
    const reused = (try client.publishOneAttempt("ids/reused", "payload", .{ .qos = .at_least_once })).packet_id.?;
    try std.testing.expectEqual(@as(u16, 4), reused);
    try std.testing.expectEqual(reused, try client.completeNextPublish());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
