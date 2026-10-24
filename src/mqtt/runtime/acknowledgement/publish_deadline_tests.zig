const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const BlockedWrite = @import("deadline_tests.zig").BlockedWrite;

const allocator = std.testing.allocator;
const Delivery = enum { complete, puback_wait, pubcomp_wait, split_puback, split_budget, repeat_pubrec, blocked_publish, blocked_pubrel };

test {
    _ = @import("publish_deadline_state_tests.zig");
}

test "MQTT publish deadlines complete all QoS levels and preserve interleaved input" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.QoS{ .at_most_once, .at_least_once, .exactly_once }) |qos| {
            for ([_]bool{ false, true }) |absolute| try exercise(protocol, qos, absolute, .complete);
        }
    }
}

test "MQTT publish deadlines resume PUBACK and PUBCOMP without retransmitting PUBLISH" {
    for ([_]bool{ false, true }) |absolute| {
        try exercise(.v5, .at_least_once, absolute, .puback_wait);
        try exercise(.v5, .exactly_once, absolute, .pubcomp_wait);
        try exercise(.v5, .at_least_once, absolute, .split_puback);
    }
}

test "MQTT publish deadlines share one budget across output and QoS2 retries" {
    for ([_]bool{ false, true }) |absolute| {
        try exercise(.v5, .exactly_once, absolute, .split_budget);
        try exercise(.v3_1, .exactly_once, absolute, .repeat_pubrec);
        try exercise(.v5, .exactly_once, absolute, .repeat_pubrec);
    }
}

test "MQTT publish deadlines cancel blocked PUBLISH and PUBREL writes" {
    for ([_]bool{ false, true }) |absolute| {
        try exercise(.v5, .exactly_once, absolute, .blocked_publish);
        try exercise(.v5, .exactly_once, absolute, .blocked_pubrel);
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS, absolute: bool, delivery: Delivery) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{
        .delegate = io,
        .delay = if (delivery == .split_budget) .fromMilliseconds(60) else .fromMilliseconds(300),
        .packet_type = if (delivery == .blocked_pubrel) .pubrel else .publish,
    };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        qos: mqtt.QoS,
        delivery: Delivery,
        release_ack: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol });
            defer accepted.deinit(allocator);
            const connection = &accepted.connection;
            var publish = connection.readPublish() catch |err| {
                if (self.delivery == .blocked_publish and abrupt(err)) return;
                return err;
            };
            defer publish.deinit(allocator);
            try std.testing.expectEqualStrings("deadline/publish", publish.publish.topic);
            try std.testing.expectEqualStrings("once", publish.publish.payload);
            try connection.publish("deadline/early", "preserved", .{});
            if (self.qos == .at_least_once) {
                const id = publish.publish.packet_id.?;
                if (self.delivery == .puback_wait) try self.release_ack.wait(self.server.io);
                if (self.delivery == .split_puback) {
                    var bytes: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
                    const encoded = try mqtt.AckPacket.writeNoPropertiesInto(&bytes, self.protocol, .puback, id, 0);
                    try connection.transport.writePacket(@constCast(encoded[0..3]));
                    try self.release_ack.wait(self.server.io);
                    try connection.transport.writePacket(@constCast(encoded[3..]));
                } else try connection.writePubAck(id, 0);
            } else if (self.qos == .exactly_once) {
                const id = publish.publish.packet_id.?;
                try connection.writePubRec(id, 0);
                var rel = connection.readSessionPubRel() catch |err| {
                    if (self.delivery == .blocked_pubrel and abrupt(err)) return;
                    return err;
                };
                defer rel.deinit(allocator);
                try std.testing.expectEqual(id, rel.ack.packet_id);
                if (self.delivery == .pubcomp_wait) try self.release_ack.wait(self.server.io);
                if (self.delivery == .split_budget) try std.Io.sleep(self.server.io, .fromMilliseconds(60), .awake);
                if (self.delivery == .repeat_pubrec) {
                    // The same publication budget must survive multiple
                    // successful retries without being renewed per PUBREC.
                    for (0..2) |_| {
                        try std.Io.sleep(self.server.io, .fromMilliseconds(10), .awake);
                        try connection.writePubRec(id, 0);
                        var repeated = try connection.readSessionPubRel();
                        defer repeated.deinit(allocator);
                        try std.testing.expectEqual(id, repeated.ack.packet_id);
                        try std.testing.expectEqual(self.protocol == .v3_1, repeated.ack.dup);
                    }
                    try self.release_ack.wait(self.server.io);
                }
                try connection.writePubComp(id, 0);
            }
            // A retry must resume the ACK stage, then send PINGREQ; a repeated
            // PUBLISH or unnecessary PUBREL makes this assertion fail.
            try connection.readPingReq();
            try connection.writePingResp();
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .qos = qos, .delivery = delivery };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release_ack.set(io);
        thread.join();
    };
    var client = try runtime.Client.connect(allocator, observed_io, server.address(), .{ .protocol = protocol, .client_id = "publish-budget" });
    var open = true;
    defer if (open) client.close();
    observer.armed.store(delivery == .split_budget or delivery == .blocked_publish or delivery == .blocked_pubrel, .release);
    const timeout: std.Io.Duration = if (delivery == .complete) .fromSeconds(2) else if (delivery == .split_budget) .fromMilliseconds(100) else .fromMilliseconds(50);
    var progress: runtime.PublishProgress = .{};
    const result = if (absolute)
        client.publishWithDeadline("deadline/publish", "once", .{ .qos = qos }, &progress, .fromNow(observed_io, .{ .clock = .awake, .raw = timeout }))
    else
        client.publishWithTimeout("deadline/publish", "once", .{ .qos = qos }, &progress, timeout);
    if (delivery == .complete) try result else try std.testing.expectError(error.Timeout, result);
    if (delivery == .blocked_publish or delivery == .blocked_pubrel) {
        try std.testing.expect(observer.entered.load(.acquire));
        try std.testing.expect(observer.canceled.load(.acquire));
        try std.testing.expect(!client.isUsable());
        try std.testing.expectEqual(delivery == .blocked_pubrel, progress.publish_sent);
        try std.testing.expect(!progress.completed);
        client.close();
        open = false;
    } else {
        try std.testing.expect(progress.publish_sent);
        try std.testing.expectEqual(delivery == .complete, progress.completed);
        if (delivery != .complete) {
            const id = progress.packet_id.?;
            try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
            try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
            try std.testing.expect(client.isUsable());
            peer.release_ack.set(io);
            if (absolute) try client.completePublishWithDeadline(id, qos, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) })) else try client.completePublishWithTimeout(id, qos, .fromSeconds(2));
        }
        try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
        var incoming = try client.readPublish();
        defer incoming.deinit(allocator);
        try std.testing.expectEqualStrings("preserved", incoming.publish.payload);
        try client.pingWithTimeout(.fromSeconds(2));
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn abrupt(err: anyerror) bool {
    return err == error.ConnectionClosed or err == error.ConnectionResetByPeer or err == error.SocketUnconnected;
}

test "MQTT publish timeouts reject zero budgets before I/O or identifier reservation" {
    var client = runtime.Connection{ .allocator = allocator, .transport = undefined };
    var progress: runtime.PublishProgress = .{ .packet_id = 5, .publish_sent = true, .completed = true };
    try std.testing.expectError(error.Timeout, client.publishWithTimeout("a", "b", .{ .qos = .exactly_once }, &progress, .zero));
    try std.testing.expectEqualDeep(runtime.PublishProgress{}, progress);
    try std.testing.expectError(error.Timeout, client.writePublishWithTimeout("a", "b", .{}, .zero));
    try std.testing.expectError(error.Timeout, client.completePublishWithTimeout(1, .exactly_once, .zero));
    try std.testing.expectError(error.Timeout, client.completePublishQoS2WithTimeout(1, .zero));
    try std.testing.expectError(error.Timeout, client.completePublishPubAckWithTimeout(1, .zero));
    try std.testing.expectError(error.Timeout, client.completePublishPubRecWithTimeout(1, .zero));
    try std.testing.expectError(error.Timeout, client.completePublishPubCompWithTimeout(1, .zero));
    try std.testing.expect(client.pending_packets == null);
    try std.testing.expectEqual(@as(u16, 1), client.next_packet_id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
}
