const std = @import("std");
const mqtt = @import("../../mod.zig");
const Pair = @import("test_connection.zig").Pair;
const allocator = std.testing.allocator;

test "MQTT acknowledgement deadlines preserve receive credit before output and commit after success" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.PacketType{ .puback, .pubrec, .pubcomp }) |packet_type| {
            var pair = try Pair.init(io, protocol);
            defer pair.deinit();
            const qos: mqtt.QoS = if (packet_type == .puback) .at_least_once else .exactly_once;
            const id = (try pair.peer.writePublish("deadline/credit", "message", .{ .qos = qos })).?;
            var publish = try pair.client.readPublish();
            publish.deinit(allocator);
            if (packet_type == .pubcomp) {
                try pair.client.writePubRec(id, 0);
                var ack = try pair.peer.readPubRec();
                ack.deinit(allocator);
                try pair.peer.writePubRel(id, 0);
                var release = try pair.client.readPubRel();
                release.deinit(allocator);
            }
            const Write = struct {
                fn run(connection: *@import("../../runtime.zig").Connection, kind: mqtt.PacketType, packet_id: u16, deadline: std.Io.Clock.Timestamp) !void {
                    return switch (kind) {
                        .puback => connection.writePubAckWithDeadline(packet_id, 0, deadline),
                        .pubrec => connection.writePubRecWithDeadline(packet_id, 0, deadline),
                        .pubcomp => connection.writePubCompWithDeadline(packet_id, 0, deadline),
                        else => unreachable,
                    };
                }
            };
            try std.testing.expectEqual(@as(u16, 1), pair.client.incoming_inflight);
            const foreign = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real });
            try std.testing.expectError(error.Timeout, Write.run(&pair.client, packet_type, id, foreign));
            try std.testing.expectError(error.Timeout, Write.run(&pair.client, packet_type, id, std.Io.Timestamp.zero.withClock(.awake)));
            try std.testing.expectEqual(@as(u16, 1), pair.client.incoming_inflight);
            try std.testing.expect(pair.client.isUsable());
            try std.testing.expectError(error.Timeout, pair.peer.readBrokerEventWithTimeout(.fromMilliseconds(5)));
            try Write.run(&pair.client, packet_type, id, .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }));
            var ack = switch (packet_type) {
                .puback => try pair.peer.readPubAck(),
                .pubrec => try pair.peer.readPubRec(),
                .pubcomp => try pair.peer.readPubComp(),
                else => unreachable,
            };
            defer ack.deinit(allocator);
            try std.testing.expectEqual(id, ack.ack.packet_id);
            try std.testing.expectEqual(@as(u16, if (packet_type == .pubrec) 1 else 0), pair.client.incoming_inflight);
        }
    }
}
