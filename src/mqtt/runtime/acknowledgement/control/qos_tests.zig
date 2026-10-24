const std = @import("std");
const mqtt = @import("../../../mod.zig");
const Pair = @import("../test_connection.zig").Pair;
const allocator = std.testing.allocator;

test "MQTT SUBACK QoS cannot exceed each requested subscription" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |correlated| {
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            const id = try pair.client.writeSubscribe(&.{
                .{ .topic_filter = "qos/zero", .qos = .at_most_once },
                .{ .topic_filter = "qos/one", .qos = .at_least_once },
                .{ .topic_filter = "qos/two", .qos = .exactly_once },
            }, .{});
            var request = try pair.peer.readSubscribe();
            defer request.deinit(allocator);
            try std.testing.expectEqual(id, request.subscribe.packet_id);
            // The second grant is illegal even though identifier, count and
            // every individual reason code are valid.
            try pair.peer.writeSubAck(id, &.{ 0, 2, 2 }, &.{});
            const result = if (correlated)
                pair.client.completeSubscribeWithTimeout(id, .fromSeconds(1))
            else
                pair.client.readSubAck();
            if (result) |value| {
                var ack = value;
                ack.deinit(allocator);
                return error.TestUnexpectedResult;
            } else |err| try std.testing.expectEqual(error.UnexpectedPacket, err);
            try std.testing.expect(pair.client.hasOutgoingPacketIdentifier(id));
            try pair.peer.writeSubAck(id, &.{ 0, 0, 2 }, &.{});
            var corrected = try pair.client.completeSubscribeWithTimeout(id, .fromSeconds(1));
            defer corrected.deinit(allocator);
            try std.testing.expectEqualSlices(u8, &.{ 0, 0, 2 }, corrected.suback.reason_codes);
            try std.testing.expect(!pair.client.hasOutgoingPacketIdentifier(id));
        }
    }
}

test "MQTT SUBACK QoS snapshots survive timeouts caller mutation and reverse ACK order" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        var pair = try Pair.init(threaded.io(), protocol);
        defer pair.deinit();
        var subscriptions = [_]mqtt.Subscription{
            .{ .topic_filter = "first/zero", .qos = .at_most_once },
            .{ .topic_filter = "first/two", .qos = .exactly_once },
        };
        const first = try pair.client.writeSubscribeWithTimeout(&subscriptions, .{}, .fromSeconds(1));
        const second = try pair.client.writeSubscribeWithDeadline(&.{.{ .topic_filter = "second/one", .qos = .at_least_once }}, .{}, pair.client.transport.deadlineFromNow(.fromSeconds(1)));
        subscriptions[0].qos = .exactly_once;
        subscriptions[1].qos = .at_most_once;
        for ([_]u16{ first, second }) |id| {
            var request = try pair.peer.readSubscribe();
            defer request.deinit(allocator);
            try std.testing.expectEqual(id, request.subscribe.packet_id);
        }
        try std.testing.expectError(error.Timeout, pair.client.completeSubscribeWithTimeout(first, .fromMilliseconds(1)));
        try pair.peer.publish("interleaved", "preserved", .{});
        try pair.peer.writeSubAck(second, &.{2}, &.{});
        try pair.peer.writeSubAck(first, &.{ 0, 2 }, &.{});
        var first_ack = try pair.client.completeSubscribeWithTimeout(first, .fromSeconds(1));
        defer first_ack.deinit(allocator);
        try std.testing.expectEqualSlices(u8, &.{ 0, 2 }, first_ack.suback.reason_codes);
        try std.testing.expect(!pair.client.hasOutgoingPacketIdentifier(first));
        if (pair.client.completeSubscribeWithTimeout(second, .fromSeconds(1))) |value| {
            var unexpected = value;
            unexpected.deinit(allocator);
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.UnexpectedPacket, err);
        try std.testing.expect(pair.client.hasOutgoingPacketIdentifier(second));
        var publish = try pair.client.readPublish();
        defer publish.deinit(allocator);
        try std.testing.expectEqualStrings("preserved", publish.publish.payload);
        try pair.peer.writeSubAck(second, &.{0x80}, &.{});
        var refused = try pair.client.completeSubscribeWithTimeout(second, .fromSeconds(1));
        defer refused.deinit(allocator);
        try std.testing.expectEqualSlices(u8, &.{0x80}, refused.suback.reason_codes);
        try std.testing.expect(!pair.client.hasOutgoingPacketIdentifier(second));
    }
}

test "MQTT SUBACK QoS snapshot allocation failures roll back before any output" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var succeeded = false;
    var failures: usize = 0;
    for (0..32) |fail_index| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const subscriptions = [_]mqtt.Subscription{
            .{ .topic_filter = "zero", .qos = .at_most_once },
            .{ .topic_filter = "one", .qos = .at_least_once },
            .{ .topic_filter = "two", .qos = .exactly_once },
        };
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        pair.client.allocator = failing.allocator();
        const attempt = pair.client.writeSubscribe(&subscriptions, .{});
        pair.client.allocator = allocator;
        const id = if (failing.has_induced_failure) retry: {
            failures += 1;
            try std.testing.expectError(error.OutOfMemory, attempt);
            try std.testing.expect(!pair.client.hasOutgoingPacketIdentifier(1));
            try std.testing.expectEqual(@as(u16, 1), pair.client.next_packet_id);
            try std.testing.expectEqual(@as(u64, 0), pair.client.traffic.stats().messages_sent);
            break :retry try pair.client.writeSubscribe(&subscriptions, .{});
        } else success: {
            succeeded = true;
            break :success try attempt;
        };
        try std.testing.expectEqual(@as(u16, 1), id);
        var request = try pair.peer.readSubscribe();
        defer request.deinit(allocator);
        try std.testing.expectEqual(id, request.subscribe.packet_id);
        for (request.subscribe.subscriptions, subscriptions) |received, sent| try std.testing.expectEqual(sent.qos, received.qos);
        try pair.peer.writeSubAck(id, &.{ 0, 1, 2 }, &.{});
        var ack = try pair.client.completeSubscribeWithTimeout(id, .fromSeconds(1));
        defer ack.deinit(allocator);
        try std.testing.expect(!pair.client.hasOutgoingPacketIdentifier(id));
        if (succeeded) break;
    }
    try std.testing.expect(succeeded);
    try std.testing.expect(failures > 0);
}
