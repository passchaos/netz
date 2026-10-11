//! ACK validation must precede every Session state transition.

const std = @import("std");
const mqtt = @import("../mod.zig");
const session = @import("mod.zig");

test "session ACK single-slot PUBREL drain excludes already-sent suffix" {
    var store = session.Store.init(std.testing.allocator, .{
        .max_inflight_payload_bytes_per_session = 10,
    });
    defer store.deinit();
    const opened = try store.open("single-slot-pubrel", false, 60, .zero);
    for ([_][]const u8{ "123456", "789012", "third" }) |payload| {
        _ = try store.enqueuePublish(opened.handle, "ack/topic", payload, .{
            .qos = .exactly_once,
            .now = .zero,
        });
    }
    var output: [1]session.Transmission = undefined;
    const first = (try store.drainInto(opened.handle, .zero, 3, &output))[0].publish.packet_id;
    try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));
    const second = (try store.drainInto(opened.handle, .zero, 3, &output))[0].publish.packet_id;
    for ([_]u16{ first, second }) |packet_id| {
        _ = try store.handleAck(opened.handle, .pubrec, packet_id, 0);
        try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));
        const pubrel = try store.drainInto(opened.handle, .zero, 3, &output);
        try std.testing.expectEqual(packet_id, pubrel[0].pubrel.packet_id);
        // A queued message is still pending, but no sent inflight packet may
        // manufacture a retransmission. The byte cap holds it until PUBCOMP.
        try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));
        try std.testing.expectEqual(@as(usize, 0), (try store.drainInto(opened.handle, .zero, 3, &output)).len);
    }
    _ = try store.handleAck(opened.handle, .pubcomp, first, 0);
    const third = try store.drainInto(opened.handle, .zero, 3, &output);
    try std.testing.expectEqualStrings("third", third[0].publish.payload);
    const third_id = third[0].publish.packet_id;
    try std.testing.expect(!try store.hasUnselectedTransmission(opened.handle));
    _ = try store.handleAck(opened.handle, .pubrec, third_id, 0);
    _ = try store.drainInto(opened.handle, .zero, 3, &output);
    try std.testing.expect(!try store.hasUnselectedTransmission(opened.handle));
    _ = try store.handleAck(opened.handle, .pubcomp, second, 0);
    _ = try store.handleAck(opened.handle, .pubcomp, third_id, 0);
    try std.testing.expectEqual(@as(usize, 0), (try store.stats(opened.handle)).inflight_count);
}

test "session ACK invalid reasons preserve transaction snapshot and credit" {
    const allocator = std.testing.allocator;
    for ([_]mqtt.PacketType{ .puback, .pubrec, .pubcomp }) |packet_type| {
        var store = session.Store.init(allocator, .{});
        defer store.deinit();
        const opened = try store.open("ack-validation", false, 60, .zero);
        _ = try store.enqueuePublish(opened.handle, "ack/topic", "payload", .{
            .qos = if (packet_type == .puback) .at_least_once else .exactly_once,
            .now = .zero,
        });
        var output: [1]session.Transmission = undefined;
        const sent = try store.drainInto(opened.handle, .zero, 1, &output);
        const packet_id = sent[0].publish.packet_id;
        if (packet_type == .pubcomp) {
            _ = try store.handleAck(opened.handle, .pubrec, packet_id, 0);
            _ = try store.drainInto(opened.handle, .zero, 1, &output);
        }
        const before = try store.stats(opened.handle);
        const pending_before = try store.hasUnselectedTransmission(opened.handle);
        var snapshot: std.ArrayList(u8) = .empty;
        defer snapshot.deinit(allocator);
        try store.writeSnapshot(&snapshot, allocator, .zero);
        var after: std.ArrayList(u8) = .empty;
        defer after.deinit(allocator);
        for (0..256) |value| {
            const reason: u8 = @intCast(value);
            const allowed = if (packet_type == .pubcomp)
                reason == 0 or reason == 0x92
            else
                std.mem.indexOfScalar(u8, &.{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 }, reason) != null;
            if (allowed) continue;
            try std.testing.expectError(error.InvalidReasonCode, store.handleAck(opened.handle, packet_type, packet_id, reason));
            try std.testing.expectEqualDeep(before, try store.stats(opened.handle));
            try std.testing.expectEqual(pending_before, try store.hasUnselectedTransmission(opened.handle));
            after.clearRetainingCapacity();
            try store.writeSnapshot(&after, allocator, .zero);
            try std.testing.expectEqualSlices(u8, snapshot.items, after.items);
        }
        // The original transaction still progresses with a legal ACK.
        const action = try store.handleAck(opened.handle, packet_type, packet_id, 0);
        if (packet_type == .pubrec) {
            try std.testing.expectEqual(session.AckAction.send_pubrel, action);
            const pubrel = try store.drainInto(opened.handle, .zero, 1, &output);
            try std.testing.expectEqual(packet_id, pubrel[0].pubrel.packet_id);
            _ = try store.handleAck(opened.handle, .pubcomp, packet_id, 0);
        } else {
            try std.testing.expectEqual(session.AckAction.completed, action);
        }
        try std.testing.expectEqual(@as(usize, 0), (try store.stats(opened.handle)).inflight_count);
    }
}

test "session ACK legal reasons complete their QoS phase" {
    for ([_]mqtt.PacketType{ .puback, .pubrec, .pubcomp }) |packet_type| {
        const reasons: []const u8 = if (packet_type == .pubcomp)
            &.{ 0, 0x92 }
        else
            &.{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 };
        for (reasons) |reason| {
            var store = session.Store.init(std.testing.allocator, .{});
            defer store.deinit();
            const opened = try store.open("legal-ack", false, 60, .zero);
            _ = try store.enqueuePublish(opened.handle, "ack/topic", "payload", .{
                .qos = if (packet_type == .puback) .at_least_once else .exactly_once,
                .now = .zero,
            });
            var output: [1]session.Transmission = undefined;
            const sent = try store.drainInto(opened.handle, .zero, 1, &output);
            const packet_id = sent[0].publish.packet_id;
            if (packet_type == .pubcomp) {
                _ = try store.handleAck(opened.handle, .pubrec, packet_id, 0);
                _ = try store.drainInto(opened.handle, .zero, 1, &output);
            }
            const action = try store.handleAck(opened.handle, packet_type, packet_id, reason);
            if (packet_type == .pubrec and reason < 0x80) {
                try std.testing.expectEqual(session.AckAction.send_pubrel, action);
                const pubrel = try store.drainInto(opened.handle, .zero, 1, &output);
                try std.testing.expectEqual(packet_id, pubrel[0].pubrel.packet_id);
                // An invalid repeated PUBREC must not schedule another PUBREL.
                try std.testing.expectError(error.InvalidReasonCode, store.handleAck(opened.handle, .pubrec, packet_id, 0x95));
                try std.testing.expectEqual(@as(usize, 0), (try store.drainInto(opened.handle, .zero, 1, &output)).len);
                _ = try store.handleAck(opened.handle, .pubcomp, packet_id, 0);
            } else {
                try std.testing.expectEqual(session.AckAction.completed, action);
            }
            const stats = try store.stats(opened.handle);
            try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);
            try std.testing.expectEqual(@as(usize, 0), stats.outgoing_publish_window_used);
            try std.testing.expectEqual(@as(usize, 0), stats.inflight_payload_bytes);
        }
    }
}
