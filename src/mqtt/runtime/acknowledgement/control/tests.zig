const std = @import("std");
const mqtt = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const Pending = @import("../pending.zig").State;

const Operation = enum { subscribe, unsubscribe };
const allocator = std.testing.allocator;

fn borrowed(bytes: []const u8) runtime.OwnedPacket {
    return .{ .bytes = @constCast(bytes), .fixed = mqtt.FixedHeader.parse(bytes) catch unreachable, .owns_bytes = false };
}

fn read(connection: *runtime.Connection, operation: Operation, correlated: bool) !u16 {
    switch (operation) {
        .subscribe => {
            var ack = if (correlated) try connection.completeSubscribe(42) else try connection.readSubAck();
            defer ack.deinit(connection.allocator);
            return ack.suback.packet_id;
        },
        .unsubscribe => {
            var ack = if (correlated) try connection.completeUnsubscribe(42) else try connection.readUnsubAck();
            defer ack.deinit(connection.allocator);
            return ack.unsuback.packet_id;
        },
    }
}

test "MQTT subscription completion and typed readers retain ACK on decode allocation failure" {
    for ([_]bool{ false, true }) |correlated| {
        for (std.enums.values(Operation)) |operation| {
            var succeeded = false;
            for (0..8) |fail_index| {
                var client = runtime.Connection{ .allocator = allocator, .transport = undefined };
                defer client.packet_identifiers.deinit(allocator);
                const stage: @import("../../packet_identifiers.zig").State.Stage = if (operation == .subscribe) .outgoing_subscribe else .outgoing_unsubscribe;
                try client.packet_identifiers.addControl(allocator, 42, stage, 1);
                var pending: Pending = .{};
                defer pending.deinit(allocator);
                client.pending_packets = &pending;
                // Independently specified MQTT 5 ACK 42, Reason String "yes",
                // and success. Both property decoding and reasons can allocate.
                const ack = if (operation == .subscribe) "\x90\x0a\x00\x2a\x06\x1f\x00\x03yes\x00" else "\xb0\x0a\x00\x2a\x06\x1f\x00\x03yes\x00";
                const first = "\x30\x05\x00\x01x\x001";
                const second = "\x30\x05\x00\x01x\x002";
                if (correlated) try pending.append(allocator, borrowed(first), 3, 100);
                try pending.append(allocator, borrowed(ack), 3, 100);
                try pending.append(allocator, borrowed(first), 3, 100);
                pending.retainOverflow(borrowed(second));
                const before_bytes = pending.queued_bytes;
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
                client.allocator = failing.allocator();
                const result = read(&client, operation, correlated);
                client.allocator = allocator;
                if (failing.has_induced_failure) {
                    try std.testing.expectError(error.OutOfMemory, result);
                    try std.testing.expectEqual(@as(usize, 3) + @intFromBool(correlated), pending.count());
                    try std.testing.expectEqual(before_bytes, pending.queued_bytes);
                    try std.testing.expectEqual(@as(usize, 0), pending.head);
                    try std.testing.expectEqualStrings(ack, pending.packets.items[@intFromBool(correlated)].bytes);
                    try std.testing.expect(client.hasOutgoingPacketIdentifier(42));
                    try std.testing.expectEqual(@as(u16, 42), try read(&client, operation, correlated));
                } else {
                    succeeded = true;
                    try std.testing.expectEqual(@as(u16, 42), try result);
                }
                try std.testing.expect(!client.hasOutgoingPacketIdentifier(42));
                if (correlated) try std.testing.expectEqualStrings(first, pending.pop().?.bytes);
                try std.testing.expectEqualStrings(first, pending.pop().?.bytes);
                try std.testing.expectEqualStrings(second, pending.pop().?.bytes);
                try std.testing.expect(pending.pop() == null);
                if (succeeded) break;
            }
            try std.testing.expect(succeeded);
        }
    }
}
