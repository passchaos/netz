//! MQTT 5 acknowledgement reason-code policy, shared by wire and Session APIs.

const std = @import("std");
const mqtt = @import("mod.zig");

/// Validate the packet-specific sets in MQTT 5 sections 3.4.2.1-3.7.2.1.
/// Packet Too Large (0x95) belongs to CONNACK/DISCONNECT, not a QoS ACK.
pub fn validate(packet_type: mqtt.PacketType, reason_code: u8) mqtt.Error!void {
    switch (packet_type) {
        .puback, .pubrec => switch (reason_code) {
            0x00, // Success.
            0x10, // No matching subscribers.
            0x80, // Unspecified error.
            0x83, // Implementation specific error.
            0x87, // Not authorized.
            0x90, // Topic Name invalid.
            0x91, // Packet Identifier in use.
            0x97, // Quota exceeded.
            0x99, // Payload format invalid.
            => {},
            else => return error.InvalidReasonCode,
        },
        .pubrel, .pubcomp => switch (reason_code) {
            0x00, // Success.
            0x92, // Packet Identifier not found.
            => {},
            else => return error.InvalidReasonCode,
        },
        else => return error.InvalidPacketType,
    }
}

test "MQTT ACK codecs enforce every packet-specific reason code" {
    const allocator = std.testing.allocator;
    for ([_]mqtt.PacketType{ .puback, .pubrec, .pubrel, .pubcomp }) |packet_type| {
        for (0..256) |value| {
            const reason: u8 = @intCast(value);
            // Independent literal sets from the specification, also exercising
            // rejection of codes that belong only to another Control Packet.
            const allowed = if (packet_type == .puback or packet_type == .pubrec)
                std.mem.indexOfScalar(u8, &.{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 }, reason) != null
            else
                reason == 0 or reason == 0x92;
            var packet = [_]u8{
                (@as(u8, @intFromEnum(packet_type)) << 4) | packet_type.defaultFlags(),
                3,
                0,
                1,
                reason,
            };
            var storage = [_]u8{0xa5} ** mqtt.AckPacket.no_properties_max_len;
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(allocator);
            try output.appendSlice(allocator, "prefix");
            if (allowed) {
                var parsed = try mqtt.AckPacket.parse(allocator, .v5, &packet);
                defer parsed.deinit(allocator);
                try std.testing.expectEqual(reason, parsed.reason_code);
                const encoded = try mqtt.AckPacket.writeNoPropertiesInto(&storage, .v5, packet_type, 1, reason);
                try mqtt.AckPacket.write(&output, allocator, .v5, packet_type, 1, reason, &.{});
                try std.testing.expectEqualSlices(u8, encoded, output.items["prefix".len..]);
            } else {
                try std.testing.expectError(error.InvalidReasonCode, mqtt.AckPacket.parse(allocator, .v5, &packet));
                try std.testing.expectError(error.InvalidReasonCode, mqtt.AckPacket.writeNoPropertiesInto(&storage, .v5, packet_type, 1, reason));
                try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** mqtt.AckPacket.no_properties_max_len), &storage);
                try std.testing.expectError(error.InvalidReasonCode, mqtt.AckPacket.write(&output, allocator, .v5, packet_type, 1, reason, &.{}));
                try std.testing.expectEqualStrings("prefix", output.items);
            }
        }
    }
}
