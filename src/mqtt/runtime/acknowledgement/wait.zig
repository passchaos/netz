//! Wait for a correlated response while preserving other packets in wire order.

const std = @import("std");
const mqtt = @import("../../mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Reader(comptime Context: type) type {
    return struct {
        /// Callers prepare the bounded pending queue before sending a request.
        /// Read only the transport: queued packets predate this operation and
        /// consuming them here would reorder traffic or repeatedly requeue it.
        pub fn read(
            connection: *Context.ConnectionType,
            expected: mqtt.PacketType,
            deadline: ?std.Io.Clock.Timestamp,
        ) Context.ErrorType!Context.PacketType {
            return readInternal(connection, expected, null, deadline);
        }

        pub fn readForIdentifier(connection: *Context.ConnectionType, expected: mqtt.PacketType, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.PacketType {
            return readInternal(connection, expected, packet_id, deadline);
        }

        fn readInternal(connection: *Context.ConnectionType, expected: mqtt.PacketType, packet_id: ?u16, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.PacketType {
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
                var packet = if (deadline) |absolute|
                    try Context.readPacketWithDeadline(connection, absolute)
                else
                    try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
                if (matches(connection, packet, expected, packet_id)) {
                    owned = false;
                    return packet;
                }
                Context.queuePacket(connection, packet) catch |err| {
                    // The packet already left the transport. An emergency
                    // slot retains it after either a quota or allocator error
                    // so ordinary reads can recover the exact wire sequence.
                    Context.retainOverflow(connection, packet);
                    owned = false;
                    return err;
                };
                owned = false;
            }
        }

        fn matches(connection: *Context.ConnectionType, packet: Context.PacketType, expected: mqtt.PacketType, packet_id: ?u16) bool {
            if (packet.fixed.packet_type != expected) return false;
            const expected_id = packet_id orelse return true;
            const payload = packet.remainingBytes();
            // Let the complete parser diagnose malformed/unknown responses.
            if (payload.len < 2) return true;
            const id = std.mem.readInt(u16, payload[0..2], .big);
            if (id == expected_id) return true;
            // A known earlier exchange keeps its ACK in wire order for its
            // typed reader, including an ACK arriving during a later wait.
            return !Context.hasControl(connection, expected, id);
        }
    };
}
