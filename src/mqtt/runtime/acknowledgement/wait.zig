//! Wait for a correlated response while preserving other packets in wire order.

const std = @import("std");
const mqtt = @import("../../mod.zig");

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
            while (true) {
                var packet = if (deadline) |absolute|
                    try Context.readPacketWithDeadline(connection, absolute)
                else
                    try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
                if (packet.fixed.packet_type == expected) {
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
    };
}
