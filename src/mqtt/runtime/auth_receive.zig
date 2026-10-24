//! Wait for AUTH while retaining established-session traffic in bounded wire
//! order. Initial authentication continues to use the strict next-packet read.
const std = @import("std");
const mqtt = @import("../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn read(connection: *Context.ConnectionType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.AuthType {
            if (!Context.canReadBuffered(connection)) return error.ConnectionClosed;
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching({}, matches)) |found| {
                    if (found.packet.fixed.packet_type == .disconnect) {
                        try Context.validateDisconnect(connection, found.packet.bytes);
                        pending.keepThrough(connection.allocator, found.index);
                        return error.ConnectionClosed;
                    }
                    const result = try Context.parse(connection, found.packet);
                    _ = pending.takeMatch(found.index);
                    return result;
                }
            }
            try Context.prepare(connection);
            while (true) {
                var packet = if (deadline) |absolute|
                    try Context.readPacketWithDeadline(connection, absolute)
                else
                    try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
                if (packet.fixed.packet_type == .auth) {
                    const result = Context.parse(connection, packet) catch |err| {
                        // AUTH decode allocates. Preserve its exact position
                        // after consumed ordinary packets on local failure.
                        if (err == error.OutOfMemory) {
                            Context.retainOverflow(connection, packet);
                            owned = false;
                        }
                        return err;
                    };
                    owned = false;
                    return result;
                }
                if (packet.fixed.packet_type == .disconnect) {
                    Context.validateDisconnect(connection, packet.bytes) catch |err| {
                        if (err == error.OutOfMemory) {
                            Context.retainOverflow(connection, packet);
                            owned = false;
                        }
                        return err;
                    };
                }
                Context.queuePacket(connection, packet) catch |err| {
                    Context.retainOverflow(connection, packet);
                    owned = false;
                    return err;
                };
                owned = false;
                // A peer's terminal packet cannot be followed by AUTH.
                // Preserve its diagnostics for the ordinary event reader.
                if (packet.fixed.packet_type == .disconnect) return error.ConnectionClosed;
            }
        }

        fn matches(_: void, packet: Context.PacketType) bool {
            return packet.fixed.packet_type == mqtt.PacketType.auth or packet.fixed.packet_type == .disconnect;
        }
    };
}
