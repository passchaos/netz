//! Retain complete packets until a typed reader accepts their wire type.
//! A terminal packet stays available to the diagnostic reader; local decode
//! allocation failures cannot detach the only copy of its bytes.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const Pending = @import("../acknowledgement/pending.zig").State;
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Reader(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;

        /// Borrow the first complete packet, retaining its exact queue index
        /// until decoding or type validation commits. Prepare the emergency
        /// slot before transport I/O, even when the ordinary quota is full.
        pub fn front(connection: *Connection, expected: ?mqtt.PacketType, deadline: ?std.Io.Clock.Timestamp) Error!Pending.Match {
            if (!Context.canReadBuffered(connection)) return error.ConnectionClosed;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
            if (comptime @hasField(Connection, "retained_receive")) {
                if (connection.retained_receive.bytes != null) try Context.prepareStorage(connection);
            }
            if (try Context.observeRetainedDisconnect(connection)) return error.ConnectionClosed;
            const ready = try peek(connection, deadline);
            if (ready.packet.fixed.packet_type == .disconnect and expected != .disconnect) {
                _ = try Context.observeDisconnect(connection, ready.packet);
                connection.pending_packets.?.keepThrough(connection.allocator, ready.index);
                return error.ConnectionClosed;
            }
            if (expected) |packet_type| {
                if (ready.packet.fixed.packet_type != packet_type) {
                    var packet = connection.pending_packets.?.takeMatch(ready.index);
                    packet.deinit(connection.allocator);
                    return error.UnexpectedPacket;
                }
            }
            return ready;
        }

        pub fn read(connection: *Connection, expected: mqtt.PacketType, deadline: ?std.Io.Clock.Timestamp) Error!Packet {
            const ready = try front(connection, expected, deadline);
            return connection.pending_packets.?.takeMatch(ready.index);
        }

        fn peek(connection: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!Pending.Match {
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching({}, anyPacket)) |ready| return ready;
            }
            if (!connection.isUsable()) return error.ConnectionClosed;
            try Context.prepareStorage(connection);
            const packet = if (deadline) |absolute|
                try Context.readPacketWithDeadline(connection, absolute)
            else
                try Context.readPacket(connection);
            const pending = connection.pending_packets.?;
            pending.retainOverflow(packet);
            return .{ .packet = packet, .index = pending.packets.items.len };
        }

        fn anyPacket(_: void, _: Packet) bool {
            return true;
        }
    };
}
