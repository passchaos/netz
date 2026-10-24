//! Borrow complete ACK packets until decoding and protocol state commit.
const std = @import("std");
const Pending = @import("pending.zig").State;
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Reader(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;
        const Incoming = @import("../receive/retained.zig").Reader(Context);

        /// Typed reads preserve wire order even with a full pending queue.
        /// Storage is prepared before I/O so an OOM while decoding cannot
        /// lose a complete packet that has already left the transport.
        pub fn front(connection: *Connection) Error!Pending.Match {
            return Incoming.front(connection, null, null);
        }

        pub fn matching(connection: *Connection, match: anytype, comptime matches: fn (@TypeOf(match), Packet) bool, deadline: ?std.Io.Clock.Timestamp) Error!Pending.Match {
            if (!Context.canReadBuffered(connection)) return error.ConnectionClosed;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
            const terminated = try Context.observeQueuedDisconnect(connection);
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching(match, matches)) |ready| return ready;
            }
            if (terminated) return error.ConnectionClosed;
            try Context.prepareQueue(connection);
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
                var packet = if (deadline) |absolute| try Context.readPacketWithDeadline(connection, absolute) else try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
                if (packet.fixed.packet_type == .disconnect) {
                    connection.pending_packets.?.retainOverflow(packet);
                    owned = false;
                    _ = try Context.observeDisconnect(connection, packet);
                    return error.ConnectionClosed;
                }
                if (matches(match, packet)) {
                    const pending = connection.pending_packets.?;
                    pending.retainOverflow(packet);
                    owned = false;
                    return .{ .packet = packet, .index = pending.packets.items.len };
                }
                Context.queuePacket(connection, packet) catch |err| {
                    connection.pending_packets.?.retainOverflow(packet);
                    owned = false;
                    return err;
                };
                owned = false;
            }
        }
    };
}
