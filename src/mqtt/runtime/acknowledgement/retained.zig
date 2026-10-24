//! Borrow complete ACK packets until decoding and protocol state commit.
const std = @import("std");
const Pending = @import("pending.zig").State;
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Reader(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;

        /// Typed reads preserve wire order even with a full pending queue.
        /// Storage is prepared before I/O so an OOM while decoding cannot
        /// lose a complete packet that has already left the transport.
        pub fn front(connection: *Connection) Error!Pending.Match {
            if (!connection.isUsable()) return error.ConnectionClosed;
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching({}, anyPacket)) |ready| return ready;
            }
            try Context.prepareStorage(connection);
            const packet = try Context.readPacket(connection);
            const pending = connection.pending_packets.?;
            pending.retainOverflow(packet);
            return .{ .packet = packet, .index = pending.packets.items.len };
        }

        pub fn matching(connection: *Connection, match: anytype, comptime matches: fn (@TypeOf(match), Packet) bool, deadline: ?std.Io.Clock.Timestamp) Error!Pending.Match {
            if (!connection.isUsable()) return error.ConnectionClosed;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching(match, matches)) |ready| return ready;
            }
            try Context.prepareQueue(connection);
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), absolute);
                var packet = if (deadline) |absolute| try Context.readPacketWithDeadline(connection, absolute) else try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
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

        fn anyPacket(_: void, _: Packet) bool {
            return true;
        }
    };
}
