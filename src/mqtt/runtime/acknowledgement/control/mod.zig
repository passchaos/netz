//! Recoverable SUBACK/UNSUBACK completion with retained raw packet ownership.
const std = @import("std");
const mqtt = @import("../../../mod.zig");
const Pending = @import("../pending.zig").State;
const Stage = @import("../../packet_identifiers.zig").State.Stage;

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;
        const Packets = @import("../retained.zig").Reader(Context);
        const Match = struct { connection: *Connection, packet_type: mqtt.PacketType, packet_id: u16 };

        pub fn suback(connection: *Connection, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!Context.SubAckType {
            if (connection.packet_identifiers.controlFilterCount(packet_id, .outgoing_subscribe) == null) return error.UnexpectedPacket;
            const match: Match = .{ .connection = connection, .packet_type = .suback, .packet_id = packet_id };
            var ack = try decodeSubAck(connection, try Packets.matching(connection, match, matches, deadline));
            errdefer ack.deinit(connection.allocator);
            if (ack.suback.packet_id != packet_id) return error.UnexpectedPacket;
            return ack;
        }

        pub fn unsuback(connection: *Connection, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!Context.UnsubAckType {
            if (connection.packet_identifiers.controlFilterCount(packet_id, .outgoing_unsubscribe) == null) return error.UnexpectedPacket;
            const match: Match = .{ .connection = connection, .packet_type = .unsuback, .packet_id = packet_id };
            var ack = try decodeUnsubAck(connection, try Packets.matching(connection, match, matches, deadline));
            errdefer ack.deinit(connection.allocator);
            if (ack.unsuback.packet_id != packet_id) return error.UnexpectedPacket;
            return ack;
        }

        pub fn readSubAck(connection: *Connection) Error!Context.SubAckType {
            return decodeSubAck(connection, try Packets.front(connection));
        }

        pub fn readUnsubAck(connection: *Connection) Error!Context.UnsubAckType {
            return decodeUnsubAck(connection, try Packets.front(connection));
        }

        fn decodeSubAck(connection: *Connection, ready: Pending.Match) Error!Context.SubAckType {
            const ack = Context.parseSubAck(connection, ready.packet) catch |err| {
                discardUnlessRetryable(connection, ready.index, err);
                return err;
            };
            _ = connection.pending_packets.?.takeMatch(ready.index);
            return ack;
        }

        fn decodeUnsubAck(connection: *Connection, ready: Pending.Match) Error!Context.UnsubAckType {
            const ack = Context.parseUnsubAck(connection, ready.packet) catch |err| {
                discardUnlessRetryable(connection, ready.index, err);
                return err;
            };
            _ = connection.pending_packets.?.takeMatch(ready.index);
            return ack;
        }

        fn discardUnlessRetryable(connection: *Connection, index: usize, err: Error) void {
            if (err == error.OutOfMemory) return;
            var packet = connection.pending_packets.?.takeMatch(index);
            packet.deinit(connection.allocator);
        }

        /// Decoders call this only after syntax and property validation. An
        /// unknown identifier is readable through ordinary typed APIs; known
        /// commands must match both stage and the expected reason count.
        pub fn finish(connection: *Connection, packet_type: mqtt.PacketType, packet_id: u16, reason_count: usize) Error!void {
            const stage = stageFor(packet_type);
            if (connection.packet_identifiers.controlFilterCount(packet_id, stage)) |expected_count| {
                if ((packet_type == .suback or connection.protocol == .v5) and reason_count != expected_count) return error.UnexpectedPacket;
                const removed = connection.packet_identifiers.remove(packet_id, stage);
                std.debug.assert(removed);
            } else if (connection.packet_identifiers.containsOutgoing(packet_id)) return error.UnexpectedPacket;
        }

        fn stageFor(packet_type: mqtt.PacketType) Stage {
            return switch (packet_type) {
                .suback => .outgoing_subscribe,
                .unsuback => .outgoing_unsubscribe,
                else => unreachable,
            };
        }

        fn matches(match: Match, packet: Packet) bool {
            switch (packet.fixed.packet_type) {
                .suback, .unsuback => {},
                else => return false,
            }
            const payload = packet.remainingBytes();
            if (payload.len < 2) return true;
            const id = std.mem.readInt(u16, payload[0..2], .big);
            if (id == match.packet_id) return true;
            if (packet.fixed.packet_type != match.packet_type) return false;
            return match.connection.packet_identifiers.controlFilterCount(id, stageFor(packet.fixed.packet_type)) == null;
        }
    };
}
