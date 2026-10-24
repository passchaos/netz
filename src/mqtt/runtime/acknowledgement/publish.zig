//! Correlated QoS completion with bounded preservation of interleaved packets.

const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;
        const Packet = Context.PacketType;
        const Ready = struct { ack: Context.AckType, index: usize };
        const Packets = @import("retained.zig").Reader(Context);
        const Match = struct {
            connection: *Connection,
            packet_type: mqtt.PacketType,
            packet_id: u16,
        };

        pub fn puback(connection: *Connection, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!void {
            if (packet_id != 0 and !Context.contains(connection, packet_id, .outgoing_qos1)) return error.UnexpectedPacket;
            while (true) {
                var ready = try read(connection, .puback, packet_id, deadline);
                const ack = &ready.ack;
                var retain = false;
                defer finish(connection, &ready, retain);
                errdefer |err| retain = err == error.Timeout and connection.isUsable();
                if (ack.ack.packet_type == .pubrec and Context.contains(connection, ack.ack.packet_id, .outgoing_qos2_pubrel)) {
                    try Context.applyPubRec(connection, ack.ack, deadline);
                    continue;
                }
                try Context.applyPubAck(connection, ack.ack);
                return;
            }
        }

        pub fn pubrec(connection: *Connection, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!u16 {
            if (packet_id != 0 and !Context.contains(connection, packet_id, .outgoing_qos2)) return error.UnexpectedPacket;
            while (true) {
                var ready = try read(connection, .pubrec, packet_id, deadline);
                const ack = &ready.ack;
                var retain = false;
                defer finish(connection, &ready, retain);
                errdefer |err| retain = err == error.Timeout and connection.isUsable();
                if (ack.ack.packet_type != .pubrec) return error.UnexpectedPacket;
                const repeated = Context.contains(connection, ack.ack.packet_id, .outgoing_qos2_pubrel);
                try Context.applyPubRec(connection, ack.ack, deadline);
                // Completing the next initial PUBREC may encounter a repeat
                // for an older exchange. Resend its PUBREL and keep waiting.
                if (repeated) continue;
                return ack.ack.packet_id;
            }
        }

        pub fn pubcomp(connection: *Connection, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!void {
            if (!Context.contains(connection, packet_id, .outgoing_qos2_pubrel)) return error.UnexpectedPacket;
            while (true) {
                var ready = try read(connection, .pubcomp, packet_id, deadline);
                const ack = &ready.ack;
                var retain = false;
                defer finish(connection, &ready, retain);
                errdefer |err| retain = err == error.Timeout and connection.isUsable();
                if (ack.ack.packet_type == .pubrec) {
                    // MQTT 4.3.3: successful PUBREC repeats require PUBREL
                    // retransmission until PUBCOMP completes the exchange.
                    try Context.applyPubRec(connection, ack.ack, deadline);
                    continue;
                }
                try Context.applyPubComp(connection, ack.ack);
                return;
            }
        }

        fn read(connection: *Connection, packet_type: mqtt.PacketType, packet_id: u16, deadline: ?std.Io.Clock.Timestamp) Error!Ready {
            const match: Match = .{ .connection = connection, .packet_type = packet_type, .packet_id = packet_id };
            const ready = try Packets.matching(connection, match, matches, deadline);
            const ack = try Context.parseAck(connection, ready.packet);
            return .{ .ack = ack, .index = ready.index };
        }

        fn finish(connection: *Connection, ready: *Ready, retain: bool) void {
            ready.ack.ack.deinit(connection.allocator);
            if (!retain) {
                var packet = connection.pending_packets.?.takeMatch(ready.index);
                packet.deinit(connection.allocator);
            }
        }

        fn matches(match: Match, packet: Packet) bool {
            switch (packet.fixed.packet_type) {
                .puback, .pubrec, .pubcomp => {},
                else => return false,
            }
            const payload = packet.remainingBytes();
            // Let the full ACK parser diagnose missing/invalid identifiers.
            if (payload.len < 2) return true;
            const id = std.mem.readInt(u16, payload[0..2], .big);
            // A retry belongs to an already active exchange and must be
            // serviced even while another publication owns this wait.
            if (packet.fixed.packet_type == .pubrec and Context.contains(match.connection, id, .outgoing_qos2_pubrel)) return true;
            if (match.packet_id == id) return true;
            if (match.packet_id == 0 and packet.fixed.packet_type == match.packet_type) return true;
            // Unknown identifiers remain state errors; only known sibling
            // exchanges can defer their ACK for a different completion call.
            return !Context.hasOutgoing(match.connection, id);
        }
    };
}
