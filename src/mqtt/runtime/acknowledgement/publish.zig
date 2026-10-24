//! Correlated QoS completion with bounded preservation of interleaved packets.

const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;
        const Packet = Context.PacketType;
        const Match = struct {
            connection: *Connection,
            packet_type: mqtt.PacketType,
            packet_id: u16,
        };

        pub fn puback(connection: *Connection, packet_id: u16) Error!void {
            if (packet_id != 0 and !Context.contains(connection, packet_id, .outgoing_qos1)) return error.UnexpectedPacket;
            while (true) {
                var ack = try read(connection, .puback, packet_id);
                defer ack.deinit(connection.allocator);
                if (ack.ack.packet_type == .pubrec and Context.contains(connection, ack.ack.packet_id, .outgoing_qos2_pubrel)) {
                    try Context.applyPubRec(connection, ack.ack);
                    continue;
                }
                try Context.applyPubAck(connection, ack.ack);
                return;
            }
        }

        pub fn pubrec(connection: *Connection, packet_id: u16) Error!u16 {
            if (packet_id != 0 and !Context.contains(connection, packet_id, .outgoing_qos2)) return error.UnexpectedPacket;
            while (true) {
                var ack = try read(connection, .pubrec, packet_id);
                defer ack.deinit(connection.allocator);
                if (ack.ack.packet_type != .pubrec) return error.UnexpectedPacket;
                const repeated = Context.contains(connection, ack.ack.packet_id, .outgoing_qos2_pubrel);
                try Context.applyPubRec(connection, ack.ack);
                // Completing the next initial PUBREC may encounter a repeat
                // for an older exchange. Resend its PUBREL and keep waiting.
                if (repeated) continue;
                return ack.ack.packet_id;
            }
        }

        pub fn pubcomp(connection: *Connection, packet_id: u16) Error!void {
            if (!Context.contains(connection, packet_id, .outgoing_qos2_pubrel)) return error.UnexpectedPacket;
            while (true) {
                var ack = try read(connection, .pubcomp, packet_id);
                defer ack.deinit(connection.allocator);
                if (ack.ack.packet_type == .pubrec) {
                    // MQTT 4.3.3: successful PUBREC repeats require PUBREL
                    // retransmission until PUBCOMP completes the exchange.
                    try Context.applyPubRec(connection, ack.ack);
                    continue;
                }
                try Context.applyPubComp(connection, ack.ack);
                return;
            }
        }

        fn read(connection: *Connection, packet_type: mqtt.PacketType, packet_id: u16) Error!Context.AckType {
            if (!connection.isUsable()) return error.ConnectionClosed;
            const match: Match = .{ .connection = connection, .packet_type = packet_type, .packet_id = packet_id };
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching(match, matches)) |queued| {
                    const ack = try Context.parseAck(connection, queued.packet);
                    _ = pending.takeMatch(queued.index);
                    return ack;
                }
            }
            try Context.prepareQueue(connection);
            while (true) {
                var packet = try Context.readPacket(connection);
                var owned = true;
                defer if (owned) packet.deinit(connection.allocator);
                if (matches(match, packet)) {
                    const ack = Context.parseAck(connection, packet) catch |err| {
                        if (err == error.OutOfMemory) {
                            connection.pending_packets.?.retainOverflow(packet);
                            owned = false;
                        }
                        return err;
                    };
                    owned = false;
                    return ack;
                }
                Context.queuePacket(connection, packet) catch |err| {
                    // This complete packet has already left the transport.
                    // Preserve it in the same emergency slot used by PING
                    // and subscription waits so the caller can drain/retry.
                    connection.pending_packets.?.retainOverflow(packet);
                    owned = false;
                    return err;
                };
                owned = false;
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
