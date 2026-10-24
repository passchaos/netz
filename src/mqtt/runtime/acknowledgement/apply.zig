//! Validate borrowed ACK metadata before releasing or advancing outgoing QoS.
const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;

        pub fn puback(connection: *Connection, ack: mqtt.AckPacket) Error!void {
            if (ack.packet_type != .puback or !connection.packet_identifiers.contains(ack.packet_id, .outgoing_qos1)) return error.UnexpectedPacket;
            try ack.validate(connection.protocol);
            Context.release(connection, ack.packet_id, .at_least_once);
            if (!ack.accepted()) return error.PublishRefused;
        }

        pub fn pubrec(connection: *Connection, ack: mqtt.AckPacket) Error!void {
            return pubrecUntil(connection, ack, null);
        }

        pub fn pubrecUntil(connection: *Connection, ack: mqtt.AckPacket, deadline: ?std.Io.Clock.Timestamp) Error!void {
            if (ack.packet_type != .pubrec) return error.UnexpectedPacket;
            if (connection.packet_identifiers.contains(ack.packet_id, .outgoing_qos2_pubrel)) {
                try ack.validate(connection.protocol);
                // A successful repeat retransmits PUBREL without advancing
                // the already committed stage or changing inflight credit.
                if (!ack.accepted()) return error.UnexpectedPacket;
                try Context.writePubRel(connection, ack.packet_id, connection.protocol == .v3_1, deadline);
                return;
            }
            if (!connection.packet_identifiers.contains(ack.packet_id, .outgoing_qos2)) return error.UnexpectedPacket;
            try ack.validate(connection.protocol);
            if (!ack.accepted()) {
                Context.release(connection, ack.packet_id, .exactly_once);
                return error.PublishRefused;
            }
            // A failed/partial write cannot claim a PUBREL stage the peer may
            // not have observed. Transport errors retain their existing scope.
            try Context.writePubRel(connection, ack.packet_id, false, deadline);
            std.debug.assert(connection.packet_identifiers.transition(ack.packet_id, .outgoing_qos2, .outgoing_qos2_pubrel));
        }

        pub fn pubcomp(connection: *Connection, ack: mqtt.AckPacket) Error!void {
            if (ack.packet_type != .pubcomp or !connection.packet_identifiers.contains(ack.packet_id, .outgoing_qos2_pubrel)) return error.UnexpectedPacket;
            try ack.validate(connection.protocol);
            Context.release(connection, ack.packet_id, .exactly_once);
            if (!ack.accepted()) return error.PublishRefused;
        }
    };
}
