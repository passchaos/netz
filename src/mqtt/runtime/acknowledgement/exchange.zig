//! Complete subscription exchanges under one optional absolute deadline.

const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn subscribe(connection: *Context.ConnectionType, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.SubAckType {
            try Context.validateType(connection, .subscribe);
            try Context.validateSubscribe(connection.*, subscriptions, options.properties);
            try Context.prepareQueue(connection);
            const initial = connection.next_packet_id;
            const packet_id = try Context.reserve(connection, .outgoing_subscribe, subscriptions.len);
            var sent = false;
            errdefer if (!sent) {
                _ = connection.packet_identifiers.remove(packet_id, .outgoing_subscribe);
                connection.next_packet_id = initial;
            };
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Subscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, subscriptions);
            try write(connection, connection.write_scratch.items, .subscribe, deadline);
            sent = true;
            var suback = try Context.finishSubAck(connection, try Context.readAck(connection, .suback, packet_id, deadline));
            errdefer suback.deinit(connection.allocator);
            if (suback.suback.packet_id != packet_id or suback.suback.reason_codes.len != subscriptions.len) return error.UnexpectedPacket;
            return suback;
        }

        pub fn unsubscribe(connection: *Context.ConnectionType, filters: []const []const u8, options: Context.UnsubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.UnsubAckType {
            try Context.validateType(connection, .unsubscribe);
            try Context.prepareQueue(connection);
            const initial = connection.next_packet_id;
            const packet_id = try Context.reserve(connection, .outgoing_unsubscribe, filters.len);
            var sent = false;
            errdefer if (!sent) {
                _ = connection.packet_identifiers.remove(packet_id, .outgoing_unsubscribe);
                connection.next_packet_id = initial;
            };
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Unsubscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, filters);
            try write(connection, connection.write_scratch.items, .unsubscribe, deadline);
            sent = true;
            var unsuback = try Context.finishUnsubAck(connection, try Context.readAck(connection, .unsuback, packet_id, deadline));
            errdefer unsuback.deinit(connection.allocator);
            try Context.validateUnsubAck(connection.protocol, unsuback.unsuback, packet_id, filters.len);
            return unsuback;
        }

        /// Typed readers also settle late responses after a timed-out wait.
        /// Unknown identifiers remain readable for callers decoding raw wire
        /// fixtures; an identifier owned by a different stage is an error.
        pub fn finish(connection: *Context.ConnectionType, packet_type: mqtt.PacketType, packet_id: u16, reason_count: usize) Context.ErrorType!void {
            const stage: @import("../packet_identifiers.zig").State.Stage = switch (packet_type) {
                .suback => .outgoing_subscribe,
                .unsuback => .outgoing_unsubscribe,
                else => unreachable,
            };
            if (connection.packet_identifiers.controlFilterCount(packet_id, stage)) |expected_count| {
                if ((packet_type == .suback or connection.protocol == .v5) and reason_count != expected_count) return error.UnexpectedPacket;
                std.debug.assert(connection.packet_identifiers.remove(packet_id, stage));
            } else if (connection.packet_identifiers.containsOutgoing(packet_id)) return error.UnexpectedPacket;
        }

        fn write(connection: *Context.ConnectionType, bytes: []u8, packet_type: mqtt.PacketType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!void {
            return if (deadline) |absolute|
                Context.writePacketWithDeadline(connection, bytes, packet_type, absolute)
            else
                Context.writePacket(connection, bytes, packet_type);
        }
    };
}
