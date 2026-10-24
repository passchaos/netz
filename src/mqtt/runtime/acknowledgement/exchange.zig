//! Complete subscription exchanges under one optional absolute deadline.

const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn subscribe(connection: *Context.ConnectionType, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.SubAckType {
            return Context.completeSubscribe(connection, try writeSubscribe(connection, subscriptions, options, deadline), deadline);
        }

        pub fn writeSubscribe(connection: *Context.ConnectionType, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!u16 {
            try Context.validateType(connection, .subscribe);
            try Context.validateSubscribe(connection.*, subscriptions, options.properties);
            try Context.prepareQueue(connection);
            const initial = connection.next_packet_id;
            const packet_id = try Context.reserve(connection, .outgoing_subscribe, subscriptions.len);
            errdefer {
                _ = connection.packet_identifiers.remove(connection.allocator, packet_id, .outgoing_subscribe);
                connection.next_packet_id = initial;
            }
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Subscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, subscriptions);
            try connection.packet_identifiers.rememberSubscribe(connection.allocator, packet_id, subscriptions);
            try write(connection, connection.write_scratch.items, .subscribe, deadline);
            return packet_id;
        }

        pub fn unsubscribe(connection: *Context.ConnectionType, filters: []const []const u8, options: Context.UnsubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.UnsubAckType {
            return Context.completeUnsubscribe(connection, try writeUnsubscribe(connection, filters, options, deadline), deadline);
        }

        pub fn writeUnsubscribe(connection: *Context.ConnectionType, filters: []const []const u8, options: Context.UnsubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!u16 {
            try Context.validateType(connection, .unsubscribe);
            try Context.prepareQueue(connection);
            const initial = connection.next_packet_id;
            const packet_id = try Context.reserve(connection, .outgoing_unsubscribe, filters.len);
            errdefer {
                _ = connection.packet_identifiers.remove(connection.allocator, packet_id, .outgoing_unsubscribe);
                connection.next_packet_id = initial;
            }
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Unsubscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, filters);
            try write(connection, connection.write_scratch.items, .unsubscribe, deadline);
            return packet_id;
        }

        fn write(connection: *Context.ConnectionType, bytes: []u8, packet_type: mqtt.PacketType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!void {
            return if (deadline) |absolute|
                Context.writePacketWithDeadline(connection, bytes, packet_type, absolute)
            else
                Context.writePacket(connection, bytes, packet_type);
        }
    };
}
