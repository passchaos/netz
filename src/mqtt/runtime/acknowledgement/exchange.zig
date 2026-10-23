//! Complete subscription exchanges under one optional absolute deadline.

const std = @import("std");
const mqtt = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn subscribe(connection: *Context.ConnectionType, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.SubAckType {
            try Context.validateType(connection, .subscribe);
            try Context.validateSubscribe(connection.*, subscriptions, options.properties);
            try Context.prepareQueue(connection);
            const packet_id = Context.nextPacketId(connection);
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Subscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, subscriptions);
            try write(connection, connection.write_scratch.items, .subscribe, deadline);
            var suback = try Context.finishSubAck(connection, try Context.readAck(connection, .suback, deadline));
            errdefer suback.deinit(connection.allocator);
            if (suback.suback.packet_id != packet_id or suback.suback.reason_codes.len != subscriptions.len) return error.UnexpectedPacket;
            return suback;
        }

        pub fn unsubscribe(connection: *Context.ConnectionType, filters: []const []const u8, options: Context.UnsubscribeOptionsType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!Context.UnsubAckType {
            try Context.validateType(connection, .unsubscribe);
            const packet_id = Context.nextPacketId(connection);
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Unsubscribe.write(&connection.write_scratch, connection.allocator, connection.protocol, packet_id, options.properties, filters);
            try Context.prepareQueue(connection);
            try write(connection, connection.write_scratch.items, .unsubscribe, deadline);
            var unsuback = try Context.finishUnsubAck(connection, try Context.readAck(connection, .unsuback, deadline));
            errdefer unsuback.deinit(connection.allocator);
            try Context.validateUnsubAck(connection.protocol, unsuback.unsuback, packet_id, filters.len);
            return unsuback;
        }

        fn write(connection: *Context.ConnectionType, bytes: []u8, packet_type: mqtt.PacketType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!void {
            return if (deadline) |absolute|
                Context.writePacketWithDeadline(connection, bytes, packet_type, absolute)
            else
                Context.writePacket(connection, bytes, packet_type);
        }
    };
}
