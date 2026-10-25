//! DISCONNECT encoding, bounded output, and post-write Session expiry.
const std = @import("std");
const mqtt = @import("../mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;

        pub fn write(connection: *Connection, reason_code: u8, properties: []const mqtt.Property) Error!void {
            return until(connection, reason_code, properties, null);
        }

        pub fn withDeadline(connection: *Connection, reason_code: u8, properties: []const mqtt.Property, deadline: std.Io.Clock.Timestamp) Error!void {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return until(connection, reason_code, properties, deadline);
        }

        pub fn withTimeout(connection: *Connection, reason_code: u8, properties: []const mqtt.Property, timeout: std.Io.Duration) Error!void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return withDeadline(connection, reason_code, properties, connection.transport.deadlineFromNow(timeout));
        }

        fn until(connection: *Connection, reason_code: u8, properties: []const mqtt.Property, deadline: ?std.Io.Clock.Timestamp) Error!void {
            try Context.validate(connection, reason_code, properties);
            if (properties.len == 0) {
                var encoded: [mqtt.Disconnect.no_properties_max_len]u8 = undefined;
                const bytes = try mqtt.Disconnect.writeNoPropertiesInto(&encoded, connection.protocol, reason_code);
                return if (deadline) |absolute|
                    Context.generateBefore(connection, bytes, .disconnect, absolute)
                else
                    Context.generate(connection, bytes, .disconnect);
            }
            connection.write_scratch.clearRetainingCapacity();
            try mqtt.Disconnect.write(&connection.write_scratch, connection.allocator, connection.protocol, reason_code, properties);
            if (deadline) |absolute|
                try Context.generateBefore(connection, connection.write_scratch.items, .disconnect, absolute)
            else
                try Context.generate(connection, connection.write_scratch.items, .disconnect);
            if (mqtt.sessionExpiryInterval(properties)) |interval| connection.session_expiry_interval = interval;
        }
    };
}
