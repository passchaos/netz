//! Split Keep Alive writes for event loops sharing a single receive owner.
const std = @import("std");
const mqtt = @import("../mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn Sender(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;

        pub fn writePingReq(connection: *Connection) Error!void {
            return write(connection, false, null);
        }

        pub fn writePingReqWithTimeout(connection: *Connection, timeout: std.Io.Duration) Error!void {
            return writePingReqWithDeadline(connection, try fromTimeout(connection, timeout));
        }

        /// A write failure retains the transport's existing retirement rule:
        /// an indeterminate MQTT or WebSocket prefix cannot be replayed.
        pub fn writePingReqWithDeadline(connection: *Connection, deadline: std.Io.Clock.Timestamp) Error!void {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return write(connection, false, deadline);
        }

        pub fn writePingResp(connection: *Connection) Error!void {
            return write(connection, true, null);
        }

        pub fn writePingRespWithTimeout(connection: *Connection, timeout: std.Io.Duration) Error!void {
            return writePingRespWithDeadline(connection, try fromTimeout(connection, timeout));
        }

        pub fn writePingRespWithDeadline(connection: *Connection, deadline: std.Io.Clock.Timestamp) Error!void {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return write(connection, true, deadline);
        }

        fn fromTimeout(connection: *Connection, timeout: std.Io.Duration) Error!std.Io.Clock.Timestamp {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return connection.transport.deadlineFromNow(timeout);
        }

        fn write(connection: *Connection, response: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const packet_type: mqtt.PacketType = if (response) .pingresp else .pingreq;
            try Context.validate(connection, packet_type);
            var storage: [mqtt.ping_packet_len]u8 = undefined;
            const encoded = mqtt.writePingInto(&storage, response);
            if (deadline) |absolute| {
                try Context.writeDeadline(connection, encoded, packet_type, absolute);
            } else try Context.write(connection, encoded, packet_type);
        }
    };
}
