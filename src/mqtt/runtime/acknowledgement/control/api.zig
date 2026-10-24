//! Split subscription submission and completion under caller-owned budgets.
const std = @import("std");
const mqtt = @import("../../../mod.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;
        const Deadline = std.Io.Clock.Timestamp;

        /// Submit one SUBSCRIBE. Keep the returned identifier and complete it
        /// later, including after timeout/OOM, without emitting another request.
        pub fn writeSubscribe(connection: *Connection, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType) Error!u16 {
            return Context.writeSubscribe(connection, subscriptions, options, null);
        }

        pub fn writeSubscribeWithTimeout(connection: *Connection, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, timeout: std.Io.Duration) Error!u16 {
            return writeSubscribeWithDeadline(connection, subscriptions, options, try fromTimeout(connection, timeout));
        }

        pub fn writeSubscribeWithDeadline(connection: *Connection, subscriptions: []const mqtt.Subscription, options: Context.SubscribeOptionsType, deadline: Deadline) Error!u16 {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return Context.writeSubscribe(connection, subscriptions, options, deadline);
        }

        /// Complete only this active SUBSCRIBE. The ACK remains owned by the
        /// pending queue until decoding succeeds; sibling traffic keeps order.
        pub fn completeSubscribe(connection: *Connection, packet_id: u16) Error!Context.SubAckType {
            return Context.completeSubscribe(connection, packet_id, null);
        }

        pub fn completeSubscribeWithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!Context.SubAckType {
            return completeSubscribeWithDeadline(connection, packet_id, try fromTimeout(connection, timeout));
        }

        pub fn completeSubscribeWithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!Context.SubAckType {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return Context.completeSubscribe(connection, packet_id, deadline);
        }

        /// Submit one UNSUBSCRIBE while keeping its identifier available to
        /// the caller for a later correlated completeUnsubscribe operation.
        pub fn writeUnsubscribe(connection: *Connection, filters: []const []const u8, options: Context.UnsubscribeOptionsType) Error!u16 {
            return Context.writeUnsubscribe(connection, filters, options, null);
        }

        pub fn writeUnsubscribeWithTimeout(connection: *Connection, filters: []const []const u8, options: Context.UnsubscribeOptionsType, timeout: std.Io.Duration) Error!u16 {
            return writeUnsubscribeWithDeadline(connection, filters, options, try fromTimeout(connection, timeout));
        }

        pub fn writeUnsubscribeWithDeadline(connection: *Connection, filters: []const []const u8, options: Context.UnsubscribeOptionsType, deadline: Deadline) Error!u16 {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return Context.writeUnsubscribe(connection, filters, options, deadline);
        }

        pub fn completeUnsubscribe(connection: *Connection, packet_id: u16) Error!Context.UnsubAckType {
            return Context.completeUnsubscribe(connection, packet_id, null);
        }

        pub fn completeUnsubscribeWithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!Context.UnsubAckType {
            return completeUnsubscribeWithDeadline(connection, packet_id, try fromTimeout(connection, timeout));
        }

        pub fn completeUnsubscribeWithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!Context.UnsubAckType {
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            return Context.completeUnsubscribe(connection, packet_id, deadline);
        }

        fn fromTimeout(connection: *Connection, timeout: std.Io.Duration) Error!Deadline {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return connection.transport.deadlineFromNow(timeout);
        }
    };
}
