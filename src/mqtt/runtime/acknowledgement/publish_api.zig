//! Public synchronous publish budgets and resumable completion entry points.

const std = @import("std");
const mqtt = @import("../../mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Progress = struct {
    /// Set only after the complete PUBLISH is submitted. On a receive timeout,
    /// completePublishWithDeadline can continue this ID under a new budget.
    packet_id: ?u16 = null,
    publish_sent: bool = false,
    completed: bool = false,
};

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;
        const Options = Context.OptionsType;
        const Deadline = std.Io.Clock.Timestamp;

        pub fn publishWithTimeout(connection: *Connection, topic: []const u8, payload: []const u8, options: Options, progress: *Progress, timeout: std.Io.Duration) Error!void {
            progress.* = .{};
            return publishWithDeadline(connection, topic, payload, options, progress, try fromTimeout(connection, timeout));
        }

        /// One awake-clock deadline spans PUBLISH output, all interleaved
        /// input, initial/repeated PUBREC, PUBREL output, and final PUBCOMP.
        /// This starts a new publication; recover a receive timeout through
        /// completePublishWithDeadline using progress.packet_id, avoiding a
        /// duplicate PUBLISH. A transport write failure retires the connection.
        pub fn publishWithDeadline(connection: *Connection, topic: []const u8, payload: []const u8, options: Options, progress: *Progress, deadline: Deadline) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            // Reserve the bounded pending queue before PUBLISH becomes visible
            // so a local queue-allocation failure cannot strand this operation.
            if (options.qos != .at_most_once) try Context.prepareQueue(connection);
            progress.packet_id = try Context.writePublish(connection, topic, payload, options, deadline);
            progress.publish_sent = true;
            if (progress.packet_id) |id| try Context.complete(connection, id, options.qos, deadline);
            progress.completed = true;
        }

        /// Submit one PUBLISH under a budget; the returned ID remains owned
        /// until a completePublish call receives its final acknowledgement.
        pub fn writePublishWithTimeout(connection: *Connection, topic: []const u8, payload: []const u8, options: Options, timeout: std.Io.Duration) Error!?u16 {
            return writePublishWithDeadline(connection, topic, payload, options, try fromTimeout(connection, timeout));
        }

        pub fn writePublishWithDeadline(connection: *Connection, topic: []const u8, payload: []const u8, options: Options, deadline: Deadline) Error!?u16 {
            return Context.writePublish(connection, topic, payload, options, deadline);
        }

        pub fn completePublishWithTimeout(connection: *Connection, packet_id: u16, qos: mqtt.QoS, timeout: std.Io.Duration) Error!void {
            return completePublishWithDeadline(connection, packet_id, qos, try fromTimeout(connection, timeout));
        }

        /// A receive timeout preserves Packet Identifier ownership, partial
        /// input, and the current QoS stage. QoS 2 already awaiting PUBCOMP
        /// resumes there rather than resending the original PUBLISH.
        pub fn completePublishWithDeadline(connection: *Connection, packet_id: u16, qos: mqtt.QoS, deadline: Deadline) Error!void {
            return Context.complete(connection, packet_id, qos, deadline);
        }

        pub fn completePublishQoS2WithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!void {
            return completePublishWithTimeout(connection, packet_id, .exactly_once, timeout);
        }

        pub fn completePublishQoS2WithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!void {
            return completePublishWithDeadline(connection, packet_id, .exactly_once, deadline);
        }

        pub fn completePublishPubAckWithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!void {
            return completePublishPubAckWithDeadline(connection, packet_id, try fromTimeout(connection, timeout));
        }

        pub fn completePublishPubAckWithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!void {
            return Context.puback(connection, packet_id, deadline);
        }

        pub fn completePublishPubRecWithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!u16 {
            return completePublishPubRecWithDeadline(connection, packet_id, try fromTimeout(connection, timeout));
        }

        pub fn completePublishPubRecWithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!u16 {
            return Context.pubrec(connection, packet_id, deadline);
        }

        pub fn completePublishPubCompWithTimeout(connection: *Connection, packet_id: u16, timeout: std.Io.Duration) Error!void {
            return completePublishPubCompWithDeadline(connection, packet_id, try fromTimeout(connection, timeout));
        }

        pub fn completePublishPubCompWithDeadline(connection: *Connection, packet_id: u16, deadline: Deadline) Error!void {
            return Context.pubcomp(connection, packet_id, deadline);
        }

        fn fromTimeout(connection: *Connection, timeout: std.Io.Duration) Error!Deadline {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return connection.transport.deadlineFromNow(timeout);
        }
    };
}
