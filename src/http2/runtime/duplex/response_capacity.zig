//! Defer application stream credit while keeping connection credit available.
const std = @import("std");
const capacity = @import("../flow/capacity.zig");

pub const ConnectionCreditPolicy = enum { immediate, low_watermark };

pub fn Capacity(comptime Hooks: anytype) type {
    return struct {
        pub fn receive(stream: anytype, data: anytype, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) Hooks.Error!void {
            return receiveWithPolicy(stream, data, end_stream, deadline, .immediate);
        }

        pub fn receiveWithPolicy(stream: anytype, data: anytype, end_stream: bool, deadline: ?std.Io.Clock.Timestamp, policy: ConnectionCreditPolicy) Hooks.Error!void {
            if (stream.deferred_response_credit == 0x80000000) return Hooks.automatic(stream.connection, stream.stream_id, data, end_stream, deadline);
            const connection = stream.connection;
            const charged = data.data.len + data.padding_bytes;
            const connection_increment: ?u31 = if (policy == .immediate)
                if (charged != 0) @intCast(charged) else null
            else
                capacity.plan(connection.recv_connection_window.available(), 0, Hooks.connectionTarget(connection.*), 0, data.padding_bytes, true).connection;
            const deferred: u31 = if (end_stream) @intCast(stream.deferred_response_credit) else std.math.cast(u31, std.math.add(usize, stream.deferred_response_credit, data.data.len) catch return error.FlowControlViolation) orelse return error.FlowControlViolation;
            Hooks.update(connection, stream.stream_id, connection_increment, if (!end_stream and data.padding_bytes != 0) @as(u31, data.padding_bytes) else null, deadline) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {
                    // A physically closed peer cannot use a grant. Restore
                    // the rolled-back local accounting and allow complete
                    // DATA/trailers already in the receive buffer to finish.
                    if (connection_increment) |increment| try connection.recv_connection_window.update(increment);
                    if (!end_stream and data.padding_bytes != 0) try (try Hooks.window(connection, stream.stream_id)).update(data.padding_bytes);
                    connection.terminal_write_failed = false;
                    connection.aggregate_timeout_unusable = false;
                },
                else => {
                    connection.aggregate_timeout_unusable = true;
                    connection.terminal_write_failed = true;
                    return err;
                },
            };
            stream.deferred_response_credit = deferred;
        }

        /// The caller retains acknowledged bytes when this returns zero.
        /// A full window always flushes available consumed credit for progress.
        pub fn releaseBatched(stream: anytype, amount: usize, deadline: std.Io.Clock.Timestamp) Hooks.Error!usize {
            if (stream.response_finished) {
                try release(stream, amount, deadline);
                return amount;
            }
            if (stream.deferred_response_credit == 0x80000000 or amount > stream.deferred_response_credit) return error.FlowControlViolation;
            if (stream.connection.aggregate_timeout_unusable) return error.ConnectionClosed;
            const threshold = @max(@as(usize, 1), @as(usize, Hooks.streamTarget(stream.connection.*)) / 2);
            if (amount < threshold and (try Hooks.window(stream.connection, stream.stream_id)).available() != 0) return 0;
            try release(stream, amount, deadline);
            return amount;
        }

        pub fn release(stream: anytype, amount: usize, deadline: std.Io.Clock.Timestamp) Hooks.Error!void {
            // A terminal peer no longer needs stream WINDOW_UPDATE. Its
            // connection credit was already returned while DATA was received.
            if (stream.response_finished) {
                stream.deferred_response_credit = 0;
                return;
            }
            if (stream.deferred_response_credit == 0x80000000 or amount > stream.deferred_response_credit) return error.FlowControlViolation;
            if (stream.connection.aggregate_timeout_unusable) return error.ConnectionClosed;
            var remaining = amount;
            while (remaining != 0) {
                const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
                Hooks.update(stream.connection, stream.stream_id, null, increment, deadline) catch |err| switch (err) {
                    error.SocketUnconnected, error.ConnectionResetByPeer => {
                        try (try Hooks.window(stream.connection, stream.stream_id)).update(increment);
                        stream.connection.terminal_write_failed = false;
                        stream.connection.aggregate_timeout_unusable = false;
                    },
                    else => {
                        stream.connection.aggregate_timeout_unusable = true;
                        stream.connection.terminal_write_failed = true;
                        return err;
                    },
                };
                remaining -= increment;
                stream.deferred_response_credit -= increment;
            }
        }
    };
}
