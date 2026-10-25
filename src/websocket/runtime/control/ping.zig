//! One non-renewing Ping wait shared by all WebSocket transports.
const std = @import("std");
const common = @import("../common.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Reader(comptime hooks: anytype) type {
    return struct {
        pub fn read(connection: anytype, payload: []const u8, deadline: std.Io.Clock.Timestamp) hooks.Error!common.PingEvent {
            while (true) {
                // Check even buffered control frames: unsolicited Pong traffic
                // cannot refresh or bypass the caller's original budget.
                _ = try deadline_policy.usableAwake(hooks.io(connection), deadline);
                var frame = try hooks.receive(connection, deadline, .ping_wait);
                switch (frame.header.opcode) {
                    .ping => frame.deinit(connection.allocator),
                    .pong => {
                        defer frame.deinit(connection.allocator);
                        // RFC 6455 5.5.3 permits unsolicited Pong. A stale or
                        // unrelated payload is legal but cannot finish this Ping.
                        if (!std.mem.eql(u8, frame.payload, payload)) continue;
                        return .{ .pong = {} };
                    },
                    .close => {
                        errdefer frame.deinit(connection.allocator);
                        return .{ .closed = try frame.takeClose(connection.allocator) };
                    },
                    .text, .binary, .continuation => return .{ .application = frame },
                    else => {
                        frame.deinit(connection.allocator);
                        return error.InvalidFrame;
                    },
                }
            }
        }
    };
}
