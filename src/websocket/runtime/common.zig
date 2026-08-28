const std = @import("std");

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    max_frame_bytes: usize = 16 * 1024 * 1024,
    max_message_bytes: usize = 16 * 1024 * 1024,
    /// Optional absolute budget for the HTTP/1 Upgrade request/response head.
    /// Partial bytes do not renew it. TLS handshake time and Extended CONNECT
    /// are governed by their underlying HTTP transports.
    http1_handshake_timeout: ?std.Io.Duration = null,
    /// Disable Nagle for latency-sensitive frame boundaries. WebSocket
    /// messages are already application-framed and control replies should not
    /// wait behind delayed ACK merely because a peer uses split writes.
    tcp_nodelay: bool = true,
};

pub const Role = enum {
    client,
    server,
};

pub const OwnedMessage = struct {
    opcode: @import("../mod.zig").Opcode,
    payload: []u8,

    pub fn deinit(self: *OwnedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};
