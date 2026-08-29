const std = @import("std");
const websocket = @import("../mod.zig");

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
    opcode: websocket.Opcode,
    payload: []u8,
    was_compressed: bool = false,

    pub fn deinit(self: *OwnedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// One observable step while awaiting the Pong for a locally sent Ping.
/// Payload-bearing variants transfer ownership to the caller so no transport
/// has to discard application data or peer Close metadata while making
/// control-frame progress.
pub const PingEvent = union(enum) {
    pong: void,
    closed: ?websocket.OwnedCloseFrame,
    application: websocket.Frame,

    pub fn deinit(self: *PingEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pong => {},
            .closed => |maybe_close| if (maybe_close) |value| {
                var close_frame = value;
                close_frame.deinit(allocator);
            },
            .application => |value| {
                var frame = value;
                frame.deinit(allocator);
            },
        }
        self.* = undefined;
    }
};

/// One observable step while completing a locally initiated Close handshake.
/// Payload-bearing variants remain owned by the event until `deinit`.
pub const CloseHandshakeEvent = union(enum) {
    closed: ?websocket.OwnedCloseFrame,
    application: websocket.Frame,

    pub fn deinit(
        self: *CloseHandshakeEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .closed => |maybe_close| if (maybe_close) |value| {
                var close_frame = value;
                close_frame.deinit(allocator);
            },
            .application => |value| {
                var frame = value;
                frame.deinit(allocator);
            },
        }
        self.* = undefined;
    }
};
