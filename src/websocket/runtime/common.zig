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

pub const Message = struct {
    opcode: websocket.Opcode,
    payload: []u8,
};

/// Resumable caller-buffer message state shared by every stream transport.
/// Once a fragmented message starts, retries must provide the same output
/// slice so already-consumed wire bytes cannot be redirected or lost.
pub const MessageIntoReceiveState = struct {
    opcode: ?websocket.Opcode = null,
    compressed: bool = false,
    written: usize = 0,
    output_address: usize = 0,
    output_len: usize = 0,

    pub fn active(self: MessageIntoReceiveState) bool {
        return self.opcode != null;
    }

    pub fn begin(
        self: *MessageIntoReceiveState,
        out: []u8,
        opcode: websocket.Opcode,
        compressed: bool,
    ) void {
        self.* = .{
            .opcode = opcode,
            .compressed = compressed,
            .output_address = @intFromPtr(out.ptr),
            .output_len = out.len,
        };
    }

    pub fn validateOutput(
        self: MessageIntoReceiveState,
        out: []u8,
    ) websocket.Error!void {
        if (!self.active()) return;
        if (self.output_address != @intFromPtr(out.ptr) or
            self.output_len != out.len)
        {
            return error.BufferTooShort;
        }
    }

    pub fn reset(self: *MessageIntoReceiveState) void {
        self.* = .{};
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

test "WebSocket caller-buffer state retains output identity" {
    var first: [16]u8 = undefined;
    var replacement: [16]u8 = undefined;
    var state: MessageIntoReceiveState = .{};
    state.begin(&first, .binary, false);
    state.written = 7;

    try state.validateOutput(&first);
    try std.testing.expectError(
        error.BufferTooShort,
        state.validateOutput(&replacement),
    );
    try std.testing.expect(state.active());
    try std.testing.expectEqual(@as(usize, 7), state.written);
    state.reset();
    try std.testing.expect(!state.active());
}
