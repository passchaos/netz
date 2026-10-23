const std = @import("std");
const websocket = @import("../mod.zig");
const socket_options = @import("../../internal/socket_options.zig");

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    /// Maximum number of HTTP/1 request headers accepted while parsing the
    /// client's Upgrade request on WS and WSS server paths.
    max_request_headers: usize = 100,
    /// Maximum number of HTTP/1 response headers accepted while parsing the
    /// server's 101 response on WS and WSS client paths.
    max_response_headers: usize = 100,
    /// Maximum number of bodyless 1xx responses accepted before the final
    /// Upgrade response. Status 101 is the final switching response.
    max_informational_responses: usize = 16,
    /// Maximum decoded body bytes retained from a rejected HTTP/1 Upgrade or
    /// HTTP/3 Extended CONNECT. Successful upgrades are unaffected.
    max_rejection_body_bytes: usize = 1024 * 1024,
    /// Maximum payload bytes in an inbound wire frame or an outbound
    /// caller-selected frame. Compressed sends also apply this bound to each
    /// uncompressed application slice before allocating compressor scratch.
    max_frame_bytes: usize = 16 * 1024 * 1024,
    /// Maximum logical application-message bytes before outbound compression
    /// and after inbound decompression or fragment assembly.
    max_message_bytes: usize = 16 * 1024 * 1024,
    /// Optional budget for the complete HTTP/1 Upgrade phase, including the
    /// body of a rejected response. One absolute deadline spans request writing
    /// and response reading; partial bytes do not renew it. TLS handshake time
    /// and Extended CONNECT are governed by their underlying HTTP transports.
    http1_handshake_timeout: ?std.Io.Duration = null,
    /// Disable Nagle for latency-sensitive frame boundaries. WebSocket
    /// messages are already application-framed and control replies should not
    /// wait behind delayed ACK merely because a peer uses split writes.
    tcp_nodelay: bool = true,
    /// Optional TCP keepalive idle, retry interval, and probe-count policy.
    tcp_keepalive: ?socket_options.TcpKeepAlive = null,
    /// Linux TCP_USER_TIMEOUT in milliseconds. Null leaves the kernel default
    /// untouched; zero is an explicit request to restore that default.
    tcp_user_timeout_ms: ?u32 = null,
};

/// Message limits retained after the HTTP/TLS handshake and TCP socket setup.
/// Keeping transport-only policy out of every live connection avoids charging
/// long-lived WebSocket sessions for one-time admission settings.
pub const MessageLimits = struct {
    max_frame_bytes: usize = 16 * 1024 * 1024,
    max_message_bytes: usize = 16 * 1024 * 1024,

    pub fn from(limits: Limits) MessageLimits {
        return .{
            .max_frame_bytes = limits.max_frame_bytes,
            .max_message_bytes = limits.max_message_bytes,
        };
    }
};

pub const OutgoingValidationError = websocket.Error || error{
    MessageTooLarge,
};

pub const MessageWriteProgress = struct {
    /// Exact cumulative RFC 6455 frame-byte prefix committed by the transport.
    /// This includes the WebSocket header before application payload.
    committed_bytes: usize = 0,
    total_bytes: usize = 0,
    frame_committed: bool = false,
};

/// Encoded control frame retained while a bounded write is incomplete.
pub const PendingControlFrame = struct {
    bytes: [websocket.max_frame_header_len + 125]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,
    payload: [125]u8 = undefined,
    payload_len: usize = 0,

    pub fn matches(
        self: *const PendingControlFrame,
        value: []const u8,
    ) bool {
        return std.mem.eql(u8, self.payload[0..self.payload_len], value);
    }
};

/// At most one resumable application write owns a WebSocket byte stream.
/// Automatic Pong/Close remains separate because a receive owner may queue it
/// behind an older application write.
pub fn PendingWriteState(comptime MessageState: type) type {
    return union(enum) {
        none,
        message: MessageState,
        ping: PendingControlFrame,
        close: PendingControlFrame,

        const Self = @This();

        pub fn isNone(self: *const Self) bool {
            return self.* == .none;
        }

        pub fn isMessage(self: *const Self) bool {
            return self.* == .message;
        }

        pub fn isPing(self: *const Self) bool {
            return self.* == .ping;
        }

        pub fn isClose(self: *const Self) bool {
            return self.* == .close;
        }

        pub fn messagePtr(self: *Self) ?*MessageState {
            return switch (self.*) {
                .message => |*pending| pending,
                else => null,
            };
        }

        pub fn pingPtr(self: *Self) ?*PendingControlFrame {
            return switch (self.*) {
                .ping => |*pending| pending,
                else => null,
            };
        }

        pub fn pingConst(self: *const Self) ?*const PendingControlFrame {
            return switch (self.*) {
                .ping => |*pending| pending,
                else => null,
            };
        }

        pub fn closePtr(self: *Self) ?*PendingControlFrame {
            return switch (self.*) {
                .close => |*pending| pending,
                else => null,
            };
        }

        pub fn closeConst(self: *const Self) ?*const PendingControlFrame {
            return switch (self.*) {
                .close => |*pending| pending,
                else => null,
            };
        }

        pub fn clear(self: *Self) void {
            switch (self.*) {
                .none => {},
                .message => |*pending| {
                    std.crypto.secureZero(u8, &pending.header);
                    if (pending.mask_key) |*mask| {
                        std.crypto.secureZero(u8, mask);
                    }
                },
                .ping, .close => |*pending| {
                    std.crypto.secureZero(u8, &pending.bytes);
                    std.crypto.secureZero(u8, &pending.payload);
                },
            }
            self.* = .none;
        }
    };
}

/// Fill independent RFC 6455 mask keys with one backend CSPRNG request. This
/// preserves a fresh unpredictable key per frame without paying one I/O
/// dispatch or `getrandom` syscall for every frame in an encoded batch.
pub inline fn randomMaskKeys(
    io: std.Io,
    keys: [][4]u8,
) std.Io.RandomSecureError!void {
    if (keys.len == 0) return;
    try std.Io.randomSecure(io, std.mem.sliceAsBytes(keys));
}

/// One automatic Pong or peer-Close echo whose encoded wire bytes must remain
/// stable across a bounded receive timeout. `frame` is populated only when
/// the receive API owes the caller the control frame after the reply commits.
pub const PendingAutomaticControl = struct {
    pub const Delivery = enum {
        frame,
        message,
        ping_wait,
        close_wait,
    };

    opcode: websocket.Opcode,
    delivery: Delivery,
    writes_reply: bool = true,
    bytes: [websocket.max_frame_header_len + 125]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,
    fin_committed: bool = false,
    frame: ?websocket.Frame = null,

    pub fn complete(self: *const PendingAutomaticControl) bool {
        return !self.writes_reply or
            (self.committed == self.len and
                (self.opcode != .close or self.fin_committed));
    }

    pub fn deinit(
        self: *PendingAutomaticControl,
        allocator: std.mem.Allocator,
    ) void {
        if (self.frame) |*frame| frame.deinit(allocator);
        std.crypto.secureZero(u8, &self.bytes);
        self.* = undefined;
    }
};

/// Release every connection-owned outbound transaction after its transport has
/// been aborted. Callers must hold their send mutex so a bounded writer cannot
/// concurrently update a cursor or borrowed-payload descriptor.
pub fn clearPendingOutboundLocked(connection: anytype) void {
    if (comptime @hasField(@TypeOf(connection.*), "pending_write")) {
        connection.pending_write.clear();
    } else {
        if (connection.pending_message) |*pending| {
            std.crypto.secureZero(u8, &pending.header);
            if (pending.mask_key) |*mask| {
                std.crypto.secureZero(u8, mask);
            }
        }
        connection.pending_message = null;
        if (connection.pending_ping) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        connection.pending_ping = null;
        if (connection.pending_close) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        connection.pending_close = null;
    }
    if (connection.pending_auto_control) |*pending| {
        pending.deinit(connection.allocator);
    }
    connection.pending_auto_control = null;
    connection.compression_send.deinit(connection.allocator);
    connection.compression_send = .{};
    connection.application_write_pending.store(false, .release);
    connection.automatic_write_pending.store(false, .release);
}

/// Validate one complete outbound application message before a transport
/// acquires its send lock, allocates compressor scratch, or masks caller data.
pub fn validateOutgoingMessage(
    limits: anytype,
    opcode: websocket.Opcode,
    payload: []const u8,
) OutgoingValidationError!void {
    switch (opcode) {
        .text, .binary => {},
        else => return error.InvalidFrame,
    }
    try validateOutgoingMessageLength(limits, payload.len);
    if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
        return error.InvalidUtf8;
    }
}

pub fn validateOutgoingMessageLength(
    limits: anytype,
    payload_len: usize,
) error{MessageTooLarge}!void {
    if (payload_len > limits.max_frame_bytes or
        payload_len > limits.max_message_bytes)
    {
        return error.MessageTooLarge;
    }
}

/// Validate borrowed slices that will be emitted as one binary frame.
pub fn validateOutgoingMessageParts(
    limits: anytype,
    parts: []const []const u8,
) OutgoingValidationError!usize {
    const payload_len = try outgoingPayloadLen(parts);
    try validateOutgoingMessageLength(limits, payload_len);
    return payload_len;
}

/// Validate caller-selected wire fragments and their logical aggregate.
pub fn validateOutgoingFragments(
    limits: anytype,
    opcode: websocket.Opcode,
    fragments: []const []const u8,
) OutgoingValidationError!usize {
    switch (opcode) {
        .text, .binary => {},
        else => return error.InvalidFrame,
    }
    if (fragments.len == 0) return error.InvalidFrame;

    var total: usize = 0;
    for (fragments) |fragment| {
        if (fragment.len > limits.max_frame_bytes) {
            return error.MessageTooLarge;
        }
        total = std.math.add(usize, total, fragment.len) catch
            return error.PayloadTooLarge;
    }
    if (total > limits.max_message_bytes) return error.MessageTooLarge;
    if (opcode == .text and !fragmentedTextIsValid(fragments)) {
        return error.InvalidUtf8;
    }
    return total;
}

/// Validate public Ping, Pong, and Close writes against both the configured
/// frame bound and RFC 6455's stricter control-frame rules.
pub fn validateOutgoingControlFrame(
    limits: anytype,
    opcode: websocket.Opcode,
    payload: []const u8,
) OutgoingValidationError!void {
    switch (opcode) {
        .close, .ping, .pong => {},
        else => return error.InvalidFrame,
    }
    if (payload.len > limits.max_frame_bytes) {
        return error.MessageTooLarge;
    }
    switch (opcode) {
        .close => try websocket.validateClosePayload(payload),
        .ping, .pong => if (payload.len > 125) {
            return error.InvalidControlFrame;
        },
        else => unreachable,
    }
}

fn outgoingPayloadLen(parts: []const []const u8) websocket.Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.PayloadTooLarge;
    }
    return total;
}

fn fragmentedTextIsValid(fragments: []const []const u8) bool {
    var validator: websocket.Utf8Validator = .{};
    for (fragments) |fragment| validator.feed(fragment) catch return false;
    validator.finish() catch return false;
    return true;
}

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
    was_compressed: bool = false,
};

/// Resumable caller-buffer message state shared by every stream transport.
/// Once a fragmented message starts, retries must provide the same output
/// slice so already-consumed wire bytes cannot be redirected or lost.
pub const MessageIntoReceiveState = struct {
    opcode: ?websocket.Opcode = null,
    compressed: bool = false,
    text_utf8: websocket.Utf8Validator = .{},
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

    pub fn validateFramePayload(
        self: *MessageIntoReceiveState,
        payload: []const u8,
        fin: bool,
    ) websocket.Error!void {
        if (self.opcode != .text or self.compressed) return;
        try self.text_utf8.feed(payload);
        if (fin) try self.text_utf8.finish();
    }

    pub fn payloadNeedsFinalUtf8Validation(
        self: MessageIntoReceiveState,
    ) bool {
        return self.opcode == .text and self.compressed;
    }
};

/// Map RFC 6455 receive failures to the status code that should be sent before
/// terminating the connection. Transport/time/allocation failures have no
/// WebSocket Close mapping and return null.
pub fn closeCodeForReceiveError(err: anyerror) ?websocket.CloseCode {
    return switch (err) {
        error.InvalidUtf8 => .invalid_payload_data,
        error.MessageTooLarge, error.PayloadTooLarge => .message_too_big,
        error.InvalidOpcode,
        error.InvalidFrame,
        error.InvalidControlFrame,
        error.UnmaskedClientFrame,
        error.MaskedServerFrame,
        error.UnexpectedRsv,
        error.NonMinimalLength,
        error.InvalidCloseCode,
        => .protocol_error,
        else => null,
    };
}

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

test "WebSocket receive failures map to RFC 6455 Close codes" {
    try std.testing.expectEqual(
        websocket.CloseCode.invalid_payload_data,
        closeCodeForReceiveError(error.InvalidUtf8).?,
    );
    try std.testing.expectEqual(
        websocket.CloseCode.message_too_big,
        closeCodeForReceiveError(error.MessageTooLarge).?,
    );
    try std.testing.expectEqual(
        websocket.CloseCode.protocol_error,
        closeCodeForReceiveError(error.UnmaskedClientFrame).?,
    );
    try std.testing.expect(closeCodeForReceiveError(error.Timeout) == null);
    try std.testing.expect(closeCodeForReceiveError(error.OutOfMemory) == null);
}

test "WebSocket outbound validation enforces frame and message limits" {
    const limits: Limits = .{
        .max_frame_bytes = 4,
        .max_message_bytes = 6,
    };

    try validateOutgoingMessage(limits, .text, "four");
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingMessage(limits, .binary, "five!"),
    );
    // Size validation is constant-time and precedes UTF-8 scanning.
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingMessage(limits, .text, "abcd\xff"),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        validateOutgoingMessage(limits, .text, "\xff"),
    );

    try std.testing.expectEqual(
        @as(usize, 4),
        try validateOutgoingMessageParts(limits, &.{ "ab", "cd" }),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        try validateOutgoingMessageParts(
            limits,
            &.{ "a", "", "bc", "d" },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try validateOutgoingMessageParts(limits, &.{}),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingMessageParts(limits, &.{ "abc", "de" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingMessageParts(limits, &.{ "ab", "", "cde" }),
    );
    try std.testing.expectEqual(
        @as(usize, 125),
        try validateOutgoingMessageParts(
            .{ .max_frame_bytes = 65_536, .max_message_bytes = 65_536 },
            &.{ "a" ** 41, "b" ** 42, "c" ** 42 },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 126),
        try validateOutgoingMessageParts(
            .{ .max_frame_bytes = 65_536, .max_message_bytes = 65_536 },
            &.{ "a" ** 41, "b" ** 42, "c" ** 43 },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 65_535),
        try validateOutgoingMessageParts(
            .{ .max_frame_bytes = 65_536, .max_message_bytes = 65_536 },
            &.{ "a" ** 32_767, "", "b" ** 32_768 },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 65_536),
        try validateOutgoingMessageParts(
            .{ .max_frame_bytes = 65_536, .max_message_bytes = 65_536 },
            &.{ "a" ** 32_767, "b" ** 32_769 },
        ),
    );

    try std.testing.expectEqual(
        @as(usize, 6),
        try validateOutgoingFragments(
            limits,
            .text,
            &.{ "ab", "cdef" },
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingFragments(limits, .binary, &.{"abcde"}),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingFragments(
            limits,
            .binary,
            &.{ "abc", "def", "g" },
        ),
    );
}

test "WebSocket outbound control validation honors configured frame limit" {
    const limits: Limits = .{ .max_frame_bytes = 4 };
    try validateOutgoingControlFrame(limits, .ping, "four");
    try std.testing.expectError(
        error.MessageTooLarge,
        validateOutgoingControlFrame(limits, .pong, "five!"),
    );
    try std.testing.expectError(
        error.InvalidControlFrame,
        validateOutgoingControlFrame(
            .{ .max_frame_bytes = 126 },
            .ping,
            "x" ** 126,
        ),
    );
    try std.testing.expectError(
        error.InvalidFrame,
        validateOutgoingControlFrame(limits, .binary, ""),
    );
}
