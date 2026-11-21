//! WebSocket framing over a caller-supplied byte stream.
//!
//! HTTP/2 extended CONNECT and HTTP/3 CONNECT provide a bidirectional byte
//! stream rather than a TCP socket. This module keeps the RFC 6455 frame
//! codec in one place so protocol adapters only supply read/write callbacks.

const std = @import("std");
const websocket = @import("mod.zig");
const assembler = @import("message/assembler.zig");

test {
    _ = @import("stream_connection_tests.zig");
}

pub const Role = enum { client, server };

pub const Transport = struct {
    context: ?*anyopaque = null,
    read_fn: *const fn (?*anyopaque, []u8) anyerror!usize,
    write_fn: *const fn (?*anyopaque, []const u8) anyerror!void,
    close_fn: ?*const fn (?*anyopaque) void = null,

    fn read(self: Transport, buffer: []u8) anyerror!usize {
        return self.read_fn(self.context, buffer);
    }

    fn write(self: Transport, bytes: []const u8) anyerror!void {
        return self.write_fn(self.context, bytes);
    }

    fn closeTransport(self: Transport) void {
        if (self.close_fn) |close_fn| close_fn(self.context);
    }
};

pub const Options = struct {
    role: Role = .server,
    max_message_bytes: usize = 16 * 1024 * 1024,
    max_frame_bytes: usize = 16 * 1024 * 1024,
};

pub const Message = struct {
    opcode: websocket.Opcode,
    payload: []u8,

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: Transport,
    options: Options,
    assembler: assembler.Assembler,
    buffer: std.ArrayList(u8) = .empty,
    start: usize = 0,
    write_buffer: std.ArrayList(u8) = .empty,
    write_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    closed: bool = false,
    peer_close_code: ?websocket.CloseCode = null,
    peer_close_reason: [123]u8 = undefined,
    peer_close_reason_len: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: Transport,
        options: Options,
    ) Connection {
        return .{
            .allocator = allocator,
            .io = io,
            .transport = transport,
            .options = options,
            .assembler = assembler.Assembler.initLimited(
                allocator,
                options.max_message_bytes,
            ),
        };
    }

    pub fn deinit(self: *Connection) void {
        if (!self.closed) {
            self.closed = true;
            self.transport.closeTransport();
        }
        self.buffer.deinit(self.allocator);
        self.write_buffer.deinit(self.allocator);
        self.assembler.deinit();
        self.* = undefined;
    }

    pub fn close(self: *Connection) void {
        if (self.closed) return;
        if (!self.close_sent) {
            self.sendClose(.normal_closure, "") catch {};
        }
        self.closed = true;
        self.transport.closeTransport();
    }

    pub fn receiveMessage(self: *Connection) !Message {
        if (self.close_received) return error.ConnectionClosed;
        while (true) {
            var frame = self.readFrame() catch |err| {
                // A malformed Close/control frame is a protocol error. Send
                // 1002 and make the failure terminal instead of re-reading
                // the same buffered bytes on the next call.
                switch (err) {
                    error.InvalidCloseCode,
                    error.InvalidUtf8,
                    error.InvalidControlFrame,
                    => {
                        self.sendClose(.protocol_error, "") catch {};
                        self.close_received = true;
                    },
                    else => {},
                }
                return err;
            };
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendPong(frame.payload);
                    continue;
                },
                .pong => continue,
                .close => {
                    const parsed = websocket.parseClosePayload(
                        frame.payload,
                    ) catch |err| {
                        // An invalid Close payload is a protocol error. Reply
                        // with 1002 before surfacing the parse failure.
                        self.sendClose(.protocol_error, "") catch {};
                        self.close_received = true;
                        return err;
                    };
                    if (parsed) |frame_close| {
                        self.peer_close_code = frame_close.code;
                        const copy = @min(
                            frame_close.reason.len,
                            self.peer_close_reason.len,
                        );
                        @memcpy(
                            self.peer_close_reason[0..copy],
                            frame_close.reason[0..copy],
                        );
                        self.peer_close_reason_len = copy;
                    }
                    if (!self.close_sent) {
                        // RFC 6455 5.5.1: echo the received status code when
                        // the peer supplied one.
                        if (parsed) |frame_close| {
                            self.sendClose(frame_close.code, "") catch {};
                        } else {
                            self.sendClose(.normal_closure, "") catch {};
                        }
                    }
                    self.close_received = true;
                    return error.ConnectionClosed;
                },
                .text, .binary, .continuation => {
                    if (try self.assembler.feed(frame)) |message| {
                        return .{
                            .opcode = message.opcode,
                            .payload = message.payload,
                        };
                    }
                },
                else => return error.InvalidOpcode,
            }
        }
    }

    pub fn sendText(self: *Connection, text: []const u8) !void {
        try self.sendFrame(.text, text);
    }

    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        try self.sendFrame(.binary, data);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) !void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *Connection, payload: []const u8) !void {
        try self.sendFrame(.pong, payload);
    }

    /// Peer Close metadata. The reason slice is valid until deinit or the next
    /// received Close. Returns null when no valid Close frame was received.
    pub fn peerClose(self: *const Connection) ?websocket.CloseFrame {
        const code = self.peer_close_code orelse return null;
        return .{
            .code = code,
            .reason = self.peer_close_reason[0..self.peer_close_reason_len],
        };
    }

    pub fn sendClose(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
    ) !void {
        if (self.close_sent) return;
        if (reason.len > 123) return error.InvalidControlFrame;
        var payload: [125]u8 = undefined;
        var length: usize = 0;
        if (@intFromEnum(code) != 0) {
            std.mem.writeInt(u16, payload[0..2], @intCast(@intFromEnum(code)), .big);
            length = 2;
            @memcpy(payload[2..][0..reason.len], reason);
            length += reason.len;
        }
        // Mark the close only after the frame is written so a failed write
        // remains retryable.
        try self.sendFrame(.close, payload[0..length]);
        self.close_sent = true;
    }

    fn sendFrame(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        if (self.closed) return error.ConnectionClosed;
        // After either side starts the closing handshake only the Close frame
        // itself may be written.
        if (opcode != .close and (self.close_sent or self.close_received)) {
            return error.ConnectionClosed;
        }
        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);
        self.write_buffer.clearRetainingCapacity();
        var mask_key: ?[4]u8 = null;
        if (self.options.role == .client) {
            var key: [4]u8 = undefined;
            std.Io.random(self.io, &key);
            mask_key = key;
        }
        try websocket.writeFrame(
            &self.write_buffer,
            self.allocator,
            opcode,
            payload,
            .{ .fin = true, .mask_key = mask_key },
        );
        try self.transport.write(self.write_buffer.items);
    }

    fn readFrame(self: *Connection) !websocket.Frame {
        while (true) {
            try self.ensure(2);
            const header = websocket.FrameHeader.parse(
                self.buffer.items[self.start..],
            ) catch |err| switch (err) {
                error.BufferTooShort => {
                    try self.ensure(websocket.max_frame_header_len);
                    continue;
                },
                else => return err,
            };
            const wire_len = try header.wireLen();
            if (wire_len > self.options.max_frame_bytes) {
                return error.PayloadTooLarge;
            }
            try self.ensure(wire_len);
            const bytes = self.buffer.items[self.start..][0..wire_len];
            const frame = try websocket.parseFrameWithHeader(
                self.allocator,
                bytes,
                header,
                .{
                    .expect_mask = if (self.options.role == .server)
                        .masked
                    else
                        .unmasked,
                    .validate_utf8 = false,
                },
            );
            self.start += wire_len;
            if (self.start == self.buffer.items.len) {
                self.buffer.clearRetainingCapacity();
                self.start = 0;
            }
            return frame;
        }
    }

    fn ensure(self: *Connection, wanted: usize) !void {
        while (self.buffer.items.len - self.start < wanted) {
            if (self.start != 0) {
                const remaining = self.buffer.items.len - self.start;
                std.mem.copyForwards(
                    u8,
                    self.buffer.items[0..remaining],
                    self.buffer.items[self.start..],
                );
                self.buffer.items.len = remaining;
                self.start = 0;
            }
            var chunk: [16 * 1024]u8 = undefined;
            const count = try self.transport.read(&chunk);
            if (count == 0) return error.EndOfStream;
            try self.buffer.appendSlice(self.allocator, chunk[0..count]);
            const limit = std.math.add(
                usize,
                self.options.max_frame_bytes,
                websocket.max_frame_header_len,
            ) catch return error.PayloadTooLarge;
            if (self.buffer.items.len > limit) return error.PayloadTooLarge;
        }
    }
};
