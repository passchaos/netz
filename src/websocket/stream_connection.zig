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
            var frame = try self.readFrame();
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendPong(frame.payload);
                    continue;
                },
                .pong => continue,
                .close => {
                    if (!self.close_sent) {
                        self.sendClose(.normal_closure, "") catch {};
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

    pub fn sendClose(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
    ) !void {
        if (self.close_sent) return;
        var payload: [125]u8 = undefined;
        var length: usize = 0;
        if (@intFromEnum(code) != 0) {
            std.mem.writeInt(u16, payload[0..2], @intCast(@intFromEnum(code)), .big);
            length = 2;
            const copy = @min(reason.len, payload.len - 2);
            @memcpy(payload[2..][0..copy], reason[0..copy]);
            length += copy;
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
