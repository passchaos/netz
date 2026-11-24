//! WebSocket framing over a caller-supplied byte stream.
//!
//! HTTP/2 extended CONNECT and HTTP/3 CONNECT provide a bidirectional byte
//! stream rather than a TCP socket. This module keeps the RFC 6455 frame
//! codec in one place so protocol adapters only supply read/write callbacks.

const std = @import("std");
const websocket = @import("mod.zig");
const assembler = @import("message/assembler.zig");
const deadline_policy = @import("../internal/deadline.zig");
const MutexGuard = @import("../internal/mutex_guard.zig").Guard;
const writes = @import("stream_connection/writes.zig");

test {
    _ = @import("stream_connection_tests.zig");
    _ = @import("stream_connection/failure_tests.zig");
    _ = @import("stream_connection/concurrency_tests.zig");
}

pub const Role = enum { client, server };

pub const Transport = struct {
    context: ?*anyopaque = null,
    read_fn: *const fn (?*anyopaque, []u8) anyerror!usize,
    /// Optional deadline-aware read. The `WithDeadline`/`WithTimeout` receive
    /// APIs require this callback and return `error.DeadlineUnsupported` when
    /// it is absent.
    read_deadline_fn: ?*const fn (
        ?*anyopaque,
        []u8,
        std.Io.Clock.Timestamp,
    ) anyerror!usize = null,
    /// Write the complete range on success. Any returned callback error is
    /// terminal because the adapter cannot reconstruct its emitted prefix.
    write_fn: *const fn (?*anyopaque, []const u8) anyerror!void,
    /// Optional two-slice write used for unmasked frames. The callback must
    /// write both ranges completely or return an error; partial output is not
    /// resumable. Empty payloads are valid.
    write_parts_fn: ?*const fn (
        ?*anyopaque,
        []const u8,
        []const u8,
    ) anyerror!void = null,
    /// Optional deadline-aware two-slice write, selected independently of
    /// the unbounded `write_parts_fn` callback.
    write_parts_deadline_fn: ?*const fn (
        ?*anyopaque,
        []const u8,
        []const u8,
        std.Io.Clock.Timestamp,
    ) anyerror!void = null,
    /// Optional header-plus-arbitrary-slices write used for unmasked frames.
    /// The callback must write the header and every slice completely or return
    /// an error; partial output is not resumable. Empty slices are valid.
    write_slices_fn: ?*const fn (
        ?*anyopaque,
        []const u8,
        []const []const u8,
    ) anyerror!void = null,
    /// Optional deadline-aware arbitrary-slice write, selected independently
    /// of the unbounded `write_slices_fn` callback.
    write_slices_deadline_fn: ?*const fn (
        ?*anyopaque,
        []const u8,
        []const []const u8,
        std.Io.Clock.Timestamp,
    ) anyerror!void = null,
    /// Optional deadline-aware write. The `WithDeadline`/`WithTimeout` send
    /// APIs require this callback and return `error.DeadlineUnsupported` when
    /// it is absent.
    write_deadline_fn: ?*const fn (
        ?*anyopaque,
        []const u8,
        std.Io.Clock.Timestamp,
    ) anyerror!void = null,
    /// Release the transport promptly without emitting WebSocket frames.
    /// Called at most once, including on terminal write failure.
    close_fn: ?*const fn (?*anyopaque) void = null,

    fn read(self: Transport, buffer: []u8) anyerror!usize {
        return self.read_fn(self.context, buffer);
    }

    fn readBefore(
        self: Transport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) anyerror!usize {
        const read_deadline_fn = self.read_deadline_fn orelse
            return error.DeadlineUnsupported;
        return read_deadline_fn(self.context, buffer, deadline);
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
    // Access these lifecycle flags through the atomic snapshots below. One
    // reader may publish Close while serialized writers inspect the state.
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

    /// Lifecycle snapshots synchronize with the single reader and serialized
    /// writers. Deinitialization still requires all active operations to finish.
    pub fn isClosed(self: *const Connection) bool {
        return @atomicLoad(bool, &self.closed, .acquire);
    }

    pub fn closeSent(self: *const Connection) bool {
        return @atomicLoad(bool, &self.close_sent, .acquire);
    }

    pub fn closeReceived(self: *const Connection) bool {
        return @atomicLoad(bool, &self.close_received, .acquire);
    }

    /// Retire the transport immediately without appending a WebSocket Close.
    /// The caller-supplied close callback runs at most once.
    pub fn abort(self: *Connection) void {
        if (!@atomicRmw(bool, &self.closed, .Xchg, true, .acq_rel)) {
            self.transport.closeTransport();
        }
    }

    pub fn deinit(self: *Connection) void {
        self.abort();
        self.buffer.deinit(self.allocator);
        self.write_buffer.deinit(self.allocator);
        self.assembler.deinit();
        self.* = undefined;
    }

    pub fn close(self: *Connection) void {
        if (self.isClosed()) return;
        if (!self.closeSent()) {
            self.sendClose(.normal_closure, "") catch {};
        }
        self.abort();
    }

    /// Best-effort Close under one absolute awake-clock deadline. On success
    /// the transport is closed. Budget/capability rejection before invoking
    /// a write leaves the connection available for retry. An invoked write
    /// callback error retires the transport because its output is unknown.
    pub fn closeWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        if (self.isClosed()) return;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (!self.closeSent()) {
            try self.sendCloseWithDeadline(.normal_closure, "", deadline);
        }
        self.abort();
    }

    /// Relative-timeout counterpart to `closeWithDeadline`. A non-positive
    /// duration returns `Timeout` without changing connection state.
    pub fn closeWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn receiveMessage(self: *Connection) !Message {
        return self.receiveMessageBefore(null);
    }

    /// Bound the complete receive by one relative timeout. A non-positive
    /// duration returns `error.Timeout` before any transport I/O.
    pub fn receiveMessageWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) !Message {
        return self.receiveMessageBefore(
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    /// Bound the complete receive, including an automatic Pong reply, by one
    /// absolute awake-clock deadline. Requires `Transport.read_deadline_fn`;
    /// without it the call returns `error.DeadlineUnsupported`.
    pub fn receiveMessageWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) !Message {
        return self.receiveMessageBefore(
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    fn receiveMessageBefore(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) !Message {
        if (self.isClosed() or self.closeReceived()) return error.ConnectionClosed;
        while (true) {
            var frame = self.readFrameBefore(deadline) catch |err| {
                // A malformed Close/control frame is a protocol error. Send
                // 1002 and make the failure terminal instead of re-reading
                // the same buffered bytes on the next call.
                switch (err) {
                    error.InvalidCloseCode,
                    error.InvalidUtf8,
                    error.InvalidControlFrame,
                    => {
                        self.sendCloseBefore(.protocol_error, "", deadline) catch {};
                        @atomicStore(bool, &self.close_received, true, .release);
                    },
                    else => {},
                }
                return err;
            };
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendFrameBefore(.pong, frame.payload, deadline);
                    continue;
                },
                .pong => continue,
                .close => {
                    const parsed = websocket.parseClosePayload(
                        frame.payload,
                    ) catch |err| {
                        // An invalid Close payload is a protocol error. Reply
                        // with 1002 before surfacing the parse failure.
                        self.sendCloseBefore(.protocol_error, "", deadline) catch {};
                        @atomicStore(bool, &self.close_received, true, .release);
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
                    if (!self.closeSent()) {
                        // RFC 6455 5.5.1: echo the received status code when
                        // the peer supplied one.
                        if (parsed) |frame_close| {
                            self.sendCloseBefore(frame_close.code, "", deadline) catch {};
                        } else {
                            self.sendCloseBefore(.normal_closure, "", deadline) catch {};
                        }
                    }
                    @atomicStore(bool, &self.close_received, true, .release);
                    return error.ConnectionClosed;
                },
                .text, .binary, .continuation => {
                    if (try self.assembler.feedOwned(&frame)) |message| {
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

    pub fn sendTextWithTimeout(
        self: *Connection,
        text: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameWithTimeout(.text, text, timeout);
    }

    pub fn sendTextWithDeadline(
        self: *Connection,
        text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameWithDeadline(.text, text, deadline);
    }

    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        try self.sendFrame(.binary, data);
    }

    /// Opcode-driven counterpart to `sendText`/`sendBinary`, matching the
    /// runtime connections. Control opcodes are rejected; text payloads must
    /// be valid UTF-8.
    pub fn sendMessage(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        try self.sendFrame(opcode, payload);
    }

    pub fn sendBinaryWithTimeout(
        self: *Connection,
        data: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameWithTimeout(.binary, data, timeout);
    }

    pub fn sendBinaryWithDeadline(
        self: *Connection,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameWithDeadline(.binary, data, deadline);
    }

    /// Send one text message from multiple payload slices without first
    /// concatenating them. The concatenation must be valid UTF-8; codepoints
    /// may span slice boundaries. Server-role frames use
    /// `Transport.write_slices_fn` when available; client-role frames are
    /// masked into the staging buffer.
    pub fn sendTextSlices(
        self: *Connection,
        slices: []const []const u8,
    ) !void {
        return self.sendFrameSlicesBefore(.text, slices, null);
    }

    pub fn sendTextSlicesWithTimeout(
        self: *Connection,
        slices: []const []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameSlicesBefore(
            .text,
            slices,
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    pub fn sendTextSlicesWithDeadline(
        self: *Connection,
        slices: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameSlicesBefore(.text, slices, deadline);
    }

    pub fn sendBinarySlices(
        self: *Connection,
        slices: []const []const u8,
    ) !void {
        return self.sendFrameSlicesBefore(.binary, slices, null);
    }

    pub fn sendBinarySlicesWithTimeout(
        self: *Connection,
        slices: []const []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameSlicesBefore(
            .binary,
            slices,
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    pub fn sendBinarySlicesWithDeadline(
        self: *Connection,
        slices: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameSlicesBefore(.binary, slices, deadline);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) !void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameWithTimeout(.ping, payload, timeout);
    }

    pub fn sendPingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameWithDeadline(.ping, payload, deadline);
    }

    pub fn sendPong(self: *Connection, payload: []const u8) !void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendPongWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameWithTimeout(.pong, payload, timeout);
    }

    pub fn sendPongWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameWithDeadline(.pong, payload, deadline);
    }

    /// Bound lock acquisition and the transport write by one relative
    /// timeout. A non-positive duration returns `error.Timeout` before any
    /// transport I/O. Requires `Transport.write_deadline_fn`.
    pub fn sendFrameWithTimeout(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameBefore(
            opcode,
            payload,
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    /// Bound lock acquisition and the transport write by one absolute
    /// deadline. Requires `Transport.write_deadline_fn`.
    pub fn sendFrameWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameBefore(
            opcode,
            payload,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    /// Send one unfragmented data frame whose payload is supplied as multiple
    /// slices. Only `.text` and `.binary` are accepted; control frames keep
    /// their contiguous APIs. Text validation spans slice boundaries.
    pub fn sendFrameSlices(
        self: *Connection,
        opcode: websocket.Opcode,
        slices: []const []const u8,
    ) !void {
        return self.sendFrameSlicesBefore(opcode, slices, null);
    }

    pub fn sendFrameSlicesWithTimeout(
        self: *Connection,
        opcode: websocket.Opcode,
        slices: []const []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendFrameSlicesBefore(
            opcode,
            slices,
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    pub fn sendFrameSlicesWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        slices: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendFrameSlicesBefore(
            opcode,
            slices,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    /// Peer Close metadata. The reason slice is valid until deinit or the next
    /// received Close. Returns null when no valid Close frame was received.
    pub fn peerClose(self: *const Connection) ?websocket.CloseFrame {
        if (!self.closeReceived()) return null;
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
        return self.sendCloseBefore(code, reason, null);
    }

    pub fn sendCloseWithTimeout(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) !void {
        return self.sendCloseBefore(
            code,
            reason,
            try deadline_policy.fromTimeout(self.io, timeout),
        );
    }

    pub fn sendCloseWithDeadline(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) !void {
        return self.sendCloseBefore(
            code,
            reason,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    fn sendCloseBefore(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        if (self.closeSent()) return;
        if (self.isClosed()) return error.ConnectionClosed;
        if (reason.len > 123) return error.InvalidControlFrame;
        var payload: [125]u8 = undefined;
        var length: usize = 0;
        if (@intFromEnum(code) != 0) {
            std.mem.writeInt(u16, payload[0..2], @intCast(@intFromEnum(code)), .big);
            length = 2;
            @memcpy(payload[2..][0..reason.len], reason);
            length += reason.len;
        }
        // The writer commits Close while still holding the write mutex.
        try self.sendFrameBefore(.close, payload[0..length], deadline);
    }

    fn sendFrame(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        return self.sendFrameBefore(opcode, payload, null);
    }

    fn ensureWritable(self: *const Connection, opcode: websocket.Opcode) !void {
        if (self.isClosed()) return error.ConnectionClosed;
        if (opcode != .close and (self.closeSent() or self.closeReceived())) {
            return error.ConnectionClosed;
        }
    }

    fn frameSent(self: *Connection, opcode: websocket.Opcode) void {
        if (opcode == .close) @atomicStore(bool, &self.close_sent, true, .release);
    }

    fn sendFrameBefore(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        try self.ensureWritable(opcode);
        // Text frames carry UTF-8; binary frames remain opaque. Validate before
        // taking the write mutex or emitting any header bytes.
        if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
            return error.InvalidUtf8;
        }
        var guard = if (deadline) |absolute|
            try MutexGuard.initBefore(
                &self.write_mutex,
                self.io,
                absolute,
            )
        else blk: {
            self.write_mutex.lockUncancelable(self.io);
            break :blk MutexGuard{
                .mutex = &self.write_mutex,
                .io = self.io,
            };
        };
        defer guard.unlock();
        try self.ensureWritable(opcode);
        if (opcode == .close and self.closeSent()) return;
        // Unmasked frames can go out as a header plus the caller's payload
        // when the transport supports two-slice writes; masked frames still
        // need the transformed copy below.
        if (self.options.role == .server) {
            const parts_available = if (deadline != null)
                self.transport.write_parts_deadline_fn != null
            else
                self.transport.write_parts_fn != null;
            if (parts_available) {
                var header_storage: [websocket.max_frame_header_len]u8 = undefined;
                const header = try websocket.writeFrameHeaderInto(
                    &header_storage,
                    opcode,
                    payload,
                    .{ .fin = true },
                );
                try writes.parts(self, header, payload, deadline);
                self.frameSent(opcode);
                return;
            }
        }
        if (deadline != null and self.transport.write_deadline_fn == null) {
            return error.DeadlineUnsupported;
        }
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
        try writes.all(self, self.write_buffer.items, deadline);
        self.frameSent(opcode);
    }

    fn sendFrameSlicesBefore(
        self: *Connection,
        opcode: websocket.Opcode,
        slices: []const []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        if (opcode != .text and opcode != .binary) {
            return error.InvalidFrame;
        }
        try self.ensureWritable(opcode);
        var total: usize = 0;
        for (slices) |slice| {
            total = std.math.add(usize, total, slice.len) catch
                return error.PayloadTooLarge;
        }
        if (opcode == .text and !websocket.utf8ValidateSlices(slices)) {
            return error.InvalidUtf8;
        }
        var guard = if (deadline) |absolute|
            try MutexGuard.initBefore(
                &self.write_mutex,
                self.io,
                absolute,
            )
        else blk: {
            self.write_mutex.lockUncancelable(self.io);
            break :blk MutexGuard{
                .mutex = &self.write_mutex,
                .io = self.io,
            };
        };
        defer guard.unlock();
        try self.ensureWritable(opcode);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        if (self.options.role == .server) {
            const slices_available = if (deadline != null)
                self.transport.write_slices_deadline_fn != null
            else
                self.transport.write_slices_fn != null;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                opcode,
                total,
                .{ .fin = true },
            );
            if (slices_available) {
                try writes.slices(self, header, slices, deadline);
                return;
            }
            if (deadline != null and self.transport.write_deadline_fn == null) {
                return error.DeadlineUnsupported;
            }
            // No slice callback: the write mutex still keeps the header and
            // payload contiguous relative to other frames on this stream.
            try writes.all(self, header, deadline);
            // Once the header is committed, even a later preflight timeout
            // leaves an incomplete frame. No subsequent frame can repair it.
            errdefer self.abort();
            for (slices) |slice| {
                if (slice.len == 0) continue;
                try writes.all(self, slice, deadline);
            }
            return;
        }
        // Client-role frames are masked; stage the header and masked payload
        // once so the transport still sees one write.
        if (deadline != null and self.transport.write_deadline_fn == null) {
            return error.DeadlineUnsupported;
        }
        self.write_buffer.clearRetainingCapacity();
        var mask_key: [4]u8 = undefined;
        std.Io.random(self.io, &mask_key);
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            opcode,
            total,
            .{ .fin = true, .mask_key = mask_key },
        );
        const required = std.math.add(
            usize,
            header.len,
            total,
        ) catch return error.PayloadTooLarge;
        try self.write_buffer.ensureUnusedCapacity(
            self.allocator,
            required,
        );
        self.write_buffer.appendSliceAssumeCapacity(header);
        var offset: usize = 0;
        for (slices) |slice| {
            const out = self.write_buffer.addManyAsSliceAssumeCapacity(
                slice.len,
            );
            @memcpy(out, slice);
            websocket.applyMask(out, mask_key, offset);
            offset += slice.len;
        }
        try writes.all(self, self.write_buffer.items, deadline);
        self.frameSent(opcode);
    }

    fn readFrame(self: *Connection) !websocket.Frame {
        return self.readFrameBefore(null);
    }

    fn readFrameBefore(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) !websocket.Frame {
        while (true) {
            if (self.isClosed()) return error.ConnectionClosed;
            try self.ensureBefore(2, deadline);
            const header = websocket.FrameHeader.parse(
                self.buffer.items[self.start..],
            ) catch |err| switch (err) {
                error.BufferTooShort => {
                    try self.ensureBefore(websocket.max_frame_header_len, deadline);
                    continue;
                },
                else => return err,
            };
            const wire_len = try header.wireLen();
            if (wire_len > self.options.max_frame_bytes) {
                return error.PayloadTooLarge;
            }
            try self.ensureBefore(wire_len, deadline);
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

    fn ensureBefore(
        self: *Connection,
        wanted: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        const limit = std.math.add(
            usize,
            self.options.max_frame_bytes,
            websocket.max_frame_header_len,
        ) catch return error.PayloadTooLarge;
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
            // Read straight into spare capacity instead of copying through a
            // stack chunk. Keep 16 KiB amortization for small headers while
            // bounding each reservation so a peer cannot force a whole-frame
            // allocation before sending the payload.
            const missing = wanted - self.buffer.items.len;
            const read_len = @min(
                @max(missing, 16 * 1024),
                @min(limit - self.buffer.items.len, 64 * 1024),
            );
            if (read_len == 0) return error.PayloadTooLarge;
            try self.buffer.ensureUnusedCapacity(self.allocator, read_len);
            const spare = self.buffer.unusedCapacitySlice();
            const count = if (deadline) |absolute|
                try self.transport.readBefore(spare[0..read_len], absolute)
            else
                try self.transport.read(spare[0..read_len]);
            if (count == 0) return error.EndOfStream;
            self.buffer.items.len += count;
            if (self.buffer.items.len > limit) return error.PayloadTooLarge;
        }
    }
};
