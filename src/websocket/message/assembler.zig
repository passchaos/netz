//! Transactional RFC 6455 fragmented message assembly.
const std = @import("std");
const websocket = @import("../mod.zig");
const Opcode = websocket.Opcode;
const Frame = websocket.Frame;
const Utf8Validator = websocket.Utf8Validator;

pub const Assembler = struct {
    allocator: std.mem.Allocator,
    max_message_bytes: usize = std.math.maxInt(usize),
    opcode: ?Opcode = null,
    compressed: bool = false,
    text_utf8: Utf8Validator = .{},
    buffer: std.ArrayList(u8) = .empty,

    /// Metadata restoration retains a current buffer pointer after growth.
    pub const Checkpoint = struct {
        opcode: ?Opcode,
        compressed: bool,
        text_utf8: Utf8Validator,
        buffered: usize,

        pub fn capture(assembler: *const Assembler) Checkpoint {
            return .{ .opcode = assembler.opcode, .compressed = assembler.compressed, .text_utf8 = assembler.text_utf8, .buffered = assembler.buffer.items.len };
        }

        pub fn restore(self: Checkpoint, assembler: *Assembler) void {
            assembler.opcode = self.opcode;
            assembler.compressed = self.compressed;
            assembler.text_utf8 = self.text_utf8;
            assembler.buffer.items.len = self.buffered;
        }

        /// A finished message that cannot yet decode donates its allocation
        /// back to the assembler, trimmed to the accepted fragment prefix.
        pub fn restoreDetached(self: Checkpoint, assembler: *Assembler, message: Message) void {
            assembler.buffer.deinit(assembler.allocator);
            assembler.buffer = .fromOwnedSlice(message.payload);
            self.restore(assembler);
        }
    };

    pub const Message = struct {
        opcode: Opcode,
        payload: []u8,
        compressed: bool = false,
        /// The assembler incrementally validated this uncompressed text.
        /// This is internal protocol evidence, not a caller assertion; runtime
        /// finalization skips its otherwise redundant full-message scan only
        /// for values produced by `feed`.
        utf8_validated: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator) Assembler {
        return .{ .allocator = allocator };
    }

    pub fn initLimited(allocator: std.mem.Allocator, max_message_bytes: usize) Assembler {
        return .{ .allocator = allocator, .max_message_bytes = max_message_bytes };
    }

    pub fn deinit(self: *Assembler) void {
        self.buffer.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn feed(self: *Assembler, frame: Frame) !?Message {
        return self.feedInternal(frame, null, null);
    }

    /// Assemble an owned frame, transferring its payload allocation when the
    /// frame completes the message by itself. The frame payload is cleared on
    /// success so the caller's `Frame.deinit` becomes a no-op for it.
    pub fn feedOwned(self: *Assembler, frame: *Frame) !?Message {
        return self.feedInternal(frame.*, null, frame);
    }

    /// Assemble a frame whose uncompressed text bytes were already checked by
    /// a transport-level incremental validator. The supplied state is copied
    /// into the assembler so continuation boundaries and final completeness
    /// retain the same proof without rescanning the frame payload.
    pub fn feedUtf8Validated(
        self: *Assembler,
        frame: anytype,
        text_utf8: Utf8Validator,
    ) !?Message {
        return self.feedInternal(frame, text_utf8, null);
    }

    fn validateFastPayload(
        self: *Assembler,
        payload: []const u8,
        validated_text_utf8: ?Utf8Validator,
    ) !void {
        if (payload.len > self.max_message_bytes) {
            return error.PayloadTooLarge;
        }
        if (self.opcode == .text and !self.compressed) {
            if (validated_text_utf8) |validator| {
                self.text_utf8 = validator;
            } else {
                try self.text_utf8.feed(payload);
            }
            try self.text_utf8.finish();
        }
    }

    fn finishFast(self: *Assembler, payload: []u8) Message {
        const opcode = self.opcode.?;
        const compressed = self.compressed;
        self.opcode = null;
        self.compressed = false;
        self.text_utf8.reset();
        return .{
            .opcode = opcode,
            .payload = payload,
            .compressed = compressed,
            .utf8_validated = opcode == .text and !compressed,
        };
    }

    fn feedInternal(
        self: *Assembler,
        frame: anytype,
        validated_text_utf8: ?Utf8Validator,
        steal_from: ?*Frame,
    ) !?Message {
        if (frame.header.opcode.isControl()) return null;
        const checkpoint = Checkpoint.capture(self);
        errdefer |err| if (err == error.OutOfMemory) checkpoint.restore(self);
        if (frame.header.opcode != .continuation) {
            if (self.opcode != null) return error.InvalidFrame;
            self.opcode = frame.header.opcode;
            self.compressed = frame.header.rsv1;
            self.text_utf8.reset();
            self.buffer.clearRetainingCapacity();
        } else if (self.opcode == null) {
            return error.InvalidFrame;
        } else if (frame.header.rsv1) {
            return error.UnexpectedRsv;
        }
        if (frame.header.fin and self.buffer.items.len == 0) {
            if (steal_from) |owned| {
                try self.validateFastPayload(
                    frame.payload,
                    validated_text_utf8,
                );
                const payload = owned.payload;
                owned.payload = &.{};
                return self.finishFast(payload);
            }
            if (self.buffer.capacity < frame.payload.len) {
                try self.validateFastPayload(
                    frame.payload,
                    validated_text_utf8,
                );
                return self.finishFast(
                    try self.allocator.dupe(u8, frame.payload),
                );
            }
        }
        // A fragmented message can be split into many individually-valid
        // frames.  Bound the aggregate payload, not only the current frame, so
        // peers cannot bypass runtime limits with many small fragments.
        const new_len = std.math.add(usize, self.buffer.items.len, frame.payload.len) catch return error.PayloadTooLarge;
        if (new_len > self.max_message_bytes) return error.PayloadTooLarge;
        try self.buffer.appendSlice(self.allocator, frame.payload);
        if (self.opcode == .text and !self.compressed) {
            if (validated_text_utf8) |validator| {
                self.text_utf8 = validator;
            } else {
                try self.text_utf8.feed(frame.payload);
            }
            if (frame.header.fin) try self.text_utf8.finish();
        }
        if (!frame.header.fin) return null;
        const payload = try self.buffer.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(payload);
        const opcode = self.opcode.?;
        const compressed = self.compressed;
        self.opcode = null;
        self.compressed = false;
        self.text_utf8.reset();
        self.buffer = .empty;
        return .{
            .opcode = opcode,
            .payload = payload,
            .compressed = compressed,
            .utf8_validated = opcode == .text and !compressed,
        };
    }
};

test "WebSocket message assembler allocation failures preserve the accepted UTF8 prefix" {
    const allocator = std.testing.allocator;
    var succeeded = false;
    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var assembler = Assembler.initLimited(failing.allocator(), 128);
        defer assembler.deinit();
        const payload = "\xe2\x98\x83: transactional message assembly";
        const pieces = [_][]const u8{ payload[0..1], payload[1..2], payload[2..] };
        var result_message: ?Assembler.Message = null;
        for (pieces, 0..) |piece, index| {
            const frame = Frame{
                .header = .{ .fin = index == pieces.len - 1, .opcode = if (index == 0) .text else .continuation, .masked = false, .mask_key = null, .header_len = 2, .payload_len = piece.len },
                .payload = @constCast(piece),
                .consumed = 2 + piece.len,
            };
            const checkpoint = Assembler.Checkpoint.capture(&assembler);
            result_message = assembler.feed(frame) catch |err| blk: {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqualDeep(checkpoint, Assembler.Checkpoint.capture(&assembler));
                failing.fail_index = std.math.maxInt(usize);
                break :blk try assembler.feed(frame);
            };
        }
        const message = result_message.?;
        defer assembler.allocator.free(message.payload);
        try std.testing.expectEqualStrings(payload, message.payload);
        try std.testing.expect(message.utf8_validated);
        if (!failing.has_induced_failure) {
            succeeded = true;
            break;
        }
    }
    try std.testing.expect(succeeded);
}

test "WebSocket message assembler transfers an owned single-frame payload" {
    const allocator = std.testing.allocator;
    var assembler = Assembler.initLimited(allocator, 128);
    defer assembler.deinit();
    const payload = try allocator.dupe(u8, "owned payload");
    var frame = Frame{
        .header = .{
            .fin = true,
            .opcode = .binary,
            .masked = false,
            .mask_key = null,
            .header_len = 2,
            .payload_len = payload.len,
        },
        .payload = payload,
        .consumed = 2 + payload.len,
    };
    const message = (try assembler.feedOwned(&frame)).?;
    defer allocator.free(message.payload);
    try std.testing.expectEqual(Opcode.binary, message.opcode);
    try std.testing.expectEqualStrings("owned payload", message.payload);
    try std.testing.expectEqual(payload.ptr, message.payload.ptr);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
    frame.deinit(allocator);
}

test "WebSocket message assembler transfers a finishing continuation payload" {
    const allocator = std.testing.allocator;
    var assembler = Assembler.initLimited(allocator, 128);
    defer assembler.deinit();
    var empty = Frame{
        .header = .{
            .fin = false,
            .opcode = .text,
            .masked = false,
            .mask_key = null,
            .header_len = 2,
            .payload_len = 0,
        },
        .payload = &.{},
        .consumed = 2,
    };
    try std.testing.expect((try assembler.feedOwned(&empty)) == null);
    const tail = try allocator.dupe(u8, "tail");
    var frame = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .mask_key = null,
            .header_len = 2,
            .payload_len = tail.len,
        },
        .payload = tail,
        .consumed = 2 + tail.len,
    };
    const message = (try assembler.feedOwned(&frame)).?;
    defer allocator.free(message.payload);
    try std.testing.expectEqual(Opcode.text, message.opcode);
    try std.testing.expectEqualStrings("tail", message.payload);
    try std.testing.expectEqual(tail.ptr, message.payload.ptr);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
    frame.deinit(allocator);
}
