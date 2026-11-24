//! Close-handshake state for the caller-supplied byte-stream adapter.
const std = @import("std");
const websocket = @import("mod.zig");
const stream_connection = @import("stream_connection.zig");
const allocator = std.testing.allocator;

const Peer = struct {
    io: std.Io = std.testing.io,
    input: []const u8,
    offset: usize = 0,
    output: std.ArrayList(u8) = .empty,
    fail_next_write: bool = false,
    writes: usize = 0,
    slice_writes: usize = 0,
    deadline_slice_writes: usize = 0,
    deadline_reads: usize = 0,
    deadline_writes: usize = 0,

    fn read(context: ?*anyopaque, buffer: []u8) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        if (self.offset == self.input.len) return 0;
        const count = @min(buffer.len, self.input.len - self.offset);
        @memcpy(buffer[0..count], self.input[self.offset..][0..count]);
        self.offset += count;
        return count;
    }

    fn readDeadline(
        context: ?*anyopaque,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.deadline_reads += 1;
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        return read(context, buffer);
    }

    fn writeDeadline(
        context: ?*anyopaque,
        bytes: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.deadline_writes += 1;
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        return write(context, bytes);
    }

    fn write(context: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        if (self.fail_next_write) {
            self.fail_next_write = false;
            return error.WriteFailed;
        }
        try self.output.appendSlice(allocator, bytes);
        self.writes += 1;
    }

    fn writeSlices(
        context: ?*anyopaque,
        header: []const u8,
        slices: []const []const u8,
    ) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        try self.output.appendSlice(allocator, header);
        for (slices) |slice| try self.output.appendSlice(allocator, slice);
        self.slice_writes += 1;
    }

    fn writeSlicesDeadline(
        context: ?*anyopaque,
        header: []const u8,
        slices: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.deadline_slice_writes += 1;
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        try writeSlices(context, header, slices);
    }

    fn deinit(self: *Peer) void {
        self.output.deinit(allocator);
    }

    fn transport(self: *Peer) stream_connection.Transport {
        return .{ .context = self, .read_fn = read, .write_fn = write };
    }

    fn deadlineTransport(self: *Peer) stream_connection.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .read_deadline_fn = readDeadline,
            .write_fn = write,
            .write_deadline_fn = writeDeadline,
        };
    }

    fn sliceTransport(self: *Peer) stream_connection.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .write_fn = write,
            .write_slices_fn = writeSlices,
        };
    }

    fn sliceDeadlineTransport(self: *Peer) stream_connection.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .read_deadline_fn = readDeadline,
            .write_fn = write,
            .write_deadline_fn = writeDeadline,
            .write_slices_fn = writeSlices,
            .write_slices_deadline_fn = writeSlicesDeadline,
        };
    }
};

fn encodePeerFrame(list: *std.ArrayList(u8), opcode: websocket.Opcode, payload: []const u8) !void {
    // The adapter runs in server role, so peer (client) frames are masked.
    try websocket.writeFrame(
        list,
        allocator,
        opcode,
        payload,
        .{ .fin = true, .mask_key = .{ 1, 2, 3, 4 } },
    );
}

test "WebSocket stream adapter rejects data after the closing handshake" {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    try encodePeerFrame(&frames, .text, "hello");
    try encodePeerFrame(&frames, .close, &.{});

    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
    try std.testing.expectEqualStrings("hello", message.payload);

    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    // The adapter replies to the peer Close, then refuses new application data.
    try std.testing.expect(connection.close_sent);
    try std.testing.expectError(error.ConnectionClosed, connection.sendText("late"));
    try std.testing.expectError(error.ConnectionClosed, connection.sendPing("late"));
    // A repeated receive does not read another frame.
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
}

test "WebSocket stream adapter retires a failed Close write without marking it sent" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    peer.fail_next_write = true;
    try std.testing.expectError(error.WriteFailed, connection.sendClose(.normal_closure, "bye"));
    try std.testing.expect(!connection.close_sent);

    try std.testing.expect(connection.isClosed());
    try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, "bye"));
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    try std.testing.expectError(error.ConnectionClosed, connection.sendBinary("late"));
}

test "WebSocket stream adapter reports and echoes peer close metadata" {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    var payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &payload_storage,
        .{ .code = .going_away, .reason = "going away" },
    );
    try encodePeerFrame(&frames, .close, close_payload);

    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    const peer_close = connection.peerClose().?;
    try std.testing.expectEqual(websocket.CloseCode.going_away, peer_close.code);
    try std.testing.expectEqualStrings("going away", peer_close.reason);

    var reply = try websocket.parseFrame(allocator, peer.output.items);
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, reply.header.opcode);
    const echoed = (try websocket.parseClosePayload(reply.payload)).?;
    try std.testing.expectEqual(websocket.CloseCode.going_away, echoed.code);
}

test "WebSocket stream adapter rejects invalid close codes and replies 1002" {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    // 1005 (no status) is reserved and must not appear on the wire. The
    // normal writer validates outgoing payloads, so build the malformed
    // masked client frame directly.
    const invalid_payload = [_]u8{ 0x03, 0xED };
    const mask = [_]u8{ 1, 2, 3, 4 };
    try frames.append(allocator, 0x88); // FIN + Close
    try frames.append(allocator, 0x80 | @as(u8, @intCast(invalid_payload.len)));
    try frames.appendSlice(allocator, &mask);
    for (invalid_payload, 0..) |byte, index| {
        try frames.append(allocator, byte ^ mask[index % mask.len]);
    }

    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(error.InvalidCloseCode, connection.receiveMessage());
    try std.testing.expect(connection.peerClose() == null);
    // The malformed frame is terminal: the adapter replies 1002 and does not
    // re-read the same buffered bytes.
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    var reply = try websocket.parseFrame(allocator, peer.output.items);
    defer reply.deinit(allocator);
    const echoed = (try websocket.parseClosePayload(reply.payload)).?;
    try std.testing.expectEqual(websocket.CloseCode.protocol_error, echoed.code);
}

test "WebSocket stream adapter rejects an oversized close reason" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();
    const reason = [_]u8{'x'} ** 124;
    try std.testing.expectError(
        error.InvalidControlFrame,
        connection.sendClose(.normal_closure, &reason),
    );
    try std.testing.expect(!connection.close_sent);
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
}

test "WebSocket stream adapter deadline forms require transport support" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();
    const future = std.Io.Clock.Timestamp.fromNow(
        std.testing.io,
        .{ .clock = .awake, .raw = .fromSeconds(1) },
    );
    try std.testing.expectError(
        error.DeadlineUnsupported,
        connection.receiveMessageWithDeadline(future),
    );
    try std.testing.expectError(
        error.DeadlineUnsupported,
        connection.sendTextWithDeadline("late", future),
    );
}

test "WebSocket stream adapter deadline forms validate before I/O and reach the transport" {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    try encodePeerFrame(&frames, .text, "deadline");
    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.deadlineTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.Timeout,
        connection.receiveMessageWithDeadline(.{ .clock = .awake, .raw = .zero }),
    );
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_reads);

    const future = std.Io.Clock.Timestamp.fromNow(
        std.testing.io,
        .{ .clock = .awake, .raw = .fromSeconds(1) },
    );
    var message = try connection.receiveMessageWithDeadline(future);
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("deadline", message.payload);
    try std.testing.expect(peer.deadline_reads > 0);

    try connection.sendTextWithDeadline("reply", future);
    try std.testing.expectEqual(@as(usize, 1), peer.deadline_writes);
    try std.testing.expect(peer.output.items.len != 0);
}

test "WebSocket stream adapter timeout forms validate before I/O and reach the transport" {
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    try encodePeerFrame(&frames, .text, "timeout");
    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.deadlineTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.Timeout,
        connection.receiveMessageWithTimeout(.fromMilliseconds(0)),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.sendTextWithTimeout("late", .fromMilliseconds(0)),
    );
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_reads);
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_writes);

    var message = try connection.receiveMessageWithTimeout(.fromSeconds(1));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("timeout", message.payload);
    try std.testing.expect(peer.deadline_reads > 0);

    try connection.sendTextWithTimeout("reply", .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 1), peer.deadline_writes);
    try std.testing.expect(peer.output.items.len != 0);
}

test "WebSocket stream adapter bounded close validates before I/O and stays retryable" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.deadlineTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.Timeout,
        connection.closeWithTimeout(.fromNanoseconds(0)),
    );
    try std.testing.expect(!connection.closed);
    try std.testing.expect(!connection.close_sent);
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_writes);

    try connection.closeWithTimeout(.fromSeconds(1));
    try std.testing.expect(connection.closed);
    try std.testing.expect(connection.close_sent);
    try std.testing.expectEqual(@as(usize, 1), peer.deadline_writes);
    try std.testing.expect(peer.output.items.len != 0);
}

test "WebSocket stream adapter bounded close reports transport deadline support" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.DeadlineUnsupported,
        connection.closeWithDeadline(.fromNow(std.testing.io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        })),
    );
    try std.testing.expect(!connection.closed);
    try std.testing.expect(!connection.close_sent);
    // The unbounded close remains available after the rejected budget.
    connection.close();
    try std.testing.expect(connection.closed);
    try std.testing.expectEqual(@as(usize, 1), peer.writes);
}

test "WebSocket stream adapter buffers frames larger than one read chunk" {
    const payload_len = 40 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(allocator);
    try encodePeerFrame(&frames, .binary, payload);

    var peer = Peer{ .input = frames.items };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
    try std.testing.expectEqualSlices(u8, payload, message.payload);
}

const PartsPeer = struct {
    io: std.Io = std.testing.io,
    output: std.ArrayList(u8) = .empty,
    parts_calls: usize = 0,
    deadline_parts_calls: usize = 0,
    header_storage: [websocket.max_frame_header_len]u8 = undefined,
    header_len: usize = 0,
    last_payload: []const u8 = &.{},

    fn read(_: ?*anyopaque, _: []u8) anyerror!usize {
        return 0;
    }

    fn write(context: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *PartsPeer = @ptrCast(@alignCast(context.?));
        try self.output.appendSlice(allocator, bytes);
    }

    fn append(
        self: *PartsPeer,
        header: []const u8,
        payload: []const u8,
    ) !void {
        @memcpy(self.header_storage[0..header.len], header);
        self.header_len = header.len;
        self.last_payload = payload;
        try self.output.appendSlice(allocator, header);
        try self.output.appendSlice(allocator, payload);
    }

    fn writeParts(
        context: ?*anyopaque,
        header: []const u8,
        payload: []const u8,
    ) anyerror!void {
        const self: *PartsPeer = @ptrCast(@alignCast(context.?));
        self.parts_calls += 1;
        try self.append(header, payload);
    }

    fn writePartsDeadline(
        context: ?*anyopaque,
        header: []const u8,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) anyerror!void {
        const self: *PartsPeer = @ptrCast(@alignCast(context.?));
        if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        self.deadline_parts_calls += 1;
        try self.append(header, payload);
    }

    fn deinit(self: *PartsPeer) void {
        self.output.deinit(allocator);
    }

    fn lastHeader(self: *const PartsPeer) []const u8 {
        return self.header_storage[0..self.header_len];
    }

    fn transport(self: *PartsPeer) stream_connection.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .write_fn = write,
            .write_parts_fn = writeParts,
            .write_parts_deadline_fn = writePartsDeadline,
        };
    }
};

test "WebSocket stream adapter sends unmasked frames as header plus payload" {
    var peer = PartsPeer{};
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    const payload = "borrowed payload";
    try connection.sendBinary(payload);
    try std.testing.expectEqual(@as(usize, 1), peer.parts_calls);
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_parts_calls);
    try std.testing.expectEqual(payload.ptr, peer.last_payload.ptr);
    const header = try websocket.FrameHeader.parse(peer.lastHeader());
    try std.testing.expectEqual(websocket.Opcode.binary, header.opcode);
    try std.testing.expectEqual(@as(u64, payload.len), header.payload_len);
    try std.testing.expect(!header.masked);
    try std.testing.expectEqual(
        header.header_len + payload.len,
        peer.output.items.len,
    );
    try std.testing.expectEqualStrings(
        payload,
        peer.output.items[header.header_len..],
    );

    const future = std.Io.Clock.Timestamp.fromNow(
        std.testing.io,
        .{ .clock = .awake, .raw = .fromSeconds(1) },
    );
    try std.testing.expectError(
        error.Timeout,
        connection.sendTextWithDeadline("late", .{
            .clock = .awake,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_parts_calls);
    try connection.sendTextWithDeadline("bounded", future);
    try std.testing.expectEqual(@as(usize, 1), peer.deadline_parts_calls);
    try std.testing.expectEqual(@as(usize, 1), peer.parts_calls);
}

test "WebSocket stream adapter masks client frames instead of borrowing payloads" {
    var peer = PartsPeer{};
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .client },
    );
    defer connection.deinit();

    try connection.sendBinary("masked payload");
    try std.testing.expectEqual(@as(usize, 0), peer.parts_calls);
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_parts_calls);
    const header = try websocket.FrameHeader.parse(peer.output.items);
    try std.testing.expect(header.masked);
    try std.testing.expectEqual(
        @as(u64, "masked payload".len),
        header.payload_len,
    );
}

test "WebSocket stream adapter sends unmasked frames from slices" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.sliceTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try connection.sendBinarySlices(&.{ "ab", "", "cde" });
    try std.testing.expectEqual(@as(usize, 1), peer.slice_writes);
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    var frame = try websocket.parseFrame(allocator, peer.output.items);
    defer frame.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
    try std.testing.expectEqualStrings("abcde", frame.payload);
    try std.testing.expectError(
        error.InvalidFrame,
        connection.sendFrameSlices(.ping, &.{"x"}),
    );
}

test "WebSocket stream adapter falls back to sequential slice writes" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try connection.sendBinarySlices(&.{ "ab", "", "cde" });
    try std.testing.expectEqual(@as(usize, 0), peer.slice_writes);
    try std.testing.expectEqual(@as(usize, 3), peer.writes);
    var frame = try websocket.parseFrame(allocator, peer.output.items);
    defer frame.deinit(allocator);
    try std.testing.expectEqualStrings("abcde", frame.payload);
}

test "WebSocket stream adapter masks sliced client frames" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .client },
    );
    defer connection.deinit();

    try connection.sendTextSlices(&.{ "h", "\xc3\xa9llo" });
    try std.testing.expectEqual(@as(usize, 1), peer.writes);
    var frame = try websocket.parseFrameOptions(
        allocator,
        peer.output.items,
        .{ .expect_mask = .masked },
    );
    defer frame.deinit(allocator);
    try std.testing.expectEqualStrings("h\xc3\xa9llo", frame.payload);
}

test "WebSocket stream adapter validates text across slice boundaries" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.sliceTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try connection.sendTextSlices(&.{ "\xc3", "\xa9" });
    try std.testing.expectEqual(@as(usize, 1), peer.slice_writes);
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.sendTextSlices(&.{ "\xc3", "x" }),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.sendTextSlices(&.{"\xa9"}),
    );
    try std.testing.expectEqual(@as(usize, 1), peer.slice_writes);
}

test "WebSocket stream adapter uses the deadline slice callback" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.sliceDeadlineTransport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    const future = std.Io.Clock.Timestamp.fromNow(
        std.testing.io,
        .{ .clock = .awake, .raw = .fromSeconds(5) },
    );
    try connection.sendBinarySlicesWithDeadline(&.{ "a", "b" }, future);
    try std.testing.expectEqual(@as(usize, 1), peer.deadline_slice_writes);
    try std.testing.expectEqual(@as(usize, 0), peer.deadline_writes);
    var frame = try websocket.parseFrame(allocator, peer.output.items);
    defer frame.deinit(allocator);
    try std.testing.expectEqualStrings("ab", frame.payload);
}

test "WebSocket stream adapter rejects invalid UTF-8 text before I/O" {
    var peer = Peer{ .input = &.{} };
    defer peer.deinit();
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{ .role = .server },
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.InvalidUtf8,
        connection.sendText(&.{ 0xff, 0xfe }),
    );
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    // The opcode-driven form shares the same validation and rejects controls.
    try std.testing.expectError(
        error.InvalidFrame,
        connection.sendMessage(.ping, "control"),
    );
    // Binary payloads remain opaque.
    try connection.sendBinary(&.{ 0xff, 0xfe });
    try connection.sendMessage(.binary, &.{ 0xfe, 0xff });
    try std.testing.expect(peer.writes != 0);
}
