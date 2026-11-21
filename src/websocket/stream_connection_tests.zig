//! Close-handshake state for the caller-supplied byte-stream adapter.
const std = @import("std");
const websocket = @import("mod.zig");
const stream_connection = @import("stream_connection.zig");
const allocator = std.testing.allocator;

const Peer = struct {
    input: []const u8,
    offset: usize = 0,
    output: std.ArrayList(u8) = .empty,
    fail_next_write: bool = false,
    writes: usize = 0,

    fn read(context: ?*anyopaque, buffer: []u8) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        if (self.offset == self.input.len) return 0;
        const count = @min(buffer.len, self.input.len - self.offset);
        @memcpy(buffer[0..count], self.input[self.offset..][0..count]);
        self.offset += count;
        return count;
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

    fn deinit(self: *Peer) void {
        self.output.deinit(allocator);
    }

    fn transport(self: *Peer) stream_connection.Transport {
        return .{ .context = self, .read_fn = read, .write_fn = write };
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

test "WebSocket stream adapter retries a failed Close write" {
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

    try connection.sendClose(.normal_closure, "bye");
    try std.testing.expect(connection.close_sent);
    const writes = peer.writes;
    // A completed close is not sent twice.
    try connection.sendClose(.normal_closure, "again");
    try std.testing.expectEqual(writes, peer.writes);
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
