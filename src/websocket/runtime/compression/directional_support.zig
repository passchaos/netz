const std = @import("std");
const websocket = @import("../../mod.zig");

pub const modes = [_]websocket.ContextTakeover{ .none, .client, .server, .both };
pub const timeout = std.Io.Duration.fromSeconds(3);
pub const payload = "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;

pub fn verifyFlags(connection: anytype, mode: websocket.ContextTakeover, is_client: bool) !void {
    const client_history = mode == .client or mode == .both;
    const server_history = mode == .server or mode == .both;
    try std.testing.expect(connection.permessage_deflate);
    try std.testing.expectEqual(if (is_client) client_history else server_history, connection.compression_send_context_takeover);
    try std.testing.expectEqual(if (is_client) server_history else client_history, connection.compression_receive_context_takeover);
}

pub fn send(connection: anytype) !void {
    for (0..2) |_| {
        var progress: websocket.runtime.MessageWriteProgress = .{};
        try connection.sendBinaryWithTimeout(payload, &progress, timeout);
        try std.testing.expect(progress.frame_committed);
    }
}

pub fn receive(connection: anytype, history: bool) !void {
    for (0..2) |index| {
        var frame = try connection.receiveFrameWithTimeout(timeout);
        defer frame.deinit(std.testing.allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
        try std.testing.expect(frame.header.fin and frame.header.rsv1);
        // Independently decode each wire message. With takeover the second
        // message requires the first one's history; without it both decode.
        if (history and index == 1) {
            try std.testing.expectError(error.InvalidFrame, websocket.decompressMessage(std.testing.allocator, frame.payload, payload.len));
        } else {
            const decoded = try websocket.decompressMessage(std.testing.allocator, frame.payload, payload.len);
            defer std.testing.allocator.free(decoded);
            try std.testing.expectEqualStrings(payload, decoded);
        }
    }
}

pub fn peer(connection: anytype, mode: websocket.ContextTakeover) !void {
    try verifyFlags(connection, mode, false);
    try receive(connection, mode == .client or mode == .both);
    try send(connection);
    try finishPeer(connection);
}

pub fn finishPeer(connection: anytype) !void {
    var closed = try connection.receiveFrameWithTimeout(timeout);
    defer closed.deinit(std.testing.allocator);
    try std.testing.expectEqual(websocket.Opcode.close, closed.header.opcode);
}

pub fn client(connection: anytype, mode: websocket.ContextTakeover) !void {
    try verifyFlags(connection, mode, true);
    try send(connection);
    try receive(connection, mode == .server or mode == .both);
    try connection.sendClose(.normal_closure, "directional complete");
}
