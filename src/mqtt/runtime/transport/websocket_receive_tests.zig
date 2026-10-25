//! Allocation failures cannot lose complete WS messages handed to MQTT.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const Transport = @import("../packet_transport.zig").Transport;
const websocket = @import("../../../websocket/mod.zig");
const allocator = std.testing.allocator;
const Mode = enum { coalesced, split, packet_allocation, close_pending, invalid_text, oversize };

test "MQTT WebSocket message handoff retains bytes across allocation failure" {
    for (std.enums.values(Mode)) |mode| try exercise(mode);
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var ws = websocket.runtime.testing.initDirectConnection(allocator, io, socket, .client, .{ .max_frame_bytes = 4096, .max_message_bytes = 4096 });
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try mqtt.writePublish(&bytes, allocator, .v5, "handoff/topic", &([_]u8{'a'} ** 1024), .{});
    const packet_len = bytes.items.len;
    try bytes.appendSlice(allocator, "\xd0\x00");
    if (mode == .invalid_text) {
        try websocket.writeFrame(&ws.inbuf, allocator, .text, "not binary", .{});
    } else if (mode == .split) {
        try websocket.writeFrame(&ws.inbuf, allocator, .binary, bytes.items[0..2], .{});
        try websocket.writeFrame(&ws.inbuf, allocator, .binary, bytes.items[2..], .{});
    } else {
        try websocket.writeFrame(&ws.inbuf, allocator, .binary, bytes.items, .{});
    }
    var transport = try Transport.initWebSocket(allocator, ws);
    defer transport.close(allocator);
    if (mode == .invalid_text or mode == .oversize) {
        try std.testing.expectError(if (mode == .invalid_text) error.InvalidWebSocketMessage else error.PacketTooLarge, transport.readPacketWithDeadline(allocator, if (mode == .oversize) 16 else 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expect(transport.websocket.pending_payload == null);
        return;
    }
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = if (mode == .split or mode == .packet_allocation) 1 else 0, .resize_fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, transport.readPacketWithDeadline(failing.allocator(), 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    if (mode == .close_pending) return;
    var retry_failure = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, transport.readPacketWithDeadline(retry_failure.allocator(), 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    var packet = try transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings(bytes.items[0..packet_len], packet.bytes);
    var next = try transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer next.deinit(allocator);
    try std.testing.expectEqual(mqtt.PacketType.pingresp, next.fixed.packet_type);
    try std.testing.expectError(error.Timeout, transport.readPacketWithDeadline(allocator, 4096, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) })));
}
