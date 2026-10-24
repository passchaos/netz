const std = @import("std");
const websocket = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const h3 = @import("../../h3.zig");

const allocator = std.testing.allocator;
const Kind = enum { text, binary, compressed, takeover };

test "WebSocket HTTP1 message allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        inline for (std.enums.values(Kind)) |kind| {
            inline for (.{ false, true }) |fragmented| try exercise(runtime.Connection, .{ .allocator = allocator, .io = undefined, .stream = undefined, .role = role }, role, kind, fragmented);
        }
    }
}

test "WebSocket HTTP2 message allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        inline for (std.enums.values(Kind)) |kind| {
            inline for (.{ false, true }) |fragmented| try exercise(runtime.H2Connection, .{ .allocator = allocator, .tunnel = undefined, .role = role }, role, kind, fragmented);
        }
    }
}

test "WebSocket HTTP3 message allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        inline for (std.enums.values(Kind)) |kind| {
            inline for (.{ false, true }) |fragmented| try exercise(h3.Connection(role), .{ .allocator = allocator, .stream_id = 0, .h3 = undefined }, role, kind, fragmented);
        }
    }
}

fn exercise(comptime Connection: type, template: Connection, role: runtime.Role, kind: Kind, fragmented: bool) !void {
    const payload = "snowman \xe2\x98\x83 and repeated history repeated history repeated history";
    var compressor = try websocket.CompressionContext.init(allocator, 15);
    defer compressor.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const first_encoded = if (kind == .takeover)
        try compressor.compressInto(&encoded, payload)
    else if (kind == .compressed)
        try websocket.compressMessage(allocator, payload)
    else
        payload;
    defer if (kind == .compressed) allocator.free(first_encoded);
    const first = try allocator.dupe(u8, first_encoded);
    defer allocator.free(first);
    const second = if (kind == .takeover)
        try allocator.dupe(u8, try compressor.compressInto(&encoded, payload))
    else
        try allocator.dupe(u8, first);
    defer allocator.free(second);
    if (kind == .takeover) try std.testing.expect(second.len < first.len);
    var succeeded = false;
    for (0..32) |fail_index| {
        var connection = template;
        connection.permessage_deflate = kind == .compressed or kind == .takeover;
        connection.compression_receive_context_takeover = kind == .takeover;
        connection.limits.max_message_bytes = 256;
        defer {
            if (connection.message_assembler) |*assembler| assembler.deinit();
            connection.inbuf.deinit(allocator);
            connection.compression_receive.deinit(allocator);
        }
        const mask: ?[4]u8 = if (role == .server) .{ 0x11, 0x22, 0x33, 0x44 } else null;
        const split = if (kind == .text) "snowman \xe2".len else first.len / 3;
        const middle_end = if (kind == .text) split + 1 else 2 * split;
        if (fragmented) {
            try websocket.writeFrameExtended(&connection.inbuf, allocator, if (kind == .binary) .binary else .text, first[0..split], .{ .fin = false, .rsv1 = connection.permessage_deflate, .mask_key = mask });
            try websocket.writeFrameExtended(&connection.inbuf, allocator, .continuation, first[split..middle_end], .{ .fin = false, .mask_key = mask });
            try websocket.writeFrameExtended(&connection.inbuf, allocator, .continuation, first[middle_end..], .{ .mask_key = mask });
        } else {
            try websocket.writeFrameExtended(&connection.inbuf, allocator, if (kind == .binary) .binary else .text, first, .{ .rsv1 = connection.permessage_deflate, .mask_key = mask });
        }
        try websocket.writeFrameExtended(&connection.inbuf, allocator, if (kind == .binary) .binary else .text, second, .{ .rsv1 = connection.permessage_deflate, .mask_key = mask });
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        connection.allocator = failing.allocator();
        const result = connection.receiveMessage();
        var received = if (failing.has_induced_failure) blk: {
            try std.testing.expectError(error.OutOfMemory, result);
            try std.testing.expect(connection.message_assembler != null);
            try std.testing.expect(!connection.receive_failed.load(.acquire));
            try std.testing.expect(!connection.close_sent.load(.acquire));
            // Retained runtime modes remain owned by receiveMessage until the
            // retry completes. This local misuse must not consume or close.
            try std.testing.expectError(error.InvalidFrame, connection.receiveFrame());
            var out: [256]u8 = undefined;
            try std.testing.expectError(error.InvalidFrame, connection.receiveMessageInto(&out));
            const before_offset = connection.inbuf_consumed;
            const before_validation = connection.incoming_frame_validated;
            const before_kind = connection.incoming_data_kind;
            const before_utf8 = connection.incoming_text_utf8;
            try std.testing.expectError(error.OutOfMemory, connection.receiveMessage());
            try std.testing.expectEqual(before_offset, connection.inbuf_consumed);
            try std.testing.expectEqual(before_validation, connection.incoming_frame_validated);
            try std.testing.expectEqual(before_kind, connection.incoming_data_kind);
            try std.testing.expectEqualDeep(before_utf8, connection.incoming_text_utf8);
            failing.fail_index = std.math.maxInt(usize);
            break :blk try connection.receiveMessage();
        } else blk: {
            succeeded = true;
            break :blk try result;
        };
        defer received.deinit(connection.allocator);
        try std.testing.expectEqualStrings(payload, received.payload);
        try std.testing.expectEqual(kind == .compressed or kind == .takeover, received.was_compressed);
        try std.testing.expect(connection.message_assembler == null);
        failing.fail_index = std.math.maxInt(usize);
        var following = try connection.receiveMessage();
        defer following.deinit(connection.allocator);
        try std.testing.expectEqualStrings(payload, following.payload);
        try std.testing.expect(!connection.receive_failed.load(.acquire));
        if (succeeded) break;
    }
    try std.testing.expect(succeeded);
}

test "WebSocket message allocation failure preserves a timed out masked UTF8 prefix" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var connection = runtime.testing.initDirectConnection(failing.allocator(), io, receiver, .server, .{});
    defer connection.close();
    try connection.inbuf.ensureTotalCapacityPrecise(allocator, 64);
    const wire = [_]u8{ 0x81, 0x83, 0x11, 0x22, 0x33, 0x44, 0xe2 ^ 0x11, 0x98 ^ 0x22, 0x83 ^ 0x33 };
    try connection.inbuf.appendSlice(allocator, wire[0..7]);
    try std.testing.expectError(error.Timeout, connection.receiveMessageWithTimeout(.fromMilliseconds(5)));
    const before_utf8 = connection.incoming_text_utf8;
    const before_kind = connection.incoming_data_kind;
    const before_validated = connection.incoming_frame_validated;
    try std.testing.expectEqual(@as(u3, 2), before_utf8.remaining);
    var writer = sender.writer(io, &.{});
    try writer.interface.writeAll(wire[7..]);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, connection.receiveMessageWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqualDeep(before_utf8, connection.incoming_text_utf8);
    try std.testing.expectEqual(before_kind, connection.incoming_data_kind);
    try std.testing.expectEqual(before_validated, connection.incoming_frame_validated);
    try std.testing.expectEqualSlices(u8, &wire, connection.inbuf.items);
    try std.testing.expect(!connection.receive_failed.load(.acquire));
    failing.fail_index = std.math.maxInt(usize);
    var message = try connection.receiveMessageWithTimeout(.fromSeconds(1));
    defer message.deinit(connection.allocator);
    try std.testing.expectEqualStrings("\xe2\x98\x83", message.payload);
    try std.testing.expectEqual(.none, connection.incoming_data_kind);
}
