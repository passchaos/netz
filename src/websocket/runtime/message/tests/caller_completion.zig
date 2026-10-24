const std = @import("std");
const websocket = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const h3 = @import("../../h3.zig");
const allocator = std.testing.allocator;

test "WebSocket HTTP1 caller completion allocation failure retains compressed input" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        try exercise(runtime.Connection, .{ .allocator = allocator, .io = undefined, .stream = undefined, .role = role }, role);
    }
}

test "WebSocket HTTP2 caller completion allocation failure retains compressed input" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        try exercise(runtime.H2Connection, .{ .allocator = allocator, .tunnel = undefined, .role = role }, role);
    }
}

test "WebSocket HTTP3 caller completion allocation failure retains compressed input" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        try exercise(h3.Connection(role), .{ .allocator = allocator, .stream_id = 0, .h3 = undefined }, role);
    }
}

fn exercise(comptime Connection: type, template: Connection, role: runtime.Role) !void {
    const payload = "snowman \xe2\x98\x83 repeated history repeated history repeated history";
    var compressor = try websocket.CompressionContext.init(allocator, 15);
    defer compressor.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const first = try allocator.dupe(u8, try compressor.compressInto(&encoded, payload));
    defer allocator.free(first);
    const second = try allocator.dupe(u8, try compressor.compressInto(&encoded, payload));
    defer allocator.free(second);
    try std.testing.expect(second.len < first.len);
    inline for (.{ false, true }) |fragmented| {
        for (0..3) |fail_index| {
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
            var connection = template;
            connection.permessage_deflate = true;
            connection.compression_receive_context_takeover = true;
            connection.limits.max_message_bytes = 256;
            defer {
                connection.inbuf.deinit(allocator);
                connection.compression_receive.deinit(allocator);
            }
            // Scratch reservation succeeds; fail each decoder allocation after
            // the complete compressed input has left the wire buffer.
            try connection.compression_receive.prepareContext(allocator, 256);
            const mask: ?[4]u8 = if (role == .server) .{ 0x11, 0x22, 0x33, 0x44 } else null;
            if (fragmented) {
                const split = first.len / 2;
                try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, first[0..split], .{ .fin = false, .rsv1 = true, .mask_key = mask });
                try websocket.writeFrameExtended(&connection.inbuf, allocator, .continuation, first[split..], .{ .mask_key = mask });
            } else {
                try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, first, .{ .rsv1 = true, .mask_key = mask });
            }
            try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, second, .{ .rsv1 = true, .mask_key = mask });
            connection.allocator = failing.allocator();
            var original: [256]u8 = undefined;
            try std.testing.expectError(error.OutOfMemory, connection.receiveMessageInto(&original));
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(!connection.receive_failed.load(.acquire));
            try std.testing.expect(connection.message_into.active());
            try std.testing.expect(connection.message_into.complete);
            try std.testing.expectEqual(@as(usize, 0), connection.message_into.output_address);
            try std.testing.expectEqualSlices(u8, first, connection.compression_receive.payload.items[0..connection.message_into.written]);
            try std.testing.expectEqual(@as(usize, 0), connection.compression_receive.context.?.history.items.len);
            var too_short: [1]u8 = undefined;
            try std.testing.expectError(error.BufferTooShort, connection.receiveMessageInto(&too_short));
            try std.testing.expect(connection.message_into.complete);
            try std.testing.expectError(error.InvalidFrame, connection.receiveFrame());
            try std.testing.expectError(error.InvalidFrame, connection.receiveMessage());
            const before = connection.inbuf_consumed;
            failing.fail_index = failing.alloc_index;
            try std.testing.expectError(error.OutOfMemory, connection.receiveMessageInto(&original));
            try std.testing.expectEqual(before, connection.inbuf_consumed);
            // The decoded destination is no longer borrowed. Replacing it must
            // finish the same first message before reading the next one.
            @memset(&original, 0xa5);
            failing.fail_index = std.math.maxInt(usize);
            var replacement: [256]u8 = undefined;
            const message = try connection.receiveMessageInto(&replacement);
            try std.testing.expectEqualStrings(payload, message.payload);
            try std.testing.expectEqual(@intFromPtr(replacement[0..].ptr), @intFromPtr(message.payload.ptr));
            try std.testing.expect(!connection.message_into.active());
            try std.testing.expectEqualSlices(u8, payload, connection.compression_receive.context.?.history.items);
            const following = try connection.receiveMessageInto(&replacement);
            try std.testing.expectEqualStrings(payload, following.payload);
            try std.testing.expect(following.was_compressed);
            try std.testing.expectEqualSlices(u8, payload ++ payload, connection.compression_receive.context.?.history.items);
        }
    }
}

test "WebSocket caller completion recovery preserves an established dictionary" {
    const first_payload = "first message history first message history";
    const second_payload = "second message with first message history";
    const third_payload = first_payload ++ second_payload;
    var compressor = try websocket.CompressionContext.init(allocator, 15);
    defer compressor.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var connection = runtime.Connection{ .allocator = failing.allocator(), .io = undefined, .stream = undefined, .role = .server, .permessage_deflate = true, .compression_receive_context_takeover = true, .limits = .{ .max_message_bytes = 256 } };
    defer {
        connection.inbuf.deinit(allocator);
        connection.compression_receive.deinit(allocator);
    }
    var out: [256]u8 = undefined;
    const mask: [4]u8 = .{ 0x11, 0x22, 0x33, 0x44 };
    try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, try compressor.compressInto(&encoded, first_payload), .{ .rsv1 = true, .mask_key = mask });
    const first = try connection.receiveMessageInto(&out);
    try std.testing.expectEqualStrings(first_payload, first.payload);
    const context = &connection.compression_receive.context.?;
    // Release only decoder workspace, preserving the committed dictionary.
    // The next full message must survive the ensuing workspace allocation OOM.
    context.input.clearAndFree(allocator);
    const second_encoded = try allocator.dupe(u8, try compressor.compressInto(&encoded, second_payload));
    defer allocator.free(second_encoded);
    const third_encoded = try compressor.compressInto(&encoded, third_payload);
    try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, second_encoded, .{ .rsv1 = true, .mask_key = mask });
    try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, third_encoded, .{ .rsv1 = true, .mask_key = mask });
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, connection.receiveMessageInto(&out));
    try std.testing.expectEqualSlices(u8, first_payload, context.history.items);
    try std.testing.expect(!context.previewPending());
    failing.fail_index = std.math.maxInt(usize);
    var replacement: [256]u8 = undefined;
    const second = try connection.receiveMessageInto(&replacement);
    try std.testing.expectEqualStrings(second_payload, second.payload);
    try std.testing.expectEqualSlices(u8, first_payload ++ second_payload, context.history.items);
    const third = try connection.receiveMessageInto(&replacement);
    try std.testing.expectEqualStrings(third_payload, third.payload);
}

test "WebSocket caller completion real TCP resumes timeout then OOM with new storage" {
    const stream_io = @import("../../../../internal/stream_io.zig");
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer sender.close(io);
        const receiver = try listener.accept(io);
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var connection = runtime.testing.initDirectConnection(failing.allocator(), io, receiver, role, .{ .max_message_bytes = 256 });
        defer connection.close();
        connection.permessage_deflate = true;
        connection.compression_receive_context_takeover = true;
        const payload = "TCP history TCP history TCP history \xe2\x98\x83";
        var encoder = try websocket.CompressionContext.init(allocator, 15);
        defer encoder.deinit();
        var compressed: std.ArrayList(u8) = .empty;
        defer compressed.deinit(allocator);
        var first_wire: std.ArrayList(u8) = .empty;
        defer first_wire.deinit(allocator);
        var next_wire: std.ArrayList(u8) = .empty;
        defer next_wire.deinit(allocator);
        const mask: ?[4]u8 = if (role == .server) .{ 0x11, 0x22, 0x33, 0x44 } else null;
        try websocket.writeFrameExtended(&first_wire, allocator, .text, try encoder.compressInto(&compressed, payload), .{ .rsv1 = true, .mask_key = mask });
        try websocket.writeFrameExtended(&next_wire, allocator, .text, try encoder.compressInto(&compressed, payload), .{ .rsv1 = true, .mask_key = mask });
        const split = first_wire.items.len / 2;
        try stream_io.writeAllSlices(io, sender, &.{first_wire.items[0..split]});
        var original: [256]u8 = undefined;
        var replacement: [256]u8 = undefined;
        try std.testing.expectError(error.Timeout, connection.receiveMessageIntoWithTimeout(&original, .fromMilliseconds(5)));
        try std.testing.expect(connection.message_into.active() and !connection.message_into.complete);
        try std.testing.expectError(error.BufferTooShort, connection.receiveMessageIntoWithTimeout(&replacement, .fromSeconds(1)));
        try stream_io.writeAllSlices(io, sender, &.{ first_wire.items[split..], next_wire.items });
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, connection.receiveMessageIntoWithTimeout(&original, .fromSeconds(1)));
        try std.testing.expect(connection.message_into.complete and !connection.receive_failed.load(.acquire));
        try std.testing.expectError(error.Timeout, connection.receiveMessageIntoWithDeadline(&replacement, .{ .clock = .awake, .raw = .zero }));
        try std.testing.expect(connection.message_into.complete);
        failing.fail_index = std.math.maxInt(usize);
        @memset(&original, 0xa5);
        const first = try connection.receiveMessageIntoWithTimeout(&replacement, .fromSeconds(1));
        try std.testing.expectEqualStrings(payload, first.payload);
        const next = try connection.receiveMessageIntoWithTimeout(&replacement, .fromSeconds(1));
        try std.testing.expectEqualStrings(payload, next.payload);
        try std.testing.expectEqualSlices(u8, payload ++ payload, connection.compression_receive.context.?.history.items);
    }
}

test "WebSocket caller completion recovery still closes invalid compressed messages" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const invalid_text = try websocket.compressMessage(allocator, "\xc0\x80");
    defer allocator.free(invalid_text);
    for ([_]bool{ false, true }) |bad_utf8| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        var peer = runtime.testing.initDirectConnection(allocator, io, sender, .server, .{});
        defer peer.close();
        const receiver = try listener.accept(io);
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var connection = runtime.testing.initDirectConnection(failing.allocator(), io, receiver, .client, .{ .max_message_bytes = 256 });
        defer connection.close();
        connection.permessage_deflate = true;
        connection.compression_receive_context_takeover = true;
        try connection.compression_receive.prepareContext(allocator, 256);
        try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, if (bad_utf8) invalid_text else "\xff", .{ .rsv1 = true });
        var out: [256]u8 = undefined;
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, connection.receiveMessageInto(&out));
        try std.testing.expect(connection.message_into.complete);
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expectError(if (bad_utf8) error.InvalidUtf8 else error.InvalidFrame, connection.receiveMessageIntoWithTimeout(&out, .fromSeconds(1)));
        try std.testing.expect(connection.receive_failed.load(.acquire));
        try std.testing.expect(!connection.message_into.active());
        try std.testing.expect(connection.compression_receive.context == null);
        var reply = try peer.receiveFrameWithTimeout(.fromSeconds(1));
        defer reply.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.close, reply.header.opcode);
        const close = (try websocket.parseClosePayload(reply.payload)).?;
        try std.testing.expectEqual(if (bad_utf8) websocket.CloseCode.invalid_payload_data else .protocol_error, close.code);
    }
}
