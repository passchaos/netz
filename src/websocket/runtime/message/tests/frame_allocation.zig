const std = @import("std");
const websocket = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const h3 = @import("../../h3.zig");

const allocator = std.testing.allocator;
const Payload = enum { text, binary, compressed_text };

test "WebSocket HTTP1 frame allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = runtime.Connection{
            .allocator = allocator,
            .io = undefined,
            .stream = undefined,
            .role = role,
            .permessage_deflate = true,
        };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role);
    }
}

test "WebSocket HTTP2 frame allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = runtime.H2Connection{
            .allocator = allocator,
            .tunnel = undefined,
            .role = role,
            .permessage_deflate = true,
        };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role);
    }
}

test "WebSocket HTTP3 frame allocation failure preserves fragmented receive" {
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = h3.Connection(role){
            .allocator = allocator,
            .stream_id = 0,
            .h3 = undefined,
            .permessage_deflate = true,
        };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role);
    }
}

fn exercise(connection: anytype, role: runtime.Role) !void {
    const mask_key: ?[4]u8 = if (role == .server) .{ 0x11, 0x22, 0x33, 0x44 } else null;
    // Every frame is already buffered. A frame allocation failure must not
    // touch the underlying transport or classify these legal bytes as a peer
    // protocol error, including first, middle, and final fragment boundaries.
    inline for (.{ Payload.text, Payload.binary, Payload.compressed_text }) |kind| {
        const opcode: websocket.Opcode = if (kind == .binary) .binary else .text;
        const pieces = if (kind == .text)
            [_][]const u8{ "\xe2", "\x98", "\x83" }
        else if (kind == .compressed_text)
            // Frame consumers receive encoded bytes; RSV1 must keep these
            // fragments out of the uncompressed UTF-8 validator on retries.
            [_][]const u8{ "\xff", "\x80", "\xc0" }
        else
            [_][]const u8{ "first", "middle", "last" };
        for (pieces, 0..) |piece, index| {
            const frame_opcode: websocket.Opcode = if (index == 0) opcode else .continuation;
            try websocket.writeFrameExtended(&connection.inbuf, allocator, frame_opcode, piece, .{
                .fin = index == pieces.len - 1,
                .mask_key = mask_key,
                .rsv1 = kind == .compressed_text and index == 0,
            });
            const before_offset = connection.inbuf_consumed;
            const before_kind = connection.incoming_data_kind;
            const before_utf8 = connection.incoming_text_utf8;
            const before_validated = connection.incoming_frame_validated;
            const wire = try allocator.dupe(u8, connection.inbuf.items);
            defer allocator.free(wire);
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            connection.allocator = failing.allocator();
            defer connection.allocator = allocator;
            for (0..2) |_| {
                try std.testing.expectError(error.OutOfMemory, connection.receiveFrame());
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(before_offset, connection.inbuf_consumed);
                try std.testing.expectEqual(before_kind, connection.incoming_data_kind);
                try std.testing.expectEqualDeep(before_utf8, connection.incoming_text_utf8);
                try std.testing.expectEqual(before_validated, connection.incoming_frame_validated);
                try std.testing.expectEqualSlices(u8, wire, connection.inbuf.items);
                try std.testing.expect(!connection.close_sent.load(.acquire));
                try std.testing.expect(!connection.receive_failed.load(.acquire));
            }
            connection.allocator = allocator;
            var frame = try connection.receiveFrame();
            defer frame.deinit(allocator);
            try std.testing.expectEqual(frame_opcode, frame.header.opcode);
            try std.testing.expectEqual(index == pieces.len - 1, frame.header.fin);
            try std.testing.expectEqual(kind == .compressed_text and index == 0, frame.header.rsv1);
            try std.testing.expectEqualStrings(piece, frame.payload);
        }
        try std.testing.expectEqual(.none, connection.incoming_data_kind);
    }
    // A following independent message confirms the successful retries have
    // committed each fragment once and left the message boundary reusable.
    try websocket.writeFrameExtended(&connection.inbuf, allocator, .text, "next", .{ .mask_key = mask_key });
    var following = try connection.receiveFrame();
    defer following.deinit(allocator);
    try std.testing.expectEqualStrings("next", following.payload);
}

test "WebSocket frame allocation failure preserves a previously timed out UTF8 prefix" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const receiver = try listener.accept(io);
    var connection = runtime.testing.initDirectConnection(allocator, io, receiver, .client, .{});
    defer connection.close();

    // Reserve the body buffer so the injected failure targets only the owned
    // frame allocation after the missing socket bytes finish validation.
    try connection.inbuf.ensureTotalCapacityPrecise(allocator, 64);
    try connection.inbuf.appendSlice(allocator, &.{ 0x81, 3, 0xe2 });
    try std.testing.expectError(error.Timeout, connection.receiveFrameWithTimeout(.fromMilliseconds(10)));
    const prefix_utf8 = connection.incoming_text_utf8;
    const prefix_validated = connection.incoming_frame_validated;
    try std.testing.expectEqual(@as(u3, 2), prefix_utf8.remaining);
    try std.testing.expectEqual(@as(usize, 3), prefix_validated);

    var writer = sender.writer(io, &.{});
    try writer.interface.writeAll(&.{ 0x98, 0x83 });
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, connection.receiveFrameWithTimeout(.fromSeconds(1)));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqualDeep(prefix_utf8, connection.incoming_text_utf8);
    try std.testing.expectEqual(prefix_validated, connection.incoming_frame_validated);
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 3, 0xe2, 0x98, 0x83 }, connection.inbuf.items);
    try std.testing.expect(!connection.receive_failed.load(.acquire));

    connection.allocator = allocator;
    var frame = try connection.receiveFrameWithTimeout(.fromSeconds(1));
    defer frame.deinit(allocator);
    try std.testing.expectEqualStrings("\xe2\x98\x83", frame.payload);
    try std.testing.expectEqual(@as(usize, 0), connection.incoming_frame_validated);
    try std.testing.expectEqual(@as(u3, 0), connection.incoming_text_utf8.remaining);
}
