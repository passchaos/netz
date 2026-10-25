const std = @import("std");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const probe: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = .{ .enable_push = true } };
        errdefer connection.close();
        for ([_]u31{ 2, 4 }) |id| {
            var promise: std.ArrayList(u8) = .empty;
            defer promise.deinit(allocator);
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, id, .big);
            try promise.appendSlice(allocator, &encoded);
            try http2.Hpack.encodeLiteralBlock(&promise, allocator, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/push" }, .{ .name = ":authority", .value = "localhost" } });
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .push_promise, 4, 1, promise.items);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, id, "\x88");
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, id, if (id == 2) "ab" else "xyz");
        }
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x88");
        var parent = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
        parent.deinit(allocator);
        return .{ .connection = connection, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

const Fault = enum { none, refund, reset };

test "HTTP/2 completed push late DATA refunds only its current payload" {
    try exercise(.none, false, false);
    try exercise(.none, false, true);
}

test "HTTP/2 completed push late DATA stops writes after partial refund or reset" {
    for ([_]Fault{ .refund, .reset }) |fault| {
        for ([_]bool{ false, true }) |peer_closed| try exercise(fault, peer_closed, true);
    }
}

fn exercise(fault: Fault, peer_closed: bool, padded: bool) !void {
    const Writer = struct {
        var current: ?*@This() = null;
        fault: Fault,
        peer_closed: bool,
        writes_after_fault: usize = 0,
        bytes: std.ArrayList(u8) = .empty,

        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = current.?;
            const trigger: u8 = if (self.fault == .refund) 8 else 3;
            if (self.fault != .none and (self.writes_after_fault != 0 or (header.len >= 9 and header[3] == trigger))) {
                self.writes_after_fault += 1;
                if (self.writes_after_fault == 1) {
                    self.bytes.appendSlice(allocator, header[0..4]) catch return error.SystemResources;
                    return 4;
                }
                return if (self.peer_closed) error.SocketUnconnected else error.NetworkDown;
            }
            self.bytes.appendSlice(allocator, header) catch return error.SystemResources;
            var count = header.len;
            for (parts[0 .. parts.len - 1]) |part| {
                self.bytes.appendSlice(allocator, part) catch return error.SystemResources;
                count += part.len;
            }
            for (0..splat) |_| {
                const part = parts[parts.len - 1];
                self.bytes.appendSlice(allocator, part) catch return error.SystemResources;
                count += part.len;
            }
            return count;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var complete = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer complete.deinit(allocator);
    var sibling = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer sibling.deinit(allocator);
    const late: []const u8 = if (padded) "\x02!!\x00\x00" else "late";
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (padded) 9 else 1, 2, late);
    // A control request may already follow in the receive buffer. Its reply
    // must not extend an indeterminate refund or reset prefix.
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 0, 0, "abcdefgh");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    var writer = Writer{ .fault = fault, .peer_closed = peer_closed };
    defer writer.bytes.deinit(allocator);
    Writer.current = &writer;
    defer Writer.current = null;
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    const result = connection.pingWithTimeout(probe, .fromSeconds(1));
    connection.io = io;
    if (fault == .none) {
        _ = try result;
        try std.testing.expect(!connection.aggregate_timeout_unusable);
    } else {
        if (!peer_closed) try std.testing.expectError(error.NetworkDown, result);
        if (writer.writes_after_fault != 2) {
            std.debug.print("late DATA {s} peer_closed={any} issued {d} writes after fault\n", .{ @tagName(fault), peer_closed, writer.writes_after_fault });
            return error.CleanupContinuedAfterPartialFrame;
        }
        try std.testing.expect(connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.terminal_write_failed);
    }
    const expected = window.default_value - 5 - @as(i64, if (fault == .refund and !peer_closed) @intCast(late.len) else 0);
    try std.testing.expectEqual(expected, connection.recv_connection_window.value);
    var response = try connection.readPushedResponseWithTimeout(complete, .fromSeconds(1));
    defer response.deinit(allocator);
    var healthy = try connection.readPushedResponseWithTimeout(sibling, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("ab", response.body);
    try std.testing.expectEqualStrings("xyz", healthy.body);
    if (fault == .none) {
        var offset: usize = 0;
        var increments: usize = 0;
        var resets: usize = 0;
        while (offset < writer.bytes.items.len) {
            const frame = try http2.Frame.parse(writer.bytes.items[offset..]);
            offset += http2.FrameHeader.encoded_len + frame.payload.len;
            switch (frame.header.frame_type) {
                .window_update => {
                    const update = try http2.WindowUpdatePayload.parse(frame);
                    try std.testing.expectEqual(@as(u31, 0), update.stream_id);
                    increments += update.increment;
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(frame);
                    try std.testing.expectEqual(@as(u31, 2), reset.stream_id);
                    try std.testing.expectEqual(http2.ErrorCode.stream_closed, reset.error_code);
                    resets += 1;
                },
                else => {},
            }
        }
        try std.testing.expectEqual(late.len, increments);
        try std.testing.expectEqual(@as(usize, 1), resets);
    }
}
