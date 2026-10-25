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
            var id_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &id_bytes, id, .big);
            try promise.appendSlice(allocator, &id_bytes);
            try http2.Hpack.encodeLiteralBlock(&promise, allocator, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/push" }, .{ .name = ":authority", .value = "localhost" } });
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .push_promise, 4, 1, promise.items);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, id, "\x88");
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (id == 4) 1 else 0, id, if (id == 4) "xyz" else "ab");
        }
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x88");
        var parent = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
        parent.deinit(allocator);
        return .{ .connection = connection, .peer = peer };
    }
    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

test "HTTP/2 push cancel allocation failure preserves promise and unreturned DATA" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    const connection = &fixture.connection;
    var promise = connection.takePromisedRequest() orelse return error.MissingPromise;
    var owned = true;
    defer if (owned) promise.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, connection.cancelPush(&promise));
    connection.allocator = allocator;
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.push_state.isRemoteReserved(2));
    try std.testing.expectEqual(@as(usize, 2), connection.push_state.state.?.received.get(2).?.unreleased_connection_bytes);
    try std.testing.expectEqual(window.default_value - 5, connection.recv_connection_window.value);
    try connection.cancelPush(&promise);
    owned = false;
    try std.testing.expectEqual(window.default_value - 3, connection.recv_connection_window.value);
}

test "HTTP/2 push failed refund or reset stops cleanup while finished sibling remains readable" {
    const Writer = struct {
        var current: ?*@This() = null;
        reset_failure: bool,
        calls: usize = 0,
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = current.?;
            if (self.calls != 0 or (header.len >= 9 and header[3] == @as(u8, if (self.reset_failure) 3 else 8))) {
                self.calls += 1;
                if (self.calls == 1) return 4;
                return error.NetworkDown;
            }
            var count = header.len;
            for (parts[0 .. parts.len - 1]) |part| count += part.len;
            return count + parts[parts.len - 1].len * splat;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    for ([_]bool{ false, true }) |reset_failure| {
        for ([_]bool{ false, true }) |peer_reset| {
            var fixture = try Fixture.init(io);
            defer fixture.deinit();
            const connection = &fixture.connection;
            var promise = connection.takePromisedRequest() orelse return error.MissingPromise;
            defer promise.deinit(allocator);
            var sibling = connection.takePromisedRequest() orelse return error.MissingPromise;
            defer sibling.deinit(allocator);
            if (peer_reset) {
                if (reset_failure) continue; // Peer RST needs a refund but no reset reply.
                try wire.appendFrame(&connection.frame_reader.buffer, allocator, .rst_stream, 0, 2, &.{ 0, 0, 0, 8 });
            } else try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 2, "\x88"); // Invalid trailer pseudo-header.
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
            var writer = Writer{ .reset_failure = reset_failure };
            Writer.current = &writer;
            defer Writer.current = null;
            connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
            const result = connection.pingWithTimeout(probe, .fromSeconds(1));
            connection.io = io;
            try std.testing.expectError(error.NetworkDown, result);
            try std.testing.expectEqual(@as(usize, 2), writer.calls);
            try std.testing.expect(connection.aggregate_timeout_unusable);
            try std.testing.expect(connection.terminal_write_failed);
            try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
            var healthy = try connection.readPushedResponseWithTimeout(sibling, .fromSeconds(1));
            defer healthy.deinit(allocator);
            try std.testing.expectEqualStrings("xyz", healthy.body);
            try std.testing.expectError(error.ConnectionClosed, connection.pingWithTimeout(probe, .fromSeconds(1)));
            try std.testing.expectEqual(@as(usize, 2), writer.calls);
        }
    }
}

test "HTTP/2 late push headers and reset preserve completed response credit" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    const connection = &fixture.connection;
    var failed = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer failed.deinit(allocator);
    var complete = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer complete.deinit(allocator);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 4, "\x40\x01x\x01y");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .rst_stream, 0, 4, &.{ 0, 0, 0, 8 });
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    _ = try connection.pingWithTimeout(probe, .fromSeconds(1));
    try std.testing.expectEqual(window.default_value - 5, connection.recv_connection_window.value);
    var healthy = try connection.readPushedResponseWithTimeout(complete, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("xyz", healthy.body);
}

test "HTTP/2 push cancellation after peer close never writes reset after failed refund" {
    const ClosedWriter = struct {
        var current: ?*@This() = null;
        calls: usize = 0,
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            current.?.calls += 1;
            return error.SocketUnconnected;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var promise = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer promise.deinit(allocator);
    var sibling = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer sibling.deinit(allocator);
    var writer: ClosedWriter = .{};
    ClosedWriter.current = &writer;
    defer ClosedWriter.current = null;
    var vtable = io.vtable.*;
    vtable.netWrite = ClosedWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    const result = connection.cancelPush(&promise);
    connection.io = io;
    try std.testing.expectError(error.ConnectionClosed, result);
    try std.testing.expectEqual(@as(usize, 1), writer.calls);
    try std.testing.expect(connection.terminal_write_failed);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(window.default_value - 3, connection.recv_connection_window.value);
    try std.testing.expect(!runtime.testing.hasActivePeerStream(connection, 2));
    try std.testing.expect(!runtime.testing.hasStreamWindow(connection, 2));
    var healthy = try connection.readPushedResponseWithTimeout(sibling, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("xyz", healthy.body);
    try std.testing.expectEqual(@as(usize, 1), writer.calls);
}
