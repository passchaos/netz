const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .next_client_stream_id = 5 };
        try runtime.testing.addActiveLocalStream(&connection, 1);
        return .{ .connection = connection, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

const Observer = struct {
    reject_head: bool,
    fn head(self: *@This(), _: runtime.StreamingResponseHead) !void {
        if (self.reject_head) return error.OutOfMemory;
    }
    fn data(_: *@This(), _: []const u8) !void {
        return error.OutOfMemory;
    }
};

const PartialWriter = struct {
    calls: usize = 0,
    fn write(context: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.calls == 1) return @min(header.len, 4);
        return error.NetworkDown;
    }
};

fn appendHead(connection: *runtime.Connection, id: u31, ended: bool) !void {
    // Indexed :status 200 is valid in the static HPACK table.
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (ended) 5 else 4, id, &.{0x88});
}

test "HTTP/2 response callback OutOfMemory remains stream local at head DATA and FIN" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |bounded| {
        for (0..3) |callback| {
            var fixture = try Fixture.init(threaded.io());
            defer fixture.deinit();
            const connection = &fixture.connection;
            try appendHead(connection, 1, false);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (callback == 2) 0x09 else 0x08, 1, "\x02ab\x00\x00");
            if (callback != 2) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 1, "cd");
            try appendHead(connection, 3, true);
            var observer = Observer{ .reject_head = callback == 0 };
            var request = runtime.RequestWriter{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = false, .body_finished = true };
            const result = if (bounded) request.readResponseStreamingWithHeadAndTimeout(.fromSeconds(1), &observer, Observer.head, Observer.data) else request.readResponseStreamingWithHead(&observer, Observer.head, Observer.data);
            try std.testing.expectError(error.OutOfMemory, result);
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
            try runtime.testing.addActiveLocalStream(connection, 3);
            var healthy = try connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1));
            defer healthy.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), healthy.status);
            try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
        }
    }
}

test "HTTP/2 response callback cleanup failure never writes after a partial refund or reset" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = PartialWriter.write;
    for ([_]bool{ false, true }) |bounded| {
        for ([_]bool{ false, true }) |reject_head| {
            var fixture = try Fixture.init(io);
            defer fixture.deinit();
            const connection = &fixture.connection;
            try appendHead(connection, 1, false);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0x08, 1, "\x02ab\x00\x00");
            var writer: PartialWriter = .{};
            var observer = Observer{ .reject_head = reject_head };
            connection.io = .{ .userdata = &writer, .vtable = &vtable };
            var request = runtime.RequestWriter{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = false, .body_finished = true };
            const result = if (bounded) request.readResponseStreamingWithHeadAndTimeout(.fromSeconds(1), &observer, Observer.head, Observer.data) else request.readResponseStreamingWithHead(&observer, Observer.head, Observer.data);
            connection.io = io;
            try std.testing.expectError(error.OutOfMemory, result);
            try std.testing.expectEqual(@as(usize, 2), writer.calls);
            try std.testing.expect(connection.aggregate_timeout_unusable);
            try std.testing.expect(connection.terminal_write_failed);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
        }
    }
}

test "HTTP/2 response allocation cleanup never writes after a partial credit refund" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = PartialWriter.write;
    var exercised_refund = false;
    for (0..100) |fail_index| {
        var fixture = try Fixture.init(io);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendHead(connection, 1, false);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0x08, 1, "\x02ab\x00\x00");
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "a" ** 255);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x00\x01x\x01y");
        var writer: PartialWriter = .{};
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
        connection.allocator = failing.allocator();
        connection.io = .{ .userdata = &writer, .vtable = &vtable };
        const result = connection.readResponseWithTimeout(1, "POST", false, .fromSeconds(1));
        connection.allocator = allocator;
        connection.io = io;
        if (result) |value| {
            var response = value;
            response.deinit(allocator);
            break;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 2), writer.calls);
            try std.testing.expect(connection.terminal_write_failed);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
            if (connection.recv_connection_window.value != window.default_value) exercised_refund = true;
        }
    }
    try std.testing.expect(exercised_refund);
}
