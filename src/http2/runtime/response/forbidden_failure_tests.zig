const std = @import("std");
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
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .next_client_stream_id = 3 };
        try runtime.testing.addActiveLocalStream(&connection, 1);
        return .{ .connection = connection, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

fn consume(_: void, _: []const u8) !void {}

fn read(connection: *runtime.Connection, streaming: bool, bounded: bool) !void {
    var request = runtime.RequestWriter{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = true, .body_finished = true };
    if (streaming) {
        var response = if (bounded) try request.readResponseStreamingWithTimeout(.fromSeconds(1), {}, consume) else try request.readResponseStreaming({}, consume);
        defer response.deinit(connection.allocator);
    } else {
        var response = if (bounded) try request.readResponseWithTimeout(.fromSeconds(1)) else try request.readResponse();
        defer response.deinit(connection.allocator);
    }
}

fn appendPrefix(connection: *runtime.Connection) !void {
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x03\x00\x00\x00");
}

test "HTTP/2 forbidden response body faults preserve padding credit and terminal policy" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |streaming| {
        for ([_]bool{ false, true }) |bounded| {
            var finished = false;
            for (0..100) |fail_index| {
                var fixture = try Fixture.init(threaded.io());
                defer fixture.deinit();
                const connection = &fixture.connection;
                try appendPrefix(connection);
                // A forbidden complete field section still must be decoded.
                try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x40\x01x\x01y");
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
                connection.allocator = failing.allocator();
                const result = read(connection, streaming, bounded);
                connection.allocator = allocator;
                if (result) |_| return error.ForbiddenTrailerAccepted else |err| {
                    if (err == error.OutOfMemory) {
                        try std.testing.expect(failing.has_induced_failure);
                        try std.testing.expect(connection.aggregate_timeout_unusable);
                    } else {
                        try std.testing.expectEqual(error.InvalidContentLength, err);
                        // Reset-history OOM during semantic-error cleanup must
                        // retain the original message error and retire reuse.
                        try std.testing.expectEqual(failing.has_induced_failure, connection.aggregate_timeout_unusable);
                        finished = !failing.has_induced_failure;
                    }
                    try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
                    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
                }
                if (finished) break;
            }
            try std.testing.expect(finished);
        }
    }
}

test "HTTP/2 forbidden response body compression and continuation failures retire reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |streaming| {
        for ([_]bool{ false, true }) |fragmented| {
            var fixture = try Fixture.init(threaded.io());
            defer fixture.deinit();
            const connection = &fixture.connection;
            try appendPrefix(connection);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (fragmented) 1 else 5, 1, if (fragmented) "\x40\x01" else "\x80");
            if (fragmented) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, "abcdefgh");
            try std.testing.expectError(if (fragmented) error.UnexpectedFrame else error.InvalidEncoding, read(connection, streaming, true));
            try std.testing.expect(connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
        }
    }
}

test "HTTP/2 forbidden response body failed padding refund forbids later cleanup writes" {
    const PartialWriter = struct {
        calls: usize = 0,
        var current: ?*@This() = null;
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = current.?;
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = PartialWriter.write;
    for ([_]bool{ false, true }) |streaming| {
        for ([_]bool{ false, true }) |bounded| {
            var fixture = try Fixture.init(io);
            defer fixture.deinit();
            const connection = &fixture.connection;
            try appendPrefix(connection);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 1, "");
            var writer: PartialWriter = .{};
            PartialWriter.current = &writer;
            defer PartialWriter.current = null;
            // Deadline writes launch std.Io tasks. Preserve Threaded userdata
            // for every backend operation except the intercepted netWrite.
            connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
            const result = read(connection, streaming, bounded);
            connection.io = io;
            try std.testing.expectError(error.NetworkDown, result);
            try std.testing.expectEqual(@as(usize, 2), writer.calls);
            try std.testing.expect(connection.aggregate_timeout_unusable);
            try std.testing.expect(connection.terminal_write_failed);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
        }
    }
}
