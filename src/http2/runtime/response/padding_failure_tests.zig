const std = @import("std");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

const Mode = enum { aggregate, streaming, batch, batch_streaming, duplex };
fn consume(_: void, _: []const u8) !void {}
fn consumeBatch(_: void, _: usize, _: []const u8) !void {}

test "HTTP/2 padding refund partial write stops cleanup and later connection use" {
    const PartialWriter = struct {
        var current: ?*@This() = null;
        calls: usize = 0,
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = current.?;
            if (self.calls != 0 or (header.len >= 9 and header[3] == 8)) {
                self.calls += 1;
                if (self.calls == 1) return 4;
                return error.NetworkDown;
            }
            var count = header.len;
            for (parts[0 .. parts.len - 1]) |part| count += part.len;
            count += parts[parts.len - 1].len * splat;
            return count;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = PartialWriter.write;
    for (std.enums.values(Mode)) |mode| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        const peer = try listener.accept(io);
        defer peer.close(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client };
        defer {
            connection.io = io;
            connection.close();
        }
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, "\x88");
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 1, "\x02ab\x00\x00");
        var writer: PartialWriter = .{};
        PartialWriter.current = &writer;
        defer PartialWriter.current = null;
        connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
        const options = runtime.RequestOptions{ .authority = "localhost" };
        switch (mode) {
            .aggregate => try std.testing.expectError(error.NetworkDown, connection.requestWithTimeout(options, .fromSeconds(1))),
            .streaming => try std.testing.expectError(error.NetworkDown, connection.requestStreamingWithTimeout(options, .fromSeconds(1), {}, consume)),
            .batch => {
                var responses: [1]runtime.OwnedResponse = undefined;
                try std.testing.expectError(error.NetworkDown, connection.requestBatchIntoWithTimeout(&.{options}, &responses, .fromSeconds(1)));
            },
            .batch_streaming => {
                var responses: [1]runtime.StreamingResponse = undefined;
                try std.testing.expectError(error.NetworkDown, connection.requestBatchStreamingIntoWithTimeout(&.{options}, &responses, .fromSeconds(1), {}, consumeBatch));
            },
            .duplex => {
                var request = try connection.startRequest(.{ .authority = "localhost" });
                defer request.deinit();
                try request.finish();
                var duplex = try request.beginDuplex();
                defer duplex.deinit();
                var head = try duplex.readResponseEventWithTimeout(.fromSeconds(1));
                defer head.deinit(allocator);
                try std.testing.expectError(error.NetworkDown, duplex.readResponseEventWithTimeout(.fromSeconds(1)));
            },
        }
        try std.testing.expectEqual(@as(usize, 2), writer.calls);
        try std.testing.expect(connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.terminal_write_failed);
        try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
        try std.testing.expectError(error.ConnectionClosed, connection.requestWithTimeout(options, .fromSeconds(1)));
        try std.testing.expectEqual(@as(usize, 2), writer.calls);
    }
}
