const std = @import("std");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const batch = @import("batch_trailer_sync_tests.zig");
const allocator = std.testing.allocator;

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,
    fn init(io: std.Io, limits: runtime.Limits) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{ .connection = .{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = limits }, .peer = peer };
    }
    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

const requests = [_]runtime.RequestOptions{ .{ .method = "HEAD", .authority = "localhost" }, .{ .authority = "localhost" } };

test "HTTP/2 batch forbidden trailers retain compression and sequence error classification" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(batch.Mode)) |mode| {
        for ([_]bool{ false, true }) |sequence| {
            var fixture = try Fixture.init(threaded.io(), .{});
            defer fixture.deinit();
            const connection = &fixture.connection;
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (sequence) 1 else 5, 1, if (sequence) "\x40\x01" else "\x80");
            if (sequence) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, "abcdefgh");
            var observer: batch.Observer = .{};
            try std.testing.expectError(if (sequence) error.UnexpectedFrame else error.InvalidEncoding, batch.readBatch(connection, mode, &requests, &observer, true));
            try std.testing.expect(connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
            const frame_io = @import("../frame/io.zig");
            try connection.stream.shutdown(connection.io, .send);
            var reader: frame_io.Reader = .{};
            defer reader.deinit(allocator);
            var goaways: usize = 0;
            while (true) {
                const frame = reader.read(allocator, connection.io, fixture.peer, 16_384) catch |err| switch (err) {
                    error.ConnectionClosed => break,
                    else => return err,
                };
                if (frame.frame.header.frame_type == .goaway) {
                    const goaway = try http2.GoAwayPayload.parse(frame.frame);
                    try std.testing.expectEqual(if (sequence) http2.ErrorCode.protocol_error else http2.ErrorCode.compression_error, goaway.error_code);
                    goaways += 1;
                }
            }
            if (goaways != 1) {
                std.debug.print("{s} sequence={any} emitted {d} GOAWAY frames\n", .{ @tagName(mode), sequence, goaways });
                return error.MissingConnectionErrorFrame;
            }
        }
    }
}

test "HTTP/2 batch forbidden trailers keep dynamic entries after field count and list limits" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(batch.Mode)) |mode| {
        for ([_]bool{ false, true }) |list_limit| {
            var fixture = try Fixture.init(threaded.io(), if (list_limit) .{ .max_header_list_size = 96 } else .{ .max_header_fields = 2 });
            defer fixture.deinit();
            const connection = &fixture.connection;
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
            // All three inserts must survive the complete output-limit error.
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x40\x01x\x01y\x40\x01z\x01v\x40\x01w\x01t");
            const independent = @intFromEnum(mode) >= @intFromEnum(batch.Mode.independent);
            if (independent) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88\xc0");
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 5, "\x88\xc0");
            var observer: batch.Observer = .{};
            const result = batch.readBatch(connection, mode, &requests, &observer, true);
            if (independent) {
                try result;
                try std.testing.expectEqual(@as(?anyerror, error.MessageTooLarge), observer.errors[0]);
                try std.testing.expectEqual(@as(?anyerror, null), observer.errors[1]);
                try std.testing.expectEqual([2]usize{ 1, 1 }, observer.results);
            } else try std.testing.expectError(error.MessageTooLarge, result);
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            var healthy = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
            defer healthy.deinit(allocator);
            try std.testing.expectEqualStrings("y", runtime.testing.findHeader(healthy.headers, "x").?);
        }
    }
}

test "HTTP/2 batch forbidden trailer decode allocation failure forbids reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(batch.Mode)) |mode| {
        var checked: usize = 0;
        var finished = false;
        for (0..100) |fail_index| {
            var fixture = try Fixture.init(threaded.io(), .{});
            defer fixture.deinit();
            const connection = &fixture.connection;
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x40\x01x\x01y");
            const trailer_end = connection.frame_reader.buffer.items.len;
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88\xbe");
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
            connection.allocator = failing.allocator();
            var observer: batch.Observer = .{};
            const result = batch.readBatch(connection, mode, &requests, &observer, true);
            connection.allocator = allocator;
            if (result) |_| {
                try std.testing.expectEqual(@as(?anyerror, error.InvalidContentLength), observer.errors[0]);
                finished = !failing.has_induced_failure;
            } else |err| {
                if (!failing.has_induced_failure) {
                    // Ordinary modes finish with a stream error; independent
                    // modes have no sibling fixture and time out afterward.
                    try std.testing.expect(err == error.InvalidContentLength or err == error.Timeout);
                    finished = true;
                } else if (connection.frame_reader.start == trailer_end and err == error.OutOfMemory and connection.serve_read_stream_error == null) {
                    checked += 1;
                    if (!connection.aggregate_timeout_unusable) {
                        std.debug.print("{s} allocation {d} discarded trailers without retiring reuse\n", .{ @tagName(mode), fail_index });
                        return error.LostTrailerStateRemainsReusable;
                    }
                    const cursor = connection.frame_reader.start;
                    try std.testing.expectError(error.ConnectionClosed, connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1)));
                    try std.testing.expectEqual(cursor, connection.frame_reader.start);
                }
            }
            if (finished) break;
        }
        try std.testing.expect(finished);
        try std.testing.expect(checked != 0);
    }
}
