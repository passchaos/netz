//! Streaming metadata and connection ownership use the same HTTP boundaries.
const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "HTTP/1 streaming response persistence metadata follows framing and method" {
    const Reader = @import("body_reader.zig").Reader(runtime.Error);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,
        split: usize,

        fn readSome(context: ?*anyopaque, destination: []u8) runtime.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(self.split, @min(destination.len, self.bytes.len - self.offset));
            @memcpy(destination[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        expected_reuse: bool,
        expected_close: bool,
        body: std.ArrayList(u8) = .empty,
        heads: usize = 0,

        fn begin(self: *@This(), head: Reader.ResponseHead) !void {
            try std.testing.expectEqual(self.expected_reuse, head.keepAlive());
            try std.testing.expectEqual(self.expected_close, head.must_close);
            self.heads += 1;
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };
    const cases = [_]struct { bytes: []const u8, method: http1.Method = .GET, reusable: bool, close: bool, body: []const u8 = "" }{
        .{ .bytes = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\npayload", .reusable = false, .close = true, .body = "payload" },
        .{ .bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\npayload", .reusable = false, .close = true, .body = "payload" },
        .{ .bytes = "HTTP/1.1 200 OK\r\n\r\n", .method = .HEAD, .reusable = true, .close = false },
        .{ .bytes = "HTTP/1.1 200 Connected\r\n\r\n", .method = .CONNECT, .reusable = false, .close = true },
        .{ .bytes = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade, keep-alive\r\nUpgrade: netz-test\r\n\r\n", .reusable = false, .close = true },
        .{ .bytes = "HTTP/1.1 204 No Content\r\n\r\n", .reusable = true, .close = false },
        .{ .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload", .reusable = true, .close = false, .body = "payload" },
    };
    for (cases) |case| {
        for ([_]bool{ false, true }) |owned_head| {
            for ([_]usize{ 3, 4096 }) |split| {
                var buffer: std.ArrayList(u8) = .empty;
                defer buffer.deinit(std.testing.allocator);
                var source = Source{ .bytes = case.bytes, .split = split };
                var reader = Reader{ .allocator = std.testing.allocator, .context = &source, .read_some = Source.readSome, .inbuf = &buffer, .limits = .{ .max_head_bytes = 4096, .max_body_bytes = 4096 }, .options = .{ .allow_obs_fold = owned_head } };
                var context = Context{ .expected_reuse = case.reusable, .expected_close = case.close };
                defer context.body.deinit(std.testing.allocator);
                var response = try reader.readResponse(case.method, &context, Context.begin, Context.consume);
                defer response.deinit(std.testing.allocator);
                try std.testing.expectEqual(@as(usize, 1), context.heads);
                try std.testing.expectEqual(case.reusable, response.keepAlive());
                try std.testing.expectEqual(case.close, response.must_close);
                try std.testing.expectEqualStrings(case.body, context.body.items);
            }
        }
    }
}

test "HTTP/1 EOF response keeps public metadata aligned with aggregate and streaming clients" {
    for ([_]bool{ false, true }) |streaming| {
        const allocator = std.testing.allocator;
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        defer server.deinit();
        const Peer = struct {
            server: *runtime.Server,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.serve() catch |err| {
                    self.err = err;
                };
            }

            fn serve(self: *@This()) !void {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try @import("../../internal/stream_io.zig").writeAllSlices(self.server.io, connection.stream, &.{"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\npayload"});
            }
        };
        var peer = Peer{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        var client = try runtime.Client.connect(allocator, io, server.address(), .{});
        defer client.close();
        if (streaming) {
            const Sink = struct {
                body: std.ArrayList(u8) = .empty,
                fn consume(self: *@This(), bytes: []const u8) !void {
                    try self.body.appendSlice(std.testing.allocator, bytes);
                }
            };
            var sink: Sink = .{};
            defer sink.body.deinit(allocator);
            var response = try client.requestStreamingWithTimeout(.{ .host = "localhost" }, .fromSeconds(2), &sink, Sink.consume);
            defer response.deinit(allocator);
            try std.testing.expect(!response.keepAlive());
            try std.testing.expect(response.must_close);
            try std.testing.expectEqualStrings("payload", sink.body.items);
        } else {
            var response = try client.requestWithTimeout(.{ .host = "localhost" }, .fromSeconds(2));
            defer response.deinit(allocator);
            try std.testing.expect(!response.response.keepAlive());
            try std.testing.expect(response.response.must_close);
            try std.testing.expectEqualStrings("payload", response.response.body);
        }
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(error.ConnectionUnusable, client.requestWithTimeout(.{ .host = "localhost" }, .fromSeconds(2)));
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
    }
}
