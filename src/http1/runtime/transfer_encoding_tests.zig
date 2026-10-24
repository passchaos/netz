const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const net = std.Io.net;

const quoted_coding = "custom; note=\"a,chunked,z\"; escape=\"x\\\",chunked,y\", chunked";

const Pair = struct {
    client: runtime.Client,
    peer: runtime.Connection,

    fn init(io: std.Io) !Pair {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .io = io, .stream = stream, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 1024 } },
            .peer = .{ .allocator = std.testing.allocator, .io = io, .stream = peer, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 1024 } },
        };
    }

    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }
};

const Sink = struct {
    bytes: std.ArrayList(u8) = .empty,

    fn consume(self: *@This(), bytes: []const u8) !void {
        try self.bytes.appendSlice(std.testing.allocator, bytes);
    }
};

test "HTTP/1 transfer parameters preserve response boundaries and persistent reuse" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |streaming| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var writer = pair.peer.stream.writer(threaded.io(), &.{});
        try writer.interface.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: " ++ quoted_coding ++ "\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
        const request: runtime.RequestOptions = .{ .method = .GET, .target = "/first", .host = "example" };
        if (streaming) {
            var sink: Sink = .{};
            defer sink.bytes.deinit(std.testing.allocator);
            var response = try pair.client.requestStreamingWithTimeout(request, .fromSeconds(1), &sink, Sink.consume);
            defer response.deinit(std.testing.allocator);
            try std.testing.expectEqual(http1.BodyFraming.chunked, response.body_framing);
            try std.testing.expectEqualStrings("ok", sink.bytes.items);
        } else {
            var response = try pair.client.requestWithTimeout(request, .fromSeconds(1));
            defer response.deinit(std.testing.allocator);
            try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
            try std.testing.expectEqualStrings("ok", response.response.body);
        }
        var following = try pair.client.requestWithTimeout(.{ .method = .GET, .target = "/next", .host = "example" }, .fromSeconds(1));
        defer following.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("next", following.response.body);
    }
}

test "HTTP/1 transfer parameters fail before waiting for response EOF" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_][]const u8{ "chunked; x=yes", "custom; note=\"unterminated" }) |value| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var bytes: [256]u8 = undefined;
        var writer = pair.peer.stream.writer(threaded.io(), &.{});
        try writer.interface.writeAll(try std.fmt.bufPrint(&bytes, "HTTP/1.1 200 OK\r\nTransfer-Encoding: {s}\r\n\r\n", .{value}));
        try std.testing.expectError(error.InvalidTransferEncoding, pair.client.requestWithTimeout(.{ .method = .GET, .target = "/invalid", .host = "example" }, .fromMilliseconds(50)));
        try std.testing.expectError(error.ConnectionUnusable, pair.client.request(.{ .method = .GET, .target = "/next", .host = "example" }));
    }
}

test "HTTP/1 transfer parameters preserve unbuffered response boundaries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pair = try Pair.init(io);
    defer pair.deinit();
    var writer = pair.peer.stream.writer(io, &.{});
    try writer.interface.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: " ++ quoted_coding ++ "\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
    var first = try runtime.readResponseFromStreamForRequestWithTimeout(std.testing.allocator, io, pair.client.stream, .{}, .{}, .GET, .fromSeconds(1));
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ok", first.response.body);
    var second = try runtime.readResponseFromStreamForRequestWithTimeout(std.testing.allocator, io, pair.client.stream, .{}, .{}, .GET, .fromSeconds(1));
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("next", second.response.body);
}

test "HTTP/1 transfer parameters preserve pipelined aggregate streaming and batch requests" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Mode = enum { aggregate, streaming, batch };
    for (std.enums.values(Mode)) |mode| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var writer = pair.client.stream.writer(threaded.io(), &.{});
        try writer.interface.writeAll("POST /first HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: " ++ quoted_coding ++ "\r\n\r\n2\r\nok\r\n0\r\nDigest: yes\r\n\r\nGET /next HTTP/1.1\r\nHost: example\r\n\r\n");
        switch (mode) {
            .aggregate => {
                var request = try pair.peer.readRequestWithTimeout(.{}, .fromSeconds(1));
                defer request.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", request.request.body);
                try std.testing.expectEqual(@as(usize, 1), request.request.trailers.len);
            },
            .streaming => {
                var sink: Sink = .{};
                defer sink.bytes.deinit(std.testing.allocator);
                var request = try pair.peer.readRequestStreaming(&sink, Sink.consume);
                defer request.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", sink.bytes.items);
                try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            },
            .batch => {
                var heads: [2]http1.RequestHead = undefined;
                var fields: [16]http1.Header = undefined;
                var bodies: [2][]const u8 = undefined;
                _ = try pair.peer.readRequestBatchInto(&heads, &fields, &bodies, .{ .max_headers = 8 });
                try std.testing.expectEqualStrings("/first", heads[0].target);
                try std.testing.expectEqualStrings("ok", bodies[0]);
                try std.testing.expectEqualStrings("/next", heads[1].target);
                try std.testing.expectEqualStrings("", bodies[1]);
                return;
            },
        }
        var following = try pair.peer.readRequestWithTimeout(.{}, .fromSeconds(1));
        defer following.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("/next", following.request.target);
    }
}
