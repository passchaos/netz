const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const net = std.Io.net;

const Shape = enum { spaced_length, spaced_transfer, folded, folded_length, folded_transfer, ignored_transfer };

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
            .client = .{ .allocator = std.testing.allocator, .io = io, .stream = stream, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 } },
            .peer = .{ .allocator = std.testing.allocator, .io = io, .stream = peer, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 16 } },
        };
    }

    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }
};

const Sink = struct {
    buffer: [16]u8 = undefined,
    len: usize = 0,

    fn consume(self: *@This(), bytes: []const u8) !void {
        if (bytes.len > self.buffer.len - self.len) return error.BodyTooLarge;
        @memcpy(self.buffer[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

fn response(shape: Shape) []const u8 {
    return switch (shape) {
        .spaced_length => "HTTP/1.1 200 OK\r\nContent-Length \t: 2\r\n\r\nok",
        .spaced_transfer => "HTTP/1.1 200 OK\r\nTransfer-Encoding \t: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        .folded => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Trace: first\r\n second\r\n\r\nok",
        .folded_length => "HTTP/1.1 200 OK\r\nContent-Length: 2,\r\n 2\r\n\r\nok",
        .folded_transfer => "HTTP/1.1 200 OK\r\nTransfer-Encoding: custom; note=\"first,\r\n chunked,last\",\r\n chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        .ignored_transfer => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: invalid\x01\r\n\r\nok",
    };
}

test "HTTP/1 compatible response heads preserve body boundaries and connection reuse" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Shape)) |shape| {
        for ([_]bool{ false, true }) |streaming| {
            var pair = try Pair.init(threaded.io());
            defer pair.deinit();
            var writer = pair.peer.stream.writer(threaded.io(), &.{});
            try writer.interface.writeAll(response(shape));
            try writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
            const options: http1.ParseOptions = .{ .allow_obs_fold = true, .allow_spaces_after_header_name_in_responses = true, .ignore_invalid_headers_in_responses = true };
            const request: runtime.RequestOptions = .{ .method = .GET, .target = "/first", .host = "example" };
            if (streaming) {
                var sink: Sink = .{};
                var received = try pair.client.requestStreamingWithParseOptionsAndTimeout(request, options, .fromSeconds(1), &sink, Sink.consume);
                defer received.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", sink.buffer[0..sink.len]);
                try expectFollowing(&pair.client);
                if (shape == .folded) try std.testing.expectEqualStrings("first second", received.header("x-trace").?);
            } else {
                var received = try pair.client.requestWithParseOptionsAndTimeout(request, options, .fromSeconds(1));
                defer received.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("ok", received.response.body);
                try expectFollowing(&pair.client);
                if (shape == .folded) try std.testing.expectEqualStrings("first second", received.response.header("x-trace").?);
            }
        }
    }
}

test "HTTP/1 compatible unbuffered response heads retain the next response" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Shape)) |shape| {
        var pair = try Pair.init(io);
        defer pair.deinit();
        var writer = pair.peer.stream.writer(io, &.{});
        try writer.interface.writeAll(response(shape));
        try writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
        const options: http1.ParseOptions = .{ .allow_obs_fold = true, .allow_spaces_after_header_name_in_responses = true, .ignore_invalid_headers_in_responses = true };
        var received = try runtime.readResponseFromStreamForRequestWithTimeout(std.testing.allocator, io, pair.client.stream, .{}, options, .GET, .fromSeconds(1));
        defer received.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("ok", received.response.body);
        var following = try runtime.readResponseFromStreamForRequestWithTimeout(std.testing.allocator, io, pair.client.stream, .{}, .{}, .GET, .fromSeconds(1));
        defer following.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("next", following.response.body);
    }
}

fn expectFollowing(client: *runtime.Client) !void {
    var following = try client.requestWithTimeout(.{ .method = .GET, .target = "/next", .host = "example" }, .fromSeconds(1));
    defer following.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("next", following.response.body);
}

test "HTTP/1 compatible heads retain strict default and borrowed parser policies" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Shape)) |shape| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var writer = pair.peer.stream.writer(threaded.io(), &.{});
        try writer.interface.writeAll(response(shape));
        const result = pair.client.requestWithTimeout(.{ .method = .GET, .target = "/strict", .host = "example" }, .fromSeconds(1));
        try std.testing.expectError(error.MalformedHeader, result);
        try std.testing.expectError(error.ConnectionUnusable, pair.client.request(.{ .method = .GET, .target = "/after", .host = "example" }));
    }
    var headers: [4]http1.Header = undefined;
    try std.testing.expectError(error.MalformedHeader, http1.parseResponseHead(response(.folded), &headers, .{ .allow_obs_fold = true }, .{}));
}

test "HTTP/1 compatible owning request readers unfold fields and preserve pipelined requests" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Mode = enum { aggregate, streaming, unbuffered };
    for (std.enums.values(Mode)) |mode| {
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var writer = pair.client.stream.writer(threaded.io(), &.{});
        try writer.interface.writeAll("POST /first HTTP/1.1\r\nHost: example\r\nContent-Length: 2,\r\n 2\r\nX-Trace: first\r\n second\r\n\r\nokGET /next HTTP/1.1\r\nHost: example\r\n\r\n");
        const options: http1.ParseOptions = .{ .allow_obs_fold = true };
        if (mode == .streaming) {
            var sink: Sink = .{};
            var received = try pair.peer.readRequestStreamingWithOptions(options, &sink, Sink.consume);
            defer received.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("ok", sink.buffer[0..sink.len]);
            var next = try pair.peer.readRequestWithTimeout(.{}, .fromSeconds(1));
            defer next.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("/next", next.request.target);
            try std.testing.expectEqualStrings("first second", received.header("x-trace").?);
        } else {
            var received = if (mode == .unbuffered)
                try runtime.readRequestFromStreamWithTimeout(std.testing.allocator, threaded.io(), pair.peer.stream, .{}, options, .fromSeconds(1))
            else
                try pair.peer.readRequestWithTimeout(options, .fromSeconds(1));
            defer received.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("ok", received.request.body);
            var next = try pair.peer.readRequestWithTimeout(.{}, .fromSeconds(1));
            defer next.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("/next", next.request.target);
            try std.testing.expectEqualStrings("first second", received.request.header("x-trace").?);
        }
    }
}

test "HTTP/1 compatible streaming response releases unfolded values on consumer failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    var writer = pair.peer.stream.writer(threaded.io(), &.{});
    try writer.interface.writeAll(response(.folded));
    const Consumer = struct {
        fn consume(_: *@This(), _: []const u8) error{ConsumerFailed}!void {
            return error.ConsumerFailed;
        }
    };
    var consumer: Consumer = .{};
    try std.testing.expectError(error.ConsumerFailed, pair.client.requestStreamingWithParseOptionsAndTimeout(.{ .method = .GET, .target = "/failed", .host = "example" }, .{ .allow_obs_fold = true }, .fromSeconds(1), &consumer, Consumer.consume));
    try std.testing.expectError(error.ConnectionUnusable, pair.client.request(.{ .method = .GET, .target = "/after", .host = "example" }));
}
