const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const Reader = @import("../runtime/body_reader.zig").Reader(anyerror);
const framing = @import("../runtime/message/framing.zig");
const allocator = std.testing.allocator;

const Bodyless = struct { status: u16, method: http1.Method };
const cases = [_]Bodyless{
    .{ .status = 200, .method = .HEAD },
    .{ .status = 103, .method = .GET },
    .{ .status = 204, .method = .GET },
    .{ .status = 304, .method = .GET },
    .{ .status = 200, .method = .CONNECT },
    .{ .status = 299, .method = .CONNECT },
};
const invalid_lengths = [_][]const u8{
    "Content-Length: +5\r\n",
    "Content-Length: 184467440737095516160000\r\n",
    "Content-Length: 4, 5\r\n",
    "Content-Length: 4\r\nContent-Length: 5\r\n",
};

test "HTTP/1 bodyless response heads ignore unusable length metadata at the wire boundary" {
    for (cases) |case| {
        for (invalid_lengths) |fields| {
            const wire = try std.fmt.allocPrint(allocator, "HTTP/1.1 {d} Status\r\n{s}X-Trace: kept\r\n\r\nNEXT", .{ case.status, fields });
            defer allocator.free(wire);
            const end = std.mem.indexOf(u8, wire, "\r\n\r\n").? + 4;
            var storage: [8]http1.Header = undefined;
            const head = try http1.parseResponseHead(wire, &storage, .{}, .{ .request_method = case.method });
            try std.testing.expect(!head.body_allowed);
            try std.testing.expectEqual(http1.BodyFraming.none, head.body_framing);
            try std.testing.expectEqual(@as(?usize, null), head.content_length);
            try std.testing.expectEqual(@as(?usize, end), try head.messageLength());
            try std.testing.expectEqualStrings("kept", head.header("x-trace").?);
            var owned = try http1.parseOwnedResponseHead(allocator, wire, .{}, .{ .request_method = case.method });
            defer owned.deinit(allocator);
            try std.testing.expectEqual(@as(?usize, end), try owned.head.messageLength());
            var aggregate = try http1.parseResponseForRequest(allocator, wire, .{}, case.method);
            defer aggregate.deinit(allocator);
            try std.testing.expectEqual(end, aggregate.consumed);
            try std.testing.expectEqual(@as(usize, 0), aggregate.body.len);
        }
    }
}

test "HTTP/1 bodyless HTTP10 responses prioritize head termination over transfer coding" {
    for (cases) |case| {
        const wire = try std.fmt.allocPrint(allocator, "HTTP/1.0 {d} Status\r\nTransfer-Encoding: invalid;\r\n\r\nNEXT", .{case.status});
        defer allocator.free(wire);
        const end = std.mem.indexOf(u8, wire, "\r\n\r\n").? + 4;
        var storage: [8]http1.Header = undefined;
        const head = try http1.parseResponseHead(wire, &storage, .{}, .{ .request_method = case.method });
        try std.testing.expectEqual(@as(?usize, end), try head.messageLength());
        var aggregate = try http1.parseResponseForRequest(allocator, wire, .{}, case.method);
        defer aggregate.deinit(allocator);
        try std.testing.expectEqual(end, aggregate.consumed);
    }
}

const Source = struct {
    bytes: []const u8,
    step: usize,
    pos: usize = 0,

    fn read(context: ?*anyopaque, out: []u8) anyerror!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const count = @min(self.step, @min(out.len, self.bytes.len - self.pos));
        @memcpy(out[0..count], self.bytes[self.pos..][0..count]);
        self.pos += count;
        return count;
    }
};
const Sink = struct {
    bytes: std.ArrayList(u8) = .empty,
    status: u16 = 0,

    fn begin(self: *@This(), head: Reader.ResponseHead) anyerror!void {
        self.status = head.status;
    }
    fn consume(self: *@This(), bytes: []const u8) anyerror!void {
        try self.bytes.appendSlice(allocator, bytes);
    }
};

test "HTTP/1 streaming bodyless responses preserve the next pipeline message" {
    for (cases) |case| {
        if (case.method == .CONNECT or case.status == 103) continue;
        for (invalid_lengths) |fields| {
            for ([_]usize{ 1, 4096 }) |step| {
                const wire = try std.fmt.allocPrint(allocator, "HTTP/1.1 {d} Status\r\n{s}\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", .{ case.status, fields });
                defer allocator.free(wire);
                var source = Source{ .bytes = wire, .step = step };
                var input: std.ArrayList(u8) = .empty;
                defer input.deinit(allocator);
                var reader = Reader{ .allocator = allocator, .context = &source, .read_some = Source.read, .inbuf = &input, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 2 }, .options = .{} };
                var sink: Sink = .{};
                defer sink.bytes.deinit(allocator);
                var response = try reader.readResponse(case.method, &sink, Sink.begin, Sink.consume);
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
                try std.testing.expectEqual(@as(usize, 0), sink.bytes.items.len);
                var next = try reader.readResponse(.GET, &sink, Sink.begin, Sink.consume);
                defer next.deinit(allocator);
                try std.testing.expectEqual(@as(u16, 200), next.status);
                try std.testing.expectEqualStrings("ok", sink.bytes.items);
            }
        }
    }
}

test "HTTP/1 bodyless metadata retains valid representation lengths and strict GET framing" {
    var storage: [8]http1.Header = undefined;
    const wire = "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nNEXT";
    const head = try http1.parseResponseHead(wire, &storage, .{}, .{ .request_method = .HEAD });
    try std.testing.expectEqual(@as(?usize, 123), head.content_length);
    try std.testing.expectEqual(head.head_len, (try head.messageLength()).?);
    for (invalid_lengths, [_]anyerror{ error.InvalidContentLength, error.ContentLengthOverflow, error.ConflictingContentLength, error.ConflictingContentLength }) |fields, expected| {
        const bad = try std.fmt.allocPrint(allocator, "HTTP/1.1 200 OK\r\n{s}\r\n", .{fields});
        defer allocator.free(bad);
        try std.testing.expectError(expected, http1.parseResponseHead(bad, &storage, .{}, .{ .request_method = .GET }));
        const refused = try std.fmt.allocPrint(allocator, "HTTP/1.1 407 Refused\r\n{s}\r\n", .{fields});
        defer allocator.free(refused);
        try std.testing.expectError(expected, http1.parseResponseHead(refused, &storage, .{}, .{ .request_method = .CONNECT }));
        try std.testing.expectError(expected, framing.messageTargetLength(bad, bad.len - 4, 1024, 1024, .GET));
    }
}

test "HTTP/1 bodyless folded response length preserves owned metadata and framing" {
    const wire = "HTTP/1.1 304 Not Modified\r\nContent-Length: 4,\r\n 5\r\nX-Trace: kept\r\n\r\nNEXT";
    var head = try http1.parseOwnedResponseHead(allocator, wire, .{ .allow_obs_fold = true }, .{ .request_method = .GET });
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(?usize, null), head.head.content_length);
    try std.testing.expectEqualStrings("4, 5", head.head.header("content-length").?);
    try std.testing.expectEqual(wire.len - 4, (try head.head.messageLength()).?);
    var aggregate = try http1.parseResponseForRequest(allocator, wire, .{ .allow_obs_fold = true }, .GET);
    defer aggregate.deinit(allocator);
    try std.testing.expectEqual(wire.len - 4, aggregate.consumed);
}

test "HTTP/1 real TCP bodyless streaming response preserves pipelined reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (cases) |case| {
        if (case.method == .CONNECT or case.status == 103) continue;
        for (invalid_lengths) |fields| {
            var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
            const peer = try listener.accept(io);
            defer peer.close(io);
            var client = try runtime.Client.adoptStream(allocator, io, stream, "localhost", .{ .max_body_bytes = 2 });
            defer client.close();
            const wire = try std.fmt.allocPrint(allocator, "HTTP/1.1 {d} Status\r\n{s}\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", .{ case.status, fields });
            defer allocator.free(wire);
            var writer = peer.writer(io, &.{});
            try writer.interface.writeAll(wire);
            var sink: Sink = .{};
            defer sink.bytes.deinit(allocator);
            var response = try client.requestStreamingWithTimeout(.{ .method = case.method, .target = "/first" }, .fromSeconds(1), &sink, Sink.consume);
            defer response.deinit(allocator);
            try std.testing.expectEqual(case.status, response.status);
            try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
            try std.testing.expectEqual(@as(usize, 0), sink.bytes.items.len);
            try std.testing.expect(client.writer_state.phase == .idle);
            var next = try client.requestStreamingWithTimeout(.{ .method = .GET, .target = "/next" }, .fromSeconds(1), &sink, Sink.consume);
            defer next.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), next.status);
            try std.testing.expectEqualStrings("ok", sink.bytes.items);
            try std.testing.expect(client.isReusable());
        }
    }
}

test "HTTP/1 bodyless CONNECT leaves exact tunnel bytes with invalid framing fields" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_][]const u8{ "HTTP/1.0", "HTTP/1.1" }) |version| {
        for ([_][]const u8{
            "Content-Length: 184467440737095516160000\r\n",
            "Transfer-Encoding: invalid;\r\nContent-Length: +5\r\n",
        }) |fields| {
            var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
            const peer = try listener.accept(io);
            defer peer.close(io);
            var client = try runtime.Client.adoptStream(allocator, io, stream, "localhost", .{ .max_body_bytes = 0 });
            defer client.close();
            const wire = try std.fmt.allocPrint(allocator, "{s} 200 Connected\r\n{s}\r\nTUNNEL", .{ version, fields });
            defer allocator.free(wire);
            var writer = peer.writer(io, &.{});
            try writer.interface.writeAll(wire);
            var tunnel = try client.openConnectTunnelWithTimeout("localhost:443", &.{}, .fromSeconds(1));
            var bytes: [6]u8 = undefined;
            var received: usize = 0;
            while (received < bytes.len) {
                const count = try tunnel.readWithTimeout(bytes[received..], .fromSeconds(1));
                try std.testing.expect(count != 0);
                received += count;
            }
            try std.testing.expectEqualStrings("TUNNEL", &bytes);
            try std.testing.expect(!client.isReusable());
        }
    }
}
