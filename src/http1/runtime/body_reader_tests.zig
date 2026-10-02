const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 2 * 1024 * 1024,
};

fn writeAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

test "HTTP/0.9 streaming response is opt in and body bounded" {
    const allocator = std.testing.allocator;
    const BodyReader = @import("body_reader.zig");
    const TestError = http1.Error || std.mem.Allocator.Error || error{
        BodyTooLarge,
        ConnectionClosed,
        HeadersTooLarge,
    };
    const Reader = BodyReader.Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(context: ?*anyopaque, destination: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(destination.len, self.bytes.len - self.offset);
            @memcpy(destination[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        body: std.ArrayList(u8) = .empty,

        fn begin(_: *@This(), head: Reader.ResponseHead) !void {
            try std.testing.expectEqual(http1.Version.http_0_9, head.version);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqual(http1.BodyFraming.close_delimited, head.body_framing);
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var source = Source{ .bytes = "legacy" };
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{ .max_head_bytes = 64, .max_body_bytes = 6 },
        .options = .{ .allow_http_0_9_responses = true },
    };
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var response = try reader.readResponse(.GET, &context, Context.begin, Context.consume);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("legacy", context.body.items);
    try std.testing.expectEqual(@as(usize, 6), response.body_bytes);

    var over_inbuf: std.ArrayList(u8) = .empty;
    defer over_inbuf.deinit(allocator);
    var over_source = Source{ .bytes = "legacy!" };
    var over_reader = Reader{
        .allocator = allocator,
        .context = &over_source,
        .read_some = Source.readSome,
        .inbuf = &over_inbuf,
        .limits = .{ .max_head_bytes = 64, .max_body_bytes = 6 },
        .options = .{ .allow_http_0_9_responses = true },
    };
    var over_context: Context = .{};
    defer over_context.body.deinit(allocator);
    try std.testing.expectError(
        error.BodyTooLarge,
        over_reader.readResponse(.GET, &over_context, Context.begin, Context.consume),
    );
}

test "HTTP/0.9 streaming response frees metadata when begin rejects it" {
    const allocator = std.testing.allocator;
    const BodyReader = @import("body_reader.zig");
    const TestError = http1.Error || std.mem.Allocator.Error || error{
        BodyTooLarge,
        ConnectionClosed,
        HeadersTooLarge,
        StopResponse,
    };
    const Reader = BodyReader.Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,
        fn readSome(context: ?*anyopaque, destination: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(destination.len, self.bytes.len - self.offset);
            @memcpy(destination[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        fn begin(_: *@This(), _: Reader.ResponseHead) !void {
            return error.StopResponse;
        }
        fn consume(_: *@This(), _: []const u8) !void {}
    };
    var source = Source{ .bytes = "legacy" };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{ .max_head_bytes = 64, .max_body_bytes = 6 },
        .options = .{ .allow_http_0_9_responses = true },
    };
    var context = Context{};
    try std.testing.expectError(
        error.StopResponse,
        reader.readResponse(.GET, &context, Context.begin, Context.consume),
    );
}

test "HTTP/1 chunked reader batches transport reads across chunk boundaries" {
    const allocator = std.testing.allocator;
    const body_reader = @import("body_reader.zig");
    const chunk_bytes = 16 * 1024;
    const head =
        "POST /batch HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    const pipeline =
        "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const TestError = http1.Error || std.mem.Allocator.Error || error{
        BodyTooLarge,
        ConnectionClosed,
        HeadersTooLarge,
    };
    const Reader = body_reader.Reader(TestError);
    const raw =
        head ++
        "4000\r\n" ++ ("a" ** chunk_bytes) ++ "\r\n" ++
        "4000\r\n" ++ ("b" ** chunk_bytes) ++ "\r\n" ++
        "4000\r\n" ++ ("c" ** chunk_bytes) ++ "\r\n" ++
        "0\r\n\r\n" ++
        pipeline;
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,
        reads: usize = 0,

        fn readSome(
            context: ?*anyopaque,
            destination: []u8,
        ) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.reads += 1;
            if (self.offset == self.bytes.len) return 0;
            var count = @min(
                destination.len,
                self.bytes.len - self.offset,
            );
            // Keep the first transport completion at the head boundary. The
            // next 16-KiB size-buffer read ends in the second payload, forcing
            // the optimized path to perform one larger cross-chunk read-ahead.
            if (self.reads == 1) count = @min(count, head.len);
            @memcpy(
                destination[0..count],
                self.bytes[self.offset..][0..count],
            );
            self.offset += count;
            return count;
        }
    };
    var source = Source{ .bytes = raw };
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{},
    };
    const Context = struct {
        chunk_index: usize = 0,
        remaining: usize = chunk_bytes,

        fn consume(self: *@This(), bytes: []const u8) !void {
            const expected_byte: u8 = switch (self.chunk_index) {
                0 => 'a',
                1 => 'b',
                2 => 'c',
                else => return error.UnexpectedChunk,
            };
            try std.testing.expect(bytes.len <= self.remaining);
            for (bytes) |byte| {
                try std.testing.expectEqual(expected_byte, byte);
            }
            self.remaining -= bytes.len;
            if (self.remaining == 0) {
                self.chunk_index += 1;
                self.remaining = chunk_bytes;
            }
        }
    };
    var context: Context = .{};
    var request = try reader.readRequest(
        &context,
        struct {
            fn begin(_: *Context, _: Reader.RequestHead) !void {}
        }.begin,
        Context.consume,
    );
    defer request.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), source.reads);
    try std.testing.expectEqual(@as(usize, 3), context.chunk_index);
    try std.testing.expectEqual(
        @as(usize, chunk_bytes * 3),
        request.body_bytes,
    );
    try std.testing.expectEqualStrings(
        pipeline,
        inbuf.items,
    );
}

test "HTTP/1 streaming chunked reader bounds a complete size line" {
    const allocator = std.testing.allocator;
    const BodyReader = @import("body_reader.zig");
    const TestError = http1.Error || std.mem.Allocator.Error || error{
        BodyTooLarge,
        ConnectionClosed,
        HeadersTooLarge,
    };
    const Reader = BodyReader.Reader(TestError);
    const head =
        "POST /bounded HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try raw.appendSlice(allocator, head ++ "1");
    try raw.appendNTimes(
        allocator,
        ' ',
        http1.max_chunk_size_line_bytes - 1,
    );
    try raw.appendSlice(allocator, "\r\nx\r\n0\r\n\r\n");

    const Source = struct {
        fn readSome(
            _: ?*anyopaque,
            _: []u8,
        ) TestError!usize {
            return 0;
        }
    };
    const Context = struct {
        fn begin(_: *@This(), _: Reader.RequestHead) !void {}
        fn consume(_: *@This(), _: []const u8) !void {}
    };
    var source = Source{};
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(allocator, raw.items);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 1 },
        .options = .{},
    };
    var context = Context{};
    try std.testing.expectError(
        error.ChunkExtensionTooLarge,
        reader.readRequest(&context, Context.begin, Context.consume),
    );
}

test "HTTP/1 streaming request reads fixed body without aggregation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const body = "fixed-stream-" ** 8192;
    const Shared = struct {
        server: *runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const Context = struct {
                connection: *runtime.Connection,
                expected: []const u8,
                offset: usize = 0,
                chunks: usize = 0,

                fn begin(
                    self: *@This(),
                    head: runtime.StreamingRequestHead,
                ) !void {
                    try std.testing.expect(head.method == .POST);
                    try std.testing.expectEqualStrings("/fixed", head.target);
                    try std.testing.expectEqual(
                        @as(?usize, self.expected.len),
                        head.content_length,
                    );
                    try std.testing.expectError(
                        error.ConnectionBusy,
                        self.connection.readRequest(.{}),
                    );
                }

                fn consume(self: *@This(), bytes: []const u8) !void {
                    try std.testing.expectEqualSlices(
                        u8,
                        self.expected[self.offset..][0..bytes.len],
                        bytes,
                    );
                    self.offset += bytes.len;
                    self.chunks += 1;
                }
            };
            var context = Context{
                .connection = &connection,
                .expected = shared.expected,
            };
            var request = try connection.readRequestStreamingWithOptionsAndHead(
                .{},
                &context,
                Context.begin,
                Context.consume,
            );
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(shared.expected.len, request.body_bytes);
            try std.testing.expectEqual(shared.expected.len, context.offset);
            try std.testing.expect(context.chunks > 1);
            try std.testing.expectEqualStrings("/fixed", request.target);
            try connection.writeResponse(.{
                .body = "ok",
                .request_method = request.method,
            });
        }
    };

    var shared = Shared{ .server = &server, .expected = body };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/fixed",
        .host = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming request reads chunked trailers and pipeline suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(server_ptr.allocator);
            const Context = struct {
                allocator: std.mem.Allocator,
                body: *std.ArrayList(u8),

                fn consume(self: *@This(), bytes: []const u8) !void {
                    try self.body.appendSlice(self.allocator, bytes);
                }
            };
            var context = Context{
                .allocator = server_ptr.allocator,
                .body = &body,
            };
            var first = try connection.readRequestStreaming(
                &context,
                Context.consume,
            );
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                http1.BodyFraming.chunked,
                first.body_framing,
            );
            try std.testing.expectEqualStrings("hello world", body.items);
            try std.testing.expect(first.header("content-length") == null);
            try std.testing.expect(!first.must_close);
            try std.testing.expectEqual(@as(usize, 1), first.trailers.len);
            try std.testing.expectEqualStrings(
                "sha-256=demo",
                first.trailers[0].value,
            );

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/next", second.request.target);
            // First-message metadata owns its wire storage and survives the
            // connection buffer compaction performed by the second read.
            try std.testing.expectEqualStrings("/chunked", first.target);
            try std.testing.expectEqualStrings(
                "sha-256=demo",
                first.trailers[0].value,
            );
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "pipeline-ok",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const raw =
        "POST /chunked HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n" ++
        "6\r\n world\r\n" ++
        "0\r\nDigest: sha-256=demo\r\n\r\n" ++
        "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    try writeAll(io, stream, raw);
    var response = try runtime.readResponseFromStreamForRequest(
        allocator,
        io,
        stream,
        limits,
        .{},
        .GET,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("pipeline-ok", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming requests retain TE plus CL must-close semantics" {
    const allocator = std.testing.allocator;
    const Reader = @import("body_reader.zig").Reader(runtime.Error);
    const requests = [_][]const u8{
        "POST /cl-first HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 9\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
        "POST /te-first HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Content-Length: 9\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
    };
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(raw_context: ?*anyopaque, out: []u8) runtime.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        saw_head: bool = false,
        body: std.ArrayList(u8) = .empty,

        fn begin(self: *@This(), head: Reader.RequestHead) !void {
            try std.testing.expectEqual(http1.BodyFraming.chunked, head.body_framing);
            try std.testing.expect(head.header("content-length") == null);
            try std.testing.expect(head.must_close);
            try std.testing.expect(!head.keepAlive());
            self.saw_head = true;
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    for (requests) |raw| {
        var source = Source{ .bytes = raw };
        var inbuf: std.ArrayList(u8) = .empty;
        defer inbuf.deinit(allocator);
        var context: Context = .{};
        defer context.body.deinit(allocator);
        var reader = Reader{
            .allocator = allocator,
            .context = &source,
            .read_some = Source.readSome,
            .inbuf = &inbuf,
            .limits = .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = limits.max_body_bytes,
            },
            .options = .{},
        };
        var request = try reader.readRequest(
            &context,
            Context.begin,
            Context.consume,
        );
        defer request.deinit(allocator);
        try std.testing.expect(context.saw_head);
        try std.testing.expectEqualStrings("ok", context.body.items);
        try std.testing.expect(request.header("content-length") == null);
        try std.testing.expect(request.must_close);
        try std.testing.expect(!request.keepAlive());
    }
}

test "HTTP/1 streaming request optionally unfolds chunked trailers" {
    const allocator = std.testing.allocator;
    const raw =
        "POST /folded HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nbody\r\n" ++
        "0\r\n" ++
        "Digest: sha-256=abc\r\n" ++
        " def\r\n" ++
        "\tghi\r\n\r\n";
    const TestError = runtime.Error;
    const Reader = @import("body_reader.zig").Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(raw_context: ?*anyopaque, out: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            if (self.offset == self.bytes.len) return 0;
            // One byte per call proves folding is independent of transport
            // read boundaries and exercises retained trailer ownership.
            out[0] = self.bytes[self.offset];
            self.offset += 1;
            return 1;
        }
    };
    const Context = struct {
        body: std.ArrayList(u8) = .empty,

        fn begin(_: *@This(), _: Reader.RequestHead) !void {}

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    var strict_source = Source{ .bytes = raw };
    var strict_inbuf: std.ArrayList(u8) = .empty;
    defer strict_inbuf.deinit(allocator);
    var strict_context: Context = .{};
    defer strict_context.body.deinit(allocator);
    var strict_reader = Reader{
        .allocator = allocator,
        .context = &strict_source,
        .read_some = Source.readSome,
        .inbuf = &strict_inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{},
    };
    try std.testing.expectError(
        error.MalformedHeader,
        strict_reader.readRequest(
            &strict_context,
            Context.begin,
            Context.consume,
        ),
    );

    var source = Source{ .bytes = raw };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{ .allow_obs_fold = true },
    };
    var request = try reader.readRequest(
        &context,
        Context.begin,
        Context.consume,
    );
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("body", context.body.items);
    try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
    try std.testing.expectEqualStrings(
        "sha-256=abc def ghi",
        request.trailers[0].value,
    );
    try std.testing.expectEqual(@as(usize, 2), request.trailer_value_storage.len);
}

test "HTTP/1 streaming request rejects connection-control trailers" {
    const allocator = std.testing.allocator;
    const raw =
        "POST /invalid-trailer HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nbody\r\n" ++
        "0\r\nConnection: close\r\n\r\n";
    const TestError = runtime.Error;
    const Reader = @import("body_reader.zig").Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(raw_context: ?*anyopaque, out: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        body: std.ArrayList(u8) = .empty,

        fn begin(_: *@This(), _: Reader.RequestHead) !void {}

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    var source = Source{ .bytes = raw };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{},
    };
    try std.testing.expectError(
        error.InvalidTrailer,
        reader.readRequest(&context, Context.begin, Context.consume),
    );
    try std.testing.expectEqualStrings("body", context.body.items);
}

test "HTTP/1 streaming response observes informational heads" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 103 Early Hints\r\n" ++
        "Link: </stream.css>; rel=preload\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nstream";
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);

    const TestError = runtime.Error;
    const Reader = @import("body_reader.zig").Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(raw_context: ?*anyopaque, out: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        informational: usize = 0,
        final_head: bool = false,
        body: std.ArrayList(u8) = .empty,

        fn observe(
            raw_context: *anyopaque,
            head: runtime.InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw_context));
            if (head.status != 103 or !std.mem.eql(
                u8,
                head.header("link") orelse @panic("missing Link"),
                "</stream.css>; rel=preload",
            )) @panic("unexpected informational response");
            self.informational += 1;
        }

        fn begin(self: *@This(), head: Reader.ResponseHead) !void {
            try std.testing.expectEqual(@as(u16, 200), head.status);
            self.final_head = true;
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    var source = Source{ .bytes = raw };
    var context = Context{};
    defer context.body.deinit(allocator);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .informational_context = &context,
        .on_informational = Context.observe,
        .inbuf = &inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{},
    };
    var response = try reader.readResponse(
        .GET,
        &context,
        Context.begin,
        Context.consume,
    );
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), context.informational);
    try std.testing.expect(context.final_head);
    try std.testing.expectEqualStrings("stream", context.body.items);
}

test "HTTP/1 streaming response optionally unfolds chunked trailers" {
    const allocator = std.testing.allocator;
    const raw =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "2\r\nok\r\n" ++
        "0\r\n" ++
        "Digest: sha-256=response\r\n" ++
        " folded\r\n\r\n";
    const TestError = runtime.Error;
    const Reader = @import("body_reader.zig").Reader(TestError);
    const Source = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn readSome(raw_context: ?*anyopaque, out: []u8) TestError!usize {
            const self: *@This() = @ptrCast(@alignCast(raw_context.?));
            if (self.offset == self.bytes.len) return 0;
            const count = @min(@as(usize, 2), @min(
                out.len,
                self.bytes.len - self.offset,
            ));
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Context = struct {
        body: std.ArrayList(u8) = .empty,

        fn begin(_: *@This(), _: Reader.ResponseHead) !void {}

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };

    var source = Source{ .bytes = raw };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var reader = Reader{
        .allocator = allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{
            .max_head_bytes = limits.max_head_bytes,
            .max_body_bytes = limits.max_body_bytes,
        },
        .options = .{ .allow_obs_fold = true },
    };
    var response = try reader.readResponse(
        .GET,
        &context,
        Context.begin,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", context.body.items);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings(
        "sha-256=response folded",
        response.trailers[0].value,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        response.trailer_value_storage.len,
    );
}

test "HTTP/1 client exposes streaming response trailer compatibility" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try writeAll(
                self.server.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\n" ++
                    "Transfer-Encoding: chunked\r\n" ++
                    "Connection: close\r\n\r\n" ++
                    "2\r\nok\r\n" ++
                    "0\r\nDigest: sha-256=abc\r\n folded\r\n\r\n",
            );
        }
    };
    const Context = struct {
        body: std.ArrayList(u8) = .empty,

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var response = try client.requestStreamingWithParseOptions(
        .{ .host = "localhost" },
        .{ .allow_obs_fold = true },
        &context,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", context.body.items);
    try std.testing.expectEqualStrings(
        "sha-256=abc folded",
        response.trailers[0].value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming response reads chunked trailers and writer handoff" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            var response = try connection.startResponse(.{
                .request_method = request.request.method,
                .trailer_names = &.{"Digest"},
                .request_accepts_trailers = request.request.acceptsTrailers(),
            });
            defer response.deinit();
            try response.write("streamed ");
            try response.write("response");
            try response.finishTrailers(&.{.{
                .name = "Digest",
                .value = "sha-256=response",
            }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/upload",
        .host = "localhost",
        .headers = &.{.{ .name = "TE", .value = "trailers" }},
        .body_length = 6,
    });
    defer writer.deinit();
    try writer.write("upload");
    try writer.finish();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    const Context = struct {
        allocator: std.mem.Allocator,
        body: *std.ArrayList(u8),
        began: bool = false,

        fn begin(
            self: *@This(),
            head: runtime.StreamingResponseHead,
        ) !void {
            self.began = true;
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqual(
                http1.BodyFraming.chunked,
                head.body_framing,
            );
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(self.allocator, bytes);
        }
    };
    var context = Context{ .allocator = allocator, .body = &body };
    var response = try writer.readResponseStreamingWithOptionsAndHead(
        .{},
        null,
        &context,
        Context.begin,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expect(context.began);
    try std.testing.expectEqualStrings("streamed response", body.items);
    try std.testing.expectEqual(@as(usize, body.items.len), response.body_bytes);
    try std.testing.expectEqualStrings(
        "sha-256=response",
        response.trailers[0].value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming response supports close-delimited bodies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try writeAll(
                server_ptr.io,
                connection.stream,
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" ++
                    "close-delimited",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    const Context = struct {
        allocator: std.mem.Allocator,
        body: *std.ArrayList(u8),
        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.body.appendSlice(self.allocator, bytes);
        }
    };
    var context = Context{ .allocator = allocator, .body = &body };
    var response = try client.requestStreaming(
        .{ .host = "localhost" },
        &context,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(
        http1.BodyFraming.close_delimited,
        response.body_framing,
    );
    try std.testing.expectEqualStrings("close-delimited", body.items);
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming callback failure poisons connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch return;
            defer connection.close();
            var request = connection.readRequest(.{}) catch return;
            defer request.deinit(shared.server.allocator);
            connection.writeResponse(.{ .body = "response" ** 4096 }) catch {};
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    const Context = struct {
        fn consume(_: *@This(), _: []const u8) !void {
            return error.Stop;
        }
    };
    var context = Context{};
    try std.testing.expectError(
        error.Stop,
        client.requestStreaming(
            .{ .host = "localhost" },
            &context,
            Context.consume,
        ),
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "localhost" }),
    );
    client.close();
    thread.join();
}

test "HTTP/1 streaming request callback failure poisons connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        observed: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const Context = struct {
                fn consume(_: *@This(), _: []const u8) !void {
                    return error.StopRequest;
                }
            };
            var context = Context{};
            try std.testing.expectError(
                error.StopRequest,
                connection.readRequestStreaming(
                    &context,
                    Context.consume,
                ),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            shared.observed = true;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(
        io,
        stream,
        "POST /fail HTTP/1.1\r\nHost: localhost\r\n" ++
            "Content-Length: 8\r\n\r\nresponse",
    );

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.observed);
}

test "HTTP/1 streaming reader enforces length before begin callback" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        began: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const Context = struct {
                began: *bool,
                fn begin(
                    self: *@This(),
                    _: runtime.StreamingRequestHead,
                ) !void {
                    self.began.* = true;
                }
                fn consume(_: *@This(), _: []const u8) !void {}
            };
            var context = Context{ .began = &shared.began };
            try std.testing.expectError(
                error.BodyTooLarge,
                connection.readRequestStreamingWithHead(
                    &context,
                    Context.begin,
                    Context.consume,
                ),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(
        io,
        stream,
        "POST /large HTTP/1.1\r\nHost: localhost\r\n" ++
            "Content-Length: 5\r\n\r\nhello",
    );

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(!shared.began);
}
