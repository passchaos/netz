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
                    try std.testing.expectEqual(http1.Method.POST, head.method);
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
            var request = try connection.readRequestStreamingWithHead(
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
        "Content-Length: 999\r\n" ++
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
    var response = try writer.readResponseStreamingWithHead(
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
