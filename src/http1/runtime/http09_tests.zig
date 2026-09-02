const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

fn readRequestHead(io: std.Io, stream: net.Stream) !void {
    var bytes: [4096]u8 = undefined;
    var length: usize = 0;
    while (std.mem.indexOf(u8, bytes[0..length], "\r\n\r\n") == null) {
        var parts = [_][]u8{bytes[length..]};
        const count = try io.vtable.netRead(io.userdata, stream.socket.handle, &parts);
        if (count == 0) return error.ConnectionClosed;
        length += count;
    }
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset != bytes.len) {
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

test "HTTP/0.9 aggregate client response is opt in and non-reusable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            // Fragmenting the first four bytes exercises the prefix classifier
            // rather than relying on one transport completion.
            try writeAll(self.io, stream, "leg");
            try writeAll(self.io, stream, "acy");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 6,
    });
    defer client.close();
    var response = try client.requestWithParseOptions(.{ .host = "localhost" }, .{
        .allow_http_0_9_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(http1.Version.http_0_9, response.response.version);
    try std.testing.expectEqualStrings("legacy", response.response.body);
    try std.testing.expect(!client.isReusable());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 strict aggregate client rejects headerless response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "legacy");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 64,
    });
    defer client.close();
    try std.testing.expectError(
        error.ConnectionClosed,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 responses are accepted only for GET requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            inline for (0..2) |_| {
                const stream = try self.listener.accept(self.io);
                defer stream.close(self.io);
                try readRequestHead(self.io, stream);
                try writeAll(self.io, stream, "legacy");
            }
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    inline for (&.{ http1.Method.HEAD, http1.Method.POST }) |method| {
        var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
            .max_head_bytes = 128,
            .max_body_bytes = 64,
        });
        defer client.close();
        try std.testing.expectError(error.ConnectionClosed, client.requestWithParseOptions(
            .{ .method = method, .host = "localhost" },
            .{ .allow_http_0_9_responses = true },
        ));
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 request writer response is GET-only" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "legacy");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 64,
    });
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .host = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    try std.testing.expectError(error.ConnectionClosed, writer.readResponseWithParseOptions(.{
        .allow_http_0_9_responses = true,
    }));
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 aggregate client enforces decoded body limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "legacy!");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 6,
    });
    defer client.close();
    try std.testing.expectError(error.BodyTooLarge, client.requestWithParseOptions(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 streaming client delivers final head before body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "streamed");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 8,
    });
    defer client.close();
    const Context = struct {
        began: bool = false,
        body: std.ArrayList(u8) = .empty,
        fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
            try std.testing.expect(!self.began);
            self.began = true;
            try std.testing.expectEqual(http1.Version.http_0_9, head.version);
        }
        fn consume(self: *@This(), bytes: []const u8) !void {
            try std.testing.expect(self.began);
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var response = try client.requestStreamingWithOptionsAndHead(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
        null,
        &context,
        Context.begin,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("streamed", context.body.items);
    try std.testing.expectEqual(@as(usize, 8), response.body_bytes);
    try std.testing.expect(!client.isReusable());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 empty EOF is not a response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 6,
    });
    defer client.close();
    try std.testing.expectError(error.ConnectionClosed, client.requestWithParseOptions(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 prefix body is accepted only after EOF" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            for ("HTTP") |byte| try writeAll(self.io, stream, &.{byte});
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 4,
    });
    defer client.close();
    var response = try client.requestWithParseOptions(.{ .host = "localhost" }, .{
        .allow_http_0_9_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("HTTP", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 EOF prefix body enforces aggregate limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            inline for (0..2) |_| {
                const stream = try self.listener.accept(self.io);
                defer stream.close(self.io);
                try readRequestHead(self.io, stream);
                try writeAll(self.io, stream, "HTTP");
            }
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var exact = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 4,
    });
    defer exact.close();
    var response = try exact.requestWithParseOptions(.{ .host = "localhost" }, .{
        .allow_http_0_9_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("HTTP", response.response.body);

    var over = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 3,
    });
    defer over.close();
    try std.testing.expectError(error.BodyTooLarge, over.requestWithParseOptions(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 response body obeys caller deadline after classification" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "legacy");
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 64,
    });
    defer client.close();
    try std.testing.expectError(error.Timeout, client.requestWithParseOptionsAndTimeout(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
        .fromMilliseconds(20),
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 aggregate response follows informational callback" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "HTTP/1.1 100 Continue\r\n\r\nlegacy");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 6,
    });
    defer client.close();
    const Observation = struct {
        count: usize = 0,
        fn observe(context: *anyopaque, response: runtime.InformationalResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            std.debug.assert(response.status == 100);
            self.count += 1;
        }
    };
    var observation: Observation = .{};
    var response = try client.requestWithParseOptionsAndInformational(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
        .{ .context = &observation, .on_response = Observation.observe },
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observation.count);
    try std.testing.expectEqualStrings("legacy", response.response.body);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 opt in does not downgrade malformed HTTP prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "HTTP/bad 200 OK\r\n\r\n");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 64,
    });
    defer client.close();
    try std.testing.expectError(error.InvalidVersion, client.requestWithParseOptions(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
    ));
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/0.9 streaming response follows informational callback" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try readRequestHead(self.io, stream);
            try writeAll(self.io, stream, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nlegacy");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(allocator, io, listener.socket.address, .{
        .max_head_bytes = 128,
        .max_body_bytes = 6,
    });
    defer client.close();
    const Context = struct {
        informational: bool = false,
        began: bool = false,
        body: std.ArrayList(u8) = .empty,
        fn observe(context: *anyopaque, response: runtime.InformationalResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            std.debug.assert(response.status == 103);
            self.informational = true;
        }
        fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
            try std.testing.expect(self.informational);
            self.began = true;
            try std.testing.expectEqual(http1.Version.http_0_9, head.version);
        }
        fn consume(self: *@This(), bytes: []const u8) !void {
            try std.testing.expect(self.began);
            try self.body.appendSlice(std.testing.allocator, bytes);
        }
    };
    var context: Context = .{};
    defer context.body.deinit(allocator);
    var response = try client.requestStreamingWithOptionsAndHead(
        .{ .host = "localhost" },
        .{ .allow_http_0_9_responses = true },
        .{ .context = &context, .on_response = Context.observe },
        &context,
        Context.begin,
        Context.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("legacy", context.body.items);
    thread.join();
    if (shared.err) |err| return err;
}
