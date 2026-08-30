const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

fn readUntilHead(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) !void {
    var length: usize = 0;
    while (std.mem.indexOf(u8, buffer[0..length], "\r\n\r\n") == null) {
        if (length == buffer.len) return error.HeadersTooLarge;
        var parts = [_][]u8{buffer[length..]};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &parts,
        );
        if (count == 0) return error.ConnectionClosed;
        length += count;
    }
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        offset += count;
    }
}

test "HTTP/1 client response head timeout starts before first byte" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try std.Io.sleep(self.io, .fromMilliseconds(200), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.request(.{ .host = "localhost" }),
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 complete response deadline bounds a fixed body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nb",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.requestWithTimeout(
            .{ .host = "localhost" },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 URI deadline spans connection and complete response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nb",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(150), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/deadline",
        .{listener.socket.address.getPort()},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriWithDeadline(
            allocator,
            io,
            uri,
            .{},
            .{
                .connect_timeout = .fromSeconds(1),
                .response_head_timeout = .fromSeconds(1),
            },
            .fromNow(io, .{
                .raw = .fromMilliseconds(40),
                .clock = .awake,
            }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 URI timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://localhost/",
            .{},
            .{},
            .zero,
        ),
    );
}

test "HTTP/1 response deadline rejects a non-awake clock before writing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var client = runtime.Client{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .stream = undefined,
    };
    defer {
        client.inbuf.deinit(std.testing.allocator);
        client.write_scratch.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(
            .{ .host = "localhost" },
            std.Io.Clock.Timestamp.fromNow(
                threaded.io(),
                .{ .raw = .fromSeconds(1), .clock = .real },
            ),
        ),
    );
    try std.testing.expect(client.isReusable());
}

test "HTTP/1 complete response deadline bounds chunk framing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .host = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    try std.testing.expectError(
        error.Timeout,
        writer.readResponseWithDeadline(.fromNow(io, .{
            .raw = .fromMilliseconds(20),
            .clock = .awake,
        })),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming response deadline bounds body delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nb",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }
    };
    const Sink = struct {
        bytes: usize = 0,

        fn consume(self: *@This(), part: []const u8) !void {
            self.bytes += part.len;
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    var sink: Sink = .{};
    try std.testing.expectError(
        error.Timeout,
        client.requestStreamingWithTimeout(
            .{ .host = "localhost" },
            .fromMilliseconds(20),
            &sink,
            Sink.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), sink.bytes);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 standalone response reader honors head timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try std.Io.sleep(self.io, .fromMilliseconds(150), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);
    try runtime.writeRequestToStream(allocator, io, stream, .{
        .host = "localhost",
    });
    try std.testing.expectError(
        error.Timeout,
        runtime.readResponseFromStreamForRequest(
            allocator,
            io,
            stream,
            .{ .response_head_timeout = .fromMilliseconds(75) },
            .{},
            .GET,
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 buffered response bypasses zero head timeout" {
    const allocator = std.testing.allocator;
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );

    var response = try runtime.readResponseFromStreamBufferedForRequest(
        allocator,
        undefined,
        undefined,
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
            .response_head_timeout = .fromNanoseconds(0),
        },
        .{},
        &inbuf,
        .GET,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);
}

test "HTTP/1 buffered response deadline retains pipelined bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const first = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
    const second = "HTTP/1.1 204 No Content\r\n\r\n";
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(allocator, first ++ second);

    var response = try runtime.readResponseFromStreamBufferedForRequestWithDeadline(
        allocator,
        io,
        undefined,
        .{},
        .{},
        &inbuf,
        .GET,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("one", response.response.body);
    try std.testing.expectEqualStrings(second, inbuf.items);
}

test "HTTP/1 buffered response resumes after body deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
        release_tail: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
            );
            try self.release_tail.wait(self.io);
            try writeAll(self.io, stream, "llo");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try std.testing.expectError(
        error.Timeout,
        runtime.readResponseFromStreamBufferedForRequestWithTimeout(
            allocator,
            io,
            stream,
            .{},
            .{},
            &inbuf,
            .GET,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(inbuf.items.len != 0);
    shared.release_tail.set(io);

    var response = try runtime.readResponseFromStreamBufferedForRequestWithDeadline(
        allocator,
        io,
        stream,
        .{},
        .{},
        &inbuf,
        .GET,
        .fromNow(io, .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("hello", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 buffered observed response shares one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            try writeAll(self.io, stream, "HTTP/1.1 103 Early Hints\r\n\r\n");
            try std.Io.sleep(self.io, .fromMilliseconds(75), .awake);
            writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    const Observer = struct {
        count: usize = 0,

        fn onResponse(context: *anyopaque, head: runtime.InformationalResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (head.status != 103) @panic("unexpected informational status");
            self.count += 1;
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    var observer: Observer = .{};

    try std.testing.expectError(
        error.Timeout,
        runtime.readResponseFromStreamBufferedForRequestObservedWithTimeout(
            allocator,
            io,
            stream,
            .{},
            .{},
            &inbuf,
            .GET,
            .{
                .context = &observer,
                .on_response = Observer.onResponse,
            },
            .fromMilliseconds(25),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), observer.count);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client response head timeout is absolute across trickled bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(self.io, stream, "HTTP/1.1 200 OK\r\n");
            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            try writeAll(self.io, stream, "Content-Length: 0\r\n");
            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            writeAll(self.io, stream, "\r\n") catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(150) },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 response head timeout resets for persistent exchanges" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            for (0..2) |index| {
                var request: [4096]u8 = undefined;
                try readUntilHead(self.io, stream, &request);
                try std.Io.sleep(
                    self.io,
                    .fromMilliseconds(300),
                    .awake,
                );
                try writeAll(
                    self.io,
                    stream,
                    if (index == 0)
                        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
                    else
                        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo",
                );
            }
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(500) },
    );
    defer client.close();
    var first = try client.request(.{
        .target = "/first",
        .host = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{
        .target = "/second",
        .host = "localhost",
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 response head timeout spans informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 103 Early Hints\r\n\r\n",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
            writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client informational response shares request deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(self.io, stream, "HTTP/1.1 103 Early Hints\r\n\r\n");
            try std.Io.sleep(self.io, .fromMilliseconds(75), .awake);
            writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    const Observer = struct {
        count: usize = 0,

        fn onResponse(context: *anyopaque, head: runtime.InformationalResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (head.status != 103) @panic("unexpected informational status");
            self.count += 1;
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    var observer: Observer = .{};

    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndTimeout(
            .{ .host = "localhost" },
            .{
                .context = &observer,
                .on_response = Observer.onResponse,
            },
            .fromMilliseconds(25),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), observer.count);
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 response head timeout excludes a slow body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(120), .awake);
            try writeAll(self.io, stream, "body");
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer client.close();
    var response = try client.request(.{ .host = "localhost" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("body", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming response head timeout excludes a slow body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(120), .awake);
            try writeAll(self.io, stream, "body");
        }
    };
    const Sink = struct {
        bytes: [4]u8 = undefined,
        len: usize = 0,

        fn consume(self: *@This(), bytes: []const u8) !void {
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer client.close();
    var sink: Sink = .{};
    var response = try client.requestStreaming(
        .{ .host = "localhost" },
        &sink,
        Sink.consume,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("body", sink.bytes[0..sink.len]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 Expect Continue uses one response head budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 103 Early Hints\r\n\r\n",
            );
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .host = "localhost",
        .body_length = 4,
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
    });
    defer writer.deinit();
    try std.testing.expectError(
        error.Timeout,
        writer.waitForContinue(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 final response receives a fresh budget after 100 Continue" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var request: [4096]u8 = undefined;
            try readUntilHead(self.io, stream, &request);
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 100 Continue\r\n\r\n",
            );
            var body: [4]u8 = undefined;
            var offset: usize = 0;
            while (offset < body.len) {
                var parts = [_][]u8{body[offset..]};
                const count = try self.io.vtable.netRead(
                    self.io.userdata,
                    stream.socket.handle,
                    &parts,
                );
                if (count == 0) return error.ConnectionClosed;
                offset += count;
            }
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            );
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(150) },
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .host = "localhost",
        .body_length = 4,
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
    });
    defer writer.deinit();
    try std.testing.expect(
        (try writer.waitForContinue()) == .proceed,
    );
    try writer.write("body");
    try writer.finish();
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 CONNECT and Upgrade honor response head timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            for (0..2) |_| {
                const stream = try self.listener.accept(self.io);
                defer stream.close(self.io);
                var request: [4096]u8 = undefined;
                try readUntilHead(self.io, stream, &request);
                try std.Io.sleep(
                    self.io,
                    .fromMilliseconds(120),
                    .awake,
                );
            }
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connect_client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer connect_client.close();
    try std.testing.expectError(
        error.Timeout,
        connect_client.openConnectTunnel("example.com:443", &.{}),
    );

    var upgrade_client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .response_head_timeout = .fromMilliseconds(75) },
    );
    defer upgrade_client.close();
    try std.testing.expectError(
        error.Timeout,
        upgrade_client.openUpgrade(
            "/upgrade",
            "localhost",
            "netz-test",
            &.{},
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 TLS client response head timeout covers records" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.TlsServer,
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
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{ .response_head_timeout = .fromMilliseconds(75) },
        .{ .verify_host = false },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.request(.{ .host = "localhost" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 io_uring rejects unsupported response head timeout" {
    if (comptime @import("builtin").os.tag != .linux) {
        return error.SkipZigTest;
    }
    var ring = std.os.linux.IoUring.init(8, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => return error.SkipZigTest,
        else => |other| return other,
    };
    defer ring.deinit();
    try std.testing.expectError(
        error.TimedReadUnsupported,
        runtime.Client.requestUriLinuxIoUring(
            std.testing.allocator,
            &ring,
            "http://127.0.0.1:1/",
            .{},
            .{ .response_head_timeout = .fromMilliseconds(1) },
        ),
    );
}
