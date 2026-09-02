const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 4096,
};

fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
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

fn readToEof(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    var scratch: [1024]u8 = undefined;
    while (true) {
        var destinations = [_][]u8{&scratch};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &destinations,
        );
        if (count == 0) return bytes.toOwnedSlice(allocator);
        try bytes.appendSlice(allocator, scratch[0..count]);
    }
}

const ServeShared = struct {
    server: *runtime.Server,
    max_requests: usize,
    served: usize = 0,
    handled: usize = 0,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var connection = try self.server.accept();
        defer connection.close();
        self.served = try connection.serve(
            self,
            handle,
            self.max_requests,
        );
    }

    fn handle(
        self: *@This(),
        request: http1.Request,
    ) runtime.Error!runtime.ResponseOptions {
        self.handled += 1;
        return .{ .body = request.target };
    }
};

fn expectServeAfterSendHalfClose(
    io: std.Io,
    server: *runtime.Server,
    request: []const u8,
    expected_served: usize,
    expected_handled: usize,
    max_requests: usize,
) !void {
    const allocator = std.testing.allocator;
    var shared = ServeShared{
        .server = server,
        .max_requests = max_requests,
    };
    const thread = try std.Thread.spawn(.{}, ServeShared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(io, client, request);
    try client.shutdown(io, .send);
    const response = try readToEof(allocator, io, client);
    defer allocator.free(response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(expected_served, shared.served);
    try std.testing.expectEqual(expected_handled, shared.handled);
    if (expected_handled != 0) {
        var response_count: usize = 0;
        var remaining = response;
        while (std.mem.indexOf(
            u8,
            remaining,
            "HTTP/1.1 200 OK\r\n",
        )) |index| {
            response_count += 1;
            remaining = remaining[index + "HTTP/1.1 200 OK\r\n".len ..];
        }
        try std.testing.expectEqual(expected_handled, response_count);
    }
}

test "HTTP/1 serve retires cleanly after peer send half-close" {
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

    try expectServeAfterSendHalfClose(
        io,
        &server,
        "GET /half-close HTTP/1.1\r\nHost: localhost\r\n\r\n",
        1,
        1,
        4,
    );
}

test "HTTP/1 serve completes fixed request body before clean half-close" {
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

    try expectServeAfterSendHalfClose(
        io,
        &server,
        "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
        1,
        1,
        4,
    );
}

test "HTTP/1 serve honors its one-request bound after peer half-close" {
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

    try expectServeAfterSendHalfClose(
        io,
        &server,
        "GET /bounded HTTP/1.1\r\nHost: localhost\r\n\r\n",
        1,
        1,
        1,
    );
}

test "HTTP/1 serve drains complete pipeline before clean half-close" {
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

    try expectServeAfterSendHalfClose(
        io,
        &server,
        "GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n" ++
            "GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n",
        2,
        2,
        4,
    );
}

test "HTTP/1 serve preserves truncated request errors after half-close" {
    const Case = struct {
        name: []const u8,
        request: []const u8,
    };
    const cases = [_]Case{
        .{ .name = "head", .request = "GET /partial HTTP/1.1\r\nHost: local" },
        .{
            .name = "fixed body",
            .request = "POST /fixed HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nabc",
        },
        .{
            .name = "chunked body",
            .request = "POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        },
    };

    for (cases) |case| {
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

        var shared = ServeShared{ .server = &server, .max_requests = 4 };
        const thread = try std.Thread.spawn(.{}, ServeShared.run, .{&shared});
        const client = try server.address().connect(io, .{ .mode = .stream });
        try writeAll(io, client, case.request);
        try client.shutdown(io, .send);
        client.close(io);
        thread.join();

        std.testing.expectEqual(@as(usize, 0), shared.handled) catch |err| {
            std.debug.print("truncated {s} unexpectedly reached handler\n", .{case.name});
            return err;
        };
        std.testing.expectEqual(error.ConnectionClosed, shared.err.?) catch |err| {
            std.debug.print("truncated {s} produced {any}\n", .{ case.name, shared.err });
            return err;
        };
    }
}

test "HTTP/1 public serveOne retains empty EOF error" {
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(self, handle) catch |err| {
                self.err = err;
                return;
            };
        }
        fn handle(
            _: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            return .{};
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    try client.shutdown(io, .send);
    client.close(io);
    thread.join();
    try std.testing.expectEqual(error.ConnectionClosed, shared.err.?);
}

test "HTTP/1 public readRequest retains empty EOF error" {
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            request.deinit(std.testing.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    try client.shutdown(io, .send);
    client.close(io);
    thread.join();
    try std.testing.expectEqual(error.ConnectionClosed, shared.err.?);
}

test "HTTP/1 persistent serve treats empty peer close as zero requests" {
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

    var shared = ServeShared{ .server = &server, .max_requests = 4 };
    const thread = try std.Thread.spawn(.{}, ServeShared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    try client.shutdown(io, .send);
    client.close(io);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.served);
    try std.testing.expectEqual(@as(usize, 0), shared.handled);
}

test "HTTP/1 serve does not hide handler ConnectionClosed" {
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serve(self, handle, 4) catch |err| {
                self.err = err;
                return;
            };
        }
        fn handle(
            _: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            return error.ConnectionClosed;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    try writeAll(
        io,
        client,
        "GET /handler-error HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    try client.shutdown(io, .send);
    client.close(io);
    thread.join();
    try std.testing.expectEqual(error.ConnectionClosed, shared.err.?);
}

test "HTTP/1 serveUntil ignores clean request-boundary EOF" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        handled: std.atomic.Value(usize) = .init(0),
        fn handle(
            self: *@This(),
            request: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            _ = self.handled.fetchAdd(1, .release);
            if (std.mem.eql(u8, request.target, "/stop")) {
                self.shutdown.set(self.io);
            }
            return .{
                .headers = if (std.mem.eql(u8, request.target, "/stop"))
                    &.{.{ .name = "Connection", .value = "close" }}
                else
                    &.{},
                .body = request.target,
            };
        }
    };
    const Observer = struct {
        count: std.atomic.Value(usize) = .init(0),
        fn observe(context: *anyopaque, _: runtime.ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.count.fetchAdd(1, .release);
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer = .{},
        context: Context,
        err: ?anyerror = null,
        fn init(server_ptr: *runtime.Server, io_value: std.Io) @This() {
            var self: @This() = undefined;
            self.server = server_ptr;
            self.shutdown = .unset;
            self.observer = .{};
            self.context = .{ .io = io_value, .shutdown = &self.shutdown };
            self.err = null;
            return self;
        }
        fn run(self: *@This()) void {
            self.context.shutdown = &self.shutdown;
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                4,
                .{
                    .shutdown = &self.shutdown,
                    .connection_error_policy = .stop,
                    .error_observer = .{
                        .context = &self.observer,
                        .observe = Observer.observe,
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared.init(&server, io);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        thread.join();
    };

    const half_closed = try server.address().connect(io, .{ .mode = .stream });
    try writeAll(
        io,
        half_closed,
        "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    try half_closed.shutdown(io, .send);
    const first_response = try readToEof(allocator, io, half_closed);
    defer allocator.free(first_response);
    half_closed.close(io);
    try std.testing.expect(std.mem.indexOf(
        u8,
        first_response,
        "/first",
    ) != null);

    // `.stop` would have terminated the accept loop if clean boundary EOF had
    // been reported as a connection error. A second connection proves the
    // worker was reused without invoking the observer.
    const stop_client = try server.address().connect(io, .{ .mode = .stream });
    defer stop_client.close(io);
    try writeAll(
        io,
        stop_client,
        "GET /stop HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    // The shutdown event may cancel this worker immediately after the handler
    // proves the second connection was admitted. Response delivery is covered
    // by the direct half-close tests above; this case validates supervisor
    // reuse and observer behavior only.
    var stop_scratch: [512]u8 = undefined;
    var stop_destinations = [_][]u8{&stop_scratch};
    _ = io.vtable.netRead(
        io.userdata,
        stop_client.socket.handle,
        &stop_destinations,
    ) catch 0;

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        shared.observer.count.load(.acquire),
    );
}
