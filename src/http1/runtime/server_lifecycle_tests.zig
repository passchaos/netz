const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

fn sendRawRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var writer = stream.writer(io, &.{});
    try writer.interface.writeAll(bytes);
}

test "HTTP/1 TCP listener accept deadline expires without a client" {
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
        .{},
    );
    defer server.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.acceptWithTimeout(.fromMilliseconds(20)),
    );
}

test "HTTP/1 serveOne rejects an informational handler result as final" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        handled: usize = 0,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled += 1;
            return .{ .status = 103, .reason = "Early Hints" };
        }

        fn run(self: *@This()) void {
            _ = self.server.serveConnection(
                self,
                @This().handle,
                2,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const Observer = struct {
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            _: runtime.InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
        }
    };

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try sendRawRequest(
        io,
        stream,
        "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n" ++
            "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    var observer: Observer = .{};
    var response = try runtime.readResponseFromStreamObserved(
        allocator,
        io,
        stream,
        .{},
        .{},
        .{
            .context = &observer,
            .on_response = Observer.observe,
        },
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 500), response.response.status);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );
    try std.testing.expectEqualStrings("", response.response.body);

    server_thread.join();
    joined = true;
    var byte: [1]u8 = undefined;
    var reader = stream.reader(io, &byte);
    try std.testing.expectError(
        error.EndOfStream,
        reader.interface.takeByte(),
    );
    try std.testing.expectEqual(@as(usize, 0), observer.count);
    try std.testing.expectEqual(@as(usize, 1), shared.handled);
    try std.testing.expectEqual(error.InvalidResponse, shared.err.?);
}

test "HTTP/1 direct response writes retain informational then final sequence" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
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
            defer request.deinit(allocator);
            try connection.writeResponse(.{
                .status = 103,
                .reason = "Early Hints",
                .headers = &.{.{
                    .name = "Link",
                    .value = "</style.css>; rel=preload",
                }},
            });
            try connection.writeResponse(.{
                .status = 200,
                .reason = "OK",
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "final",
            });
        }
    };
    const Observer = struct {
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            response: runtime.InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (response.status != 103) @panic("unexpected status");
            if (!std.mem.eql(
                u8,
                response.header("link") orelse @panic("missing Link"),
                "</style.css>; rel=preload",
            )) @panic("unexpected Link");
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var observer: Observer = .{};
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var response = try client.requestWithInformational(
        .{ .target = "/", .host = "localhost" },
        .{
            .context = &observer,
            .on_response = Observer.observe,
        },
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observer.count);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 serve loop stops after protocol-switching responses" {
    const allocator = std.testing.allocator;

    inline for (.{
        .{
            .method = http1.Method.GET,
            .request = "GET /upgrade HTTP/1.1\r\n" ++
                "Host: localhost\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Upgrade: netz-test\r\n\r\n" ++
                "tunnel-bytes",
            .response = runtime.ResponseOptions{
                .status = 101,
                .reason = "Switching Protocols",
                .headers = &.{
                    .{ .name = "Connection", .value = "Upgrade" },
                    .{ .name = "Upgrade", .value = "netz-test" },
                },
            },
        },
        .{
            .method = http1.Method.CONNECT,
            .request = "CONNECT example.com:443 HTTP/1.1\r\n" ++
                "Host: example.com:443\r\n\r\n" ++
                "tunnel-bytes",
            .response = runtime.ResponseOptions{
                .status = 200,
                .reason = "Connection Established",
            },
        },
    }) |case| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var server = try runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{},
        );
        defer server.deinit();
        const Shared = struct {
            server: *runtime.Server,
            response: runtime.ResponseOptions,
            handled: usize = 0,
            served: ?usize = null,
            err: ?anyerror = null,

            fn handle(
                self: *@This(),
                _: http1.Request,
            ) runtime.Error!runtime.ResponseOptions {
                self.handled += 1;
                return self.response;
            }

            fn run(self: *@This()) void {
                self.served = self.server.serveConnection(
                    self,
                    @This().handle,
                    2,
                ) catch |err| {
                    self.err = err;
                    return;
                };
            }
        };
        var shared = Shared{
            .server = &server,
            .response = case.response,
        };
        const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) server_thread.join();

        const stream = try server.address().connect(io, .{ .mode = .stream });
        defer stream.close(io);
        try sendRawRequest(io, stream, case.request);
        var response = try runtime.readResponseFromStreamForRequest(
            allocator,
            io,
            stream,
            .{},
            .{},
            case.method,
        );
        defer response.deinit(allocator);
        try std.testing.expectEqual(case.response.status, response.response.status);

        server_thread.join();
        joined = true;
        try std.testing.expectEqual(@as(usize, 1), shared.handled);
        try std.testing.expectEqual(@as(?usize, 1), shared.served);
        try std.testing.expectEqual(@as(?anyerror, null), shared.err);
    }
}

test "HTTP/1 serveOne returns 400 for a malformed request head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        handled: bool = false,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled = true;
            return .{};
        }

        fn run(self: *@This()) void {
            self.server.serveOne(self, @This().handle) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try sendRawRequest(
        io,
        stream,
        "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n",
    );
    var response = try runtime.readResponseFromStream(
        allocator,
        io,
        stream,
        .{},
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 400), response.response.status);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );
    try std.testing.expectEqualStrings("", response.response.body);

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.MalformedHeader, shared.err.?);
    try std.testing.expect(!shared.handled);
}

test "HTTP/1 serveOne returns 414 for an oversized request target" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_request_target_bytes = 8,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        handled: bool = false,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled = true;
            return .{};
        }

        fn run(self: *@This()) void {
            self.server.serveOne(self, @This().handle) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try sendRawRequest(
        io,
        stream,
        "GET /too-long HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    var response = try runtime.readResponseFromStream(
        allocator,
        io,
        stream,
        .{},
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 414), response.response.status);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.UriTooLong, shared.err.?);
    try std.testing.expect(!shared.handled);
}

test "HTTP/1 serveOne does not reflect malformed request trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        handled: bool = false,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled = true;
            return .{};
        }

        fn run(self: *@This()) void {
            self.server.serveOne(self, @This().handle) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try sendRawRequest(
        io,
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "1\r\nx\r\n0\r\nBad Header: value\r\n\r\n",
    );
    var byte: [1]u8 = undefined;
    var reader = stream.reader(io, &byte);
    try std.testing.expectError(
        error.EndOfStream,
        reader.interface.takeByte(),
    );

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.MalformedHeader, shared.err.?);
    try std.testing.expect(!shared.handled);
}

test "HTTP/1 serveUntil returns 431 for too many headers and reuses worker" {
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
        .{
            .max_head_bytes = 4096,
            .max_request_headers = 2,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        err: ?anyerror = null,

        fn observe(context_ptr: *anyopaque, event: runtime.ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.err = event.err;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
    const Context = struct {
        handled: std.atomic.Value(usize) = .init(0),

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            _ = self.handled.fetchAdd(1, .release);
            return .{ .body = "ok" };
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer,
        context: Context,
        err: ?anyerror = null,

        fn init(server_ptr: *runtime.Server, io_value: std.Io) @This() {
            var shared: @This() = undefined;
            shared.server = server_ptr;
            shared.shutdown = .unset;
            shared.observer = .{ .io = io_value };
            shared.context = .{};
            shared.err = null;
            return shared;
        }

        fn run(self: *@This()) void {
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                8,
                .{
                    .shutdown = &self.shutdown,
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
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    const rejected_stream = try server.address().connect(io, .{
        .mode = .stream,
    });
    defer rejected_stream.close(io);
    try sendRawRequest(
        io,
        rejected_stream,
        "GET /too-many HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "X-Extra: one\r\n" ++
            "X-Other: two\r\n\r\n",
    );
    var rejected = try runtime.readResponseFromStream(
        allocator,
        io,
        rejected_stream,
        .{},
        .{},
    );
    defer rejected.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 431), rejected.response.status);
    try std.testing.expectEqualStrings(
        "0",
        rejected.response.header("content-length").?,
    );
    try std.testing.expectEqualStrings(
        "close",
        rejected.response.header("connection").?,
    );
    try std.testing.expectEqualStrings("", rejected.response.body);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(error.TooManyHeaders, shared.observer.err.?);
    try std.testing.expectEqual(
        @as(usize, 0),
        shared.context.handled.load(.acquire),
    );

    var client = try runtime.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
    );
    defer client.close();
    var response = try client.request(.{ .target = "/stop" });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
    shared.shutdown.set(io);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.observer.count.load(.acquire),
    );
}

test "HTTP/1 serveOne returns 431 for an oversized request head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 48 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        handled: bool = false,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled = true;
            return .{};
        }

        fn run(self: *@This()) void {
            self.server.serveOne(self, @This().handle) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try sendRawRequest(io, stream, "GET / HTTP/1.1\r\nHost: localhost\r\n");
    try sendRawRequest(io, stream, "X-Long: 012345678901234567890123456789\r\n\r\n");
    var response = try runtime.readResponseFromStream(
        allocator,
        io,
        stream,
        .{},
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 431), response.response.status);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.HeadersTooLarge, shared.err.?);
    try std.testing.expect(!shared.handled);
}

test "HTTP/1 serveUntil isolates malformed requests and reuses its worker" {
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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        stage: runtime.ServeErrorStage = .accept,

        fn observe(context_ptr: *anyopaque, event: runtime.ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.stage = event.stage;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
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
            return .{ .body = request.target };
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer,
        context: Context,
        err: ?anyerror = null,

        fn init(server_ptr: *runtime.Server, io_value: std.Io) @This() {
            var shared: @This() = undefined;
            shared.server = server_ptr;
            shared.shutdown = .unset;
            shared.observer = .{ .io = io_value };
            shared.context = .{
                .io = io_value,
                .shutdown = &shared.shutdown,
            };
            shared.err = null;
            return shared;
        }

        fn run(self: *@This()) void {
            self.context.shutdown = &self.shutdown;
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                8,
                .{
                    .shutdown = &self.shutdown,
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
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    const malformed = try server.address().connect(io, .{ .mode = .stream });
    var writer = malformed.writer(io, &.{});
    try writer.interface.writeAll("BROKEN\r\n\r\n");
    malformed.close(io);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(
        runtime.ServeErrorStage.connection,
        shared.observer.stage,
    );

    var client = try runtime.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
    );
    defer client.close();
    var first = try client.request(.{ .target = "/first" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("/first", first.response.body);
    var stop = try client.request(.{ .target = "/stop" });
    defer stop.deinit(allocator);
    try std.testing.expectEqualStrings("/stop", stop.response.body);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.observer.count.load(.acquire),
    );
}

test "HTTP/1 serveUntil can stop on a handler error" {
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
        .{},
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            return error.InvalidResponse;
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                1,
                .{
                    .shutdown = &self.shutdown,
                    .connection_error_policy = .stop,
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    var client = try runtime.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.ConnectionClosed,
        client.request(.{ .target = "/fail" }),
    );

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.InvalidResponse, shared.err.?);
}
