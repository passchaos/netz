const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

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
