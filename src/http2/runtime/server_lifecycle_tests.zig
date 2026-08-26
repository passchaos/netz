const std = @import("std");
const runtime = @import("../runtime.zig");

test "HTTP/2 serveUntil isolates handshake errors and reuses its worker" {
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
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        stage: runtime.ServeErrorStage = .connection,

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
            request: runtime.OwnedRequest,
        ) runtime.Error!runtime.ResponseOptions {
            _ = self.handled.fetchAdd(1, .release);
            if (std.mem.eql(u8, request.path, "/stop")) {
                self.shutdown.set(self.io);
            }
            return .{ .body = request.path };
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
    try writer.interface.writeAll("not-an-http2-preface");
    malformed.close(io);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(runtime.ServeErrorStage.accept, shared.observer.stage);

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var first = try client.request(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("/first", first.body);
    var stop = try client.request(.{
        .method = "GET",
        .path = "/stop",
        .authority = "localhost",
    });
    defer stop.deinit(allocator);
    try std.testing.expectEqualStrings("/stop", stop.body);

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
