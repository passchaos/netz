const std = @import("std");
const grpc = @import("../mod.zig");
const codec = @import("../stream/codec.zig");

const allocator = std.testing.allocator;

test "ordinary Channel health gate follows a Watch and blocks NOT_SERVING" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    _ = try registry.setStatus("demo.Echo", .serving);

    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();

    const Handler = struct {
        fn run(
            connection: grpc.runtime.ServerConnection,
            registry_ptr: *grpc.health.Registry,
            response: []const u8,
        ) anyerror!void {
            var conn = connection;
            defer conn.deinit();
            while (true) {
                var stream = conn.acceptDuplexWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                    error.Canceled => return,
                    else => return err,
                };
                defer stream.deinit();
                if (std.mem.eql(u8, stream.path, grpc.health.watch_path)) {
                    try conn.serveHealthWatch(registry_ptr, &stream);
                    return;
                }
                const Context = struct {
                    got: bool = false,
                    fn consume(self: *@This(), message: codec.DecodedMessage) !void {
                        try std.testing.expectEqualStrings("ping", message.payload);
                        self.got = true;
                    }
                };
                var context: Context = .{};
                while (!context.got) {
                    var event = try stream.readRequestEvent(&context, Context.consume);
                    defer event.deinit();
                    switch (event) {
                        .messages => {},
                        .finished, .reset => return error.UnexpectedEndOfStream,
                    }
                }
                try stream.startResponse(.{});
                _ = try stream.writeMessage(response);
                try stream.finishOk();
            }
        }
    };

    const Peer = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.health.Registry,
        tasks: *[8]?std.Io.Future(anyerror!void),
        accepted: usize = 0,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            while (true) {
                const connection = self.server.acceptWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        self.err = err;
                        return;
                    },
                };
                if (self.accepted == self.tasks.len) {
                    self.err = error.TooManyConnections;
                    return;
                }
                self.tasks[self.accepted] = self.io.async(Handler.run, .{
                    connection,
                    self.registry,
                    "pong",
                });
                self.accepted += 1;
            }
        }
    };

    var tasks: [8]?std.Io.Future(anyerror!void) = .{null} ** 8;
    defer for (&tasks) |*task| {
        if (task.*) |*future| {
            _ = future.cancel(io) catch {};
        }
    };
    var peer = Peer{
        .server = &server,
        .registry = &registry,
        .tasks = &tasks,
        .io = io,
    };
    var peer_task = io.async(Peer.run, .{&peer});
    defer peer_task.cancel(io);

    var channel = try grpc.Channel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{ .health_check_service = "demo.Echo" },
    );
    defer channel.deinit();

    var response = try channel.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "ping",
        .timeout = .{ .value = 3, .unit = .second },
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);

    _ = try registry.setStatus("demo.Echo", .not_serving);
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try std.testing.expectError(
        error.ConnectionUnavailable,
        channel.unary(.{
            .path = "/demo.Echo/Unary",
            .message = "ping",
            .timeout = .{ .value = 1, .unit = .second },
        }),
    );

    const Recovery = struct {
        fn run(recovery_io: std.Io, registry_ptr: *grpc.health.Registry) void {
            std.Io.sleep(recovery_io, .fromMilliseconds(100), .awake) catch {};
            _ = registry_ptr.setStatus("demo.Echo", .serving) catch {};
        }
    };
    var recovery_task = io.async(Recovery.run, .{ io, &registry });
    defer recovery_task.cancel(io);
    var recovered = try channel.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "ping",
        .wait_for_ready = true,
        .timeout = .{ .value = 3, .unit = .second },
    });
    defer recovered.deinit();
    try std.testing.expectEqualStrings("pong", recovered.message.?.payload);

    if (peer.err) |err| return err;
}
