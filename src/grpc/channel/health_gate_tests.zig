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
    try std.testing.expectEqual(@as(?bool, true), channel.healthServing());

    _ = try registry.setStatus("demo.Echo", .not_serving);
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try std.testing.expectEqual(@as(?bool, false), channel.healthServing());
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
    try std.testing.expectEqual(@as(?bool, true), channel.healthServing());

    if (peer.err) |err| return err;
}

test "ordinary Channel health gate covers streaming and duplex starts" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    _ = try registry.setStatus("demo.Echo", .not_serving);

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
        ) anyerror!void {
            var conn = connection;
            defer conn.deinit();
            var stream = try conn.acceptDuplexWithTimeout(.fromSeconds(3));
            defer stream.deinit();
            if (!std.mem.eql(u8, stream.path, grpc.health.watch_path)) {
                return error.UnexpectedPath;
            }
            try conn.serveHealthWatch(registry_ptr, &stream);
        }
    };

    const Peer = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.health.Registry,
        tasks: *[4]?std.Io.Future(anyerror!void),
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
                });
                self.accepted += 1;
            }
        }
    };

    var tasks: [4]?std.Io.Future(anyerror!void) = .{null} ** 4;
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

    try std.testing.expectError(
        error.ConnectionUnavailable,
        channel.startStreaming(.{
            .path = "/demo.Echo/Stream",
            .timeout = .{ .value = 1, .unit = .second },
        }),
    );
    try std.testing.expectError(
        error.ConnectionUnavailable,
        channel.startDuplex(.{
            .path = "/demo.Echo/Duplex",
            .timeout = .{ .value = 1, .unit = .second },
        }),
    );
    if (peer.err) |err| return err;
}

test "ordinary Channel health gate validates service names before allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var too_long: [grpc.health.max_service_name_len + 1]u8 = @splat('x');
    try std.testing.expectError(
        error.InvalidChannelOptions,
        grpc.Channel.init(
            allocator,
            io,
            .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(0) } } },
            .{ .health_check_service = &too_long },
        ),
    );
    var invalid_utf8 = [_]u8{0xff};
    try std.testing.expectError(
        error.InvalidChannelOptions,
        grpc.Channel.init(
            allocator,
            io,
            .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(0) } } },
            .{ .health_check_service = &invalid_utf8 },
        ),
    );
}

const HealthPeer = struct {
    server: *grpc.runtime.Server,
    registry: *grpc.health.Registry,
    io: std.Io,
    tasks: [8]?std.Io.Future(anyerror!void) = .{null} ** 8,
    accepted: usize = 0,
    err: ?anyerror = null,

    fn deinit(self: *HealthPeer) void {
        for (&self.tasks) |*task| {
            if (task.*) |*future| {
                _ = future.cancel(self.io) catch {};
            }
        }
    }

    fn run(self: *HealthPeer) void {
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
            self.tasks[self.accepted] = self.io.async(HealthPeer.handle, .{
                connection,
                self.registry,
            });
            self.accepted += 1;
        }
    }

    fn handle(
        connection: grpc.runtime.ServerConnection,
        registry: *grpc.health.Registry,
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
                try conn.serveHealthWatch(registry, &stream);
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
            _ = try stream.writeMessage("pong");
            try stream.finishOk();
        }
    }
};

test "ordinary Channel health gate selects serving endpoints independently" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var bad_registry = try grpc.health.Registry.init(allocator, io);
    defer bad_registry.deinit();
    _ = try bad_registry.setStatus("demo.Echo", .not_serving);
    var good_registry = try grpc.health.Registry.init(allocator, io);
    defer good_registry.deinit();
    _ = try good_registry.setStatus("demo.Echo", .serving);

    var bad_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer bad_server.deinit();
    var good_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer good_server.deinit();

    var bad_peer = HealthPeer{
        .server = &bad_server,
        .registry = &bad_registry,
        .io = io,
    };
    defer bad_peer.deinit();
    var bad_task = io.async(HealthPeer.run, .{&bad_peer});
    defer bad_task.cancel(io);

    var good_peer = HealthPeer{
        .server = &good_server,
        .registry = &good_registry,
        .io = io,
    };
    defer good_peer.deinit();
    var good_task = io.async(HealthPeer.run, .{&good_peer});
    defer good_task.cancel(io);

    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = bad_server.address() } },
        .{ .cleartext_ip = .{ .address = good_server.address() } },
    };
    var channel = try grpc.Channel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints, .policy = .pick_first } },
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
    try std.testing.expectEqual(@as(?bool, false), channel.healthServingAt(0));
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(1));
    try std.testing.expectEqual(@as(?bool, true), channel.healthServing());

    _ = try good_registry.setStatus("demo.Echo", .not_serving);
    try waitHealthStatus(&channel, io, .{ .index = .{ .index = 1, .expected = false } });
    try waitHealthStatus(&channel, io, .{ .aggregate = .{ .expected = false } });
    try std.testing.expectEqual(@as(?bool, false), channel.healthServing());
    try std.testing.expectError(
        error.ConnectionUnavailable,
        channel.unary(.{
            .path = "/demo.Echo/Unary",
            .message = "ping",
            .timeout = .{ .value = 1, .unit = .second },
        }),
    );

    _ = try bad_registry.setStatus("demo.Echo", .serving);
    try waitHealthStatus(&channel, io, .{ .index = .{ .index = 0, .expected = true } });
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    try std.testing.expectEqual(@as(?bool, true), channel.healthServing());
    var recovered = try channel.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "ping",
        .timeout = .{ .value = 3, .unit = .second },
    });
    defer recovered.deinit();
    try std.testing.expectEqualStrings("pong", recovered.message.?.payload);

    if (bad_peer.err) |err| return err;
    if (good_peer.err) |err| return err;
}

const HealthStatusWait = union(enum) {
    index: struct { index: usize, expected: ?bool },
    aggregate: struct { expected: ?bool },
};

fn waitHealthStatus(
    channel: *const grpc.Channel,
    io: std.Io,
    wait: HealthStatusWait,
) !void {
    var attempts: usize = 0;
    while (true) : (attempts += 1) {
        var current: ?bool = undefined;
        var expected: ?bool = undefined;
        switch (wait) {
            .index => |query| {
                current = channel.healthServingAt(query.index);
                expected = query.expected;
            },
            .aggregate => |query| {
                current = channel.healthServing();
                expected = query.expected;
            },
        }
        if (std.meta.eql(current, expected)) return;
        if (attempts == 200) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(5), .awake);
    }
}
