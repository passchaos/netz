const std = @import("std");
const grpc = @import("mod.zig");
const http2 = @import("../http2/mod.zig");
const tls_testing = @import("../tls/testing.zig");

test "gRPC h2c runtime reuses one channel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.deinit();
            for (0..2) |index| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                const expected = if (index == 0) "one" else "two";
                if (!std.mem.eql(
                    u8,
                    request.request.message.payload,
                    expected,
                )) {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnary(request.request.stream_id, .{
                    .message = if (index == 0) "first" else "second",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var first = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "one",
    });
    defer first.deinit();
    var second = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "two",
    });
    defer second.deinit();
    try std.testing.expectEqualStrings("first", first.message.?.payload);
    try std.testing.expectEqualStrings("second", second.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "gRPC h2c unary retry reuses one deadline and reports attempts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        attempts: usize = 0,
        first_timeout_ns: i96 = 0,
        last_timeout_ns: i96 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            for (0..3) |index| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                self.attempts += 1;
                const previous = grpc.call.headerValue(
                    request.request.headers,
                    "grpc-previous-rpc-attempts",
                );
                if (index == 0) {
                    if (previous != null) {
                        self.err = error.InvalidMetadata;
                        return;
                    }
                    self.first_timeout_ns =
                        request.request.timeout.?.duration().nanoseconds;
                } else {
                    var expected_buffer: [1]u8 = undefined;
                    const expected = std.fmt.bufPrint(
                        &expected_buffer,
                        "{d}",
                        .{index},
                    ) catch unreachable;
                    if (!std.mem.eql(u8, previous orelse "", expected)) {
                        self.err = error.InvalidMetadata;
                        return;
                    }
                    self.last_timeout_ns =
                        request.request.timeout.?.duration().nanoseconds;
                }
                connection.writeUnary(request.request.stream_id, if (index < 2) .{
                    .status = .unavailable,
                    .status_message = "retry",
                    .retry_pushback_ms = 1,
                    .trailers_only = true,
                } else .{ .message = "ready" }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var response = try client.unaryWithRetry(.{
        .path = "/demo.Retry/Unary",
        .authority = "localhost",
        .message = "once",
        .timeout = try grpc.Timeout.init(2, .second),
    }, .{
        .max_attempts = 3,
        .initial_backoff = .fromSeconds(1),
        .max_backoff = .fromSeconds(2),
        .backoff_multiplier = 2,
        .retryable_status_codes = &.{.unavailable},
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("ready", response.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), shared.attempts);
    try std.testing.expect(shared.last_timeout_ns < shared.first_timeout_ns);
}

test "gRPC h2c unary retry honors negative server pushback" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        attempts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            self.attempts += 1;
            connection.writeUnary(request.request.stream_id, .{
                .status = .unavailable,
                .retry_pushback_ms = -1,
                .trailers_only = true,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var response = try client.unaryWithRetry(.{
        .path = "/demo.Retry/Unary",
        .authority = "localhost",
        .message = "once",
    }, .{
        .max_attempts = 5,
        .initial_backoff = .fromMilliseconds(1),
        .max_backoff = .fromMilliseconds(10),
        .backoff_multiplier = 2,
        .retryable_status_codes = &.{.unavailable},
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.attempts);
}

test "gRPC h2c unary retry throttling suppresses a new attempt" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        attempts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            self.attempts += 1;
            connection.writeUnary(request.request.stream_id, .{
                .status = .unavailable,
                .trailers_only = true,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var throttler = try grpc.RetryThrottler.init(2, 1);
    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var response = try client.unaryWithRetry(.{
        .path = "/demo.Retry/Unary",
        .authority = "localhost",
        .message = "once",
    }, .{
        .max_attempts = 5,
        .initial_backoff = .fromMilliseconds(1),
        .max_backoff = .fromMilliseconds(10),
        .backoff_multiplier = 2,
        .retryable_status_codes = &.{.unavailable},
        .throttler = &throttler,
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.attempts);
    try std.testing.expectEqual(@as(u64, 1000), throttler.milliTokens());
}

test "gRPC h2c unary retry does not replay a committed response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        attempts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            self.attempts += 1;
            connection.writeUnary(request.request.stream_id, .{
                .status = .unavailable,
                .message = "committed",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var response = try client.unaryWithRetry(.{
        .path = "/demo.Retry/Unary",
        .authority = "localhost",
        .message = "once",
    }, .{
        .max_attempts = 5,
        .initial_backoff = .fromMilliseconds(1),
        .max_backoff = .fromMilliseconds(10),
        .backoff_multiplier = 2,
        .retryable_status_codes = &.{.unavailable},
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);
    try std.testing.expectEqualStrings(
        "committed",
        response.message.?.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.attempts);
}

test "gRPC h2c unary retry backoff cannot renew the RPC deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        attempts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            self.attempts += 1;
            connection.writeUnary(request.request.stream_id, .{
                .status = .unavailable,
                .trailers_only = true,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    try std.testing.expectError(error.Timeout, client.unaryWithRetry(.{
        .path = "/demo.Retry/Unary",
        .authority = "localhost",
        .message = "once",
        .timeout = try grpc.Timeout.init(100, .millisecond),
    }, .{
        .max_attempts = 3,
        .initial_backoff = .fromSeconds(1),
        .max_backoff = .fromSeconds(1),
        .backoff_multiplier = 1,
        .retryable_status_codes = &.{.unavailable},
    }));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.attempts);
}

test "gRPC h2c health Check serves known and unknown services" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    try std.testing.expect(try registry.setStatus(
        "demo.Echo",
        .serving,
    ));
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.health.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            for (0..3) |_| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                connection.writeHealthCheck(
                    self.registry,
                    &request,
                ) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    const known = try client.healthCheck(.{
        .authority = "localhost",
        .service = "demo.Echo",
    });
    try std.testing.expectEqual(
        grpc.health.ServingStatus.serving,
        known.response.status,
    );
    const missing = try client.healthCheck(.{
        .authority = "localhost",
        .service = "demo.Missing",
    });
    try std.testing.expectEqual(grpc.Status.not_found, missing.rpc_failure);

    var malformed = try client.unary(.{
        .path = grpc.health.check_path,
        .authority = "localhost",
        .message = &.{ 0x0a, 0x02, 'x' },
    });
    defer malformed.deinit();
    try std.testing.expectEqual(grpc.Status.invalid_argument, malformed.status);
    try std.testing.expectEqualStrings(
        "could not parse request",
        malformed.status_message,
    );
    try std.testing.expect(malformed.message == null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c health Watch streams changes and observes cancellation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.health.Registry,
        watch_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var watch = try connection.acceptDuplex();
            var watch_live = true;
            defer if (watch_live) watch.deinit();
            try connection.serveHealthWatch(self.registry, &watch);
            watch.deinit();
            watch_live = false;
            self.watch_done.set(self.registry.io);

            var request = try connection.readUnary();
            defer request.deinit();
            try std.testing.expectEqualStrings(
                "after",
                request.request.message.payload,
            );
            try connection.writeUnary(request.request.stream_id, .{
                .message = "reused",
            });
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var watch = try client.startHealthWatch(.{
        .authority = "localhost",
        .service = "demo.Echo",
    });
    var watch_live = true;
    defer if (watch_live) watch.deinit();

    var initial = try watch.nextWithTimeout(.fromSeconds(2));
    defer initial.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.service_unknown,
        initial.status.status,
    );
    try std.testing.expectError(
        error.Timeout,
        watch.nextWithTimeout(.fromMilliseconds(1)),
    );
    // Queue a sibling unary request while Watch owns the connection reader.
    // The server must keep streaming Watch updates while preserving this
    // request, and the client must preserve its response for the later read.
    var sibling = try client.startStreaming(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
    });
    defer sibling.deinit();
    try sibling.writeMessage("after");
    try sibling.finish();
    try std.testing.expect(try registry.setStatus(
        "demo.Echo",
        .serving,
    ));
    var serving = try watch.nextWithTimeout(.fromSeconds(2));
    defer serving.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.serving,
        serving.status.status,
    );
    try std.testing.expect(try registry.setStatus(
        "demo.Echo",
        .not_serving,
    ));
    var not_serving = try watch.nextWithTimeout(.fromSeconds(2));
    defer not_serving.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.not_serving,
        not_serving.status.status,
    );
    try std.testing.expect(try registry.clearStatus("demo.Echo"));
    var cleared = try watch.nextWithTimeout(.fromSeconds(2));
    defer cleared.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.service_unknown,
        cleared.status.status,
    );

    try watch.cancel();
    watch.deinit();
    watch_live = false;
    try shared.watch_done.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    const Collector = struct {
        count: usize = 0,

        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            if (self.count != 0) return error.UnexpectedMessage;
            try std.testing.expectEqualStrings("reused", message.payload);
            self.count += 1;
        }
    };
    var collector: Collector = .{};
    var response = try sibling.readResponse(&collector, Collector.consume);
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqual(@as(usize, 1), collector.count);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c health Watch rejects malformed protobuf" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.health.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var stream = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            defer stream.deinit();
            connection.serveHealthWatch(
                self.registry,
                &stream,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    const Consumer = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var stream = try client.startDuplex(.{
        .path = grpc.health.watch_path,
        .authority = "localhost",
    });
    defer stream.deinit();
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try stream.writeFinalMessage(&.{ 0x0a, 0x02, 'x' }),
    );
    var terminal = try stream.readResponseEvent({}, Consumer.consume);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(
        grpc.Status.internal,
        terminal.terminal.status,
    );
    try std.testing.expectEqualStrings(
        "could not parse request",
        terminal.terminal.status_message,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c runtime composes sequential message streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 64, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        received: usize = 0,
        err: ?anyerror = null,

        fn consume(
            self: *@This(),
            message: grpc.StreamingMessage,
        ) !void {
            const expected = switch (self.received) {
                0 => "one",
                1 => "two",
                else => return error.UnexpectedMessage,
            };
            if (!std.mem.eql(u8, message.payload, expected)) {
                return error.InvalidGrpcRequest;
            }
            self.received += 1;
        }

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var request = try connection.readStreaming(self, consume);
            defer request.deinit();
            if (!std.mem.eql(u8, request.service, "demo.Echo") or
                !std.mem.eql(u8, request.method, "Stream") or
                request.message_count != 2)
            {
                return error.InvalidGrpcRequest;
            }
            var response = try connection.startStreamingResponse(
                request.transport.stream_id,
                .{
                    .request_accepted_encodings = request.accepted_encodings,
                },
            );
            defer response.deinit();
            try response.writeMessage("first");
            try response.writeMessage("second");
            try response.finishOk();
        }
    };

    const Collector = struct {
        count: usize = 0,

        fn consume(
            self: *@This(),
            message: grpc.StreamingMessage,
        ) !void {
            const expected = switch (self.count) {
                0 => "first",
                1 => "second",
                else => return error.UnexpectedMessage,
            };
            if (!std.mem.eql(u8, message.payload, expected)) {
                return error.UnexpectedMessage;
            }
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 64, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var stream = try client.startStreaming(.{
        .path = "/demo.Echo/Stream",
        .authority = "localhost",
    });
    defer stream.deinit();
    try stream.writeMessage("one");
    try stream.writeMessage("two");
    var collector: Collector = .{};
    var response = try stream.finishAndRead(
        &collector,
        Collector.consume,
    );
    defer response.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.received);
    try std.testing.expectEqual(@as(usize, 2), collector.count);
    try std.testing.expectEqual(grpc.Status.ok, response.status);
}

test "gRPC sequential stream may cancel after request FIN and reuse channel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
        .max_body_bytes = 4096,
    };
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        request_finished: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(
                .fromSeconds(2),
            );
            var stream_live = true;
            defer if (stream_live) stream.deinit();
            var finished = try stream.readRequestEventWithTimeout(
                .fromSeconds(2),
                {},
                consume,
            );
            defer finished.deinit();
            try std.testing.expect(finished == .finished);
            self.request_finished.set(self.server.transport.io);
            const reset = try stream.waitForPeerResetWithTimeout(
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.error_code,
            );
            stream.deinit();
            stream_live = false;

            var next = try connection.readUnary();
            defer next.deinit();
            try connection.writeUnary(next.request.stream_id, .{
                .message = "reused",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.deinit();
    var stream = try client.startStreaming(.{
        .path = "/demo.Stream/Cancel",
        .authority = "localhost",
    });
    try stream.finish();
    try shared.request_finished.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    try stream.cancel();
    stream.deinit();

    var response = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "next",
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("reused", response.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC sequential stream deadline bounds flow control wait" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
        .max_body_bytes = 4096,
        .initial_window_size = 5,
    };
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,

        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            try std.Io.sleep(
                self.server.transport.io,
                .fromMilliseconds(200),
                .awake,
            );
            var stream = try connection.acceptDuplexWithTimeout(
                .fromSeconds(2),
            );
            defer stream.deinit();
            while (true) {
                var event = try stream.readRequestEventWithTimeout(
                    .fromSeconds(2),
                    {},
                    consume,
                );
                defer event.deinit();
                switch (event) {
                    .reset => |reset| {
                        try std.testing.expectEqual(
                            http2.ErrorCode.cancel,
                            reset.error_code,
                        );
                        break;
                    },
                    .messages => {},
                    .finished => return error.UnexpectedFrame,
                }
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.deinit();
    var stream = try client.startStreaming(.{
        .path = "/demo.Stream/Deadline",
        .authority = "localhost",
        .timeout = try grpc.Timeout.init(50, .millisecond),
    });
    try std.testing.expectError(error.Timeout, stream.writeMessage("blocked"));
    stream.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC sequential stream deadline bounds response wait" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
        .max_body_bytes = 4096,
    };
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,

        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(
                .fromSeconds(2),
            );
            defer stream.deinit();
            var finished = try stream.readRequestEventWithTimeout(
                .fromSeconds(2),
                {},
                consume,
            );
            defer finished.deinit();
            try std.testing.expect(finished == .finished);
            const reset = try stream.waitForPeerResetWithTimeout(
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.error_code,
            );
        }
    };
    const Consumer = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.deinit();
    var stream = try client.startStreaming(.{
        .path = "/demo.Stream/Deadline",
        .authority = "localhost",
        .timeout = try grpc.Timeout.init(100, .millisecond),
    });
    defer stream.deinit();
    try stream.finish();
    try std.testing.expectError(
        error.Timeout,
        stream.readResponse({}, Consumer.consume),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c reflection serves ordered v1 queries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = grpc.reflection.Registry.init(allocator, io);
    defer registry.deinit();
    try registry.addFile(.{
        .name = "echo.proto",
        .descriptor = "echo-descriptor",
        .symbols = &.{"demo.Echo"},
    });
    try registry.addService("demo.Echo");
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        4096,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.reflection.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var stream = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            defer stream.deinit();
            connection.serveReflection(self.registry, &stream) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var reflection = try client.startReflection(.{
        .authority = "localhost",
    });
    defer reflection.deinit();

    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.writeRequest(.{
            .host = "example.test",
            .query = .{ .list_services = "" },
        }),
    );
    var services = try reflection.nextWithTimeout(.fromSeconds(2));
    defer services.deinit();
    try std.testing.expectEqualStrings(
        "example.test",
        services.response.value.valid_host,
    );
    try std.testing.expectEqual(@as(usize, 1), services.response.value.result.services.len);
    try std.testing.expectEqualStrings(
        "demo.Echo",
        services.response.value.result.services[0],
    );

    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.writeRequest(.{
            .query = .{ .file_containing_symbol = "demo.Echo" },
        }),
    );
    var descriptor = try reflection.nextWithTimeout(.fromSeconds(2));
    defer descriptor.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        descriptor.response.value.result.file_descriptors.len,
    );
    try std.testing.expectEqualStrings(
        "echo-descriptor",
        descriptor.response.value.result.file_descriptors[0],
    );

    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.writeRequest(.{
            .query = .{ .file_by_filename = "missing.proto" },
        }),
    );
    var missing = try reflection.nextWithTimeout(.fromSeconds(2));
    defer missing.deinit();
    try std.testing.expectEqual(
        grpc.Status.not_found,
        missing.response.value.result.failure.code,
    );
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.finishRequests(),
    );
    var terminal = try reflection.nextWithTimeout(.fromSeconds(2));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c reflection supports v1alpha and cancellation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = grpc.reflection.Registry.init(allocator, io);
    defer registry.deinit();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        4096,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.reflection.Registry,
        reflection_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var stream = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            var stream_live = true;
            defer if (stream_live) stream.deinit();
            connection.serveReflection(self.registry, &stream) catch |err| {
                self.err = err;
                return;
            };
            stream.deinit();
            stream_live = false;
            self.reflection_done.set(self.registry.io);

            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            connection.writeUnary(request.request.stream_id, .{
                .message = "reused",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var reflection = try client.startReflection(.{
        .version = .v1alpha,
        .authority = "localhost",
    });
    var reflection_live = true;
    defer if (reflection_live) reflection.deinit();
    try std.testing.expectError(
        error.Timeout,
        reflection.nextWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.writeRequest(.{ .query = .{ .list_services = "" } }),
    );
    var response = try reflection.nextWithTimeout(.fromSeconds(2));
    defer response.deinit();
    try std.testing.expectEqual(@as(usize, 0), response.response.value.result.services.len);
    try reflection.cancel();
    reflection.deinit();
    reflection_live = false;
    try shared.reflection_done.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    var reused = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "after",
    });
    defer reused.deinit();
    try std.testing.expectEqualStrings("reused", reused.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC h2c reflection rejects malformed requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = grpc.reflection.Registry.init(allocator, io);
    defer registry.deinit();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        4096,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        registry: *grpc.reflection.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var stream = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            defer stream.deinit();
            connection.serveReflection(self.registry, &stream) catch |err| {
                self.err = err;
            };
        }
    };
    const Consumer = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var stream = try client.startDuplex(.{
        .path = grpc.reflection.v1_path,
        .authority = "localhost",
    });
    defer stream.deinit();
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try stream.writeFinalMessage(&.{ 0x1a, 0x02, 'x' }),
    );
    var event = try stream.readResponseEvent({}, Consumer.consume);
    defer event.deinit(allocator);
    try std.testing.expect(event == .initial_metadata);
    event.deinit(allocator);
    event = try stream.readResponseEvent({}, Consumer.consume);
    try std.testing.expectEqual(
        grpc.Status.invalid_argument,
        event.terminal.status,
    );
    try std.testing.expectEqualStrings(
        "could not parse request",
        event.terminal.status_message,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC TLS runtime verifies ALPN and reuses one channel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.TlsServer,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.deinit();
            if (!std.mem.eql(
                u8,
                connection.negotiatedAlpn() orelse {
                    self.err = error.InvalidAlpn;
                    return;
                },
                "h2",
            )) {
                self.err = error.InvalidAlpn;
                return;
            }
            for (0..2) |index| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                const expected = if (index == 0) "one" else "two";
                if (!std.mem.eql(
                    u8,
                    request.request.message.payload,
                    expected,
                )) {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnary(request.request.stream_id, .{
                    .message = if (index == 0) "first" else "second",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "h2",
        client.negotiatedAlpn().?,
    );
    var first = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "one",
    });
    defer first.deinit();
    var second = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "two",
    });
    defer second.deinit();
    try std.testing.expectEqual(grpc.Status.ok, first.status);
    try std.testing.expectEqualStrings("first", first.message.?.payload);
    try std.testing.expectEqualStrings("second", second.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "gRPC TLS runtime serves health Check" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    try std.testing.expect(registry.enterGracefulShutdown());
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.TlsServer,
        registry: *grpc.health.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            connection.writeHealthCheck(
                self.registry,
                &request,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
    );
    defer client.deinit();
    const result = try client.healthCheck(.{});
    try std.testing.expectEqual(
        grpc.health.ServingStatus.not_serving,
        result.response.status,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC TLS runtime streams health Watch updates" {
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
    const public_key = key_pair.public_key.toUncompressedSec1();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.TlsServer,
        registry: *grpc.health.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var watch = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            defer watch.deinit();
            connection.serveHealthWatch(
                self.registry,
                &watch,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
    );
    defer client.deinit();
    var watch = try client.startHealthWatch(.{});
    defer watch.deinit();
    var initial = try watch.nextWithTimeout(.fromSeconds(2));
    defer initial.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.serving,
        initial.status.status,
    );
    try std.testing.expect(try registry.setStatus("", .not_serving));
    var changed = try watch.nextWithTimeout(.fromSeconds(2));
    defer changed.deinit();
    try std.testing.expectEqual(
        grpc.health.ServingStatus.not_serving,
        changed.status.status,
    );
    try watch.cancel();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC TLS runtime serves reflection v1" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var registry = grpc.reflection.Registry.init(allocator, io);
    defer registry.deinit();
    try registry.addService("demo.Tls");
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        }, .max_message_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.TlsServer,
        registry: *grpc.reflection.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var stream = connection.acceptDuplex() catch |err| {
                self.err = err;
                return;
            };
            defer stream.deinit();
            connection.serveReflection(self.registry, &stream) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
    );
    defer client.deinit();
    var reflection = try client.startReflection(.{});
    defer reflection.deinit();
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.writeRequest(.{ .query = .{ .list_services = "" } }),
    );
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try reflection.finishRequests(),
    );
    var response = try reflection.nextWithTimeout(.fromSeconds(2));
    defer response.deinit();
    try std.testing.expectEqualStrings(
        "demo.Tls",
        response.response.value.result.services[0],
    );
    var terminal = try reflection.nextWithTimeout(.fromSeconds(2));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
