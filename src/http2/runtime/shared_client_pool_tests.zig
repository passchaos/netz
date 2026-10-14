const std = @import("std");
const http2 = @import("../mod.zig");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");

fn waitQueued(io: std.Io, dispatcher: *pool_mod.SharedDispatcher, expected: usize) !void {
    for (0..500) |_| {
        if (dispatcher.queuedCount() == expected) return;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

fn findHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP/2 shared senders coalesce concurrent requests through one driver" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .initial_window_size = 4096 },
    );
    defer server.deinit();

    const ServerWorker = struct {
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
            var requests: [3]runtime.StreamingRequest = undefined;
            const BodyContext = struct {
                counts: [3]usize = .{ 0, 0, 0 },
                fn consume(context: *@This(), _: u31, data: []const u8) !void {
                    for (data) |byte| switch (byte) {
                        'a' => context.counts[0] += 1,
                        'b' => context.counts[1] += 1,
                        'c' => context.counts[2] += 1,
                        else => return error.InvalidRequest,
                    };
                }
            };
            var body_context: BodyContext = .{};
            try connection.readRequestBatchStreamingInto(
                &requests,
                &body_context,
                BodyContext.consume,
            );
            defer for (&requests) |*request| request.deinit(self.server.allocator);
            for (&requests) |*request| {
                try std.testing.expectEqualStrings("POST", request.method);
                try std.testing.expectEqual(@as(usize, 32 * 1024), request.body_bytes);
                const expected_trailer: []const u8 = if (std.mem.eql(
                    u8,
                    request.path,
                    "/one",
                ))
                    "one"
                else if (std.mem.eql(u8, request.path, "/two"))
                    "two"
                else if (std.mem.eql(u8, request.path, "/three"))
                    "three"
                else
                    return error.InvalidRequest;
                try std.testing.expectEqualStrings(
                    expected_trailer,
                    findHeader(
                        request.trailers,
                        "x-shared-request-finished",
                    ).?,
                );
            }
            for (body_context.counts) |count| {
                try std.testing.expectEqual(@as(usize, 32 * 1024), count);
            }
            var stream_ids: [requests.len]u31 = undefined;
            var fields: [requests.len]http2.Hpack.HeaderField = undefined;
            var responses: [requests.len]runtime.ResponseOptions = undefined;
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                const out = requests.len - 1 - index;
                stream_ids[out] = requests[index].stream_id;
                fields[out] = .{ .name = "x-path", .value = requests[index].path };
                responses[out] = .{
                    .headers = fields[out..][0..1],
                    .request_method = requests[index].method,
                };
            }
            try connection.writeResponseBatch(&stream_ids, &responses);
        }
    };
    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        request: runtime.RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.response = self.sender.requestWithDeadline(
                self.uri,
                self.request,
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var server_worker = ServerWorker{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerWorker.run, .{&server_worker});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .batch_body_chunk_size = 1024,
    });
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 8, .max_batch_requests = 8 },
    );
    defer dispatcher.deinit();
    const base = try std.fmt.allocPrint(allocator, "http://localhost:{d}", .{server.address().ip4.port});
    defer allocator.free(base);
    const first_uri = try std.fmt.allocPrint(allocator, "{s}/one", .{base});
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(allocator, "{s}/two", .{base});
    defer allocator.free(second_uri);
    const third_uri = try std.fmt.allocPrint(allocator, "{s}/three", .{base});
    defer allocator.free(third_uri);
    const sender = dispatcher.sender();
    const first_body = [_]u8{'a'} ** (32 * 1024);
    const second_body = [_]u8{'b'} ** (32 * 1024);
    const third_body = [_]u8{'c'} ** (32 * 1024);
    const deadlines = [_]std.Io.Clock.Timestamp{
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(6), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(7), .clock = .awake }),
    };
    var producers = [_]Producer{
        .{
            .sender = sender.clone(),
            .uri = first_uri,
            .deadline = deadlines[0],
            .request = .{
                .method = "POST",
                .body = &first_body,
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "one",
                }},
            },
        },
        .{
            .sender = sender.clone(),
            .uri = second_uri,
            .deadline = deadlines[1],
            .request = .{
                .method = "POST",
                .body = &second_body,
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "two",
                }},
            },
        },
        .{
            .sender = sender.clone(),
            .uri = third_uri,
            .deadline = deadlines[2],
            .request = .{
                .method = "POST",
                .body = &third_body,
                .trailers = &.{.{
                    .name = "x-shared-request-finished",
                    .value = "three",
                }},
            },
        },
    };
    var threads: [producers.len]std.Thread = undefined;
    for (&threads, &producers) |*thread, *producer| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{producer});
    }
    try waitQueued(io, &dispatcher, producers.len);
    var driver = try std.Io.concurrent(io, pool_mod.SharedDispatcher.run, .{&dispatcher});
    for (&threads) |*thread| thread.join();
    dispatcher.close();
    try driver.await(io);

    const expected = [_][]const u8{ "/one", "/two", "/three" };
    for (&producers, expected) |*producer, path| {
        if (producer.err) |err| {
            std.debug.print("shared body batch producer failed: {s}\n", .{@errorName(err)});
            if (server_worker.err) |server_err| {
                std.debug.print("shared body batch server failed: {s}\n", .{@errorName(server_err)});
            }
            return err;
        }
        var response = producer.response.?;
        try std.testing.expectEqualStrings(path, findHeader(response.headers, "x-path").?);
        response.deinit(allocator);
        producer.response = null;
    }
    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.batches);
    try std.testing.expectEqual(@as(u64, 3), stats.coalesced_requests);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
}

test "HTTP/2 shared senders coalesce independent bodyless deadlines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const ServerWorker = struct {
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
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/same-one", first.path);
            try std.testing.expectEqualStrings("/same-two", second.path);
            const stream_ids = [_]u31{ second.stream_id, first.stream_id };
            const headers = [_]http2.Hpack.HeaderField{
                .{ .name = "x-path", .value = second.path },
                .{ .name = "x-path", .value = first.path },
            };
            const responses = [_]runtime.ResponseOptions{
                .{ .headers = headers[0..1] },
                .{ .headers = headers[1..2] },
            };
            try connection.writeResponseBatch(&stream_ids, &responses);

            var third = try connection.readRequest();
            defer third.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/different", third.path);
            try connection.writeResponse(third.stream_id, .{
                .headers = &.{.{ .name = "x-path", .value = third.path }},
            });
        }
    };

    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        deadline: std.Io.Clock.Timestamp,
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.response = self.sender.requestWithDeadline(
                self.uri,
                .{},
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var server_worker = ServerWorker{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 8, .max_batch_requests = 8 },
    );
    defer dispatcher.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const first_uri = try std.fmt.allocPrint(allocator, "{s}/same-one", .{base});
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(allocator, "{s}/same-two", .{base});
    defer allocator.free(second_uri);
    const third_uri = try std.fmt.allocPrint(allocator, "{s}/different", .{base});
    defer allocator.free(third_uri);
    const common_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    const different_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(6),
        .clock = .awake,
    });
    const sender = dispatcher.sender();
    var producers = [_]Producer{
        .{ .sender = sender.clone(), .uri = first_uri, .deadline = common_deadline },
        .{ .sender = sender.clone(), .uri = second_uri, .deadline = common_deadline },
        .{ .sender = sender.clone(), .uri = third_uri, .deadline = different_deadline },
    };
    var threads: [producers.len]std.Thread = undefined;
    for (&threads, &producers, 1..) |*thread, *producer, queued| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{producer});
        try waitQueued(io, &dispatcher, queued);
    }
    var driver = try std.Io.concurrent(
        io,
        pool_mod.SharedDispatcher.run,
        .{&dispatcher},
    );
    for (&threads) |*thread| thread.join();
    dispatcher.close();
    try driver.await(io);

    const expected = [_][]const u8{ "/same-one", "/same-two", "/different" };
    for (&producers, expected) |*producer, path| {
        if (producer.err) |err| return err;
        var response = producer.response.?;
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings(
            path,
            findHeader(response.headers, "x-path").?,
        );
    }
    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.batches);
    try std.testing.expectEqual(@as(u64, 3), stats.coalesced_requests);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
}

test "HTTP/2 shared sender timeout preserves later-deadline sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const ServerWorker = struct {
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
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            const timed = if (std.mem.eql(u8, first.path, "/timeout"))
                &first
            else if (std.mem.eql(u8, second.path, "/timeout"))
                &second
            else
                return error.InvalidRequest;
            const sibling = if (timed == &first) &second else &first;
            try std.testing.expectEqualStrings("/sibling", sibling.path);
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(timed.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
            try connection.writeResponse(sibling.stream_id, .{
                .headers = &.{.{
                    .name = "x-path",
                    .value = sibling.path,
                }},
                .body = "sibling-finished",
            });
        }
    };

    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        io: std.Io,
        start: *std.Io.Event,
        deadline: *const std.Io.Clock.Timestamp,
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.start.wait(self.io) catch |err| {
                self.err = err;
                return;
            };
            self.response = self.sender.requestWithDeadline(
                self.uri,
                .{},
                self.deadline.*,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var server_worker = ServerWorker{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 4, .max_batch_requests = 4 },
    );
    defer dispatcher.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const first_uri = try std.fmt.allocPrint(allocator, "{s}/timeout", .{base});
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(allocator, "{s}/sibling", .{base});
    defer allocator.free(second_uri);
    const sender = dispatcher.sender();
    var start: std.Io.Event = .unset;
    var deadlines: [2]std.Io.Clock.Timestamp = undefined;
    var producers = [_]Producer{
        .{ .sender = sender.clone(), .uri = first_uri, .io = io, .start = &start, .deadline = &deadlines[0] },
        .{ .sender = sender.clone(), .uri = second_uri, .io = io, .start = &start, .deadline = &deadlines[1] },
    };
    var threads: [producers.len]std.Thread = undefined;
    for (&threads, &producers) |*thread, *producer| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{producer});
    }
    deadlines[0] = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(250),
        .clock = .awake,
    });
    deadlines[1] = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    start.set(io);
    try waitQueued(io, &dispatcher, producers.len);
    var driver = try std.Io.concurrent(
        io,
        pool_mod.SharedDispatcher.run,
        .{&dispatcher},
    );
    for (&threads) |*thread| thread.join();
    dispatcher.close();
    try driver.await(io);

    try std.testing.expectEqual(error.Timeout, producers[0].err.?);
    try std.testing.expect(producers[0].response == null);
    try std.testing.expect(producers[1].err == null);
    var sibling_response = producers[1].response.?;
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings("sibling-finished", sibling_response.body);
    try std.testing.expectEqualStrings(
        "/sibling",
        findHeader(sibling_response.headers, "x-path").?,
    );
    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.batches);
    try std.testing.expectEqual(@as(u64, 2), stats.coalesced_requests);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
}

test "HTTP/2 shared task cancellation wakes blocked frame reader" {
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

    const ServerWorker = struct {
        server: *runtime.Server,
        io: std.Io,
        requests_ready: std.Io.Event = .unset,
        saw_cancel: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            const canceled = if (std.mem.eql(
                u8,
                first.path,
                "/active-cancel",
            ))
                &first
            else if (std.mem.eql(u8, second.path, "/active-cancel"))
                &second
            else
                return error.InvalidRequest;
            const sibling = if (canceled == &first) &second else &first;
            try std.testing.expectEqualStrings(
                "/active-sibling",
                sibling.path,
            );
            self.requests_ready.set(self.io);

            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(3),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(canceled.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
            self.saw_cancel = true;
            try connection.writeResponse(sibling.stream_id, .{
                .body = "active-sibling-finished",
            });

            var reused = try connection.readRequest();
            defer reused.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/active-reuse", reused.path);
            try connection.writeResponse(reused.stream_id, .{
                .body = "active-reused",
            });
        }
    };

    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        deadline: std.Io.Clock.Timestamp,
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.response = self.sender.requestWithDeadline(
                self.uri,
                .{},
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var server_worker = ServerWorker{ .server = &server, .io = io };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 4, .max_batch_requests = 4 },
    );
    defer dispatcher.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const cancel_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/active-cancel",
        .{base},
    );
    defer allocator.free(cancel_uri);
    const sibling_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/active-sibling",
        .{base},
    );
    defer allocator.free(sibling_uri);
    const sender = dispatcher.sender();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var producers = [_]Producer{
        .{ .sender = sender.clone(), .uri = cancel_uri, .deadline = deadline },
        .{ .sender = sender.clone(), .uri = sibling_uri, .deadline = deadline },
    };
    var producer_futures = .{
        try std.Io.concurrent(io, Producer.run, .{&producers[0]}),
        try std.Io.concurrent(io, Producer.run, .{&producers[1]}),
    };
    try waitQueued(io, &dispatcher, producers.len);
    var driver = try std.Io.concurrent(
        io,
        pool_mod.SharedDispatcher.run,
        .{&dispatcher},
    );
    try server_worker.requests_ready.waitTimeout(io, .{
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        }),
    });
    const cancel_started = std.Io.Clock.awake.now(io);
    producer_futures[0].cancel(io);
    const cancel_elapsed = cancel_started.durationTo(
        std.Io.Clock.awake.now(io),
    );
    try std.testing.expect(cancel_elapsed.nanoseconds <
        std.Io.Duration.fromSeconds(2).nanoseconds);
    try std.testing.expectEqual(error.Canceled, producers[0].err.?);
    try std.testing.expect(producers[0].response == null);

    producer_futures[1].await(io);
    if (producers[1].err) |err| return err;
    var sibling_response = producers[1].response.?;
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "active-sibling-finished",
        sibling_response.body,
    );

    const reuse_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/active-reuse",
        .{base},
    );
    defer allocator.free(reuse_uri);
    var reused = try sender.requestWithTimeout(
        reuse_uri,
        .{},
        .fromSeconds(2),
    );
    defer reused.deinit(allocator);
    try std.testing.expectEqualStrings("active-reused", reused.body);

    dispatcher.close();
    try driver.await(io);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
    try std.testing.expect(server_worker.saw_cancel);
}

test "HTTP/2 shared task cancellation wakes pool capacity admission" {
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

    const ServerWorker = struct {
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
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/capacity-reuse", request.path);
            try connection.writeResponse(request.stream_id, .{
                .body = "capacity-reused",
            });
        }
    };
    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        deadline: std.Io.Clock.Timestamp,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var response = self.sender.requestWithDeadline(
                self.uri,
                .{},
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            response.deinit(std.testing.allocator);
        }
    };

    var server_worker = ServerWorker{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    var seed = try pool.acquireUri(base);
    defer if (seed.active) seed.discard();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 2, .max_batch_requests = 2 },
    );
    defer dispatcher.deinit();
    const canceled_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/capacity-cancel",
        .{base},
    );
    defer allocator.free(canceled_uri);
    const sender = dispatcher.sender();
    var producer = Producer{
        .sender = sender.clone(),
        .uri = canceled_uri,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(5),
            .clock = .awake,
        }),
    };
    var producer_future = try std.Io.concurrent(
        io,
        Producer.run,
        .{&producer},
    );
    try waitQueued(io, &dispatcher, 1);
    var driver = try std.Io.concurrent(
        io,
        pool_mod.SharedDispatcher.run,
        .{&dispatcher},
    );
    var capacity_waiting = false;
    for (0..500) |_| {
        if (pool.waitingCount() == 1) {
            capacity_waiting = true;
            break;
        }
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    if (!capacity_waiting) return error.Timeout;

    const cancel_started = std.Io.Clock.awake.now(io);
    producer_future.cancel(io);
    const cancel_elapsed = cancel_started.durationTo(
        std.Io.Clock.awake.now(io),
    );
    try std.testing.expect(cancel_elapsed.nanoseconds <
        std.Io.Duration.fromSeconds(2).nanoseconds);
    try std.testing.expectEqual(error.Canceled, producer.err.?);
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());

    seed.release();
    const reuse_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/capacity-reuse",
        .{base},
    );
    defer allocator.free(reuse_uri);
    var reused = try sender.requestWithTimeout(
        reuse_uri,
        .{},
        .fromSeconds(2),
    );
    defer reused.deinit(allocator);
    try std.testing.expectEqualStrings("capacity-reused", reused.body);

    dispatcher.close();
    try driver.await(io);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
}

test "HTTP/2 shared streaming isolates callback failure and reuses connection" {
    const allocator = std.testing.allocator;
    const response_bytes = 64 * 1024;
    const response_chunk = 4096;
    const response_a = [_]u8{'a'} ** response_bytes;
    const response_b = [_]u8{'b'} ** response_bytes;
    const rejected_prefix = [_]u8{'r'} ** response_chunk;
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
            .max_body_bytes = response_bytes,
            .max_frame_payload = response_chunk,
        },
    );
    defer server.deinit();

    const ServerWorker = struct {
        server: *runtime.Server,
        saw_callback_cancel: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var requests: [4]runtime.StreamingRequest = undefined;
            const BodyContext = struct {
                bytes: [4]usize = @splat(0),

                fn consume(
                    context: *@This(),
                    stream_id: u31,
                    data: []const u8,
                ) !void {
                    const index: usize = @intCast((stream_id - 1) / 2);
                    if (index >= context.bytes.len) {
                        return error.InvalidRequest;
                    }
                    context.bytes[index] += data.len;
                }
            };
            var body_context: BodyContext = .{};
            try connection.readRequestBatchStreamingInto(
                &requests,
                &body_context,
                BodyContext.consume,
            );
            defer for (&requests) |*request| {
                request.deinit(self.server.allocator);
            };
            for (&requests) |*request| {
                try std.testing.expectEqualStrings("POST", request.method);
                try std.testing.expectEqual(@as(usize, 16 * 1024), request.body_bytes);
                try std.testing.expectEqualStrings(
                    "done",
                    findHeader(request.trailers, "x-request-finished").?,
                );
            }
            for (body_context.bytes) |bytes| {
                try std.testing.expectEqual(@as(usize, 16 * 1024), bytes);
            }

            const rejected = for (&requests) |*request| {
                if (std.mem.eql(u8, request.path, "/stream-reject")) {
                    break request;
                }
            } else return error.InvalidRequest;
            const timed = for (&requests) |*request| {
                if (std.mem.eql(u8, request.path, "/stream-timeout")) {
                    break request;
                }
            } else return error.InvalidRequest;
            var rejected_writer = try connection.startResponse(
                rejected.stream_id,
                .{
                    .headers = &.{
                        .{ .name = "content-length", .value = "65536" },
                        .{ .name = "x-path", .value = rejected.path },
                    },
                },
            );
            defer rejected_writer.deinit();
            try rejected_writer.write(&rejected_prefix);
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(rejected.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
            self.saw_callback_cancel = true;

            var timed_writer = try connection.startResponse(
                timed.stream_id,
                .{
                    .headers = &.{
                        .{ .name = "content-length", .value = "65536" },
                        .{ .name = "x-path", .value = timed.path },
                    },
                },
            );
            defer timed_writer.deinit();
            try timed_writer.write(&rejected_prefix);
            var timed_reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(4),
            );
            defer timed_reset.deinit(self.server.allocator);
            try std.testing.expectEqual(
                timed.stream_id,
                timed_reset.reset.stream_id,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                timed_reset.reset.error_code,
            );

            for (&requests) |*request| {
                if (request == rejected or request == timed) continue;
                const body: []const u8 = if (std.mem.eql(
                    u8,
                    request.path,
                    "/stream-one",
                ))
                    &response_a
                else if (std.mem.eql(u8, request.path, "/stream-two"))
                    &response_b
                else
                    return error.InvalidRequest;
                var writer = try connection.startResponse(
                    request.stream_id,
                    .{
                        .headers = &.{
                            .{ .name = "content-length", .value = "65536" },
                            .{ .name = "x-path", .value = request.path },
                        },
                    },
                );
                defer writer.deinit();
                var offset: usize = 0;
                while (offset < body.len) : (offset += response_chunk) {
                    try writer.write(body[offset..][0..response_chunk]);
                }
                try writer.finishTrailers(&.{.{
                    .name = "x-response-finished",
                    .value = request.path,
                }});
            }

            var reused_streaming = try connection.readRequest();
            defer reused_streaming.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/reuse-streaming",
                reused_streaming.path,
            );
            try connection.writeResponse(reused_streaming.stream_id, .{
                .body = "stream-reused",
            });

            var reused = try connection.readRequest();
            defer reused.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/reuse", reused.path);
            try connection.writeResponse(reused.stream_id, .{
                .body = "reused",
            });
        }
    };

    const StreamContext = struct {
        expected_byte: u8,
        expected_path: []const u8,
        reject: bool = false,
        saw_head: bool = false,
        body_bytes: usize = 0,

        fn begin(
            self: *@This(),
            head: runtime.StreamingResponseHead,
        ) !void {
            try std.testing.expect(!self.saw_head);
            try std.testing.expectEqual(@as(u16, 200), head.status);
            try std.testing.expectEqualStrings(
                self.expected_path,
                findHeader(head.headers, "x-path").?,
            );
            self.saw_head = true;
        }

        fn consume(self: *@This(), data: []const u8) !void {
            try std.testing.expect(self.saw_head);
            for (data) |byte| {
                try std.testing.expectEqual(self.expected_byte, byte);
            }
            self.body_bytes += data.len;
            if (self.reject) return error.RejectSharedStream;
        }
    };
    const Producer = struct {
        sender: pool_mod.SharedSender,
        uri: []const u8,
        deadline: std.Io.Clock.Timestamp,
        context: StreamContext,
        response: ?runtime.StreamingResponse = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const body = [_]u8{'q'} ** (16 * 1024);
            self.response = self.sender.requestStreamingWithHeadAndDeadline(
                self.uri,
                .{
                    .method = "POST",
                    .body = &body,
                    .trailers = &.{.{
                        .name = "x-request-finished",
                        .value = "done",
                    }},
                },
                self.deadline,
                &self.context,
                StreamContext.begin,
                StreamContext.consume,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var server_worker = ServerWorker{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerWorker.run,
        .{&server_worker},
    );
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .batch_body_chunk_size = 1024,
        .limits = .{
            .max_body_bytes = response_bytes,
            .max_frame_payload = response_chunk,
        },
    });
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 8, .max_batch_requests = 8 },
    );
    defer dispatcher.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const uris = [_][]u8{
        try std.fmt.allocPrint(allocator, "{s}/stream-one", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/stream-reject", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/stream-timeout", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/stream-two", .{base}),
    };
    defer for (uris) |uri| allocator.free(uri);
    const paths = [_][]const u8{
        "/stream-one",
        "/stream-reject",
        "/stream-timeout",
        "/stream-two",
    };
    const expected_bytes = [_]u8{ 'a', 'r', 'r', 'b' };
    const sender = dispatcher.sender();
    var producers: [4]Producer = undefined;
    for (&producers, uris, paths, expected_bytes, 0..) |
        *producer,
        uri,
        path,
        expected_byte,
        index,
    | {
        producer.* = .{
            .sender = sender.clone(),
            .uri = uri,
            .deadline = .fromNow(io, .{
                .raw = if (index == 2)
                    .fromSeconds(2)
                else
                    .fromSeconds(@intCast(8 + index)),
                .clock = .awake,
            }),
            .context = .{
                .expected_byte = expected_byte,
                .expected_path = path,
                .reject = index == 1,
            },
        };
    }
    var producer_threads: [producers.len]std.Thread = undefined;
    for (&producer_threads, &producers) |*thread, *producer| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{producer});
    }
    try waitQueued(io, &dispatcher, producers.len);
    var driver = try std.Io.concurrent(
        io,
        pool_mod.SharedDispatcher.run,
        .{&dispatcher},
    );
    for (&producer_threads) |*thread| thread.join();

    for (&producers, paths, 0..) |*producer, path, index| {
        if (index == 1) {
            try std.testing.expectEqual(
                error.RejectSharedStream,
                producer.err.?,
            );
            try std.testing.expect(producer.response == null);
            try std.testing.expect(producer.context.saw_head);
            try std.testing.expectEqual(
                @as(usize, response_chunk),
                producer.context.body_bytes,
            );
            continue;
        }
        if (index == 2) {
            try std.testing.expectEqual(error.Timeout, producer.err.?);
            try std.testing.expect(producer.response == null);
            try std.testing.expect(producer.context.saw_head);
            try std.testing.expectEqual(
                @as(usize, response_chunk),
                producer.context.body_bytes,
            );
            continue;
        }
        if (producer.err) |err| return err;
        var response = producer.response.?;
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqual(response_bytes, response.body_bytes);
        try std.testing.expectEqual(response_bytes, producer.context.body_bytes);
        try std.testing.expectEqualStrings(
            path,
            findHeader(response.trailers, "x-response-finished").?,
        );
    }

    const ReuseStreamContext = struct {
        body_bytes: usize = 0,

        fn consume(self: *@This(), data: []const u8) !void {
            self.body_bytes += data.len;
        }
    };
    const reuse_streaming_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/reuse-streaming",
        .{base},
    );
    defer allocator.free(reuse_streaming_uri);
    var reuse_stream_context: ReuseStreamContext = .{};
    var reuse_stream_response = try sender.requestStreamingWithTimeout(
        reuse_streaming_uri,
        .{},
        .fromSeconds(2),
        &reuse_stream_context,
        ReuseStreamContext.consume,
    );
    defer reuse_stream_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, "stream-reused".len),
        reuse_stream_context.body_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, "stream-reused".len),
        reuse_stream_response.body_bytes,
    );

    const reuse_uri = try std.fmt.allocPrint(allocator, "{s}/reuse", .{base});
    defer allocator.free(reuse_uri);
    var reuse_response = try sender.requestWithTimeout(
        reuse_uri,
        .{},
        .fromSeconds(2),
    );
    defer reuse_response.deinit(allocator);
    try std.testing.expectEqualStrings("reused", reuse_response.body);
    dispatcher.close();
    try driver.await(io);
    const stats = dispatcher.stats();
    try std.testing.expectEqual(@as(u64, 3), stats.batches);
    try std.testing.expectEqual(@as(u64, 4), stats.coalesced_requests);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    server_thread.join();
    server_joined = true;
    if (server_worker.err) |err| return err;
    try std.testing.expect(server_worker.saw_callback_cancel);
}

test "HTTP/2 shared sender removes timed out queued command" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    var dispatcher = try pool_mod.SharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_queued_requests = 1, .max_batch_requests = 1 },
    );
    defer dispatcher.deinit();
    const sender = dispatcher.sender();
    try std.testing.expectError(
        error.Timeout,
        sender.requestWithTimeout("http://localhost:1/timeout", .{}, .fromMilliseconds(5)),
    );
    try std.testing.expectEqual(@as(usize, 0), dispatcher.queuedCount());
    try std.testing.expect(sender.isReady());

    const Producer = struct {
        sender: pool_mod.SharedSender,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var response = self.sender.request(
                "http://localhost:1/queued",
                .{},
            ) catch |err| {
                self.err = err;
                return;
            };
            response.deinit(std.testing.allocator);
        }
    };
    var producer = Producer{ .sender = sender.clone() };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    try waitQueued(io, &dispatcher, 1);
    try std.testing.expectError(
        error.SharedQueueFull,
        sender.request("http://localhost:1/full", .{}),
    );
    dispatcher.close();
    thread.join();
    try std.testing.expectEqual(error.SharedDriverClosed, producer.err.?);
}
