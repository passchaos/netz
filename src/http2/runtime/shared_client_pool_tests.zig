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
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.response = self.sender.request(self.uri, self.request) catch |err| {
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
    var producers = [_]Producer{
        .{
            .sender = sender.clone(),
            .uri = first_uri,
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
