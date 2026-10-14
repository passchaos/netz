const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Connection = runtime.Connection;
const Limits = runtime.Limits;
const OwnedRequest = runtime.OwnedRequest;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const Server = runtime.Server;
const StreamingResponse = runtime.StreamingResponse;
const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

test "HTTP/2 response body batch streams interleaved DATA" {
    const allocator = std.testing.allocator;
    const response_body = "response-batch-" ** 1024;
    const parallel = 3;
    const chunk_size = 4096;
    const chunks_per_stream =
        (response_body.len + chunk_size - 1) / chunk_size;
    const total_body_bytes = response_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = @max(total_body_bytes, 65_535),
        .initial_connection_window_size = @max(total_body_bytes, 65_535),
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                chunk_size,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        bytes: [parallel]usize = @splat(0),
        events: [parallel * chunks_per_stream]usize = undefined,
        event_count: usize = 0,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            self.bytes[index] += data.len;
            self.events[self.event_count] = index;
            self.event_count += 1;
        }
    };
    var context: Context = .{};
    try client.requestBatchStreamingIntoWithTimeout(
        &requests,
        &responses,
        .fromSeconds(2),
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    for (responses, context.bytes) |response, bytes| {
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqual(
            @as(usize, 29),
            runtime.testing.findHeader(response.headers, "date").?.len,
        );
        try std.testing.expectEqual(response_body.len, response.body_bytes);
        try std.testing.expectEqual(response_body.len, bytes);
    }
    try std.testing.expectEqual(
        parallel * chunks_per_stream,
        context.event_count,
    );
    for (0..chunks_per_stream) |round| {
        for (0..parallel) |stream_index| {
            try std.testing.expectEqual(
                stream_index,
                context.events[round * parallel + stream_index],
            );
        }
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 body request streaming response batch deadline is not renewed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        reset_stream_id: ?u31 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var requests: [2]runtime.StreamingRequest = undefined;
            try connection.readRequestBatchStreamingIntoWithTimeout(
                &requests,
                .fromSeconds(1),
                {},
                struct {
                    fn consume(_: void, _: u31, _: []const u8) !void {}
                }.consume,
            );
            defer for (&requests) |*request| {
                request.deinit(self.server.allocator);
            };

            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
            try connection.writeResponse(requests[0].stream_id, .{
                .body = "first",
            });
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(350),
                .awake,
            );
            try connection.writeResponse(requests[1].stream_id, .{
                .body = "late",
            });
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            self.reset_stream_id = reset.reset.stream_id;
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/first",
            .authority = "localhost",
            .body = "one",
        },
        .{
            .method = "POST",
            .path = "/second",
            .authority = "localhost",
            .body = "two",
        },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    var body_bytes: [requests.len]usize = @splat(0);
    try std.testing.expectError(
        error.Timeout,
        client.requestBodyBatchStreamingIntoWithTimeout(
            &requests,
            3,
            &responses,
            .fromMilliseconds(400),
            &body_bytes,
            struct {
                fn consume(
                    bytes: *[requests.len]usize,
                    index: usize,
                    data: []const u8,
                ) !void {
                    bytes[index] += data.len;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqualSlices(usize, &.{ 5, 0 }, &body_bytes);
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u31, 3), shared.reset_stream_id);
}

test "HTTP/2 streaming response batch deadline covers continuation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
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

            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(self.server.allocator);
            try http2.Hpack.encodeLiteralBlock(
                &block,
                self.server.allocator,
                &.{.{ .name = ":status", .value = "204" }},
            );
            try runtime.testing.writeRawFrame(
                &connection,
                .headers,
                0x1, // END_STREAM without END_HEADERS.
                request.stream_id,
                block.items[0..1],
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    const requests = [_]RequestOptions{.{
        .path = "/partial-head",
        .authority = "localhost",
    }};
    var responses: [requests.len]StreamingResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBatchStreamingIntoWithTimeout(
            &requests,
            &responses,
            .fromMilliseconds(20),
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch streams interleaved responses and trailers" {
    const allocator = std.testing.allocator;
    const request_body = "request-batch-" ** 256;
    const response_body = "response-batch-" ** 512;
    const parallel = 3;
    const total_request_bytes = request_body.len * (parallel - 1);
    const total_response_bytes = response_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = @max(request_body.len, response_body.len),
        .initial_window_size = @max(
            @max(total_request_bytes, total_response_bytes),
            65_535,
        ),
        .initial_connection_window_size = @max(
            @max(total_request_bytes, total_response_bytes),
            65_535,
        ),
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        request_bytes: [parallel]usize = @splat(0),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(
            self: *@This(),
            stream_id: u31,
            data: []const u8,
        ) !void {
            const index: usize = (stream_id - 1) / 2;
            self.request_bytes[index] += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var requests: [parallel]runtime.StreamingRequest = undefined;
            try connection.readRequestBatchStreamingIntoWithTimeout(
                &requests,
                .fromSeconds(2),
                self,
                consume,
            );
            defer for (&requests) |*request| {
                request.deinit(self.server.allocator);
            };
            const expected_request_bytes = [_]usize{
                request_body.len,
                request_body.len,
                0,
            };
            const expected_trailers = [_][]const u8{ "one", "two", "three" };
            for (requests, self.request_bytes, expected_request_bytes, expected_trailers) |
                request,
                bytes,
                expected_bytes,
                expected_trailer,
            | {
                try std.testing.expectEqual(expected_bytes, request.body_bytes);
                try std.testing.expectEqual(expected_bytes, bytes);
                try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
                try std.testing.expectEqualStrings(
                    "x-request-finished",
                    request.trailers[0].name,
                );
                try std.testing.expectEqualStrings(
                    expected_trailer,
                    request.trailers[0].value,
                );
            }
            var stream_ids: [parallel]u31 = undefined;
            var responses: [parallel]ResponseOptions = undefined;
            for (&stream_ids, &responses, 0..) |*stream_id, *response, index| {
                const reverse = parallel - 1 - index;
                stream_id.* = requests[reverse].stream_id;
                response.* = .{ .body = response_body };
            }
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                4096,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/one",
            .authority = "localhost",
            .body = request_body,
            .trailers = &.{.{
                .name = "x-request-finished",
                .value = "one",
            }},
        },
        .{
            .method = "POST",
            .path = "/two",
            .authority = "localhost",
            .body = request_body,
            .trailers = &.{.{
                .name = "x-request-finished",
                .value = "two",
            }},
        },
        .{
            .method = "POST",
            .path = "/three",
            .authority = "localhost",
            .trailers = &.{.{
                .name = "x-request-finished",
                .value = "three",
            }},
        },
    };
    var responses: [parallel]StreamingResponse = undefined;
    var response_bytes: [parallel]usize = @splat(0);
    try client.requestBodyBatchStreamingIntoWithTimeout(
        &requests,
        1024,
        &responses,
        .fromSeconds(2),
        &response_bytes,
        struct {
            fn consume(
                bytes: *[parallel]usize,
                index: usize,
                data: []const u8,
            ) !void {
                bytes[index] += data.len;
            }
        }.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    for (responses, response_bytes) |response, bytes| {
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqual(response_body.len, response.body_bytes);
        try std.testing.expectEqual(response_body.len, bytes);
    }
    try std.testing.expect(client.isReusable());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch rolls back unsent trailer HPACK after reset" {
    const allocator = std.testing.allocator;
    const request_body = [_]u8{'x'} ** (16 * 1024);
    const limits: Limits = .{
        .max_body_bytes = request_body.len,
        .initial_window_size = 4096,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var reset = try connection.acceptDuplexRequest();
            defer reset.deinit();
            try std.testing.expectEqualStrings("/reset-before-trailers", reset.path);
            try reset.reset(.cancel);

            var after = try connection.readRequest();
            defer after.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after-reset", after.path);
            try std.testing.expectEqualStrings(
                "marker",
                runtime.testing.findHeader(
                    after.headers,
                    "x-unsent-trailer",
                ).?,
            );
            try connection.writeResponse(after.stream_id, .{ .body = "reused" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var responses: [1]runtime.OwnedResponse = undefined;
    try std.testing.expectError(
        error.StreamReset,
        client.requestBodyBatchInto(
            &.{.{
                .method = "POST",
                .path = "/reset-before-trailers",
                .authority = "localhost",
                .body = &request_body,
                .trailers = &.{.{
                    .name = "x-unsent-trailer",
                    .value = "marker",
                }},
            }},
            4096,
            &responses,
        ),
    );
    try std.testing.expect(client.isReusable());

    var after = try client.request(.{
        .path = "/after-reset",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-unsent-trailer",
            .value = "marker",
        }},
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("reused", after.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 per-stream batch deadline cancels one response and reuses sibling" {
    const allocator = std.testing.allocator;
    const partial_body = [_]u8{'p'} ** (20 * 1024);
    const sibling_body = [_]u8{'s'} ** (60 * 1024);
    const limits: Limits = .{
        .max_body_bytes = sibling_body.len,
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var timed = try connection.readRequest();
            defer timed.deinit(self.server.allocator);
            var sibling = try connection.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/timed", timed.path);
            try std.testing.expectEqualStrings("/sibling", sibling.path);

            try runtime.testing.writeHeaders(
                &connection,
                timed.stream_id,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "32768" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                timed.stream_id,
                &partial_body,
                false,
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(timed.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );

            // Model response DATA already in flight when CANCEL reached the
            // peer. The client must discard it and restore connection credit
            // before consuming the complete sibling response.
            try runtime.testing.writeRawFrame(
                &connection,
                .data,
                0,
                timed.stream_id,
                "late",
            );
            var late_trailers: std.ArrayList(u8) = .empty;
            defer late_trailers.deinit(self.server.allocator);
            try connection.hpack_encoder.encodeBlock(
                &late_trailers,
                self.server.allocator,
                &.{.{ .name = "x-late-dynamic", .value = "marker" }},
            );
            try runtime.testing.writeRawFrame(
                &connection,
                .headers,
                flag_end_headers | flag_end_stream,
                timed.stream_id,
                late_trailers.items,
            );
            try connection.writeResponse(sibling.stream_id, .{
                .headers = &.{.{
                    .name = "x-late-dynamic",
                    .value = "marker",
                }},
                .body = &sibling_body,
            });

            var after = try connection.readRequest();
            defer after.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/after", after.path);
            try connection.writeResponse(after.stream_id, .{ .body = "reused" });
        }
    };

    const ResultSlot = struct {
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,
    };
    const ResultContext = struct {
        slots: [2]ResultSlot = .{ .{}, .{} },

        fn observe(
            raw_context: *anyopaque,
            index: usize,
            result: runtime.BatchOwnedResponseResult,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw_context));
            switch (result) {
                .response => |response| self.slots[index].response = response,
                .err => |err| self.slots[index].err = err,
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/timed", .authority = "localhost" },
        .{ .path = "/sibling", .authority = "localhost" },
    };
    const deadlines = [_]?std.Io.Clock.Timestamp{
        .fromNow(io, .{ .raw = .fromMilliseconds(100), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    };
    var result_context: ResultContext = .{};
    try client.requestBatchWithPerStreamDeadlines(
        &requests,
        &deadlines,
        .{
            .context = &result_context,
            .on_result = ResultContext.observe,
        },
    );
    try std.testing.expectEqual(error.Timeout, result_context.slots[0].err.?);
    try std.testing.expect(result_context.slots[0].response == null);
    try std.testing.expect(result_context.slots[1].err == null);
    var sibling_response = result_context.slots[1].response.?;
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &sibling_body, sibling_response.body);
    try std.testing.expectEqualStrings(
        "marker",
        runtime.testing.findHeader(
            sibling_response.headers,
            "x-late-dynamic",
        ).?,
    );
    try std.testing.expect(client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("reused", after.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 per-stream deadline cancels one upload and preserves sibling trailers" {
    const allocator = std.testing.allocator;
    const timed_body = [_]u8{'t'} ** (32 * 1024);
    const sibling_body = [_]u8{'s'} ** (32 * 1024);
    const limits: Limits = .{
        .max_body_bytes = sibling_body.len,
        .initial_window_size = 4096,
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        timed_bytes: usize = 0,
        sibling_bytes: usize = 0,
        saw_cancel: bool = false,
        saw_sibling_trailers: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn readApplicationFrame(
            connection: *runtime.Connection,
            frame_allocator: std.mem.Allocator,
        ) !runtime.OwnedFrame {
            while (true) {
                var owned = try runtime.testing.readOwnedFrame(connection);
                if (try runtime.testing.handleConnectionFrame(
                    connection,
                    owned.frame,
                )) {
                    owned.deinit(frame_allocator);
                    continue;
                }
                return owned;
            }
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first_head = try readApplicationFrame(
                &connection,
                self.server.allocator,
            );
            defer first_head.deinit(self.server.allocator);
            var second_head = try readApplicationFrame(
                &connection,
                self.server.allocator,
            );
            defer second_head.deinit(self.server.allocator);
            try std.testing.expectEqual(http2.FrameType.headers, first_head.frame.header.frame_type);
            try std.testing.expectEqual(http2.FrameType.headers, second_head.frame.header.frame_type);
            try std.testing.expectEqual(@as(u31, 1), first_head.frame.header.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second_head.frame.header.stream_id);
            try runtime.testing.addActivePeerStream(&connection, 1);
            try runtime.testing.addActivePeerStream(&connection, 3);

            while (!self.saw_cancel or !self.saw_sibling_trailers) {
                var owned = try readApplicationFrame(
                    &connection,
                    self.server.allocator,
                );
                defer owned.deinit(self.server.allocator);
                const frame = owned.frame;
                switch (frame.header.frame_type) {
                    .data => {
                        const data = try http2.DataPayload.parse(frame);
                        if (frame.header.stream_id == 1) {
                            self.timed_bytes += data.data.len;
                        } else if (frame.header.stream_id == 3) {
                            self.sibling_bytes += data.data.len;
                            try connection.sendWindowUpdate(
                                3,
                                @intCast(frame.payload.len),
                            );
                        } else {
                            return error.InvalidStreamId;
                        }
                    },
                    .rst_stream => {
                        const reset = try http2.ResetStreamPayload.parse(frame);
                        try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
                        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                        self.saw_cancel = true;
                    },
                    .headers => {
                        if (frame.header.stream_id == 1) {
                            return error.UnexpectedFrame;
                        }
                        try std.testing.expectEqual(@as(u31, 3), frame.header.stream_id);
                        try std.testing.expect(
                            (frame.header.flags & flag_end_stream) != 0,
                        );
                        self.saw_sibling_trailers = true;
                    },
                    else => return error.UnexpectedFrame,
                }
            }
            try std.testing.expect(self.timed_bytes < timed_body.len);
            try std.testing.expectEqual(sibling_body.len, self.sibling_bytes);
            try runtime.testing.writeRawFrame(
                &connection,
                .headers,
                flag_end_headers,
                3,
                &.{0x88},
            );
            try runtime.testing.writeRawFrame(
                &connection,
                .data,
                flag_end_stream,
                3,
                "sibling-finished",
            );
        }
    };

    const ResultSlot = struct {
        response: ?runtime.OwnedResponse = null,
        err: ?anyerror = null,
    };
    const ResultContext = struct {
        slots: [2]ResultSlot = .{ .{}, .{} },

        fn observe(
            raw_context: *anyopaque,
            index: usize,
            result: runtime.BatchOwnedResponseResult,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw_context));
            switch (result) {
                .response => |response| self.slots[index].response = response,
                .err => |err| self.slots[index].err = err,
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/timed-upload",
            .authority = "localhost",
            .body = &timed_body,
            .trailers = &.{.{
                .name = "x-upload-finished",
                .value = "timed",
            }},
        },
        .{
            .method = "POST",
            .path = "/sibling-upload",
            .authority = "localhost",
            .body = &sibling_body,
            .trailers = &.{.{
                .name = "x-upload-finished",
                .value = "sibling",
            }},
        },
    };
    const deadlines = [_]?std.Io.Clock.Timestamp{
        .fromNow(io, .{ .raw = .fromMilliseconds(100), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    };
    var result_context: ResultContext = .{};
    client.requestBodyBatchWithPerStreamDeadlines(
        &requests,
        1024,
        &deadlines,
        .{
            .context = &result_context,
            .on_result = ResultContext.observe,
        },
    ) catch |err| {
        std.debug.print("per-stream upload client failed: {s}\n", .{@errorName(err)});
        if (shared.err) |server_err| {
            std.debug.print("per-stream upload server failed: {s}\n", .{@errorName(server_err)});
        }
        return err;
    };
    try std.testing.expectEqual(error.Timeout, result_context.slots[0].err.?);
    try std.testing.expect(result_context.slots[0].response == null);
    try std.testing.expect(result_context.slots[1].err == null);
    var sibling_response = result_context.slots[1].response.?;
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings("sibling-finished", sibling_response.body);
    try std.testing.expect(client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response body batch resumes fairly under small windows" {
    const allocator = std.testing.allocator;
    const parallel = 5;
    const chunk_size = 16 * 1024;
    const response_body = "flow-controlled-response-" ** 2048;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = 32 * 1024,
        .initial_connection_window_size = 65_535,
        .max_frame_payload = chunk_size,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        client_finished: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                chunk_size,
            );
            // This test targets flow-control fairness, not TCP teardown. Keep
            // the accepted socket alive until the client parses every final
            // DATA frame; otherwise unread WINDOW_UPDATE bytes can make Linux
            // close abortive and turn a successful response into EOF.
            shared.client_finished.waitUncancelable(shared.io);
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
        .{ .path = "/four", .authority = "localhost" },
        .{ .path = "/five", .authority = "localhost" },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        bytes: [parallel]usize = @splat(0),
        first_round: [parallel]usize = undefined,
        first_round_count: usize = 0,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            if (self.first_round_count < parallel) {
                self.first_round[self.first_round_count] = index;
                self.first_round_count += 1;
            }
            self.bytes[index] += data.len;
        }
    };
    var context: Context = .{};
    try client.requestBatchStreamingInto(
        &requests,
        &responses,
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    for (responses, context.bytes) |response, bytes| {
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqual(response_body.len, response.body_bytes);
        try std.testing.expectEqual(response_body.len, bytes);
    }
    try std.testing.expectEqual(parallel, context.first_round_count);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, 1, 2, 3, 4 },
        &context.first_round,
    );
    shared.client_finished.set(io);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch serves urgency and non-incremental order" {
    const allocator = std.testing.allocator;
    const parallel = 3;
    const chunk_size = 1024;
    const response_body = "priority-response-" ** 256;
    const chunks_per_stream = std.math.divCeil(
        usize,
        response_body.len,
        chunk_size,
    ) catch unreachable;
    const total_body_bytes = response_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = @max(total_body_bytes, 65_535),
        .initial_connection_window_size = @max(total_body_bytes, 65_535),
        .max_frame_payload = chunk_size,
        .no_rfc7540_priorities = true,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                chunk_size,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    // Stream 3 and 5 share the highest urgency and are non-incremental.
    // RFC 9218 recommends serving them one by one in stream-ID order before
    // the lower-urgency incremental stream 1.
    const requests = [_]RequestOptions{
        .{
            .path = "/low-incremental",
            .authority = "localhost",
            .priority = .{ .urgency = 5, .incremental = true },
        },
        .{
            .path = "/high-first",
            .authority = "localhost",
            .priority = .{ .urgency = 1 },
        },
        .{
            .path = "/high-second",
            .authority = "localhost",
            .priority = .{ .urgency = 1 },
        },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        const event_capacity = parallel *
            ((response_body.len + chunk_size - 1) / chunk_size);

        events: [event_capacity]usize = undefined,
        event_count: usize = 0,

        fn consume(
            self: *@This(),
            index: usize,
            _: []const u8,
        ) !void {
            self.events[self.event_count] = index;
            self.event_count += 1;
        }
    };
    var context: Context = .{};
    try client.requestBatchStreamingInto(
        &requests,
        &responses,
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqual(
        parallel * chunks_per_stream,
        context.event_count,
    );
    for (0..chunks_per_stream) |index| {
        try std.testing.expectEqual(
            @as(usize, 1),
            context.events[index],
        );
        try std.testing.expectEqual(
            @as(usize, 2),
            context.events[chunks_per_stream + index],
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            context.events[2 * chunks_per_stream + index],
        );
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch shares incremental urgency and honors update" {
    const allocator = std.testing.allocator;
    const parallel = 3;
    const chunk_size = 1024;
    const response_body = "incremental-priority-" ** 192;
    const chunks_per_stream = std.math.divCeil(
        usize,
        response_body.len,
        chunk_size,
    ) catch unreachable;
    const total_body_bytes = response_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = @max(total_body_bytes, 65_535),
        .initial_connection_window_size = @max(total_body_bytes, 65_535),
        .max_frame_payload = chunk_size,
        .no_rfc7540_priorities = true,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                chunk_size,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    // Pre-prioritize stream 3. Its later Priority request header deliberately
    // conflicts; PRIORITY_UPDATE must remain authoritative for scheduling.
    try client.sendPriorityUpdate(
        3,
        .{ .urgency = 0, .incremental = true },
    );
    const requests = [_]RequestOptions{
        .{
            .path = "/default-one",
            .authority = "localhost",
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .path = "/updated",
            .authority = "localhost",
            .priority = .{ .urgency = 7 },
        },
        .{
            .path = "/default-two",
            .authority = "localhost",
            .priority = .{ .urgency = 3, .incremental = true },
        },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        const event_capacity = parallel *
            ((response_body.len + chunk_size - 1) / chunk_size);

        events: [event_capacity]usize = undefined,
        event_count: usize = 0,

        fn consume(
            self: *@This(),
            index: usize,
            _: []const u8,
        ) !void {
            self.events[self.event_count] = index;
            self.event_count += 1;
        }
    };
    var context: Context = .{};
    try client.requestBatchStreamingInto(
        &requests,
        &responses,
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqual(
        parallel * chunks_per_stream,
        context.event_count,
    );
    for (context.events[0..chunks_per_stream]) |event| {
        try std.testing.expectEqual(@as(usize, 1), event);
    }
    // Once updated stream 3 completes, the two equal incremental streams
    // share every scheduler pass. Rotation continues after stream 3, so the
    // first peer can be either member; each adjacent pair must contain both.
    for (0..chunks_per_stream) |round| {
        const start = chunks_per_stream + round * 2;
        const first = context.events[start];
        const second = context.events[start + 1];
        try std.testing.expect(first == 0 or first == 2);
        try std.testing.expect(second == 0 or second == 2);
        try std.testing.expect(first != second);
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch reprioritizes after flow-control wait" {
    const allocator = std.testing.allocator;
    const parallel = 2;
    const chunk_size = 32 * 1024;
    const response_body = "dynamic-priority-" ** 6144;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = @intCast(response_body.len),
        .initial_connection_window_size = 65_535,
        .max_frame_payload = chunk_size,
        .no_rfc7540_priorities = true,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                chunk_size,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .path = "/incremental-one",
            .authority = "localhost",
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .path = "/incremental-two",
            .authority = "localhost",
            .priority = .{ .urgency = 3, .incremental = true },
        },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        client: *Connection,
        bytes: [parallel]usize = @splat(0),
        event_count: usize = 0,
        update_sent: bool = false,
        resumed_first_before_second_complete: bool = false,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            if (self.event_count == 0) {
                // The first 65,535-byte connection window lets each stream
                // contribute once. Reprioritize stream 3 before receive-side
                // credit is returned; the server must apply this update when
                // its capacity pump resumes.
                try self.client.sendPriorityUpdate(
                    3,
                    .{ .urgency = 0 },
                );
                self.update_sent = true;
            } else if (self.event_count >= 2 and
                index == 0 and self.bytes[1] != response_body.len)
            {
                self.resumed_first_before_second_complete = true;
            }
            self.bytes[index] += data.len;
            self.event_count += 1;
        }
    };
    var context = Context{ .client = &client };
    try client.requestBatchStreamingInto(
        &requests,
        &responses,
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expect(context.update_sent);
    try std.testing.expect(
        !context.resumed_first_before_second_complete,
    );
    try std.testing.expectEqual(
        @as(usize, response_body.len),
        context.bytes[0],
    );
    try std.testing.expectEqual(
        @as(usize, response_body.len),
        context.bytes[1],
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response priority bypasses blocked urgent stream" {
    const allocator = std.testing.allocator;
    const parallel = 2;
    const response_body = "blocked-priority-" ** 256;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = response_body.len,
        .initial_connection_window_size = 65_535,
        .max_frame_payload = 1024,
        .no_rfc7540_priorities = true,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(shared.server.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            // The peer deliberately advertises no stream credit for the
            // urgency-0 response. The urgency-5 stream must consume available
            // connection credit rather than being head-of-line blocked.
            (try runtime.testing.sendStreamWindow(
                &connection,
                stream_ids[0],
            )).value = 0;
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try connection.writeResponseBodyBatch(
                &stream_ids,
                &responses,
                1024,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .path = "/blocked-urgent",
            .authority = "localhost",
            .priority = .{ .urgency = 0 },
        },
        .{
            .path = "/sendable-low",
            .authority = "localhost",
            .priority = .{ .urgency = 5 },
        },
    };
    var responses: [parallel]StreamingResponse = undefined;
    const Context = struct {
        client: *Connection,
        update_amount: u31,
        bytes: [parallel]usize = @splat(0),
        first_event: ?usize = null,
        update_sent: bool = false,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            if (self.first_event == null) self.first_event = index;
            self.bytes[index] += data.len;
            if (!self.update_sent) {
                // Receiving lower-priority stream 3 proves the server used
                // otherwise-idle connection credit. Unblock stream 1 from the
                // same callback so no second writer races on the connection.
                try self.client.sendWindowUpdate(
                    1,
                    self.update_amount,
                );
                self.update_sent = true;
            }
        }
    };
    var context = Context{
        .client = &client,
        .update_amount = @intCast(response_body.len),
    };
    try client.requestBatchStreamingInto(
        &requests,
        &responses,
        &context,
        Context.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqual(@as(?usize, 1), context.first_event);
    try std.testing.expectEqual(
        @as(usize, response_body.len),
        context.bytes[0],
    );
    try std.testing.expectEqual(
        @as(usize, response_body.len),
        context.bytes[1],
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response body batch validation is transactional" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    try runtime.testing.addActivePeerStream(&connection, 1);
    try runtime.testing.addActivePeerStream(&connection, 3);
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBodyBatch(
            &.{ 1, 3 },
            &.{
                .{ .body = "valid" },
                .{ .status = 205, .body = "forbidden" },
            },
            4096,
        ),
    );
    try std.testing.expectEqual(
        @as(i64, 65_535),
        connection.send_connection_window.value,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.active_peer_streams.items.len,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBodyBatch(
            &.{ 1, 3 },
            &.{
                .{ .body = "valid" },
                .{
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "9",
                    }},
                    .body = "short",
                },
            },
            4096,
        ),
    );
    try std.testing.expectEqual(
        @as(i64, 65_535),
        connection.send_connection_window.value,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.active_peer_streams.items.len,
    );
}

test "HTTP/2 response body batch observes reset while flow blocked" {
    const allocator = std.testing.allocator;
    const parallel = 2;
    const response_body = "cancel-flow-controlled-response-" ** 4096;
    const limits: Limits = .{
        .max_body_bytes = response_body.len,
        .initial_window_size = 4096,
        .initial_connection_window_size = 65_535,
        .max_frame_payload = 4096,
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_reset: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(shared.server.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            const responses = [_]ResponseOptions{
                .{ .body = response_body },
            } ** parallel;
            try std.testing.expectError(
                error.StreamReset,
                connection.writeResponseBodyBatch(
                    &stream_ids,
                    &responses,
                    4096,
                ),
            );
            shared.saw_reset = true;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/cancel", .authority = "localhost" },
        .{ .path = "/peer", .authority = "localhost" },
    };
    var responses: [parallel]StreamingResponse = undefined;
    var callback_calls: usize = 0;
    try std.testing.expectError(
        error.CancelBatch,
        client.requestBatchStreamingInto(
            &requests,
            &responses,
            &callback_calls,
            struct {
                fn consume(
                    calls: *usize,
                    _: usize,
                    _: []const u8,
                ) !void {
                    calls.* += 1;
                    return error.CancelBatch;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), callback_calls);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_reset);
}

test "HTTP/2 streaming response batch callback failure cancels every stream" {
    const allocator = std.testing.allocator;
    const parallel = 3;
    const limits: Limits = .{ .max_body_bytes = 4096 };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            var stream_ids: [parallel]u31 = undefined;
            for (&requests, &stream_ids) |*request, *stream_id| {
                request.* = try connection.readRequest();
                initialized += 1;
                stream_id.* = request.stream_id;
            }
            for (stream_ids) |stream_id| {
                try runtime.testing.writeHeaders(
                    &connection,
                    stream_id,
                    &.{
                        .{ .name = ":status", .value = "200" },
                        .{ .name = "content-length", .value = "12" },
                    },
                    false,
                );
                try runtime.testing.writeData(
                    &connection,
                    stream_id,
                    "first",
                    false,
                );
            }

            var cancelled: [parallel]bool = @splat(false);
            for (0..parallel) |_| {
                var reset = try connection.readResetStream();
                defer reset.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    http2.ErrorCode.cancel,
                    reset.reset.error_code,
                );
                var matched = false;
                for (stream_ids, &cancelled) |
                    stream_id,
                    *was_cancelled,
                | {
                    if (stream_id != reset.reset.stream_id) continue;
                    try std.testing.expect(!was_cancelled.*);
                    was_cancelled.* = true;
                    matched = true;
                    break;
                }
                try std.testing.expect(matched);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
    };
    var responses: [parallel]StreamingResponse = undefined;
    var callback_calls: usize = 0;
    try std.testing.expectError(
        error.ConsumerRejected,
        client.requestBatchStreamingInto(
            &requests,
            &responses,
            &callback_calls,
            struct {
                fn consume(
                    calls: *usize,
                    _: usize,
                    _: []const u8,
                ) !void {
                    calls.* += 1;
                    return error.ConsumerRejected;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), callback_calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.active_local_streams.items.len,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded body request streaming response callback Timeout remains reusable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var rejected = try connection.readRequest();
            defer rejected.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("body", rejected.body);
            try runtime.testing.writeHeaders(
                &connection,
                rejected.stream_id,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "12" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                rejected.stream_id,
                "first",
                false,
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(rejected.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );

            var next = try connection.readRequest();
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 3), next.stream_id);
            try connection.writeResponse(next.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const requests = [_]RequestOptions{.{
        .method = "POST",
        .path = "/callback-timeout",
        .authority = "localhost",
        .body = "body",
    }};
    var responses: [requests.len]StreamingResponse = undefined;
    var callback_calls: usize = 0;
    try std.testing.expectError(
        error.Timeout,
        client.requestBodyBatchStreamingIntoWithTimeout(
            &requests,
            4,
            &responses,
            .fromSeconds(2),
            &callback_calls,
            struct {
                fn consume(
                    calls: *usize,
                    _: usize,
                    _: []const u8,
                ) !void {
                    calls.* += 1;
                    return error.Timeout;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), callback_calls);
    try std.testing.expect(client.isReusable());

    var next = try client.request(.{
        .path = "/after-callback-timeout",
        .authority = "localhost",
    });
    defer next.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), next.status);

    thread.join();
    if (shared.err) |err| return err;
}
