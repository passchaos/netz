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
