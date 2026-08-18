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

test "HTTP/2 response body batch rejects insufficient credit" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .send_connection_window = .{ .value = 7 },
        .peer_initial_stream_window = 4,
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
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    try runtime.testing.addActivePeerStream(&connection, 1);
    try runtime.testing.addActivePeerStream(&connection, 3);
    try std.testing.expectError(
        error.FlowControlBlocked,
        connection.writeResponseBodyBatch(
            &.{ 1, 3 },
            &.{
                .{ .body = "1234" },
                .{ .body = "5678" },
            },
            4,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(i64, 7),
        connection.send_connection_window.value,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.active_peer_streams.items.len,
    );
}

test "HTTP/2 response body batch honors existing stream credit" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .send_connection_window = .{ .value = 32 },
        .peer_initial_stream_window = 16,
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
    const stream_window =
        try runtime.testing.sendStreamWindow(&connection, 1);
    try stream_window.reserve(12);
    try std.testing.expectError(
        error.FlowControlBlocked,
        connection.writeResponseBodyBatch(
            &.{1},
            &.{.{ .body = "12345" }},
            5,
        ),
    );
    try std.testing.expectEqual(@as(i64, 4), stream_window.value);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
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
