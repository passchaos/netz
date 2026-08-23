const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Limits = runtime.Limits;
const RequestOptions = runtime.RequestOptions;
const Server = runtime.Server;

const BatchEvent = struct {
    request_index: usize,
    stream_id: u31,
    status: u16,
};

const BatchObserverContext = struct {
    const expected_markers = [_][]const u8{
        "two-early",
        "one-progress",
        "two-progress",
        "one-early",
    };

    events: [expected_markers.len]BatchEvent = undefined,
    count: usize = 0,
    headers_valid: bool = true,

    fn observe(
        self_ptr: *anyopaque,
        request_index: usize,
        stream_id: u31,
        response: runtime.StreamingResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(self_ptr));
        if (self.count >= self.events.len) {
            self.headers_valid = false;
            return;
        }
        self.events[self.count] = .{
            .request_index = request_index,
            .stream_id = stream_id,
            .status = response.status,
        };
        self.headers_valid = self.headers_valid and std.mem.eql(
            u8,
            findHeader(response.headers, "x-batch-event") orelse "",
            expected_markers[self.count],
        );
        self.count += 1;
    }
};

fn findHeader(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn expectInterleavedEvents(observer: *const BatchObserverContext) !void {
    try std.testing.expect(observer.headers_valid);
    try std.testing.expectEqual(observer.events.len, observer.count);
    const expected = [_]BatchEvent{
        .{ .request_index = 1, .stream_id = 3, .status = 103 },
        .{ .request_index = 0, .stream_id = 1, .status = 102 },
        .{ .request_index = 1, .stream_id = 3, .status = 102 },
        .{ .request_index = 0, .stream_id = 1, .status = 103 },
    };
    try std.testing.expectEqualSlices(BatchEvent, &expected, &observer.events);
}

test "HTTP/2 batch informational observers correlate interleaved streams" {
    const allocator = std.testing.allocator;
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        // Four callbacks are legal because this bound applies independently to
        // each of the two streams, rather than to the batch as a whole.
        .max_informational_responses = 2,
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

        fn consume(
            body_bytes: *usize,
            _: u31,
            data: []const u8,
        ) !void {
            body_bytes.* += data.len;
        }

        fn runFallible(self: *@This()) !void {
            for (0..3) |scenario| {
                var connection = try self.server.accept();
                defer connection.close();

                var requests: [2]runtime.StreamingRequest = undefined;
                var requests_initialized = false;
                defer if (requests_initialized) {
                    for (&requests) |*request| {
                        request.deinit(self.server.allocator);
                    }
                };
                var body_bytes: usize = 0;
                try connection.readRequestBatchStreamingInto(
                    &requests,
                    &body_bytes,
                    consume,
                );
                requests_initialized = true;
                try std.testing.expect(std.mem.endsWith(
                    u8,
                    requests[0].path,
                    "/one",
                ));
                try std.testing.expect(std.mem.endsWith(
                    u8,
                    requests[1].path,
                    "/two",
                ));
                try std.testing.expectEqual(
                    if (scenario == 2) @as(usize, 5) else 0,
                    body_bytes,
                );

                // Deliberately alternate streams and start with the second
                // request. This exercises request-index lookup independently
                // from both wire order and per-stream informational ordering.
                try connection.writeInformationalResponse(
                    requests[1].stream_id,
                    103,
                    &.{.{ .name = "x-batch-event", .value = "two-early" }},
                );
                try connection.writeInformationalResponse(
                    requests[0].stream_id,
                    102,
                    &.{.{ .name = "x-batch-event", .value = "one-progress" }},
                );
                try connection.writeInformationalResponse(
                    requests[1].stream_id,
                    102,
                    &.{.{ .name = "x-batch-event", .value = "two-progress" }},
                );
                try connection.writeInformationalResponse(
                    requests[0].stream_id,
                    103,
                    &.{.{ .name = "x-batch-event", .value = "one-early" }},
                );
                try connection.writeResponse(requests[1].stream_id, .{
                    .body = "two",
                    .request_method = requests[1].method,
                });
                try connection.writeResponse(requests[0].stream_id, .{
                    .body = "one",
                    .request_method = requests[0].method,
                });
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    {
        var client = try Client.connect(allocator, io, server.address(), limits);
        defer client.close();
        const requests = [_]RequestOptions{
            .{ .path = "/aggregate/one", .authority = "localhost" },
            .{ .path = "/aggregate/two", .authority = "localhost" },
        };
        var responses: [requests.len]runtime.OwnedResponse = undefined;
        var observer: BatchObserverContext = .{};
        try client.requestBatchWithInformationalInto(
            &requests,
            &responses,
            .{
                .context = &observer,
                .on_response = BatchObserverContext.observe,
            },
        );
        defer for (&responses) |*response| response.deinit(allocator);
        try expectInterleavedEvents(&observer);
        try std.testing.expectEqualStrings("one", responses[0].body);
        try std.testing.expectEqualStrings("two", responses[1].body);
    }

    {
        var client = try Client.connect(allocator, io, server.address(), limits);
        defer client.close();
        const requests = [_]RequestOptions{
            .{ .path = "/streaming/one", .authority = "localhost" },
            .{ .path = "/streaming/two", .authority = "localhost" },
        };
        var responses: [requests.len]runtime.StreamingResponse = undefined;
        var observer: BatchObserverContext = .{};
        const BodyContext = struct {
            bytes: [2]usize = @splat(0),

            fn consume(
                self: *@This(),
                request_index: usize,
                data: []const u8,
            ) !void {
                self.bytes[request_index] += data.len;
            }
        };
        var body_context: BodyContext = .{};
        try client.requestBatchStreamingWithInformationalInto(
            &requests,
            &responses,
            .{
                .context = &observer,
                .on_response = BatchObserverContext.observe,
            },
            &body_context,
            BodyContext.consume,
        );
        defer for (&responses) |*response| response.deinit(allocator);
        try expectInterleavedEvents(&observer);
        try std.testing.expectEqualSlices(usize, &.{ 3, 3 }, &body_context.bytes);
        try std.testing.expectEqual(@as(usize, 3), responses[0].body_bytes);
        try std.testing.expectEqual(@as(usize, 3), responses[1].body_bytes);
    }

    {
        var client = try Client.connect(allocator, io, server.address(), limits);
        defer client.close();
        const requests = [_]RequestOptions{
            .{
                .method = "POST",
                .path = "/body/one",
                .authority = "localhost",
                .body = "one",
            },
            .{
                .method = "POST",
                .path = "/body/two",
                .authority = "localhost",
                .body = "22",
            },
        };
        var responses: [requests.len]runtime.OwnedResponse = undefined;
        var observer: BatchObserverContext = .{};
        try client.requestBodyBatchWithInformationalInto(
            &requests,
            1,
            &responses,
            .{
                .context = &observer,
                .on_response = BatchObserverContext.observe,
            },
        );
        defer for (&responses) |*response| response.deinit(allocator);
        try expectInterleavedEvents(&observer);
        try std.testing.expectEqualStrings("one", responses[0].body);
        try std.testing.expectEqualStrings("two", responses[1].body);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 batch informational limit is enforced per stream" {
    const allocator = std.testing.allocator;
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_informational_responses = 2,
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
            var requests: [2]runtime.OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(self.server.allocator);
            };
            for (&requests) |*request| {
                request.* = try connection.readRequest();
                initialized += 1;
            }
            for (0..3) |ordinal| {
                _ = ordinal;
                try connection.writeInformationalResponse(
                    requests[1].stream_id,
                    103,
                    &.{.{ .name = "x-batch-event", .value = "two-early" }},
                );
            }
        }
    };

    const CountingObserver = struct {
        count: usize = 0,
        correlation_valid: bool = true,

        fn observe(
            self_ptr: *anyopaque,
            request_index: usize,
            stream_id: u31,
            _: runtime.StreamingResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(self_ptr));
            self.correlation_valid = self.correlation_valid and
                request_index == 1 and stream_id == 3;
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/limit/one", .authority = "localhost" },
        .{ .path = "/limit/two", .authority = "localhost" },
    };
    var responses: [requests.len]runtime.OwnedResponse = undefined;
    var observer: CountingObserver = .{};
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.requestBatchWithInformationalInto(
            &requests,
            &responses,
            .{
                .context = &observer,
                .on_response = CountingObserver.observe,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), observer.count);
    try std.testing.expect(observer.correlation_valid);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
