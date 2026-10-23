const std = @import("std");
const h2 = @import("../../http2/runtime.zig");
const metadata = @import("response_tests.zig");

const Mode = enum { single, batch, body_batch, streaming, individual_batch, individual_streaming, duplex };

fn checkResponse(response: h2.OwnedResponse, index: usize) !void {
    if (index < 2) {
        try std.testing.expect(!response.body_allowed);
        try metadata.expectEmpty(response);
    } else {
        try std.testing.expect(response.body_allowed);
        try std.testing.expectError(error.InvalidContentEncoding, response.decodeContentAlloc(std.testing.allocator, 1024));
    }
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try h2.Server.listen(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *h2.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            for (0..3) |_| {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(std.testing.allocator);
                const not_modified = std.mem.eql(u8, request.path, "/not-modified");
                const ordinary = std.mem.eql(u8, request.path, "/truncated");
                try connection.writeResponse(request.stream_id, .{
                    .status = if (not_modified) 304 else 200,
                    .request_method = request.method,
                    .headers = &.{
                        .{ .name = "content-encoding", .value = "gzip" },
                        .{ .name = "content-length", .value = if (ordinary) "0" else "123" },
                    },
                });
            }
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try h2.Client.connect(std.testing.allocator, io, server.address(), .{ .max_body_bytes = 1 });
    defer client.close();
    var requests = [_]h2.RequestOptions{
        .{ .method = "HEAD", .path = "/head", .authority = "localhost" },
        .{ .path = "/not-modified", .authority = "localhost" },
        .{ .path = "/truncated", .authority = "localhost" },
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    switch (mode) {
        .single => for (requests, 0..) |request, index| {
            var response = try client.requestWithDeadline(request, deadline);
            defer response.deinit(std.testing.allocator);
            try checkResponse(response, index);
        },
        .batch, .body_batch => {
            if (mode == .body_batch) requests[2].body = "x";
            var responses: [3]h2.OwnedResponse = undefined;
            if (mode == .batch)
                try client.requestBatchIntoWithDeadline(&requests, &responses, deadline)
            else
                try client.requestBodyBatchWithInformationalIntoWithDeadline(&requests, 2, &responses, null, deadline);
            defer for (&responses) |*response| response.deinit(std.testing.allocator);
            for (responses, 0..) |response, index| try checkResponse(response, index);
        },
        .streaming => {
            const Context = struct {
                index: usize,

                fn begin(self: *@This(), head: h2.StreamingResponseHead) !void {
                    if (self.index < 2) {
                        try std.testing.expect(!head.body_allowed);
                        try metadata.expectEmptyStream(head);
                    } else {
                        try std.testing.expect(head.body_allowed);
                        var decoder = try head.streamContentDecoder(std.testing.allocator, .{
                            .max_encoded_bytes = 1024,
                            .max_decoded_bytes = 1024,
                        });
                        defer decoder.deinit();
                        try std.testing.expectError(error.InvalidContentEncoding, decoder.finish(&.{}));
                    }
                }

                fn consume(_: *@This(), data: []const u8) !void {
                    try std.testing.expectEqual(@as(usize, 0), data.len);
                }
            };
            for (requests, 0..) |request, index| {
                var context = Context{ .index = index };
                var response = try client.requestStreamingWithHeadAndDeadline(request, deadline, &context, Context.begin, Context.consume);
                defer response.deinit(std.testing.allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
            }
        },
        .individual_batch => {
            const Observer = struct {
                err: ?anyerror = null,
                count: usize = 0,

                fn result(context: *anyopaque, index: usize, value: h2.BatchOwnedResponseResult) void {
                    const self: *@This() = @ptrCast(@alignCast(context));
                    self.count += 1;
                    switch (value) {
                        .err => |err| self.err = err,
                        .response => |owned| {
                            var response = owned;
                            defer response.deinit(std.testing.allocator);
                            checkResponse(response, index) catch |err| {
                                self.err = err;
                            };
                        },
                    }
                }
            };
            var observer: Observer = .{};
            const deadlines = [_]?std.Io.Clock.Timestamp{deadline} ** 3;
            try client.requestBatchWithPerStreamDeadlines(&requests, &deadlines, .{ .context = &observer, .on_result = Observer.result });
            if (observer.err) |err| return err;
            try std.testing.expectEqual(@as(usize, 3), observer.count);
        },
        .individual_streaming => {
            const Observer = struct {
                err: ?anyerror = null,
                count: usize = 0,

                fn head(_: *anyopaque, index: usize, value: h2.StreamingResponseHead) !void {
                    if (index < 2) {
                        try std.testing.expect(!value.body_allowed);
                        try metadata.expectEmptyStream(value);
                    } else {
                        try std.testing.expect(value.body_allowed);
                    }
                }

                fn data(_: *anyopaque, _: usize, bytes: []const u8) !void {
                    try std.testing.expectEqual(@as(usize, 0), bytes.len);
                }

                fn result(context: *anyopaque, _: usize, value: h2.BatchStreamingResponseResult) void {
                    const self: *@This() = @ptrCast(@alignCast(context));
                    self.count += 1;
                    switch (value) {
                        .err => |err| self.err = err,
                        .response => |owned| {
                            var response = owned;
                            response.deinit(std.testing.allocator);
                        },
                    }
                }
            };
            var observer: Observer = .{};
            const deadlines = [_]?std.Io.Clock.Timestamp{deadline} ** 3;
            try client.requestBatchStreamingWithPerStreamDeadlines(&requests, &deadlines, .{
                .context = &observer,
                .on_head = Observer.head,
                .on_data = Observer.data,
                .on_result = Observer.result,
            });
            if (observer.err) |err| return err;
            try std.testing.expectEqual(@as(usize, 3), observer.count);
        },
        .duplex => for (requests, 0..) |request, index| {
            var writer = try client.startRequest(.{ .method = request.method, .path = request.path, .authority = request.authority });
            defer writer.deinit();
            try writer.finish();
            var stream = try writer.beginDuplex();
            defer stream.deinit();
            var event = try stream.readResponseEventWithDeadline(deadline);
            defer event.deinit(std.testing.allocator);
            try std.testing.expect(event == .head);
            try std.testing.expectEqual(index >= 2, event.head.body_allowed);
            if (index < 2) {
                try metadata.expectEmptyStream(event.head);
            } else {
                var decoder = try event.head.streamContentDecoder(std.testing.allocator, .{ .max_encoded_bytes = 1024, .max_decoded_bytes = 1024 });
                defer decoder.deinit();
                try std.testing.expectError(error.InvalidContentEncoding, decoder.finish(&.{}));
            }
        },
    }
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP content decoding preserves response metadata across HTTP2 receive APIs" {
    for ([_]Mode{ .single, .batch, .body_batch, .streaming, .individual_batch, .individual_streaming, .duplex }) |mode| try exercise(mode);
}
