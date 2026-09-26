const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const server_mod = @import("server.zig");

const http1 = netz.http1;
const runtime = http1.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    const sequence = input[0..@min(input.len, model.max_operations)];
    if (sequence.len == 0) return .{};
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
        .{
            .max_head_bytes = 4096,
            .max_body_bytes = 4096,
        },
    );
    var server_open = true;
    defer if (server_open) server.deinit();
    var server_state = server_mod.State{
        .server = &server,
        .allocator = allocator,
        .input = sequence,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        server_mod.State.run,
        .{&server_state},
    );
    var joined = false;
    defer if (!joined) {
        server.deinit();
        server_open = false;
        server_thread.join();
    };

    var client: ?runtime.Client = null;
    defer if (client) |*value| value.close();
    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        if (client == null) {
            client = try runtime.Client.connectWithTimeout(
                allocator,
                io,
                server.address(),
                .{
                    .max_head_bytes = 4096,
                    .max_body_bytes = 4096,
                },
                model.timeout,
            );
            if (index != 0) summary.reconnects += 1;
        }
        switch (model.kind(operation)) {
            0, 1, 4, 5, 6, 7 => try completeExchange(
                &client.?,
                operation,
                index,
                &summary,
            ),
            2 => try fixedStreamingRequest(
                &client.?,
                operation,
                index,
                &summary,
            ),
            3 => try chunkedStreamingRequest(
                &client.?,
                operation,
                index,
                &summary,
            ),
        }
        summary.requests += 1;
        if (model.closesConnection(operation)) {
            try std.testing.expect(!client.?.isReusable());
            client.?.close();
            client = null;
            if (model.kind(operation) == 5) {
                summary.server_closes += 1;
            } else {
                summary.client_closes += 1;
            }
        } else {
            try std.testing.expect(client.?.isReusable());
            summary.reused += 1;
        }
    }

    if (client) |*value| {
        value.close();
        client = null;
    }
    server_thread.join();
    joined = true;
    if (server_state.err) |err| return err;
    try std.testing.expectEqual(summary.requests, server_state.summary.requests);
    try std.testing.expectEqual(
        summary.server_closes + summary.client_closes,
        server_state.summary.server_closes,
    );
    return summary;
}

fn completeExchange(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    const headers: []const http1.Header = switch (model.kind(operation)) {
        5 => &.{.{ .name = "TE", .value = "trailers" }},
        7 => &.{.{ .name = "Connection", .value = "close" }},
        else => &.{},
    };
    var response = try client.requestWithTimeout(.{
        .method = model.method(operation),
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .headers = headers,
        .body = if (model.requestHasBody(operation))
            &request_body.value
        else
            &.{},
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.complete_bodies += 1;
    switch (model.kind(operation)) {
        4 => summary.streaming_fixed_responses += 1,
        5 => summary.streaming_chunked_responses += 1,
        6 => summary.head_responses += 1,
        else => {},
    }
}

fn fixedStreamingRequest(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .body_length = request_body.value.len,
    });
    defer writer.deinit();
    try writer.write(request_body.value[0..1]);
    try writer.writeChunks(&.{
        request_body.value[1..2],
        &.{},
        request_body.value[2..],
    });
    try writer.finish();
    var response = try writer.readResponseWithTimeout(model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.streaming_fixed_requests += 1;
}

fn chunkedStreamingRequest(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .trailer_names = &.{"X-Request-Digest"},
    });
    defer writer.deinit();
    try writer.writeChunks(&.{
        request_body.value[0..1],
        request_body.value[1..],
    });
    try writer.finishTrailers(&.{.{
        .name = "X-Request-Digest",
        .value = "complete",
    }});
    var response = try writer.readResponseWithTimeout(model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.streaming_chunked_requests += 1;
}

fn validateResponse(
    response: http1.Response,
    operation: u8,
    index: usize,
) !void {
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const expected = model.Bytes.response(operation, index);
    if (model.method(operation) == .HEAD) {
        try std.testing.expectEqual(@as(usize, 0), response.body.len);
        try std.testing.expectEqual(
            @as(?usize, expected.value.len),
            http1.contentLength(response.headers),
        );
        return;
    }
    try std.testing.expectEqualSlices(u8, &expected.value, response.body);
    if (model.kind(operation) == 5) {
        try std.testing.expectEqual(http1.BodyFraming.chunked, response.body_framing);
        try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
        try std.testing.expectEqualStrings(
            "X-Response-Digest",
            response.trailers[0].name,
        );
        try std.testing.expectEqualStrings(
            "complete",
            response.trailers[0].value,
        );
    }
}
