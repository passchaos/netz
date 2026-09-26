const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const server_mod = @import("server.zig");

const http3 = netz.http3;
const runtime = http3.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    const length = model.normalizedLength(input);
    if (length == 0) return .{};
    const sequence = input[0..length];
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    } };
    const server_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xa4} ** 32,
                .x25519_secret_key = [_]u8{0xa5} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 256,
                .max_frames_per_packet = 8,
            },
        },
    );
    defer server.deinit();
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
    defer if (!joined) server_thread.join();

    const original_dcid = [_]u8{
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    };
    const client_cid = [_]u8{ 0xb8, 0xb9, 0xba, 0xbb };
    var client = try runtime.HandshakeClient.connectWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xbc} ** 32,
                .x25519_secret_key = [_]u8{0xbd} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 256,
                .max_frames_per_packet = 8,
            },
        },
        model.timeout,
    );
    defer client.deinit();

    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        switch (model.kind(operation)) {
            0, 6 => {
                try completeRequest(&client, operation, index);
                summary.streams += 1;
                if (model.kind(operation) == 6) {
                    summary.head_responses += 1;
                } else {
                    summary.simple += 1;
                }
            },
            1 => {
                try completeRequestWithTrailers(&client, operation, index);
                summary.streams += 1;
                summary.request_trailers += 1;
            },
            2 => {
                try streamingRequest(&client, operation, index);
                summary.streams += 1;
                summary.streaming_requests += 1;
            },
            3 => {
                try streamingResponse(&client, operation, index);
                summary.streams += 1;
                summary.streaming_responses += 1;
            },
            4 => {
                try multiplexedPair(&client, operation, index);
                summary.streams += 2;
                summary.multiplexed_pairs += 1;
            },
            5 => {
                try cancelRequest(&client, operation, index);
                summary.streams += 1;
                summary.cancellations += 1;
            },
            7 => {
                try observeGoAway(&client, @intCast(summary.streams * 4));
                summary.goaways += 1;
                break;
            },
        }
        try std.testing.expect(client.isReusable());
    }
    if (summary.goaways == 0) {
        try observeGoAway(&client, @intCast(summary.streams * 4));
        summary.goaways += 1;
    }
    server_thread.join();
    joined = true;
    if (server_state.err) |err| return err;
    return summary;
}

fn completeRequest(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    var response = try client.requestWithTimeout(.{
        .method = if (model.kind(operation) == 6) "HEAD" else "GET",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index, false);
}

fn completeRequestWithTrailers(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const body = model.Bytes.request(operation, index);
    var response = try client.requestWithTimeout(.{
        .method = "POST",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
        .body = &body.value,
        .trailers = &.{.{ .name = "x-request-state", .value = "complete" }},
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index, false);
}

fn streamingRequest(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const body = model.Bytes.request(operation, index);
    const stream_id = try client.startRequestWithTimeout(.{
        .method = "POST",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
    }, body.value.len, model.timeout);
    try client.sendRequestBodyPartsPaced(
        stream_id,
        &.{ body.value[0..1], &.{}, body.value[1..] },
        false,
    );
    try client.finishRequestTrailersPacedWithTimeout(
        stream_id,
        &.{.{ .name = "x-request-state", .value = "complete" }},
        model.timeout,
    );
    var response = try client.receiveResponseWithTimeout(
        stream_id,
        model.timeout,
    );
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index, false);
}

fn streamingResponse(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
    });
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    var saw_head = false;
    var saw_trailers = false;
    while (true) {
        var event = (try client.receiveResponseEventWithTimeout(
            stream_id,
            model.timeout,
        )) orelse continue;
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                saw_head = true;
            },
            .data_available => {
                var scratch: [16]u8 = undefined;
                const count = try client.readResponseData(stream_id, &scratch);
                try std.testing.expect(count != 0);
                try body.appendSlice(std.testing.allocator, scratch[0..count]);
            },
            .trailers => |trailers| {
                try std.testing.expectEqual(@as(usize, 1), trailers.fields.len);
                try std.testing.expectEqualStrings(
                    "complete",
                    trailers.fields[0].value,
                );
                saw_trailers = true;
            },
            .finished => break,
            .push_promise => return error.UnexpectedPushPromise,
        }
    }
    const expected = model.Bytes.response(operation, index);
    try std.testing.expectEqualSlices(u8, &expected.value, body.items);
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
}

fn multiplexedPair(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var first_path: [40]u8 = undefined;
    var second_path: [40]u8 = undefined;
    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = try model.pathBuffer(&first_path, operation, index, "/a"),
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = try model.pathBuffer(&second_path, operation, index, "/b"),
        .authority = "localhost",
    });
    var first = try client.receiveNextResponseWithTimeout(model.timeout);
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first == .response);
    try std.testing.expectEqual(second_id, first.response.stream_id);
    try validateResponse(first.response.value.response, operation, index, true);
    var second = try client.receiveNextResponseWithTimeout(model.timeout);
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(second == .response);
    try std.testing.expectEqual(first_id, second.response.stream_id);
    try validateResponse(second.response.value.response, operation, index, false);
}

fn cancelRequest(
    client: *runtime.HandshakeClient,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const stream_id = try client.startRequestWithTimeout(.{
        .method = "POST",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
    }, 3, model.timeout);
    try client.sendRequestBodyPaced(stream_id, &.{operation}, false);
    try client.cancelRequest(
        stream_id,
        http3.ApplicationErrorCode.request_cancelled,
    );
}

fn observeGoAway(
    client: *runtime.HandshakeClient,
    final_stream_id: u64,
) !void {
    var attempts: usize = 0;
    while (client.peerGoAwayId() != final_stream_id) {
        if (attempts == 32) return error.GoAwayProgressLimitExceeded;
        try client.pollControlWithTimeout(model.timeout);
        attempts += 1;
    }
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(error.GoAwayReceived, client.sendRequest(.{
        .method = "GET",
        .path = "/after-goaway",
        .authority = "localhost",
    }));
}

fn validateResponse(
    response: http3.DecodedResponse,
    operation: u8,
    index: usize,
    second: bool,
) !void {
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const expected = model.Bytes.response(operation, index);
    if (model.kind(operation) == 6) {
        try std.testing.expectEqual(@as(usize, 0), response.body.len);
        return;
    }
    if (second) {
        const second_body = [_]u8{
            expected.value[0],
            expected.value[1],
            expected.value[2] ^ 0xff,
        };
        try std.testing.expectEqualSlices(u8, &second_body, response.body);
    } else {
        try std.testing.expectEqualSlices(u8, &expected.value, response.body);
    }
}
