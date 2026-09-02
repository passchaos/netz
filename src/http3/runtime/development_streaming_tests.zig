const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

const test_limits: runtime.Limits = .{
    .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    },
    // Splitting HEADERS and DATA across several datagrams makes these tests
    // exercise persistent stream offsets rather than a one-packet happy path.
    .max_stream_frame_data = 7,
};

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
}

fn peerIndex(
    from: net.IpAddress,
    first: net.IpAddress,
    second: net.IpAddress,
) !usize {
    if (from.eql(&first)) return 0;
    if (from.eql(&second)) return 1;
    return error.TestUnexpectedResult;
}

fn expectResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *runtime.Client,
    stream_id: u62,
    expected_status: u16,
    expected_body: []const u8,
) !void {
    var body: [128]u8 = undefined;
    var body_len: usize = 0;
    var saw_head = false;
    var finished = false;
    const deadline = futureDeadline(io);
    while (!finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .response => |response| {
                    try std.testing.expect(!saw_head);
                    try std.testing.expectEqual(
                        expected_status,
                        response.status,
                    );
                    try std.testing.expectEqual(
                        @as(?usize, expected_body.len),
                        response.content_length,
                    );
                    saw_head = true;
                },
                .request => return error.TestUnexpectedResult,
            },
            .data_available => {
                body_len += try client.readResponseData(
                    stream_id,
                    body[body_len..],
                );
            },
            .finished => finished = true,
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expectEqualStrings(expected_body, body[0..body_len]);
}

test "HTTP/3 dev streaming roundtrip isolates two peers using stream zero" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var first = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer first.deinit();
    var second = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer second.deinit();

    const request_bodies = [_][]const u8{
        "alpha-stream-body",
        "beta-stream-body",
    };
    const response_bodies = [_][]const u8{
        "response-for-alpha",
        "response-for-beta",
    };
    const first_id = try first.startRequest(.{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
    }, request_bodies[0].len);
    const second_id = try second.startRequest(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
    }, request_bodies[1].len);
    try std.testing.expectEqual(@as(u62, 0), first_id);
    try std.testing.expectEqual(@as(u62, 0), second_id);
    try first.sendRequestBody(first_id, request_bodies[0][0..5], false);
    try first.sendRequestBody(first_id, request_bodies[0][5..], true);
    try second.sendRequestBody(second_id, request_bodies[1][0..4], false);
    try second.sendRequestBody(second_id, request_bodies[1][4..], true);

    var received: [2][64]u8 = undefined;
    var received_len = [_]usize{ 0, 0 };
    var saw_head = [_]bool{ false, false };
    var finished = [_]bool{ false, false };
    var finished_count: usize = 0;
    const request_deadline = futureDeadline(io);
    while (finished_count != 2) {
        var event = try server.receiveRequestEventWithDeadline(
            request_deadline,
        );
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.TestUnexpectedResult,
            .message => |message| {
                const index = try peerIndex(
                    message.from,
                    first.address(),
                    second.address(),
                );
                try std.testing.expectEqual(@as(u62, 0), message.stream_id);
                switch (message.value) {
                    .head => |head| switch (head) {
                        .request => |request| {
                            try std.testing.expect(!saw_head[index]);
                            try std.testing.expectEqualStrings(
                                if (index == 0) "/first" else "/second",
                                request.path,
                            );
                            saw_head[index] = true;
                        },
                        .response => return error.TestUnexpectedResult,
                    },
                    .data_available => {
                        received_len[index] += try server.readRequestData(
                            message.from,
                            message.stream_id,
                            received[index][received_len[index]..],
                        );
                    },
                    .finished => {
                        try std.testing.expect(!finished[index]);
                        finished[index] = true;
                        finished_count += 1;
                    },
                    .push_promise, .trailers => return error.TestUnexpectedResult,
                }
            },
        }
    }
    for (request_bodies, 0..) |expected, index| {
        try std.testing.expect(saw_head[index]);
        try std.testing.expectEqualStrings(
            expected,
            received[index][0..received_len[index]],
        );
    }

    try server.startResponse(
        first.address(),
        first_id,
        .{ .status = 201 },
        response_bodies[0].len,
    );
    try server.sendResponseBody(
        first.address(),
        first_id,
        response_bodies[0][0..6],
        false,
    );
    try server.sendResponseBody(
        first.address(),
        first_id,
        response_bodies[0][6..],
        true,
    );
    try server.startResponse(
        second.address(),
        second_id,
        .{ .status = 202 },
        response_bodies[1].len,
    );
    try server.sendResponseBody(
        second.address(),
        second_id,
        response_bodies[1],
        true,
    );

    try expectResponse(
        allocator,
        io,
        &first,
        first_id,
        201,
        response_bodies[0],
    );
    try expectResponse(
        allocator,
        io,
        &second,
        second_id,
        202,
        response_bodies[1],
    );
}

test "HTTP/3 dev streaming timeout preserves request and response progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/timeout-resume",
        .authority = "localhost",
    }, null);
    try client.sendRequestBody(stream_id, "request-one", false);

    var request_body: [64]u8 = undefined;
    var request_len: usize = 0;
    var saw_request_head = false;
    while (!saw_request_head or request_len != "request-one".len) {
        var event = try server.receiveRequestEventWithDeadline(
            futureDeadline(io),
        );
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.TestUnexpectedResult,
            .message => |message| switch (message.value) {
                .head => |head| switch (head) {
                    .request => |request| {
                        try std.testing.expectEqualStrings(
                            "/timeout-resume",
                            request.path,
                        );
                        try std.testing.expectEqual(
                            @as(?usize, null),
                            request.content_length,
                        );
                        saw_request_head = true;
                    },
                    .response => return error.TestUnexpectedResult,
                },
                .data_available => {
                    request_len += try server.readRequestData(
                        message.from,
                        stream_id,
                        request_body[request_len..],
                    );
                },
                .finished, .push_promise, .trailers => return error.TestUnexpectedResult,
            },
        }
    }
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestEventWithTimeout(.fromMilliseconds(20)),
    );
    try client.sendRequestBody(stream_id, "-request-two", true);

    var request_finished = false;
    while (!request_finished) {
        var event = try server.receiveRequestEventWithDeadline(
            futureDeadline(io),
        );
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.TestUnexpectedResult,
            .message => |message| switch (message.value) {
                .data_available => {
                    request_len += try server.readRequestData(
                        message.from,
                        stream_id,
                        request_body[request_len..],
                    );
                },
                .finished => request_finished = true,
                .head, .push_promise, .trailers => return error.TestUnexpectedResult,
            },
        }
    }
    try std.testing.expectEqualStrings(
        "request-one-request-two",
        request_body[0..request_len],
    );

    try server.startResponse(
        client.address(),
        stream_id,
        .{ .status = 200 },
        null,
    );
    try server.sendResponseBody(
        client.address(),
        stream_id,
        "response-one",
        false,
    );

    var response_body: [64]u8 = undefined;
    var response_len: usize = 0;
    var saw_response_head = false;
    while (!saw_response_head or response_len != "response-one".len) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            futureDeadline(io),
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .response => |response| {
                    try std.testing.expectEqual(@as(u16, 200), response.status);
                    try std.testing.expectEqual(
                        @as(?usize, null),
                        response.content_length,
                    );
                    saw_response_head = true;
                },
                .request => return error.TestUnexpectedResult,
            },
            .data_available => {
                response_len += try client.readResponseData(
                    stream_id,
                    response_body[response_len..],
                );
            },
            .finished, .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseEventWithTimeout(
            stream_id,
            .fromMilliseconds(20),
        ),
    );
    try server.sendResponseBody(
        client.address(),
        stream_id,
        "-response-two",
        true,
    );

    var response_finished = false;
    while (!response_finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            futureDeadline(io),
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .data_available => {
                response_len += try client.readResponseData(
                    stream_id,
                    response_body[response_len..],
                );
            },
            .finished => response_finished = true,
            .head, .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings(
        "response-one-response-two",
        response_body[0..response_len],
    );
}

test "HTTP/3 dev streaming rejects invalid timeout and deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "GET",
        .path = "/invalid-deadline",
        .authority = "localhost",
    }, 0);
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestEventWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveRequestEventWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseEventWithTimeout(stream_id, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseEventWithDeadline(stream_id, .{
            .raw = .zero,
            .clock = .real,
        }),
    );
}

test "HTTP/3 dev streaming enforces content length and terminal state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    try std.testing.expectError(
        error.InvalidContentLength,
        client.startRequest(.{
            .method = "POST",
            .path = "/bad-declared-length",
            .authority = "localhost",
            .headers = &.{.{
                .name = "content-length",
                .value = "4",
            }},
        }, 3),
    );
    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/length",
        .authority = "localhost",
    }, 3);
    // A local validation error is retryable and must not consume body state.
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBody(stream_id, "four", true),
    );
    try client.sendRequestBody(stream_id, "abc", true);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendRequestBody(stream_id, "late", true),
    );

    var request_body: [8]u8 = undefined;
    var request_len: usize = 0;
    var request_finished = false;
    while (!request_finished) {
        var event = try server.receiveRequestEventWithDeadline(
            futureDeadline(io),
        );
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.TestUnexpectedResult,
            .message => |message| switch (message.value) {
                .data_available => {
                    request_len += try server.readRequestData(
                        message.from,
                        stream_id,
                        request_body[request_len..],
                    );
                },
                .finished => request_finished = true,
                .head => |head| switch (head) {
                    .request => |request| try std.testing.expectEqual(
                        @as(?usize, 3),
                        request.content_length,
                    ),
                    .response => return error.TestUnexpectedResult,
                },
                .push_promise, .trailers => return error.TestUnexpectedResult,
            },
        }
    }
    try std.testing.expectEqualStrings("abc", request_body[0..request_len]);

    try server.startResponse(
        client.address(),
        stream_id,
        .{ .status = 200 },
        3,
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        server.sendResponseBody(
            client.address(),
            stream_id,
            "four",
            true,
        ),
    );
    try server.sendResponseBody(
        client.address(),
        stream_id,
        "xyz",
        true,
    );
    try std.testing.expectError(
        error.UnexpectedStream,
        server.sendResponseBody(
            client.address(),
            stream_id,
            "late",
            true,
        ),
    );
    try expectResponse(allocator, io, &client, stream_id, 200, "xyz");
    try std.testing.expectError(
        error.UnexpectedStream,
        client.receiveResponseEvent(stream_id),
    );
}

test "HTTP/3 dev streaming keeps extended CONNECT directions open" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/session",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }, null);
    var request_head = try server.receiveRequestEventWithDeadline(
        futureDeadline(io),
    );
    defer request_head.deinit(allocator);
    try std.testing.expect(request_head == .message);
    try std.testing.expect(request_head.message.value == .head);
    try std.testing.expect(request_head.message.value.head == .request);
    try std.testing.expectEqualStrings(
        "CONNECT",
        request_head.message.value.head.request.method,
    );
    try server.startResponse(
        client.address(),
        stream_id,
        .{
            .status = 200,
            .request_method = "CONNECT",
            .extended_connect = true,
        },
        null,
    );
    try client.sendRequestBody(stream_id, "client-control", false);
    try server.sendResponseBody(
        client.address(),
        stream_id,
        "server-control",
        false,
    );

    var request_buffer: [32]u8 = undefined;
    var request_len: usize = 0;
    while (request_len != "client-control".len) {
        var request_data = try server.receiveRequestEventWithDeadline(
            futureDeadline(io),
        );
        defer request_data.deinit(allocator);
        try std.testing.expect(request_data == .message);
        try std.testing.expect(
            request_data.message.value == .data_available,
        );
        request_len += try server.readRequestData(
            client.address(),
            stream_id,
            request_buffer[request_len..],
        );
    }
    try std.testing.expectEqualStrings(
        "client-control",
        request_buffer[0..request_len],
    );

    var saw_response_head = false;
    var response_buffer: [32]u8 = undefined;
    var response_len: usize = 0;
    while (response_len != "server-control".len) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            futureDeadline(io),
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .response => |response| {
                    try std.testing.expectEqual(@as(u16, 200), response.status);
                    saw_response_head = true;
                },
                .request => return error.TestUnexpectedResult,
            },
            .data_available => response_len += try client.readResponseData(
                stream_id,
                response_buffer[response_len..],
            ),
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_response_head);
    try std.testing.expectEqualStrings(
        "server-control",
        response_buffer[0..response_len],
    );

    try client.sendRequestBody(stream_id, &.{}, true);
    try server.sendResponseBody(client.address(), stream_id, &.{}, true);
}

test "HTTP/3 dev streaming cancellation uses valid local final sizes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/cancel",
        .authority = "localhost",
    }, 0);
    var request = try server.receiveRequestEventWithDeadline(
        futureDeadline(io),
    );
    defer request.deinit(allocator);
    try std.testing.expect(request == .message);
    try std.testing.expect(request.message.value == .head);

    // The server has not emitted response bytes, so cancellation uses final
    // size zero. The client already FINished its request in startRequest and
    // therefore sends only STOP_SENDING rather than an illegal second final.
    try server.cancelRequest(
        client.address(),
        stream_id,
        http3.ApplicationErrorCode.message_error,
    );
    var server_cancel = try client.quic_client.receiveWithDeadline(
        futureDeadline(io),
    );
    defer server_cancel.deinit(allocator);
    var saw_reset = false;
    var saw_stop = false;
    for (server_cancel.frames) |frame| switch (frame) {
        .reset_stream => |reset| {
            try std.testing.expectEqual(@as(u64, 0), reset.final_size);
            saw_reset = true;
        },
        .stop_sending => saw_stop = true,
        else => {},
    };
    try std.testing.expect(saw_reset and saw_stop);

    // Use a separate exchange for the client-side half-closed case.
    var second_server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer second_server.deinit();
    var second_client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        second_server.address(),
        test_limits,
    );
    defer second_client.deinit();
    const second_id = try second_client.startRequest(.{
        .method = "POST",
        .path = "/cancel-after-fin",
        .authority = "localhost",
    }, 0);
    try second_client.cancelRequest(
        second_id,
        http3.ApplicationErrorCode.message_error,
    );
    var client_saw_reset = false;
    var client_saw_stop = false;
    const cancel_deadline = futureDeadline(io);
    while (!client_saw_stop) {
        var client_cancel = try second_server.quic_server
            .receiveWithDeadline(cancel_deadline);
        defer client_cancel.deinit(allocator);
        for (client_cancel.frames) |frame| switch (frame) {
            .reset_stream => client_saw_reset = true,
            .stop_sending => client_saw_stop = true,
            else => {},
        };
    }
    try std.testing.expect(!client_saw_reset);
    try std.testing.expect(client_saw_stop);
}

test "HTTP/3 dev informational response reset retires prefix offset" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "CONNECT",
        .path = "/informational-reset",
        .authority = "localhost",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }, null);
    var head = try server.receiveRequestHeadWithDeadline(futureDeadline(io));
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expect(head.message.value == .head);

    try server.sendInformationalResponse(
        client.address(),
        stream_id,
        .{ .status = 103 },
    );
    try client.cancelRequest(
        stream_id,
        http3.ApplicationErrorCode.request_cancelled,
    );
    var reset = try server.receiveRequestEventForWithDeadline(
        client.address(),
        stream_id,
        futureDeadline(io),
    );
    defer reset.deinit(allocator);
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.request_cancelled),
        reset.reset.application_error_code,
    );

    // Reset delivery owns the terminal cleanup. A second cancellation must not
    // rediscover an informational-only offset as a phantom live request.
    try std.testing.expectError(
        error.UnexpectedStream,
        server.cancelRequest(
            client.address(),
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ),
    );
}
