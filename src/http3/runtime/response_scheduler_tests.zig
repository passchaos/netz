const std = @import("std");
const runtime = @import("../runtime.zig");

const quic = @import("../../quic/mod.zig");

test "HTTP/3 handshake server schedules response bodies by priority" {
    const allocator = std.testing.allocator;
    const body = "0123456789abcdef" ** 192;
    const chunk_size: usize = 384;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x51} ** 32,
                .x25519_secret_key = [_]u8{0x52} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1200,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        body: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var requests: [3]runtime.OwnedHandshakeRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(
                    session.established.connection.endpoint.allocator,
                );
            };
            while (initialized < requests.len) : (initialized += 1) {
                requests[initialized] = try session.receiveRequest();
            }
            for (requests) |request| {
                try session.startResponse(
                    request.stream_id,
                    .{ .status = 200 },
                    shared.body.len,
                );
            }
            var responses: [3]runtime.ResponseBody = undefined;
            for (&responses, requests) |*response, request| {
                response.* = .{
                    .stream_id = request.stream_id,
                    .data = shared.body,
                };
            }
            try session.sendResponseBodiesPaced(&responses);
        }
    };

    var shared = Shared{ .server = &server, .body = body };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x53} ** 32,
                .x25519_secret_key = [_]u8{0x54} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1200,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer client.deinit();

    const low = try client.sendRequest(.{
        .method = "GET",
        .path = "/low",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=6, i",
        }},
    });
    const urgent_later = try client.sendRequest(.{
        .method = "GET",
        .path = "/urgent-later",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=1",
        }},
    });
    const urgent_first = try client.sendRequest(.{
        .method = "GET",
        .path = "/urgent-first",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=1",
        }},
    });
    var received = [_]usize{ 0, 0, 0 };
    var finished: [3]u62 = undefined;
    var finished_count: usize = 0;
    while (finished_count < finished.len) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        const index: usize = if (event.message.stream_id == low)
            0
        else if (event.message.stream_id == urgent_later)
            1
        else if (event.message.stream_id == urgent_first)
            2
        else
            return error.TestUnexpectedResult;
        switch (event.message.value) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(
                    @as(?usize, body.len),
                    head.response.content_length,
                );
            },
            .data_available => {
                received[index] += try client.skipResponseData(
                    event.message.stream_id,
                );
            },
            .finished => {
                try std.testing.expectEqual(body.len, received[index]);
                finished[finished_count] = event.message.stream_id;
                finished_count += 1;
            },
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    // Both urgency-1 responses are non-incremental, so the lower stream ID
    // completes first. The urgency-6 response cannot finish ahead of either.
    try std.testing.expectEqual(urgent_later, finished[0]);
    try std.testing.expectEqual(urgent_first, finished[1]);
    try std.testing.expectEqual(low, finished[2]);
}

test "HTTP/3 handshake scheduler shares incremental response bodies" {
    const allocator = std.testing.allocator;
    const body = "incremental-response-" ** 192;
    const chunk_size: usize = 320;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
    };
    const client_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x65} ** 32,
                .x25519_secret_key = [_]u8{0x66} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1200,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        body: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                first.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.startResponse(
                second.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.sendResponseBodiesPaced(&.{
                .{ .stream_id = first.stream_id, .data = shared.body },
                .{ .stream_id = second.stream_id, .data = shared.body },
            });
        }
    };

    var shared = Shared{ .server = &server, .body = body };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x67} ** 32,
                .x25519_secret_key = [_]u8{0x68} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1200,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer client.deinit();

    const first = try client.sendRequest(.{
        .method = "GET",
        .path = "/incremental-first",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=2, i",
        }},
    });
    const second = try client.sendRequest(.{
        .method = "GET",
        .path = "/incremental-second",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=2, i",
        }},
    });
    var first_received: usize = 0;
    var second_received: usize = 0;
    var first_finished = false;
    var second_finished = false;
    while (!first_finished or !second_finished) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        switch (event.message.value) {
            .head => {},
            .data_available => {
                const skipped = try client.skipResponseData(
                    event.message.stream_id,
                );
                if (event.message.stream_id == first) {
                    first_received += skipped;
                } else if (event.message.stream_id == second) {
                    second_received += skipped;
                } else {
                    return error.TestUnexpectedResult;
                }
                // With both responses much larger than one packet, neither
                // incremental peer may finish before the other has progressed.
                if (first_received == body.len) {
                    try std.testing.expect(second_received != 0);
                }
                if (second_received == body.len) {
                    try std.testing.expect(first_received != 0);
                }
            },
            .finished => {
                if (event.message.stream_id == first) {
                    first_finished = true;
                } else if (event.message.stream_id == second) {
                    second_finished = true;
                } else {
                    return error.TestUnexpectedResult;
                }
            },
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(body.len, first_received);
    try std.testing.expectEqual(body.len, second_received);
}

test "HTTP/3 handshake scheduler bypasses a blocked urgent response" {
    const allocator = std.testing.allocator;
    const body = "blocked-urgent-response-" ** 96;
    const chunk_size: usize = 256;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 32 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 1150;
    client_transport.initial_max_stream_data_bidi_remote = 1150;
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x79} ** 32,
                .x25519_secret_key = [_]u8{0x7a} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1000,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        body: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var urgent = try session.receiveRequest();
            defer urgent.deinit(
                session.established.connection.endpoint.allocator,
            );
            var lower = try session.receiveRequest();
            defer lower.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                urgent.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.startResponse(
                lower.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.sendResponseBodiesPaced(&.{
                .{ .stream_id = urgent.stream_id, .data = shared.body },
                .{ .stream_id = lower.stream_id, .data = shared.body },
            });
        }
    };

    var shared = Shared{ .server = &server, .body = body };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x7b} ** 32,
                .x25519_secret_key = [_]u8{0x7c} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1000,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer client.deinit();

    const urgent = try client.sendRequest(.{
        .method = "GET",
        .path = "/blocked-urgent",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=0",
        }},
    });
    const lower = try client.sendRequest(.{
        .method = "GET",
        .path = "/sendable-lower",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=5",
        }},
    });

    var urgent_received: usize = 0;
    // Consume just enough urgent DATA to send one MAX_STREAM_DATA update, then
    // stop reading that stream. Its receive window becomes blocked again while
    // the lower-urgency stream remains independently sendable.
    while (urgent_received < 256) {
        if (try client.receiveResponseEvent(urgent)) |value| {
            var event = value;
            defer event.deinit(allocator);
            switch (event) {
                .head => {},
                .data_available => {
                    urgent_received += try client.skipResponseData(urgent);
                },
                else => return error.TestUnexpectedResult,
            }
        }
    }
    const urgent_limit = client.established.connection
        .recvStreamStats(urgent).?.receive_limit;
    var lower_received: usize = 0;
    var lower_finished = false;
    while (!lower_finished and
        client.established.connection.recvStreamStats(
            urgent,
        ).?.highest_received_offset < urgent_limit)
    {
        if (try client.receiveResponseEvent(lower)) |value| {
            var event = value;
            defer event.deinit(allocator);
            switch (event) {
                .head => {},
                .data_available => {
                    lower_received += try client.skipResponseData(lower);
                },
                .finished => lower_finished = true,
                else => return error.TestUnexpectedResult,
            }
        }
    }

    while (!lower_finished) {
        if (try client.receiveResponseEvent(lower)) |value| {
            var event = value;
            defer event.deinit(allocator);
            switch (event) {
                .head => {},
                .data_available => {
                    lower_received += try client.skipResponseData(lower);
                },
                .finished => lower_finished = true,
                .push_promise, .trailers => {
                    return error.TestUnexpectedResult;
                },
            }
        }
    }
    try std.testing.expectEqual(body.len, lower_received);
    try std.testing.expect(urgent_received < body.len);

    var urgent_finished = false;
    while (!urgent_finished) {
        if (try client.receiveResponseEvent(urgent)) |value| {
            var event = value;
            defer event.deinit(allocator);
            switch (event) {
                .head => {},
                .data_available => {
                    urgent_received += try client.skipResponseData(urgent);
                },
                .finished => urgent_finished = true,
                .push_promise, .trailers => {
                    return error.TestUnexpectedResult;
                },
            }
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(body.len, urgent_received);
}

test "HTTP/3 handshake response scheduler honors live priority update" {
    const allocator = std.testing.allocator;
    const body = "priority-update-body-" ** 512;
    const chunk_size: usize = 256;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    };
    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 8 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 4 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 4 * 1024;
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1000,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        body: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.startResponse(
                first.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.startResponse(
                second.stream_id,
                .{ .status = 200 },
                shared.body.len,
            );
            try session.sendResponseBodiesPaced(&.{
                .{ .stream_id = first.stream_id, .data = shared.body },
                .{ .stream_id = second.stream_id, .data = shared.body },
            });
        }
    };

    var shared = Shared{ .server = &server, .body = body };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                    .enable_pacing = false,
                },
                .random = [_]u8{0x83} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 1000,
                .paced_body_chunk_bytes = chunk_size,
            },
        },
    );
    defer client.deinit();

    const first = try client.sendRequest(.{
        .method = "GET",
        .path = "/first-incremental",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=3, i",
        }},
    });
    const second = try client.sendRequest(.{
        .method = "GET",
        .path = "/second-incremental",
        .authority = "localhost",
        .headers = &.{.{
            .name = "priority",
            .value = "u=3, i",
        }},
    });
    var first_received: usize = 0;
    var second_received: usize = 0;
    var update_sent = false;
    var first_finished = false;
    var second_finished = false;
    var first_finished_before_second = false;
    while (!first_finished or !second_finished) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        switch (event.message.value) {
            .head => {},
            .data_available => {
                const skipped = try client.skipResponseData(
                    event.message.stream_id,
                );
                if (event.message.stream_id == first) {
                    first_received += skipped;
                } else if (event.message.stream_id == second) {
                    second_received += skipped;
                } else {
                    return error.TestUnexpectedResult;
                }
                if (!update_sent and
                    first_received != 0 and
                    second_received != 0)
                {
                    try client.sendPriorityUpdate(first, .{
                        .urgency = 0,
                        .incremental = false,
                    });
                    update_sent = true;
                }
            },
            .finished => {
                if (event.message.stream_id == first) {
                    first_finished = true;
                    first_finished_before_second = !second_finished;
                } else if (event.message.stream_id == second) {
                    second_finished = true;
                } else {
                    return error.TestUnexpectedResult;
                }
            },
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(update_sent);
    try std.testing.expectEqual(body.len, first_received);
    try std.testing.expectEqual(body.len, second_received);
    try std.testing.expect(first_finished_before_second);
}
