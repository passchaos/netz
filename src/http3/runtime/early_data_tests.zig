const std = @import("std");
const runtime = @import("../runtime.zig");

const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

const early_body = "accepted zero-rtt body";
const one_rtt_body = "ordinary one-rtt body";

fn receiveStreamingRequest(
    session: *runtime.HandshakeServerSession,
    expected_stream_id: u62,
    expected_early_data: bool,
    expected_path: []const u8,
    expected_body: []const u8,
) !void {
    var body: [128]u8 = undefined;
    var body_len: usize = 0;
    var saw_head = false;
    var saw_data = false;
    var finished = false;
    while (!finished) {
        var event = try session.receiveRequestEventWithTimeout(
            .fromSeconds(2),
        );
        defer event.deinit(session.established.connection.endpoint.allocator);
        try std.testing.expect(event == .message);
        const message = &event.message;
        try std.testing.expectEqual(expected_stream_id, message.stream_id);
        try std.testing.expectEqual(
            expected_early_data,
            message.was_early_data,
        );
        try std.testing.expectEqual(
            expected_early_data,
            session.established.connection.recvStreamReceivedEarlyData(
                message.stream_id,
            ),
        );
        switch (message.value) {
            .head => |head| {
                try std.testing.expect(!saw_head);
                try std.testing.expect(head == .request);
                try std.testing.expectEqualStrings(
                    expected_path,
                    head.request.path,
                );
                saw_head = true;
            },
            .data_available => {
                try std.testing.expect(body_len < body.len);
                body_len += try session.readRequestData(
                    message.stream_id,
                    body[body_len..],
                );
                saw_data = true;
            },
            .finished => finished = true,
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_data);
    try std.testing.expectEqualStrings(expected_body, body[0..body_len]);
}

test "HTTP/3 handshake streaming accepted early request exposes provenance" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-streaming-early-provenance-ticket";
    const psk = [_]u8{0x81} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 29,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var early = try runtime.PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/early-streaming",
            .authority = "localhost",
            .body = early_body,
        },
        .{},
        .{},
    );
    defer early.deinit();

    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    const original_dcid = [_]u8{
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    };
    const client_cid = [_]u8{ 0x8a, 0x8b, 0x8c, 0x8d };
    const server_cid = [_]u8{ 0x8e, 0x8f, 0x90, 0x91 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x92} ** 32,
            .x25519_secret_key = [_]u8{0x93} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 29,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "streaming-request-provenance",
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.accepted,
                session.established.early_data_status,
            );
            try receiveStreamingRequest(
                &session,
                0,
                true,
                "/early-streaming",
                early_body,
            );
            try session.sendResponse(0, .{ .status = 200 });

            try receiveStreamingRequest(
                &session,
                4,
                false,
                "/after-early-streaming",
                one_rtt_body,
            );
            try session.sendResponse(4, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const connected = try runtime.HandshakeClient.connectWithEarlyRequest(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x94} ** 32,
            .x25519_secret_key = [_]u8{0x95} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &early,
        &cache,
        &lease,
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        runtime.EarlyRequestDisposition.accepted,
        connected.disposition,
    );
    var early_response = try client.receiveResponseWithTimeout(
        early.stream_id,
        .fromSeconds(2),
    );
    defer early_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 200),
        early_response.response.status,
    );

    const next_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/after-early-streaming",
            .authority = "localhost",
        },
        one_rtt_body.len,
    );
    try std.testing.expectEqual(@as(u62, 4), next_id);
    try client.sendRequestBody(next_id, one_rtt_body, true);
    var next_response = try client.receiveResponseWithTimeout(
        next_id,
        .fromSeconds(2),
    );
    defer next_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 204),
        next_response.response.status,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const automatic_request_body = "request body replayed exactly once";

const AutomaticRetryScenario = struct {
    reject_early_data: bool = false,
    initial_status: u16 = 425,
    retry_status: u16,
};

fn headerValue(
    fields: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

fn expectAutomaticRequest(
    request: *const runtime.OwnedHandshakeRequest,
    stream_id: u62,
    was_early_data: bool,
) !void {
    try std.testing.expectEqual(stream_id, request.stream_id);
    try std.testing.expectEqual(was_early_data, request.was_early_data);
    try std.testing.expectEqualStrings("GET", request.request.method);
    try std.testing.expectEqualStrings(
        "/automatic-early-retry",
        request.request.path,
    );
    try std.testing.expectEqualStrings(
        automatic_request_body,
        request.request.body,
    );
    try std.testing.expectEqualStrings(
        "original",
        headerValue(request.request.headers, "x-early-request").?,
    );
    try std.testing.expectEqualStrings(
        "complete",
        headerValue(request.request.trailers, "x-early-trailer").?,
    );
}

fn runAutomaticEarlyRetryScenario(
    scenario: AutomaticRetryScenario,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ticket = "h3-automatic-early-retry-ticket";
    const psk = [_]u8{0xa1} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 31,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const original_dcid = [_]u8{
        0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
    };
    const client_cid = [_]u8{ 0xaa, 0xab, 0xac, 0xad };
    const server_cid = [_]u8{ 0xae, 0xaf, 0xb0, 0xb1 };
    var server_options = runtime.HandshakeServerOptions{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb2} ** 32,
            .x25519_secret_key = [_]u8{0xb3} ** 32,
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 31,
                .issued_at_ms = 1000,
                .lifetime_seconds = 3600,
                .now_ms = 1500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "automatic-early-retry",
            },
        },
    };
    if (scenario.reject_early_data) {
        server_options.handshake.cipher_suites =
            &.{.chacha20_poly1305_sha256};
    }
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        server_options,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        scenario: AutomaticRetryScenario,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            const expected_status: quic.zero_rtt.handshake.Status =
                if (shared.scenario.reject_early_data)
                    .rejected
                else
                    .accepted;
            try std.testing.expectEqual(
                expected_status,
                session.established.early_data_status,
            );

            var first = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            if (shared.scenario.reject_early_data) {
                try expectAutomaticRequest(&first, 0, false);
                try session.sendResponse(0, .{
                    .status = shared.scenario.retry_status,
                    .request_method = "GET",
                    .body = "final response",
                });
                return;
            }

            try expectAutomaticRequest(&first, 0, true);
            try session.sendResponse(0, .{
                .status = shared.scenario.initial_status,
                .request_method = "GET",
                .body = if (shared.scenario.initial_status == 425)
                    ""
                else
                    "early response",
            });
            if (shared.scenario.initial_status != 425) return;

            var retry = try session.receiveRequestWithTimeout(
                .fromSeconds(2),
            );
            defer retry.deinit(
                session.established.connection.endpoint.allocator,
            );
            try expectAutomaticRequest(&retry, 4, false);
            try session.sendResponse(4, .{
                .status = shared.scenario.retry_status,
                .request_method = "GET",
                .body = if (shared.scenario.retry_status == 425)
                    "still too early"
                else
                    "final response",
            });
        }
    };
    var shared = Shared{ .server = &server, .scenario = scenario };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const request_options = http3.Request{
        .method = "GET",
        .path = "/automatic-early-retry",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-early-request",
            .value = "original",
        }},
        .body = automatic_request_body,
        .trailers = &.{.{
            .name = "x-early-trailer",
            .value = "complete",
        }},
    };
    var result = runtime.HandshakeClient
        .requestWithEarlyDataWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        request_options,
        .{},
        .{},
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
        } },
        &cache,
        &lease,
        .fromSeconds(5),
    ) catch |err| {
        thread.join();
        joined = true;
        if (shared.err) |server_err| return server_err;
        return err;
    };
    defer result.deinit(allocator);
    try std.testing.expectEqual(
        if (scenario.reject_early_data)
            runtime.EarlyRequestDisposition.rejected
        else
            runtime.EarlyRequestDisposition.accepted,
        result.disposition,
    );
    try std.testing.expectEqual(
        if (scenario.reject_early_data)
            runtime.EarlyDataRetryReason.early_data_rejected
        else if (scenario.initial_status == 425)
            runtime.EarlyDataRetryReason.too_early
        else
            runtime.EarlyDataRetryReason.none,
        result.retry_reason,
    );
    const expected_status = if (!scenario.reject_early_data and
        scenario.initial_status != 425)
        scenario.initial_status
    else
        scenario.retry_status;
    try std.testing.expectEqual(
        expected_status,
        result.response.response.status,
    );
    try std.testing.expectEqualStrings(
        if (!scenario.reject_early_data and scenario.initial_status != 425)
            "early response"
        else if (scenario.retry_status == 425)
            "still too early"
        else
            "final response",
        result.response.response.body,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 early-data request retries accepted 425 once in 1-RTT" {
    try runAutomaticEarlyRetryScenario(.{ .retry_status = 201 });
}

test "HTTP/3 early-data request returns accepted non-425 without replay" {
    try runAutomaticEarlyRetryScenario(.{
        .initial_status = 200,
        .retry_status = 500,
    });
}

test "HTTP/3 early-data request returns the 1-RTT 425 without a loop" {
    try runAutomaticEarlyRetryScenario(.{ .retry_status = 425 });
}

test "HTTP/3 early-data request replays TLS rejection in 1-RTT" {
    try runAutomaticEarlyRetryScenario(.{
        .reject_early_data = true,
        .retry_status = 202,
    });
}

test "HTTP/3 early-data zero timeout preserves allocation and ticket state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const ticket = "h3-zero-timeout-ticket";
    const psk = [_]u8{0xb6} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 37,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const options = runtime.HandshakeClientOptions{ .handshake = .{
        .original_destination_connection_id = "zero-timeout-odcid",
        .local_connection_id = "zero-timeout-client",
        .server_name = "localhost",
        .resumption_now_ms = 1500,
        .resumption_server_id = "localhost:443",
    } };
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClient.requestWithEarlyDataWithTimeout(
            no_alloc.allocator(),
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(9) },
            .{
                .method = "GET",
                .path = "/zero-timeout",
                .authority = "localhost",
            },
            .{},
            .{},
            .{},
            options,
            &cache,
            &lease,
            .zero,
        ),
    );
    var prepared = try runtime.PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/zero-timeout",
            .authority = "localhost",
        },
        .{},
        .{},
    );
    defer prepared.deinit();
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectWithEarlyRequestWithTimeout(
            no_alloc.allocator(),
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(9) },
            .{},
            options,
            &prepared,
            &cache,
            &lease,
            .zero,
        ),
    );
    const stats = cache.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.active_early_data_leases);
    try std.testing.expectEqual(@as(usize, 0), stats.consumed_early_data_tickets);
}
