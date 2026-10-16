const std = @import("std");
const runtime = @import("../runtime.zig");

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
