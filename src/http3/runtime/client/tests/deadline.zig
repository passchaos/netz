const std = @import("std");
const NativeSendIo = @import("../../../../internal/testing/deadline_send_io.zig").Native;
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const http3 = @import("../../../mod.zig");
const control_sender = @import("../../control/send.zig");

const server_control_stream_id: u62 = 3;

test "HTTP/3 protected response deadlines preserve aggregate and streaming progress" {
    try @import("../../../../internal/testing/native_protocol_io.zig").run(protectedResponseDeadlines);
}

fn protectedResponseDeadlines(io: std.Io) !void {
    const allocator = std.testing.allocator;

    const client_cid = [_]u8{ 0xa9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xaa, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xab} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xac} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    const direct_body = "direct-after-timeout";
    const next_body = "next-after-timeout";
    const streaming_body = "streaming-after-timeout";
    const Shared = struct {
        server: *runtime.ProtectedServer,
        io: std.Io,
        direct_head_sent: std.Io.Event = .unset,
        direct_timed_out: std.Io.Event = .unset,
        next_head_sent: std.Io.Event = .unset,
        next_timed_out: std.Io.Event = .unset,
        streaming_head_sent: std.Io.Event = .unset,
        streaming_timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.direct_head_sent.set(self.io);
                self.direct_timed_out.set(self.io);
                self.next_head_sent.set(self.io);
                self.next_timed_out.set(self.io);
                self.streaming_head_sent.set(self.io);
                self.streaming_timed_out.set(self.io);
            };
        }

        fn sendSplitResponse(
            self: *@This(),
            body: []const u8,
            head_sent: *std.Io.Event,
            timed_out: *std.Io.Event,
        ) !void {
            var request = try self.server.receiveRequest();
            defer request.deinit(allocator);
            try self.server.startResponse(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                body.len,
            );
            head_sent.set(self.io);
            try timed_out.wait(self.io);
            try self.server.sendResponseBody(
                request.from,
                request.stream_id,
                body,
                true,
            );
        }

        fn runFallible(self: *@This()) !void {
            try self.sendSplitResponse(
                direct_body,
                &self.direct_head_sent,
                &self.direct_timed_out,
            );
            try self.sendSplitResponse(
                next_body,
                &self.next_head_sent,
                &self.next_timed_out,
            );
            try self.sendSplitResponse(
                streaming_body,
                &self.streaming_head_sent,
                &self.streaming_timed_out,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    var peer_work = try std.Io.concurrent(io, Shared.run, .{&shared});
    defer peer_work.cancel(io);

    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        client.requestWithDeadline(
            .{
                .method = "GET",
                .path = "/invalid-send-deadline",
                .authority = "localhost",
            },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());

    {
        const delegate_timed_io = client.quic_client.endpoint.io;
        var timed_io: NativeSendIo = .{
            .backend = .init(allocator, .{ .async_limit = .nothing }),
            .delegate_io = delegate_timed_io,
            .now_ns = .init(@intCast(1_000_000)),
            .advance_after_send_ns = std.time.ns_per_s,
        };
        defer timed_io.backend.deinit();
        client.quic_client.endpoint.io = timed_io.io();
        defer client.quic_client.endpoint.io = delegate_timed_io;
        try std.testing.expectError(
            error.Timeout,
            client.requestWithDeadline(
                .{
                    .method = "GET",
                    .path = "/send-timeout",
                    .authority = "localhost",
                },
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(timed_io.now_ns.load(.acquire) + 1),
                },
            ),
        );
        try std.testing.expectEqual(@as(usize, 1), timed_io.send_calls.load(.acquire));
        try std.testing.expect(client.control.settings.sent);
        try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
        try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
        try std.testing.expectEqual(
            @as(usize, 0),
            client.qpack_encode.pending_sections.items.len,
        );
    }

    const direct_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/direct-deadline",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), direct_id);
    try shared.direct_head_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveResponseWithTimeout(
            direct_id,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(client.request_lifecycle.contains(direct_id));
    try std.testing.expect(!client.response_streams.isEmpty());
    shared.direct_timed_out.set(io);
    var direct = try client.receiveResponseWithDeadline(
        direct_id,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer direct.deinit(allocator);
    try std.testing.expectEqualStrings(direct_body, direct.response.body);
    try std.testing.expect(!client.request_lifecycle.contains(direct_id));

    const next_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/next-deadline",
        .authority = "localhost",
    });
    try shared.next_head_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(next_id));
    try std.testing.expect(!client.response_streams.isEmpty());
    shared.next_timed_out.set(io);
    var next = try client.receiveNextResponseWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer next.deinit(allocator);
    try std.testing.expect(next == .response);
    try std.testing.expectEqual(next_id, next.response.stream_id);
    try std.testing.expectEqualStrings(
        next_body,
        next.response.value.response.body,
    );
    try std.testing.expect(!client.request_lifecycle.contains(next_id));

    const streaming_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-next-deadline",
        .authority = "localhost",
    });
    try shared.streaming_head_sent.wait(io);
    var head = try client.receiveNextResponseEventWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expectEqual(streaming_id, head.message.stream_id);
    try std.testing.expect(head.message.value == .head);
    try std.testing.expectEqual(
        @as(?runtime.StreamingResponseEvent, null),
        try client.pollNextResponseEvent(),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveNextResponseEventWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(client.request_lifecycle.contains(streaming_id));
    try std.testing.expect(
        client.streaming_responses.find(streaming_id) != null,
    );
    shared.streaming_timed_out.set(io);

    var body: [32]u8 = undefined;
    var body_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    while (!finished) {
        var event = try client.receiveNextResponseEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        try std.testing.expectEqual(streaming_id, event.message.stream_id);
        switch (event.message.value) {
            .data_available => {
                body_len += try client.readResponseData(
                    streaming_id,
                    body[body_len..],
                );
            },
            .finished => finished = true,
            .head, .trailers, .push_promise => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings(
        streaming_body,
        body[0..body_len],
    );
    try std.testing.expect(
        !client.request_lifecycle.contains(streaming_id),
    );

    peer_work.await(io);
    if (shared.err) |err| return err;
}

test "HTTP/3 protected peer SETTINGS deadline retains early response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb5, 0x71, 0x72, 0x73 };
    const server_cid = [_]u8{ 0xb6, 0x71, 0x72, 0x73 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/settings-race",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "before-settings",
    }).write(&response_bytes, allocator);
    try server.protected_send.sendFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = stream_id,
            .data = response_bytes.items,
            .fin = true,
        } }},
        server.config.max_frames_per_packet,
    );

    try std.testing.expectError(
        error.Timeout,
        client.receivePeerSettingsWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expect(!client.control.settings.received);
    try std.testing.expect(!client.response_streams.isEmpty());
    try std.testing.expect(client.request_lifecycle.contains(stream_id));

    try control_sender.sendProtectedSettings(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config,
        &server.control,
        &server.control_send,
        &server.qpack_encoder_send,
        &server.qpack_encoder_prefix_sent,
        &server.qpack_decoder_send,
        &server.qpack_decoder_prefix_sent,
        &server.next_packet_number,
        &server.protected_send,
        server_control_stream_id,
    );
    _ = try client.receivePeerSettingsWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "before-settings",
        response.response.body,
    );
}
