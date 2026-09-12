const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

const DeadlineAfterSendIo = struct {
    delegate: std.Io,
    now_ns: i96,
    send_calls: usize = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        self.send_calls += 1;
        const result = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
        if (result[1] != 0) self.now_ns += std.time.ns_per_s;
        return result;
    }
};

test "HTTP/3 protected runtime streams request and response DATA chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
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
            .max_stream_frame_data = 5,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(
                server_ptr.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "request-chunks",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            // Give the head and trailer encodings one deliberately shared
            // backing allocation so this test detects either helper falling
            // back to private temporary lists.
            try server_ptr.stream_send_scratch.encoded.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                256,
            );
            try server_ptr.stream_send_scratch.frames.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                32,
            );
            const packet_number = server_ptr.next_packet_number;
            const control_offset = server_ptr.control_send.next_offset;
            const pending_sections =
                server_ptr.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.startResponseWithDeadline(
                    request.from,
                    request.stream_id,
                    .{ .status = 200 },
                    "response-chunks".len,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                server_ptr.next_packet_number,
            );
            try std.testing.expectEqual(
                control_offset,
                server_ptr.control_send.next_offset,
            );
            try std.testing.expectEqual(
                pending_sections,
                server_ptr.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                server_ptr.outbound_bodies.count(),
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                server_ptr.request_lifecycle.count(),
            );
            try server_ptr.startResponseWithTimeout(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                "response-chunks".len,
                .fromSeconds(1),
            );
            try server_ptr.outbound_bodies.frame_scratch.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                16,
            );
            const head_encoded_capacity =
                server_ptr.stream_send_scratch.encoded.capacity;
            const head_frame_capacity =
                server_ptr.stream_send_scratch.frames.capacity;
            const head_encoded_ptr = server_ptr.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            const head_frame_ptr = server_ptr.stream_send_scratch.frames
                .allocatedSlice().ptr;
            const body_frame_capacity =
                server_ptr.outbound_bodies.frame_scratch.capacity;
            const body_frame_ptr = server_ptr.outbound_bodies.frame_scratch
                .allocatedSlice().ptr;
            const response_body = "response-chunks";
            const response_before = server_ptr.outbound_bodies.find(
                request.stream_id,
            ).?.*;
            const body_packet_number = server_ptr.next_packet_number;
            const body_pending_sections =
                server_ptr.qpack_encode.pending_sections.items.len;
            var body_progress: runtime.BodyWriteProgress = .{
                .committed_bytes = 99,
                .fin_committed = true,
            };
            try std.testing.expectError(
                error.Timeout,
                server_ptr.sendResponseBodyPacedWithDeadline(
                    request.from,
                    request.stream_id,
                    response_body,
                    false,
                    &body_progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            const response_after_invalid = server_ptr.outbound_bodies.find(
                request.stream_id,
            ).?.*;
            try std.testing.expectEqual(@as(usize, 0), body_progress.committed_bytes);
            try std.testing.expect(!body_progress.fin_committed);
            try std.testing.expectEqual(
                body_packet_number,
                server_ptr.next_packet_number,
            );
            try std.testing.expectEqual(
                response_before.written,
                response_after_invalid.written,
            );
            try std.testing.expectEqual(
                response_before.send.next_offset,
                response_after_invalid.send.next_offset,
            );
            try std.testing.expectEqual(
                body_pending_sections,
                server_ptr.qpack_encode.pending_sections.items.len,
            );

            {
                var timed = DeadlineAfterSendIo{
                    .delegate = server_ptr.quic_server.endpoint.io,
                    .now_ns = std.Io.Clock.awake.now(
                        server_ptr.quic_server.endpoint.io,
                    ).nanoseconds,
                };
                var timed_vtable = timed.delegate.vtable.*;
                timed_vtable.now = DeadlineAfterSendIo.now;
                timed_vtable.netSend = DeadlineAfterSendIo.netSend;
                server_ptr.quic_server.endpoint.io = .{
                    .userdata = &timed,
                    .vtable = &timed_vtable,
                };
                defer server_ptr.quic_server.endpoint.io = timed.delegate;
                try std.testing.expectError(
                    error.Timeout,
                    server_ptr.sendResponseBodyPacedWithDeadline(
                        request.from,
                        request.stream_id,
                        response_body,
                        false,
                        &body_progress,
                        .{
                            .clock = .awake,
                            .raw = .fromNanoseconds(timed.now_ns + 1),
                        },
                    ),
                );
                try std.testing.expectEqual(
                    @as(usize, 1),
                    body_progress.committed_bytes,
                );
                try std.testing.expect(!body_progress.fin_committed);
                try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
            }
            try server_ptr.sendResponseBodyPacedWithTimeout(
                request.from,
                request.stream_id,
                response_body[body_progress.committed_bytes..],
                false,
                &body_progress,
                .fromSeconds(1),
            );
            try std.testing.expectEqual(
                response_body.len - 1,
                body_progress.committed_bytes,
            );
            try std.testing.expect(!body_progress.fin_committed);
            try std.testing.expectError(
                error.InvalidContentLength,
                server_ptr.sendResponseBody(
                    request.from,
                    request.stream_id,
                    "too-long-chunk",
                    true,
                ),
            );
            try std.testing.expectEqual(
                body_frame_capacity,
                server_ptr.outbound_bodies.frame_scratch.capacity,
            );
            try std.testing.expectEqual(
                body_frame_ptr,
                server_ptr.outbound_bodies.frame_scratch.allocatedSlice().ptr,
            );
            // The direct DATA-prefix path borrows the application bytes and
            // should never materialize a complete DATA frame in payload scratch.
            try std.testing.expectEqual(
                @as(usize, 0),
                server_ptr.outbound_bodies.payload_scratch.capacity,
            );
            const response_entry = server_ptr.outbound_bodies.find(
                request.stream_id,
            ).?;
            const trailer_before = response_entry.*;
            const trailer_packet_number = server_ptr.next_packet_number;
            const trailer_pending_sections =
                server_ptr.qpack_encode.pending_sections.items.len;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.finishResponseTrailersPacedWithDeadline(
                    request.from,
                    request.stream_id,
                    &.{.{
                        .name = "x-response-checksum",
                        .value = "ok",
                    }},
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            const trailer_after = server_ptr.outbound_bodies.find(
                request.stream_id,
            ).?.*;
            try std.testing.expectEqual(
                trailer_packet_number,
                server_ptr.next_packet_number,
            );
            try std.testing.expectEqual(
                trailer_before.written,
                trailer_after.written,
            );
            try std.testing.expectEqual(
                trailer_before.send.next_offset,
                trailer_after.send.next_offset,
            );
            try std.testing.expectEqual(
                trailer_pending_sections,
                server_ptr.qpack_encode.pending_sections.items.len,
            );
            response_entry.flow_limit = response_entry.send.next_offset;
            try std.testing.expectError(
                error.FlowControlBlocked,
                server_ptr.finishResponseTrailers(
                    request.from,
                    request.stream_id,
                    &.{.{
                        .name = "x-response-checksum",
                        .value = "ok",
                    }},
                ),
            );
            response_entry.flow_limit = null;
            try server_ptr.finishResponseTrailersPacedWithTimeout(
                request.from,
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
                .fromSeconds(1),
            );
            try std.testing.expectEqual(
                head_encoded_capacity,
                server_ptr.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                head_frame_capacity,
                server_ptr.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                head_encoded_ptr,
                server_ptr.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                head_frame_ptr,
                server_ptr.stream_send_scratch.frames.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                server_ptr.outbound_bodies.count(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
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
            .max_stream_frame_data = 5,
        },
    );
    defer client.deinit();

    try client.stream_send_scratch.encoded.ensureTotalCapacity(allocator, 256);
    try client.stream_send_scratch.frames.ensureTotalCapacity(allocator, 32);
    try client.outbound_bodies.frame_scratch.ensureTotalCapacity(allocator, 16);
    const packet_number = client.next_packet_number;
    const control_offset = client.control_send.next_offset;
    const pending_sections = client.qpack_encode.pending_sections.items.len;
    try std.testing.expectError(
        error.Timeout,
        client.startRequestWithDeadline(
            .{
                .method = "POST",
                .path = "/stream-body",
                .authority = "localhost",
            },
            "request-chunks".len,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(packet_number, client.next_packet_number);
    try std.testing.expectEqual(control_offset, client.control_send.next_offset);
    try std.testing.expectEqual(@as(u62, 0), client.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expectEqual(@as(usize, 0), client.outbound_bodies.count());
    try std.testing.expectEqual(
        pending_sections,
        client.qpack_encode.pending_sections.items.len,
    );
    const stream_id = try client.startRequestWithTimeout(
        .{
            .method = "POST",
            .path = "/stream-body",
            .authority = "localhost",
        },
        "request-chunks".len,
        .fromSeconds(1),
    );
    const head_encoded_capacity = client.stream_send_scratch.encoded.capacity;
    const head_frame_capacity = client.stream_send_scratch.frames.capacity;
    const head_encoded_ptr = client.stream_send_scratch.encoded
        .allocatedSlice().ptr;
    const head_frame_ptr = client.stream_send_scratch.frames
        .allocatedSlice().ptr;
    const body_frame_capacity = client.outbound_bodies.frame_scratch.capacity;
    const body_frame_ptr = client.outbound_bodies.frame_scratch
        .allocatedSlice().ptr;
    const request_body = "request-chunks";
    const request_before = client.outbound_bodies.find(stream_id).?.*;
    const body_packet_number = client.next_packet_number;
    const body_pending_sections = client.qpack_encode.pending_sections.items.len;
    var body_progress: runtime.BodyWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendRequestBodyPartsPacedWithDeadline(
            stream_id,
            &.{ "request-", "", "chunks" },
            false,
            &body_progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const request_after_invalid = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expectEqual(@as(usize, 0), body_progress.committed_bytes);
    try std.testing.expect(!body_progress.fin_committed);
    try std.testing.expectEqual(body_packet_number, client.next_packet_number);
    try std.testing.expectEqual(
        request_before.written,
        request_after_invalid.written,
    );
    try std.testing.expectEqual(
        request_before.send.next_offset,
        request_after_invalid.send.next_offset,
    );
    try std.testing.expectEqual(
        body_pending_sections,
        client.qpack_encode.pending_sections.items.len,
    );

    {
        var timed = DeadlineAfterSendIo{
            .delegate = client.quic_client.endpoint.io,
            .now_ns = std.Io.Clock.awake.now(
                client.quic_client.endpoint.io,
            ).nanoseconds,
        };
        var timed_vtable = timed.delegate.vtable.*;
        timed_vtable.now = DeadlineAfterSendIo.now;
        timed_vtable.netSend = DeadlineAfterSendIo.netSend;
        client.quic_client.endpoint.io = .{
            .userdata = &timed,
            .vtable = &timed_vtable,
        };
        defer client.quic_client.endpoint.io = timed.delegate;
        try std.testing.expectError(
            error.Timeout,
            client.sendRequestBodyPartsPacedWithDeadline(
                stream_id,
                &.{ "request-", "", "chunks" },
                false,
                &body_progress,
                .{
                    .clock = .awake,
                    .raw = .fromNanoseconds(timed.now_ns + 1),
                },
            ),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            body_progress.committed_bytes,
        );
        try std.testing.expect(!body_progress.fin_committed);
        try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    }
    try client.sendRequestBodyPartsPacedWithTimeout(
        stream_id,
        &.{request_body[body_progress.committed_bytes..]},
        false,
        &body_progress,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        request_body.len - 1,
        body_progress.committed_bytes,
    );
    try std.testing.expect(!body_progress.fin_committed);
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBody(stream_id, "short", true),
    );
    try std.testing.expectEqual(
        body_frame_capacity,
        client.outbound_bodies.frame_scratch.capacity,
    );
    try std.testing.expectEqual(
        body_frame_ptr,
        client.outbound_bodies.frame_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.payload_scratch.capacity,
    );
    const request_entry = client.outbound_bodies.find(stream_id).?;
    const trailer_before = request_entry.*;
    const trailer_packet_number = client.next_packet_number;
    const trailer_pending_sections =
        client.qpack_encode.pending_sections.items.len;
    try std.testing.expectError(
        error.Timeout,
        client.finishRequestTrailersPacedWithDeadline(
            stream_id,
            &.{.{ .name = "x-request-checksum", .value = "ok" }},
            .{ .clock = .real, .raw = .zero },
        ),
    );
    const trailer_after = client.outbound_bodies.find(stream_id).?.*;
    try std.testing.expectEqual(
        trailer_packet_number,
        client.next_packet_number,
    );
    try std.testing.expectEqual(trailer_before.written, trailer_after.written);
    try std.testing.expectEqual(
        trailer_before.send.next_offset,
        trailer_after.send.next_offset,
    );
    try std.testing.expectEqual(
        trailer_pending_sections,
        client.qpack_encode.pending_sections.items.len,
    );
    request_entry.flow_limit = request_entry.send.next_offset;
    try std.testing.expectError(
        error.FlowControlBlocked,
        client.finishRequestTrailers(
            stream_id,
            &.{.{ .name = "x-request-checksum", .value = "ok" }},
        ),
    );
    request_entry.flow_limit = null;
    try client.finishRequestTrailersPacedWithTimeout(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        head_encoded_capacity,
        client.stream_send_scratch.encoded.capacity,
    );
    try std.testing.expectEqual(
        head_frame_capacity,
        client.stream_send_scratch.frames.capacity,
    );
    try std.testing.expectEqual(
        head_encoded_ptr,
        client.stream_send_scratch.encoded.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        head_frame_ptr,
        client.stream_send_scratch.frames.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.count(),
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings(
        "response-chunks",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );
}

test "HTTP/3 protected server streams interleaved requests through small windows" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
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
            .local_settings = .{
                .qpack_max_table_capacity = 512,
                .qpack_blocked_streams = 2,
            },
            .max_stream_buffer = 512,
            .max_stream_frame_data = 480,
        },
    );
    defer server.deinit();
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
            .local_settings = .{
                .qpack_max_table_capacity = 512,
                .qpack_blocked_streams = 2,
            },
            .max_stream_buffer = 512,
            .max_stream_frame_data = 480,
        },
    );
    defer client.deinit();

    // Two exchanges are required by the non-blocking encoder policy: the first
    // advertises SETTINGS and queues inserts, while feedback received during
    // the second unlocks dynamic references for the streamed requests below.
    for (0..2) |_| {
        const warmup_id = try client.sendRequest(.{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
            .body = "warmup",
            .trailers = &.{.{
                .name = "x-request-finished",
                .value = "yes",
            }},
        });
        var warmup = try server.receiveRequest();
        defer warmup.deinit(allocator);
        try std.testing.expectEqual(warmup_id, warmup.stream_id);
        try server.sendResponse(warmup.from, warmup.stream_id, .{
            .status = 204,
        });
        var warmup_response = try client.receiveResponse(warmup_id);
        defer warmup_response.deinit(allocator);
    }

    const first_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
        },
        body_len,
    );
    try client.sendRequestBody(first_id, &([_]u8{0xa5} ** 400), false);
    const second_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
        },
        6,
    );
    try client.sendRequestBody(second_id, "second", false);
    try client.finishRequestTrailers(second_id, &.{.{
        .name = "x-request-finished",
        .value = "yes",
    }});

    const Sender = struct {
        client: *runtime.ProtectedClient,
        stream_id: u62,
        err: ?anyerror = null,

        fn run(sender: *@This()) void {
            sender.runFallible() catch |err| {
                sender.err = err;
            };
        }

        fn runFallible(sender: *@This()) !void {
            var chunk: [400]u8 = undefined;
            for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
            var remaining = body_len - 400;
            while (remaining != 0) {
                const count = @min(chunk.len, remaining);
                try sender.client.sendRequestBody(
                    sender.stream_id,
                    chunk[0..count],
                    false,
                );
                remaining -= count;
            }
            try sender.client.finishRequestTrailers(sender.stream_id, &.{.{
                .name = "x-request-finished",
                .value = "yes",
            }});
        }
    };
    var sender = Sender{ .client = &client, .stream_id = first_id };
    const sender_thread = try std.Thread.spawn(.{}, Sender.run, .{&sender});
    var sender_joined = false;
    defer if (!sender_joined) sender_thread.join();

    var heads: usize = 0;
    var dynamic_heads: usize = 0;
    var trailers: usize = 0;
    var dynamic_trailers: usize = 0;
    var finished: usize = 0;
    var first_read: usize = 0;
    var second_skipped: usize = 0;
    var first_checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (finished != 2) {
        var event = try server.receiveRequestEvent();
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        const message = &event.message;
        switch (message.value) {
            .head => |head| {
                try std.testing.expect(head == .request);
                if (head.request.qpack_section_acknowledgments != 0) {
                    dynamic_heads += 1;
                }
                heads += 1;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = server.streaming_requests.find(
                        message.stream_id,
                    ).?;
                    if (!active.reader.hasPendingFrame()) break;
                    if (message.stream_id == first_id) {
                        const read = try server.readRequestData(
                            message.stream_id,
                            &read_buf,
                        );
                        if (read == 0) break;
                        for (read_buf[0..read]) |byte| {
                            first_checksum +%= byte;
                        }
                        first_read += read;
                    } else {
                        try std.testing.expectEqual(second_id, message.stream_id);
                        const skipped = try server.skipRequestData(
                            message.stream_id,
                        );
                        if (skipped == 0) break;
                        second_skipped += skipped;
                    }
                }
                const active = server.streaming_requests.find(
                    message.stream_id,
                ).?;
                try std.testing.expect(
                    active.reader.bufferedBytes() <= 512,
                );
            },
            .trailers => |decoded| {
                try std.testing.expectEqualStrings(
                    "yes",
                    decoded.fields[0].value,
                );
                if (decoded.qpack_section_acknowledgments != 0) {
                    dynamic_trailers += 1;
                }
                trailers += 1;
            },
            .finished => finished += 1,
        }
    }
    sender_thread.join();
    sender_joined = true;
    if (sender.err) |err| return err;

    var expected_first: u64 = 400 * 0xa5;
    var chunk: [400]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
    const remaining = body_len - 400;
    var chunk_sum: u64 = 0;
    for (chunk) |byte| chunk_sum += byte;
    expected_first += chunk_sum * (remaining / chunk.len);
    for (chunk[0 .. remaining % chunk.len]) |byte| expected_first += byte;
    try std.testing.expectEqual(@as(usize, 2), heads);
    try std.testing.expect(dynamic_heads != 0);
    try std.testing.expectEqual(@as(usize, 2), trailers);
    try std.testing.expect(dynamic_trailers != 0);
    try std.testing.expectEqual(body_len, first_read);
    try std.testing.expectEqual(@as(usize, 6), second_skipped);
    try std.testing.expectEqual(expected_first, first_checksum);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.streaming_requests.retainedCount(),
    );
}
