const std = @import("std");
const http3 = @import("../../../../../http3/mod.zig");
const runtime = @import("../../../../runtime.zig");
const quic = @import("../../../../../quic/mod.zig");
const server_response = @import("../../../server/response.zig");

const first_server_push_stream_id: u62 = 15;

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

test "HTTP/3 protected server sends promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xf5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xf6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf8} ** quic.protection.secret_len,
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
    try client.sendMaxPushId(3);
    var parent_capacity: usize = 0;
    var pushed_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var parent_ptr: [*]u8 = undefined;
    var pushed_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    for (0..2) |exchange| {
        const request_stream_id = try client.sendRequest(.{
            .method = "GET",
            .path = "/",
            .authority = "example.test",
        });
        var request = try server.receiveRequest();
        defer request.deinit(allocator);
        const push_id: u64 = @intCast(exchange + 2);
        const pushed_body = if (exchange == 0) "css" else "";
        const pushed_trailers: []const http3.Qpack.HeaderField =
            if (exchange == 0) &.{} else &.{.{
                .name = "x-push-finished",
                .value = "yes",
            }};
        const push = runtime.ServerPush{
            .push_id = push_id,
            .request = .{
                .method = "GET",
                .path = "/style.css",
                .authority = "example.test",
            },
            .response = .{
                .status = 200,
                .body = pushed_body,
                .trailers = pushed_trailers,
            },
        };
        const packet_number = server.next_packet_number;
        const control_offset = server.control_send.next_offset;
        const next_push_stream_id = server.next_push_stream_id;
        const promised_range_count = server.promised_push_ids.rangeCount();
        try std.testing.expect(!server.promised_push_ids.contains(push_id));
        const pending_sections = server.qpack_encode.pending_sections.items.len;
        try std.testing.expectError(
            error.Timeout,
            server.sendResponseWithPushAndDeadline(
                request.from,
                request.stream_id,
                .{ .status = 204 },
                push,
                .{ .clock = .real, .raw = .zero },
            ),
        );
        try std.testing.expectEqual(packet_number, server.next_packet_number);
        try std.testing.expectEqual(control_offset, server.control_send.next_offset);
        try std.testing.expectEqual(next_push_stream_id, server.next_push_stream_id);
        try std.testing.expectEqual(
            promised_range_count,
            server.promised_push_ids.rangeCount(),
        );
        try std.testing.expect(!server.promised_push_ids.contains(push_id));
        try std.testing.expectEqual(
            pending_sections,
            server.qpack_encode.pending_sections.items.len,
        );
        try std.testing.expectEqual(@as(usize, 1), server.request_lifecycle.count());
        if (exchange == 0) {
            var timed_io = DeadlineAfterSendIo{
                .delegate = server.quic_server.endpoint.io,
                .now_ns = 1_000_000,
            };
            var timed_vtable = server.quic_server.endpoint.io.vtable.*;
            timed_vtable.now = DeadlineAfterSendIo.now;
            timed_vtable.netSend = DeadlineAfterSendIo.netSend;
            server.quic_server.endpoint.io = .{
                .userdata = &timed_io,
                .vtable = &timed_vtable,
            };
            defer server.quic_server.endpoint.io = timed_io.delegate;
            try std.testing.expectError(
                error.Timeout,
                server.sendResponseWithPushAndDeadline(
                    request.from,
                    request.stream_id,
                    .{ .status = 204 },
                    push,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed_io.now_ns + 1),
                    },
                ),
            );
            try std.testing.expect(server.control.settings.sent);
            try std.testing.expectEqual(@as(usize, 1), timed_io.send_calls);
            try std.testing.expect(server.next_packet_number > packet_number);
            try std.testing.expect(server.control_send.next_offset > control_offset);
            try std.testing.expectEqual(next_push_stream_id, server.next_push_stream_id);
            try std.testing.expectEqual(
                promised_range_count,
                server.promised_push_ids.rangeCount(),
            );
            try std.testing.expect(!server.promised_push_ids.contains(push_id));
            try std.testing.expectEqual(
                pending_sections,
                server.qpack_encode.pending_sections.items.len,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                server.request_lifecycle.count(),
            );
            server.quic_server.endpoint.io = timed_io.delegate;
        }
        const push_stream_id = if (exchange == 0)
            try server.sendResponseWithPushAndTimeout(
                request.from,
                request.stream_id,
                .{ .status = 204 },
                push,
                .fromSeconds(1),
            )
        else
            try server.sendResponseWithPushPacedAndTimeout(
                request.from,
                request.stream_id,
                .{ .status = 204 },
                push,
                .fromSeconds(1),
            );
        try std.testing.expectEqual(
            first_server_push_stream_id + @as(u62, @intCast(exchange * 4)),
            push_stream_id,
        );
        try std.testing.expect(server.promised_push_ids.contains(push_id));
        try std.testing.expectEqual(
            @as(usize, 1),
            server.promised_push_ids.rangeCount(),
        );
        if (exchange == 0) {
            parent_capacity = server.push_send_scratch.parent.capacity;
            pushed_capacity = server.push_send_scratch.pushed.capacity;
            frame_capacity = server.push_send_scratch.frames.capacity;
            try std.testing.expect(parent_capacity != 0);
            try std.testing.expect(pushed_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            parent_ptr = server.push_send_scratch.parent.allocatedSlice().ptr;
            pushed_ptr = server.push_send_scratch.pushed.allocatedSlice().ptr;
            frame_ptr = server.push_send_scratch.frames.allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                parent_capacity,
                server.push_send_scratch.parent.capacity,
            );
            try std.testing.expectEqual(
                pushed_capacity,
                server.push_send_scratch.pushed.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                server.push_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                parent_ptr,
                server.push_send_scratch.parent.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                pushed_ptr,
                server.push_send_scratch.pushed.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                server.push_send_scratch.frames.allocatedSlice().ptr,
            );
        }
        var promise = while (true) {
            if (try client.receiveResponseEvent(request_stream_id)) |event| {
                break event;
            }
        };
        defer promise.deinit(allocator);
        try std.testing.expect(promise == .push_promise);
        try std.testing.expectEqual(push_id, promise.push_promise.push_id);
        try std.testing.expectEqualStrings(
            "/style.css",
            promise.push_promise.request.path,
        );
        var parent_head = while (true) {
            if (try client.receiveResponseEvent(request_stream_id)) |event| {
                break event;
            }
        };
        defer parent_head.deinit(allocator);
        try std.testing.expect(parent_head == .head);
        try std.testing.expectEqual(
            @as(u16, 204),
            parent_head.head.response.status,
        );
        const parent_date = server_response.headerValue(
            parent_head.head.response.headers,
            "date",
        ) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            @as(usize, server_response.date_value_len),
            parent_date.len,
        );
        var pushed = try client.receivePush();
        defer pushed.deinit(allocator);
        try std.testing.expectEqual(push_stream_id, pushed.stream_id);
        try std.testing.expectEqualStrings(pushed_body, pushed.response.body);
        if (exchange == 1) {
            try std.testing.expectEqualStrings(
                "yes",
                pushed.response.trailers[0].value,
            );
        }
        const pushed_date = server_response.headerValue(
            pushed.response.headers,
            "date",
        ) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            @as(usize, server_response.date_value_len),
            pushed_date.len,
        );
    }
}

test "HTTP/3 handshake paced push crosses small connection and stream windows" {
    const allocator = std.testing.allocator;
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    server_transport.initial_max_stream_data_uni = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    client_transport.initial_max_stream_data_uni = 16 * 1024;

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{ .max_datagram_size = 1200 },
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
            .session = .{
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
                .paced_body_chunk_bytes = 400,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            while (session.control.peer_max_push_id != 0) {
                try session.pollControlWithTimeout(.fromSeconds(2));
            }
            var body: [body_len]u8 = undefined;
            for (&body, 0..) |*byte, index| byte.* = @truncate(index);
            var parent_body: [24 * 1024]u8 = undefined;
            @memset(&parent_body, 0xc3);
            const response: http3.Response = .{
                .status = 200,
                .body = &parent_body,
            };
            const push: runtime.ServerPush = .{
                .push_id = 0,
                .request = .{
                    .method = "GET",
                    .path = "/large-push.bin",
                    .authority = "localhost",
                },
                .response = .{
                    .status = 200,
                    .body = &body,
                    .trailers = &.{.{
                        .name = "x-push-finished",
                        .value = "yes",
                    }},
                },
            };
            const packet_number =
                session.established.connection.next_packet_number;
            const next_push_stream_id = session.next_push_stream_id;
            const outbound_count = session.outbound_bodies.count();
            try std.testing.expectError(
                error.Timeout,
                session.sendResponseWithPushPacedAndDeadline(
                    request.stream_id,
                    response,
                    push,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                packet_number,
                session.established.connection.next_packet_number,
            );
            try std.testing.expectEqual(
                next_push_stream_id,
                session.next_push_stream_id,
            );
            try std.testing.expectEqual(
                outbound_count,
                session.outbound_bodies.count(),
            );
            try std.testing.expect(!session.promised_push_ids.contains(0));
            _ = try session.sendResponseWithPushPacedAndTimeout(
                request.stream_id,
                response,
                push,
                .fromSeconds(5),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{ .max_datagram_size = 1200 },
                .random = [_]u8{0x83} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            },
            .session = .{
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var promise = while (true) {
        if (try client.receiveResponseEventWithTimeout(
            request_stream_id,
            .fromSeconds(5),
        )) |event| break event;
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 0), promise.push_promise.push_id);

    var pushed = try client.receivePushWithTimeout(.fromSeconds(5));
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, body_len), pushed.response.body.len);
    for (pushed.response.body, 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    }
    try std.testing.expectEqualStrings(
        "yes",
        pushed.response.trailers[0].value,
    );
    var saw_parent_head = false;
    var parent_body_len: usize = 0;
    var parent_buf: [257]u8 = undefined;
    while (client.request_lifecycle.contains(request_stream_id)) {
        const event = (try client.receiveResponseEventWithTimeout(
            request_stream_id,
            .fromSeconds(5),
        )) orelse continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                saw_parent_head = true;
            },
            .data_available => {
                while (client.streaming_responses.find(
                    request_stream_id,
                ).?.reader.hasPendingFrame()) {
                    const count = try client.readResponseData(
                        request_stream_id,
                        &parent_buf,
                    );
                    for (parent_buf[0..count]) |byte| {
                        try std.testing.expectEqual(@as(u8, 0xc3), byte);
                    }
                    parent_body_len += count;
                }
            },
            .finished => {},
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_parent_head);
    try std.testing.expectEqual(@as(usize, 24 * 1024), parent_body_len);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake paced push stops after client cancellation" {
    const allocator = std.testing.allocator;
    const body_len: usize = 256 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    const server_cid = [_]u8{ 0x9d, 0x9e, 0x9f, 0xa0 };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    server_transport.initial_max_stream_data_uni = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    client_transport.initial_max_stream_data_uni = 16 * 1024;

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{ .max_datagram_size = 1200 },
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
                .paced_body_chunk_bytes = 400,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,
        pushed_bytes: u64 = 0,
        cancelled: bool = false,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            while (session.control.peer_max_push_id != 0) {
                try session.pollControlWithTimeout(.fromSeconds(2));
            }
            var body: [body_len]u8 = undefined;
            @memset(&body, 0x5a);
            const parent_body = "parent-survives-push-cancel";
            const result = session.sendResponseWithPushPacedAndTimeout(
                request.stream_id,
                .{ .status = 200, .body = parent_body },
                .{
                    .push_id = 0,
                    .request = .{
                        .method = "GET",
                        .path = "/cancelled-push.bin",
                        .authority = "localhost",
                    },
                    .response = .{ .status = 200, .body = &body },
                },
                .fromSeconds(5),
            );
            try std.testing.expectError(error.RequestCancelled, result);
            const stats = session.established.connection.sendStreamStats(
                first_server_push_stream_id,
            ) orelse return error.TestUnexpectedResult;
            shared.pushed_bytes = stats.highest_sent_offset;
            shared.cancelled = session.control.pushCancelled(0);
            try std.testing.expect(stats.reset != null);
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                stats.reset.?.application_error_code,
            );
            try std.testing.expect(
                session.outbound_bodies.find(first_server_push_stream_id) == null,
            );
            try std.testing.expect(!session.established.connection.closed());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{ .max_datagram_size = 1200 },
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = .{
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var promise = while (true) {
        if (try client.receiveResponseEventWithTimeout(
            request_stream_id,
            .fromSeconds(5),
        )) |event| break event;
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try client.cancelPushWithTimeout(0, .fromSeconds(5));
    var saw_parent_head = false;
    var parent_body: ["parent-survives-push-cancel".len]u8 = undefined;
    var parent_body_len: usize = 0;
    while (client.request_lifecycle.contains(request_stream_id)) {
        const event = (try client.receiveResponseEventWithTimeout(
            request_stream_id,
            .fromSeconds(5),
        )) orelse continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expect(head == .response);
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                saw_parent_head = true;
            },
            .data_available => {
                while (client.streaming_responses.find(
                    request_stream_id,
                ).?.reader.hasPendingFrame()) {
                    parent_body_len += try client.readResponseData(
                        request_stream_id,
                        parent_body[parent_body_len..],
                    );
                }
            },
            .finished => {},
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_parent_head);
    try std.testing.expectEqualStrings(
        "parent-survives-push-cancel",
        parent_body[0..parent_body_len],
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.cancelled);
    try std.testing.expect(shared.pushed_bytes < body_len);
}
