const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const control_receive = @import("../../control/receive.zig");
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "HTTP/3 protected cancellation clears request state on send failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x98, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x98, 0x40, 0x50, 0x60 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x96} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
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
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(.{
        .method = "GET",
        .path = "/cancel",
        .authority = "localhost",
    }, 0);
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqual(stream_id, request.stream_id);

    var failed_send = ObservedBatchSend{
        .delegate = server.quic_server.endpoint.io,
        .fail_after_prefix = 0,
    };
    server.quic_server.endpoint.io = failed_send.io();
    defer server.quic_server.endpoint.io = failed_send.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        server.cancelRequest(
            request.from,
            request.stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(!server.request_lifecycle.contains(stream_id));
    try std.testing.expect(!server.request_streams.contains(stream_id));
    try std.testing.expect(!server.streaming_requests.contains(stream_id));
    try std.testing.expect(server.outbound_bodies.find(stream_id) == null);
    try std.testing.expect(!server.protected_send.isUsable());
}

test "HTTP/3 protected aggregate request queues QPACK ack across send failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x95, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x95, 0x40, 0x50, 0x60 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
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
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    while (!server.control.settings.received) try server.pollControl();

    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-request-kind", "dynamic");
    var request_block: std.ArrayList(u8) = .empty;
    defer request_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&request_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/feedback-retry" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-request-kind", .value = "dynamic" },
    }, table);
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = request_block.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-request-kind",
            .value = "dynamic",
        } },
    );
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{
            .{ .stream = .{
                .stream_id = 6,
                .data = encoder_bytes.items,
            } },
            .{ .stream = .{
                .stream_id = 0,
                .data = request_bytes.items,
                .fin = true,
            } },
        },
        client.config.max_frames_per_packet,
    );
    while (true) {
        if (try server.request_streams.copyReady(
            server.qpack_decode.table,
            server.config.local_settings.qpack_blocked_streams,
        )) |ready| {
            allocator.free(ready.bytes);
            break;
        }
        try server.pollControl();
    }
    server.qpack_decode.decoder_instructions.deinit(allocator);
    server.qpack_decode.decoder_instructions = .empty;
    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    server.qpack_decode.allocator = failed_alloc.allocator();
    try std.testing.expectError(error.OutOfMemory, server.receiveRequest());
    server.qpack_decode.allocator = allocator;
    try std.testing.expect(failed_alloc.has_induced_failure);
    try std.testing.expect(server.request_streams.contains(0));
    try std.testing.expect(!server.request_lifecycle.contains(0));

    var failed_send = ObservedBatchSend{
        .delegate = server.quic_server.endpoint.io,
        .fail_after_prefix = 0,
    };
    server.quic_server.endpoint.io = failed_send.io();
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), request.stream_id);
    try std.testing.expectEqualStrings(
        "/feedback-retry",
        request.request.path,
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(server.request_lifecycle.contains(request.stream_id));
    try std.testing.expect(!server.request_streams.contains(request.stream_id));
    try std.testing.expect(
        server.qpack_decode.pendingDecoderInstructions().len != 0,
    );

    server.quic_server.endpoint.io = failed_send.delegate;
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{.{ .ping = {} }},
        client.config.max_frames_per_packet,
    );
    try server.pollControl();
    try std.testing.expectEqual(
        @as(usize, 0),
        server.qpack_decode.pendingDecoderInstructions().len,
    );
}

test "HTTP/3 protected streaming request preflights QPACK ack" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x91, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x91, 0x40, 0x50, 0x60 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x90} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8f} ** quic.protection.secret_len,
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
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

    try client.sendMaxPushId(0);
    while (!server.control.settings.received) try server.pollControl();
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-request-kind", "streaming");
    var request_block: std.ArrayList(u8) = .empty;
    defer request_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&request_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/streaming-feedback" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-request-kind", .value = "streaming" },
    }, table);
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = request_block.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-request-kind",
            .value = "streaming",
        } },
    );
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{
            .{ .stream = .{ .stream_id = 6, .data = encoder_bytes.items } },
            .{ .stream = .{
                .stream_id = 0,
                .data = request_bytes.items,
                .fin = true,
            } },
        },
        client.config.max_frames_per_packet,
    );
    while (!server.request_streams.contains(0)) try server.pollControl();

    server.qpack_decode.decoder_instructions.deinit(allocator);
    server.qpack_decode.decoder_instructions = .empty;
    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    server.qpack_decode.allocator = failed_alloc.allocator();
    try std.testing.expectError(error.OutOfMemory, server.pollRequestEvent());
    server.qpack_decode.allocator = allocator;
    try std.testing.expect(failed_alloc.has_induced_failure);
    try std.testing.expect(server.request_streams.contains(0));
    try std.testing.expect(server.streaming_requests.find(0) == null);
    try std.testing.expect(!server.request_lifecycle.contains(0));

    var failed_send = ObservedBatchSend{
        .delegate = server.quic_server.endpoint.io,
        .fail_after_prefix = 0,
    };
    server.quic_server.endpoint.io = failed_send.io();
    var head = (try server.pollRequestEvent()) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .message);
    try std.testing.expect(head.message.value == .head);
    try std.testing.expectEqualStrings(
        "/streaming-feedback",
        head.message.value.head.request.path,
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(server.request_lifecycle.contains(0));
    try std.testing.expect(
        server.qpack_decode.pendingDecoderInstructions().len != 0,
    );
}

test "HTTP/3 protected server surfaces request reset and clears reassembly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x99, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x9a, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9b} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9c} ** quic.protection.secret_len,
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

    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = "partial request",
        } },
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            .final_size = "partial request".len,
        } },
    };
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
    );
    try std.testing.expectError(error.RequestCancelled, server.receiveRequest());
    try std.testing.expectEqual(@as(usize, 0), server.request_streams.count());
}

test "HTTP/3 protected server performs two-phase graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x9d, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x9e, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9f} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa0} ** quic.protection.secret_len,
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

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/drain",
        .authority = "localhost",
    }).write(&request_bytes, allocator);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        request_bytes.items,
        request_bytes.items.len,
        true,
    );
    try client.protected_send.sendFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
    );

    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    const packet_number = server.next_packet_number;
    const control_offset = server.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        server.initiateShutdownWithDeadline(
            request.from,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(packet_number, server.next_packet_number);
    try std.testing.expectEqual(control_offset, server.control_send.next_offset);
    try std.testing.expectEqual(
        runtime.ShutdownState.active,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(@as(?u64, null), server.control.local_goaway_id);
    try server.initiateShutdownWithTimeout(
        request.from,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        runtime.ShutdownState.initial_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expect(!server.drainComplete());
    const initial_goaway_id = server.control.local_goaway_id;
    const initial_control_offset = server.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        server.completeShutdownWithDeadline(
            request.from,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(
        runtime.ShutdownState.initial_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(
        initial_goaway_id,
        server.control.local_goaway_id,
    );
    try std.testing.expectEqual(
        initial_control_offset,
        server.control_send.next_offset,
    );
    try server.completeShutdownWithTimeout(
        request.from,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        runtime.ShutdownState.final_goaway,
        server.request_lifecycle.state(),
    );
    try std.testing.expectEqual(@as(?u64, 4), server.control.local_goaway_id);
    try std.testing.expect(!server.drainComplete());

    try server.sendResponse(request.from, request.stream_id, .{
        .status = 204,
    });
    try std.testing.expect(server.drainComplete());

    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 4)
    {
        var packet = try quic.one_rtt.receive(
            &client.quic_client.endpoint,
            server_keys,
            client_cid.len,
            client.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        client.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try control_receive.applyControlStreamFrameForRole(
                &client.control,
                allocator,
                frame.stream,
                .client,
            );
        }
    }
    client.next_stream_id = 4;
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-drain",
    }));
}
