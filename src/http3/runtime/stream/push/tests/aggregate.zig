const std = @import("std");
const http3 = @import("../../../../mod.zig");
const runtime = @import("../../../../runtime.zig");
const quic = @import("../../../../../quic/mod.zig");
const ObservedBatchSend =
    @import("../../../../../quic/one_rtt/tests/observed_batch_send.zig")
        .ObservedBatchSend;

const ProtectedServer = runtime.ProtectedServer;
const ProtectedClient = runtime.ProtectedClient;
const server_qpack_encoder_stream_id: u62 = 7;
const client_qpack_decoder_stream_id: u62 = 10;
const first_server_push_stream_id: u62 = 15;

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: anytype,
) !void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

test "HTTP/3 protected client aggregates promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xe2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var fields: std.ArrayList(u8) = .empty;
    defer fields.deinit(allocator);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try http3.Qpack.encodeDynamicBlock(&fields, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/app.js" },
        .{ .name = ":authority", .value = "example.test" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &response_bytes,
        allocator,
        1,
        fields.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &response_bytes,
        allocator,
    );
    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 1);
    try http3.writeResponseSequence(
        &push_bytes,
        allocator,
        &.{ .{ .status = 103 }, .{ .status = 102 } },
        .{
            .status = 200,
            .body = "javascript",
            .trailers = &.{.{ .name = "x-push", .value = "done" }},
        },
    );
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = request_stream_id,
            .data = response_bytes.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 15,
            .data = push_bytes.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    var pushed = try client.receivePush();
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(@as(u16, 200), pushed.response.status);
    try std.testing.expectEqualStrings("javascript", pushed.response.body);
    try std.testing.expectEqualStrings(
        "done",
        pushed.response.trailers[0].value,
    );
}

test "HTTP/3 protected aggregate response rolls back promise on malformed final head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xea, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xec} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(1);
    const malformed_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/malformed-parent",
        .authority = "example.test",
    });
    const sibling_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "example.test",
    });
    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try std.testing.expectEqual(malformed_id, first.stream_id);
    try std.testing.expectEqual(sibling_id, second.stream_id);

    var promise_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer promise_table.deinit();
    try promise_table.setCapacity(256);
    _ = try promise_table.insert("x-promise-kind", "dynamic-asset");
    var promise_block: std.ArrayList(u8) = .empty;
    defer promise_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&promise_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, promise_table);
    var malformed_bytes: std.ArrayList(u8) = .empty;
    defer malformed_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &malformed_bytes,
        allocator,
        0,
        promise_block.items,
    );
    var response_block: std.ArrayList(u8) = .empty;
    defer response_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&response_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "2" },
    }, promise_table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = response_block.items,
        .consumed = 0,
    }).write(&malformed_bytes, allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.data,
        .payload = "x",
        .consumed = 0,
    }).write(&malformed_bytes, allocator);
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
            .name = "x-promise-kind",
            .value = "dynamic-asset",
        } },
    );
    var sibling_bytes: std.ArrayList(u8) = .empty;
    defer sibling_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &sibling_bytes,
        allocator,
        1,
        promise_block.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &sibling_bytes,
        allocator,
    );
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{
            .{ .stream = .{
                .stream_id = server_qpack_encoder_stream_id,
                .data = encoder_bytes.items,
            } },
            .{ .stream = .{
                .stream_id = malformed_id,
                .data = malformed_bytes.items,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = sibling_id,
                .data = sibling_bytes.items,
                .fin = true,
            } },
        },
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    try std.testing.expectError(
        error.InvalidContentLength,
        client.receiveResponse(malformed_id),
    );
    try std.testing.expect(client.push_streams.isIdle());
    try std.testing.expect(!client.request_lifecycle.contains(malformed_id));
    try std.testing.expect(client.request_lifecycle.contains(sibling_id));

    var sibling = try client.receiveResponse(sibling_id);
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(!client.push_streams.hasPromise(0));
    try std.testing.expect(client.push_streams.hasPromise(1));
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.promiseCount());

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    var saw_cancellation = false;
    var saw_malformed_ack = false;
    var saw_sibling_ack = false;
    var saw_stop = false;
    while (!saw_cancellation or !saw_sibling_ack or !saw_stop) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .stop_sending => |stop| if (stop.stream_id == malformed_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            .stream => |stream| if (stream.stream_id == client_qpack_decoder_stream_id) {
                try feedback.appendSlice(allocator, stream.data);
            },
            else => {},
        };
        var offset: usize = @intFromBool(
            feedback.items.len != 0 and
                feedback.items[0] ==
                    @intFromEnum(http3.StreamType.qpack_decoder),
        );
        while (offset < feedback.items.len) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                feedback.items[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return err,
            };
            switch (decoded.instruction) {
                .stream_cancellation => |id| if (id == malformed_id) {
                    saw_cancellation = true;
                },
                .section_acknowledgment => |id| if (id == malformed_id) {
                    saw_malformed_ack = true;
                } else if (id == sibling_id) {
                    saw_sibling_ack = true;
                },
                .insert_count_increment => {},
            }
            offset += decoded.consumed;
        }
    }
    try std.testing.expect(!saw_malformed_ack);

    const malformed_qpack_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/malformed-promise-qpack",
        .authority = "example.test",
    });
    var third = try server.receiveRequest();
    defer third.deinit(allocator);
    try std.testing.expectEqual(malformed_qpack_id, third.stream_id);
    var malformed_qpack: std.ArrayList(u8) = .empty;
    defer malformed_qpack.deinit(allocator);
    try http3.writePushPromiseFrame(
        &malformed_qpack,
        allocator,
        0,
        // Valid field-section prefix followed by a truncated literal field.
        // The aggregate decoder, rather than its QPACK dependency prepass,
        // must detect this as a decompression failure.
        &.{ 0x00, 0x00, 0x20 },
    );
    try (http3.Response{ .status = 204 }).write(
        &malformed_qpack,
        allocator,
    );
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = malformed_qpack_id,
            .data = malformed_qpack.items,
            .fin = true,
        } }},
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        client.receiveResponse(malformed_qpack_id),
    );
    try std.testing.expect(!client.push_streams.hasPromise(0));
    var saw_qpack_close = false;
    while (!saw_qpack_close) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .application_close => |close| {
                try std.testing.expectEqual(
                    @as(
                        u64,
                        http3.ApplicationErrorCode.qpack_decompression_failed,
                    ),
                    close.error_code,
                );
                saw_qpack_close = true;
            },
            else => {},
        };
    }
}

test "HTTP/3 protected aggregate response queues QPACK ack across send failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xed, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xee, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xef} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf0} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/feedback-retry",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-response-kind", "dynamic");
    var response_block: std.ArrayList(u8) = .empty;
    defer response_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&response_block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-response-kind", .value = "dynamic" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = response_block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
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
            .name = "x-response-kind",
            .value = "dynamic",
        } },
    );
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{
            .{ .stream = .{
                .stream_id = server_qpack_encoder_stream_id,
                .data = encoder_bytes.items,
            } },
            .{ .stream = .{
                .stream_id = stream_id,
                .data = response_bytes.items,
                .fin = true,
            } },
        },
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    while ((try client.response_streams.firstReadyStream(
        client.qpack_decode.table,
        client.config.local_settings.qpack_blocked_streams,
    )) == null) {
        try client.pollControl();
    }
    client.qpack_decode.decoder_instructions.deinit(allocator);
    client.qpack_decode.decoder_instructions = .empty;
    try client.request_lifecycle.prepareFinish();
    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    client.qpack_decode.allocator = failed_alloc.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        client.receiveResponse(stream_id),
    );
    client.qpack_decode.allocator = allocator;
    try std.testing.expect(failed_alloc.has_induced_failure);
    try std.testing.expect(client.request_lifecycle.contains(stream_id));
    try std.testing.expect(client.response_streams.contains(stream_id));

    var failed_send = ObservedBatchSend{
        .delegate = client.quic_client.endpoint.io,
        .fail_after_prefix = 0,
    };
    client.quic_client.endpoint.io = failed_send.io();
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(!client.request_lifecycle.contains(stream_id));
    try std.testing.expect(!client.response_streams.contains(stream_id));
    try std.testing.expect(
        client.qpack_decode.pendingDecoderInstructions().len != 0,
    );

    client.quic_client.endpoint.io = failed_send.delegate;
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{.{ .ping = {} }},
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    try client.pollControl();
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_decode.pendingDecoderInstructions().len,
    );

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    var saw_ack = false;
    while (!saw_ack) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| {
            if (frame != .stream or
                frame.stream.stream_id != client_qpack_decoder_stream_id)
            {
                continue;
            }
            try feedback.appendSlice(allocator, frame.stream.data);
        }
        var offset: usize = 0;
        while (offset < feedback.items.len) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                feedback.items[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return err,
            };
            if (decoded.instruction == .section_acknowledgment and
                decoded.instruction.section_acknowledgment == stream_id)
            {
                saw_ack = true;
            }
            offset += decoded.consumed;
        }
    }
}

test "HTTP/3 protected streaming response preflights QPACK ack" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xf1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xf2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-feedback",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-response-kind", "streaming");
    var response_block: std.ArrayList(u8) = .empty;
    defer response_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&response_block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-response-kind", .value = "streaming" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = response_block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
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
            .name = "x-response-kind",
            .value = "streaming",
        } },
    );
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{
            .{ .stream = .{
                .stream_id = server_qpack_encoder_stream_id,
                .data = encoder_bytes.items,
            } },
            .{ .stream = .{
                .stream_id = stream_id,
                .data = response_bytes.items,
                .fin = true,
            } },
        },
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    while ((try client.response_streams.firstReadyStream(
        client.qpack_decode.table,
        client.config.local_settings.qpack_blocked_streams,
    )) == null) {
        try client.pollControl();
    }

    client.qpack_decode.decoder_instructions.deinit(allocator);
    client.qpack_decode.decoder_instructions = .empty;
    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    client.qpack_decode.allocator = failed_alloc.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        client.pollResponseEvent(stream_id),
    );
    client.qpack_decode.allocator = allocator;
    try std.testing.expect(failed_alloc.has_induced_failure);
    const active = client.streaming_responses.find(stream_id) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(active.reader.awaitingInitialHead());

    var failed_send = ObservedBatchSend{
        .delegate = client.quic_client.endpoint.io,
        .fail_after_prefix = 0,
    };
    client.quic_client.endpoint.io = failed_send.io();
    var head = (try client.pollResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    try std.testing.expectEqual(@as(u16, 204), head.head.response.status);
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    try std.testing.expect(
        client.qpack_decode.pendingDecoderInstructions().len != 0,
    );
}

test "HTTP/3 protected aggregate push deadline preserves progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xe6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/push-deadline",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var fields: std.ArrayList(u8) = .empty;
    defer fields.deinit(allocator);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try http3.Qpack.encodeDynamicBlock(&fields, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/deadline.js" },
        .{ .name = ":authority", .value = "example.test" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &response_bytes,
        allocator,
        1,
        fields.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &response_bytes,
        allocator,
    );

    const body = "javascript-after-timeout";
    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 1);
    try (http3.Response{ .status = 200, .body = body }).write(
        &push_bytes,
        allocator,
    );
    const body_prefix_len = body.len / 2;
    const split = push_bytes.items.len - body.len + body_prefix_len;
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{
            .{ .stream = .{
                .stream_id = request_stream_id,
                .data = response_bytes.items,
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = first_server_push_stream_id,
                .data = push_bytes.items[0..split],
            } },
        },
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectError(
        error.Timeout,
        client.receivePushWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(@as(?u64, 1), client.push_aggregate.push_id);
    try std.testing.expect(client.push_aggregate.head != null);
    try std.testing.expectEqualStrings(
        body[0..body_prefix_len],
        client.push_aggregate.body.items,
    );
    // Aggregate and incremental consumption cannot safely share one reader.
    try std.testing.expectError(
        error.UnexpectedStream,
        client.receivePushEvent(),
    );

    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = first_server_push_stream_id,
            .offset = split,
            .data = push_bytes.items[split..],
            .fin = true,
        } }},
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    var pushed = try client.receivePushWithDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqualStrings(body, pushed.response.body);
    try std.testing.expect(client.push_aggregate.push_id == null);
    try std.testing.expect(client.push_aggregate.head == null);
    try std.testing.expect(client.push_aggregate.trailers == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.push_aggregate.body.items.len,
    );
}
