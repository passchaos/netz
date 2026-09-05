const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const wire = @import("../../../../internal/wire.zig");
const control_sender = @import("../../control/send.zig");

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const server_qpack_decoder_stream_id: u62 = 11;
const sendProtectedSettings = control_sender.sendProtectedSettings;

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

test "HTTP/3 protected server decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xda, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xdb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd4} ** quic.protection.secret_len);

    var server = try runtime.ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer server.deinit();

    var client = try runtime.ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );

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
            .name = "x-live",
            .value = "protected-runtime",
        } },
    );
    var encoder_send = quic.stream_state.SendState.init(client_qpack_encoder_stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-live", "protected-runtime");
    const request_fields = [_]http3.Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/qpack-live" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-live", .value = "protected-runtime" },
    };
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &field_section,
        allocator,
        &request_fields,
        encoder_table,
    );
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        request_bytes.items,
        request_bytes.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var received = try server.receiveRequest();
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("GET", received.request.method);
    try std.testing.expectEqualStrings("/qpack-live", received.request.path);
    var live_value: ?[]const u8 = null;
    for (received.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-live")) live_value = header.value;
    }
    try std.testing.expectEqualStrings("protected-runtime", live_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), server.qpack_decode.table.insert_count);

    // Decoder feedback is sent after successful request decoding. Because the
    // server has not sent SETTINGS yet, this first write also carries the
    // decoder-stream type prefix at offset zero, followed by Increment +
    // Section Ack.
    var feedback_packet = try quic.one_rtt.receive(
        &client.quic_client.endpoint,
        server_keys,
        client_cid.len,
        0,
        8,
    );
    defer feedback_packet.deinit(allocator);
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(allocator);
    for (feedback_packet.frames) |frame| {
        if (frame != .stream or frame.stream.stream_id != server_qpack_decoder_stream_id) continue;
        try feedback_bytes.appendSlice(allocator, frame.stream.data);
    }
    try std.testing.expect(feedback_bytes.items.len != 0);
    var feedback_cursor = wire.Cursor.init(
        feedback_bytes.items,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(http3.StreamType.qpack_decoder)),
        try quic.varint.decode(&feedback_cursor),
    );
    const increment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos..],
    );
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos + increment.consumed ..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 protected server resumes multiple blocked QPACK requests" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
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
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 2,
            },
            .max_stream_frame_data = 1024,
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    );
    defer client.deinit();

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "message-before-insert");
    var first_field_section: std.ArrayList(u8) = .empty;
    defer first_field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &first_field_section,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/blocked-one" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-blocked", .value = "message-before-insert" },
        },
        encoder_table,
    );
    var second_field_section: std.ArrayList(u8) = .empty;
    defer second_field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &second_field_section,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/blocked-two" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-blocked", .value = "message-before-insert" },
        },
        encoder_table,
    );
    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = first_field_section.items,
        .consumed = 0,
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = second_field_section.items,
        .consumed = 0,
    }).write(&second_message, allocator);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var first_send = quic.stream_state.SendState.init(0);
    try first_send.appendFrames(
        &frames,
        allocator,
        first_message.items,
        first_message.items.len,
        true,
    );
    var second_send = quic.stream_state.SendState.init(4);
    try second_send.appendFrames(
        &frames,
        allocator,
        second_message.items,
        second_message.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    // Send the encoder instructions only after the complete dependent request.
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-blocked",
            .value = "message-before-insert",
        } },
    );
    frames.clearRetainingCapacity();
    // SETTINGS already emitted the encoder-stream type at offset zero.
    client.qpack_encoder_send.next_offset = @max(
        client.qpack_encoder_send.next_offset,
        1,
    );
    try client.qpack_encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("/blocked-one", first.request.path);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.request_streams.count(),
    );
    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("/blocked-two", second.request.path);
    var value: ?[]const u8 = null;
    for (second.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-blocked")) value = header.value;
    }
    try std.testing.expectEqualStrings(
        "message-before-insert",
        value orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(@as(u64, 1), server.qpack_decode.table.insert_count);
    try std.testing.expectEqual(
        @as(u64, 2),
        server.config.local_settings.qpack_blocked_streams,
    );
}

test "HTTP/3 protected server closes when zero blocked streams are advertised" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xd0, 0x21, 0x22, 0x23 };
    const server_cid = [_]u8{ 0xd1, 0x21, 0x22, 0x23 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
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

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "request");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked-request" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-blocked", .value = "request" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = message.items,
            .fin = true,
        } }},
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    try std.testing.expectError(
        error.QpackDecompressionFailed,
        server.receiveRequest(),
    );
    var saw_close = false;
    while (!saw_close) {
        var packet = try quic.one_rtt.receive(
            &client.quic_client.endpoint,
            server_keys,
            client_cid.len,
            client.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        client.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| switch (frame) {
            .application_close => |close| {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.qpack_decompression_failed),
                    close.error_code,
                );
                saw_close = true;
            },
            else => {},
        };
    }
}
