const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_sender = @import("send.zig");
const protected_send_module = @import("../send/protected.zig");
const send_scratch = @import("../send/scratch.zig");
const qpack_state = @import("../qpack/state.zig");

const net = std.Io.net;
const ProtectedSendState = protected_send_module.State;
const CriticalStreamSendScratch = send_scratch.Critical;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const controlFramesInto = control_sender.controlFramesInto;
const sendProtectedSettings = control_sender.sendProtectedSettings;
const sendProtectedQpackEncoderInstructions =
    control_sender.sendProtectedQpackEncoderInstructions;
const sendProtectedQpackFeedback = control_sender.sendProtectedQpackFeedback;
const sendConnectionSettings = control_sender.sendConnectionSettings;

const ProtectedOptions = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_frame_data: usize = 1200,
};

test "HTTP/3 control frame splitting uses caller storage transactionally" {
    var send = quic.stream_state.SendState.init(client_control_stream_id);
    send.next_offset = 9;
    var storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(&send, &storage, "abcdef", 2);
    try std.testing.expectEqual(@as(usize, 3), frames.len);
    try std.testing.expectEqual(@as(u64, 15), send.next_offset);
    for (frames, 0..) |frame, i| {
        try std.testing.expect(frame == .stream);
        try std.testing.expectEqual(client_control_stream_id, frame.stream.stream_id);
        try std.testing.expectEqual(@as(u64, 9 + i * 2), frame.stream.offset);
        try std.testing.expectEqualSlices(
            u8,
            "abcdef"[i * 2 ..][0..2],
            frame.stream.data,
        );
        try std.testing.expect(!frame.stream.fin);
    }

    const before = send;
    try std.testing.expectError(
        error.InvalidStreamRange,
        controlFramesInto(&send, &storage, "x", 0),
    );
    try std.testing.expectEqualDeep(before, send);
}

test "HTTP/3 protected critical streams reuse send scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x7b} ** quic.protection.secret_len,
    );
    const local_cid = "client";
    const peer_cid = "server";
    const config: ProtectedOptions = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = peer_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 2,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var next_packet_number: u64 = 0;

    // Allocation failure before the first SETTINGS write must leave all
    // protocol offsets and sent flags retryable.
    var control = http3.ControlState{};
    defer control.deinit(allocator);
    var control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var qpack_encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var qpack_decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var encoder_prefix_sent = false;
    var decoder_prefix_sent = false;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = fail_first.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        sendProtectedSettings(
            &sender,
            receiver.address(),
            config,
            &control,
            &control_send,
            &qpack_encoder_send,
            &encoder_prefix_sent,
            &qpack_decoder_send,
            &decoder_prefix_sent,
            &next_packet_number,
            &protected_send,
            client_control_stream_id,
        ),
    );
    sender.allocator = allocator;
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expect(!control.settings.sent);
    try std.testing.expectEqual(@as(u64, 0), control_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), qpack_encoder_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), qpack_decoder_send.next_offset);
    try std.testing.expect(!encoder_prefix_sent);
    try std.testing.expect(!decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), next_packet_number);

    try sendProtectedSettings(
        &sender,
        receiver.address(),
        config,
        &control,
        &control_send,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
        client_control_stream_id,
    );

    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    _ = try encoder.insertField(
        "x-critical-one",
        "encoder-instruction",
    );
    try sendProtectedQpackEncoderInstructions(
        &sender,
        receiver.address(),
        config,
        &encoder,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );

    var decoder = QpackDecodeState.init(allocator, 256, 4096);
    defer decoder.deinit();
    try decoder.recordStreamCancellation(quic.varint.max_value);
    try sendProtectedQpackFeedback(
        &sender,
        receiver.address(),
        config,
        &decoder,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );

    const critical_payload_capacity =
        protected_send.critical_stream_payload.capacity;
    const critical_frame_capacity =
        protected_send.critical_stream_frames.capacity;
    const wire_payload_capacity = protected_send.payload_scratch.capacity;
    const wire_packet_capacity = protected_send.packet_scratch.capacity;
    const critical_payload_ptr = protected_send.critical_stream_payload
        .allocatedSlice().ptr;
    const critical_frame_ptr = protected_send.critical_stream_frames
        .allocatedSlice().ptr;
    const wire_payload_ptr = protected_send.payload_scratch.allocatedSlice().ptr;
    const wire_packet_ptr = protected_send.packet_scratch.allocatedSlice().ptr;
    try std.testing.expect(critical_payload_capacity != 0);
    try std.testing.expect(critical_frame_capacity != 0);
    try std.testing.expect(wire_payload_capacity != 0);
    try std.testing.expect(wire_packet_capacity != 0);

    // Prepare all protocol-owned instructions before switching allocators so
    // the assertion isolates transport scratch rather than QPACK table growth.
    _ = try encoder.insertField(
        "x-critical-two",
        "encoder-instruction",
    );
    try decoder.recordStreamCancellation(quic.varint.max_value - 4);
    var second_control = http3.ControlState{};
    defer second_control.deinit(allocator);
    var second_control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var second_encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var second_decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var second_encoder_prefix = false;
    var second_decoder_prefix = false;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = no_alloc.allocator();
    protected_send.allocator = no_alloc.allocator();
    defer {
        sender.allocator = allocator;
        protected_send.allocator = allocator;
    }
    try sendProtectedSettings(
        &sender,
        receiver.address(),
        config,
        &second_control,
        &second_control_send,
        &second_encoder_send,
        &second_encoder_prefix,
        &second_decoder_send,
        &second_decoder_prefix,
        &next_packet_number,
        &protected_send,
        client_control_stream_id,
    );
    try sendProtectedQpackEncoderInstructions(
        &sender,
        receiver.address(),
        config,
        &encoder,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );
    try sendProtectedQpackFeedback(
        &sender,
        receiver.address(),
        config,
        &decoder,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        critical_payload_capacity,
        protected_send.critical_stream_payload.capacity,
    );
    try std.testing.expectEqual(
        critical_frame_capacity,
        protected_send.critical_stream_frames.capacity,
    );
    try std.testing.expectEqual(
        wire_payload_capacity,
        protected_send.payload_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_packet_capacity,
        protected_send.packet_scratch.capacity,
    );
    try std.testing.expectEqual(
        critical_payload_ptr,
        protected_send.critical_stream_payload.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        critical_frame_ptr,
        protected_send.critical_stream_frames.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_payload_ptr,
        protected_send.payload_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_packet_ptr,
        protected_send.packet_scratch.allocatedSlice().ptr,
    );
}

test "HTTP/3 connection SETTINGS allocation failure rolls back state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8b} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .tls_handshake_complete = true,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    var control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var encoder_prefix_sent = false;
    var decoder_prefix_sent = false;
    var scratch: CriticalStreamSendScratch = .{};
    defer scratch.deinit(allocator);
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    endpoint.allocator = fail_first.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        sendConnectionSettings(
            &connection,
            &scratch,
            &control,
            &control_send,
            &encoder_send,
            &encoder_prefix_sent,
            &decoder_send,
            &decoder_prefix_sent,
            .{},
            client_control_stream_id,
        ),
    );
    endpoint.allocator = allocator;
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expect(!control.settings.sent);
    try std.testing.expectEqual(@as(u64, 0), control_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), encoder_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), decoder_send.next_offset);
    try std.testing.expect(!encoder_prefix_sent);
    try std.testing.expect(!decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);

    try sendConnectionSettings(
        &connection,
        &scratch,
        &control,
        &control_send,
        &encoder_send,
        &encoder_prefix_sent,
        &decoder_send,
        &decoder_prefix_sent,
        .{},
        client_control_stream_id,
    );
    try std.testing.expect(control.settings.sent);
    try std.testing.expect(encoder_prefix_sent);
    try std.testing.expect(decoder_prefix_sent);
    try std.testing.expect(scratch.payload.capacity != 0);
    try std.testing.expect(scratch.frames.capacity != 0);
}
