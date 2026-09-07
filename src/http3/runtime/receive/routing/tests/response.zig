const std = @import("std");
const http3 = @import("../../../../mod.zig");
const quic = @import("../../../../../quic/mod.zig");
const response_routing = @import("../response.zig");
const qpack_state = @import("../../../qpack/state.zig");
const connect_datagram = @import("../../../datagram.zig");
const buffered_response = @import("../../../stream/buffered/response.zig");
const stream_lifecycle = @import("../../../stream/lifecycle.zig");
const streaming_set = @import("../../../stream/set.zig");
const push_state = @import("../../../stream/push/state.zig");

const net = std.Io.net;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const ResponseStreamSet = buffered_response.Set;
const StreamingResponseSet = streaming_set.Set;
const ClientRequestLifecycle = stream_lifecycle.Client;
const PushStreamSet = push_state.Set;

test "HTTP/3 response reset preserves buffered stream when QPACK feedback allocation fails" {
    const allocator = std.testing.allocator;
    const stream_id: u62 = 0;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var qpack_decode = QpackDecodeState.init(allocator, 256, 512);
    defer qpack_decode.deinit();
    try qpack_decode.table.setCapacity(256);
    _ = try qpack_decode.table.insert("x-reset", "dynamic");

    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &field_section,
        allocator,
        &.{.{ .name = "x-reset", .value = "dynamic" }},
        qpack_decode.table,
    );
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&message, allocator);

    var responses = ResponseStreamSet.init(allocator, 512, 2);
    defer responses.deinit();
    try responses.insert(from, .{
        .stream_id = stream_id,
        .data = message.items,
    });
    try std.testing.expect(try responses.requiresQpackCancellation(
        stream_id,
        qpack_decode.table,
    ));

    var fail_feedback = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    qpack_decode.allocator = fail_feedback.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        response_routing.recordClientResponseReset(
            &responses,
            null,
            &qpack_decode,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ),
    );
    qpack_decode.allocator = allocator;

    try std.testing.expect(fail_feedback.has_induced_failure);
    try std.testing.expect(responses.contains(stream_id));
    try std.testing.expectEqual(@as(usize, 1), responses.count());
    try std.testing.expectEqual(@as(usize, 0), responses.resetCount());
    try std.testing.expect(qpack_decode.pendingDecoderInstructions().len == 0);

    try std.testing.expect(try response_routing.recordClientResponseReset(
        &responses,
        null,
        &qpack_decode,
        stream_id,
        http3.ApplicationErrorCode.request_cancelled,
    ));
    try std.testing.expect(responses.contains(stream_id));
    try std.testing.expectEqual(@as(usize, 1), responses.resetCount());
    try std.testing.expect(qpack_decode.pendingDecoderInstructions().len != 0);
}

test "HTTP/3 response router requests QPACK insert-count feedback" {
    const allocator = std.testing.allocator;
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 512);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        512,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 512, 2);
    defer responses.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&payload, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &payload,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &payload,
        allocator,
        .{ .insert_literal = .{ .name = "x-route", .value = "one" } },
    );

    var state: response_routing.State = .{
        .allocator = allocator,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
    };
    try std.testing.expect(try response_routing.routePacket(
        &state,
        .{ .ip4 = .loopback(443) },
        &.{.{ .stream = .{
            .stream_id = 7,
            .data = payload.items,
        } }},
    ));
    try std.testing.expectEqual(@as(u64, 1), qpack_decode.table.insert_count);
    try std.testing.expect(qpack_decode.pendingDecoderInstructions().len != 0);
}

test "HTTP/3 response router classifies reordered peer uni streams by prefix" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    try qpack_decode.table.setCapacity(256);
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 2);
    defer responses.deinit();
    var state: response_routing.State = .{
        .allocator = allocator,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
    };

    // Stream 7 is often the server QPACK encoder stream, but stream IDs do
    // not define HTTP/3 stream types. A reserved type arriving after an
    // out-of-order suffix must remain an ignored extension stream.
    try std.testing.expect(!try response_routing.routePacket(
        &state,
        from,
        &.{.{ .stream = .{
            .stream_id = 7,
            .offset = 1,
            .data = &.{0xaa},
        } }},
    ));
    try std.testing.expect(!try response_routing.routePacket(
        &state,
        from,
        &.{.{ .stream = .{
            .stream_id = 7,
            .offset = 0,
            .data = &.{0x21},
        } }},
    ));
    try std.testing.expect(control.peer_qpack_encoder_stream_id == null);
    try std.testing.expect(qpack_decode.encoder_stream == null);

    var encoder: std.ArrayList(u8) = .empty;
    defer encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder,
        allocator,
        .{ .insert_literal = .{ .name = "x-reordered", .value = "yes" } },
    );
    try std.testing.expect(encoder.items.len > 1);
    try std.testing.expect(!try response_routing.routePacket(
        &state,
        from,
        &.{.{ .stream = .{
            .stream_id = 15,
            .offset = 1,
            .data = encoder.items[1..],
        } }},
    ));
    try std.testing.expect(try response_routing.routePacket(
        &state,
        from,
        &.{.{ .stream = .{
            .stream_id = 15,
            .offset = 0,
            .data = encoder.items[0..1],
        } }},
    ));
    try std.testing.expectEqual(
        @as(?u64, 15),
        control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(@as(u64, 1), qpack_decode.table.insert_count);
}

test "HTTP/3 response router returns QPACK receive credit to QUIC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc4} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-client",
        .peer_connection_id = "credit-server",
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data_uni = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_uni = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    try qpack_decode.table.setCapacity(256);
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
    };

    var encoder: std.ArrayList(u8) = .empty;
    defer encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder,
        allocator,
        .{ .insert_literal = .{ .name = "x", .value = "123456789" } },
    );
    try std.testing.expect(encoder.items.len > 8);
    try std.testing.expect(encoder.items.len <= 16);
    const stream_frame = quic.Frame{ .stream = .{
        .stream_id = 7,
        .data = encoder.items,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{stream_frame},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        endpoint.address(),
        &.{stream_frame},
    );

    const stats = connection.recvStreamStats(7) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, encoder.items.len), stats.bytes_read);
    try std.testing.expectEqual(
        @as(u64, 16 + encoder.items.len),
        stats.receive_limit,
    );
}

test "HTTP/3 response router returns control receive credit to QUIC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc6} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "control-client",
        .peer_connection_id = "control-server",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data_uni = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
    };

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&bytes, allocator);
    try http3.writeSettingsFrame(&bytes, allocator, .{});
    const stream_frame = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = bytes.items,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{stream_frame},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        endpoint.address(),
        &.{stream_frame},
    );

    const stats = connection.recvStreamStats(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, bytes.items.len), stats.bytes_read);
    try std.testing.expect(control.settings.received);
}

test "HTTP/3 response router retires drained unknown uni stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "unknown-client",
        .peer_connection_id = "unknown-server",
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
    };

    const unknown = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = &.{ 0x21, 0xaa },
        .fin = true,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{unknown},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        endpoint.address(),
        &.{unknown},
    );
    try std.testing.expect(connection.peerStreamClosed(3));

    const reset = quic.Frame{ .reset_stream = .{
        .stream_id = 7,
        .application_error_code = 0,
        .final_size = 0,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{reset},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        endpoint.address(),
        &.{reset},
    );
    try std.testing.expect(connection.peerStreamClosed(7));

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        2,
        &.{.{ .stream = .{
            .stream_id = 11,
            .data = &.{0x21},
            .fin = true,
        } }},
        null,
        .not_ect,
    );
}

test "HTTP/3 response router preserves reordered WebTransport uni prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-client",
        .peer_connection_id = "wt-server",
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var detached = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer detached.deinit();
    try detached.register(0);
    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
        .detached_streams = &detached,
    };

    const bytes = [_]u8{ 0x40, 0x54, 0x00, 'w', 't' };
    const suffix = quic.Frame{ .stream = .{
        .stream_id = 3,
        .offset = 1,
        .data = bytes[1..],
    } };
    const first = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = bytes[0..1],
    } };
    for ([_]quic.Frame{ suffix, first }, 0..) |frame, packet_number| {
        try quic.one_rtt.testing.applyReceivedFrames(
            &connection,
            packet_number,
            &.{frame},
            null,
            .not_ect,
        );
        _ = try response_routing.routePacket(
            &state,
            endpoint.address(),
            &.{frame},
        );
    }
    const stats = connection.recvStreamStats(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_read);
    try std.testing.expectEqual(bytes.len, stats.available_bytes);
}

test "HTTP/3 response router preserves reset WebTransport uni stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-client",
        .peer_connection_id = "wt-reset-server",
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var detached = connect_datagram.Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer detached.deinit();
    try detached.register(0);
    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = null,
        .detached_streams = &detached,
    };

    const prefix = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = &.{ 0x40, 0x54, 0x00 },
    } };
    const reset = quic.Frame{ .reset_stream = .{
        .stream_id = 3,
        .application_error_code = 7,
        .final_size = 3,
    } };
    for ([_]quic.Frame{ prefix, reset }, 0..) |frame, packet_number| {
        try quic.one_rtt.testing.applyReceivedFrames(
            &connection,
            packet_number,
            &.{frame},
            null,
            .not_ect,
        );
        _ = try response_routing.routePacket(
            &state,
            endpoint.address(),
            &.{frame},
        );
    }
    try std.testing.expect(!connection.peerStreamClosed(3));
    try std.testing.expectEqual(@as(u64, 3), connection.recvStreamStats(3).?.available_bytes);
}

test "HTTP/3 fragmented push prefix credits QUIC once and reset retires stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc3} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "push-reset-client",
        .peer_connection_id = "push-reset-server",
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    control.settings.markSent(.{});
    control.settings.markReceived(.{});
    control.local_max_push_id = 0;
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(allocator, 1024);
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 1);
    defer responses.deinit();
    var pushes = PushStreamSet.init(allocator, 1, 1024, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(0);
    try pushes.registerPromise(0, 0);

    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(allocator);
    try quic.varint.encode(&prefix, allocator, @intFromEnum(http3.StreamType.push));
    try quic.varint.encode(&prefix, allocator, 0);
    const prefix_len = prefix.items.len;
    try prefix.appendSlice(allocator, &.{ 0x00, 0x01, 'x' });
    const prefix_fragment = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = prefix.items[0..1],
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{prefix_fragment},
        null,
        .not_ect,
    );

    var state: response_routing.State = .{
        .allocator = allocator,
        .connection = &connection,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = &pushes,
        .request_lifecycle = null,
    };
    _ = try response_routing.routePacket(
        &state,
        .{ .ip4 = .loopback(443) },
        &.{prefix_fragment},
    );
    const partial_stats = connection.recvStreamStats(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), partial_stats.bytes_read);

    const remainder = quic.Frame{ .stream = .{
        .stream_id = 3,
        .offset = 1,
        .data = prefix.items[1..],
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{remainder},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        .{ .ip4 = .loopback(443) },
        &.{remainder},
    );
    try std.testing.expect(pushes.containsStream(3));
    const push_reader = pushes.readerForStream(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), push_reader.uncreditedConsumed());
    const push_stats = connection.recvStreamStats(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, prefix_len), push_stats.bytes_read);
    try std.testing.expectEqual(
        @as(usize, prefix.items.len - prefix_len),
        push_stats.available_bytes,
    );

    const reset = quic.Frame{ .reset_stream = .{
        .stream_id = 3,
        .application_error_code = http3.ApplicationErrorCode.request_cancelled,
        .final_size = prefix.items.len,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        2,
        &.{reset},
        null,
        .not_ect,
    );
    _ = try response_routing.routePacket(
        &state,
        .{ .ip4 = .loopback(443) },
        &.{reset},
    );
    try std.testing.expect(connection.peerStreamClosed(3));
    try std.testing.expect(!pushes.containsStream(3));
}

test "HTTP/3 response router enforces blocked budget across buffered and streaming sets" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    const local_settings: http3.Settings = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    };
    try std.testing.expect(!control.settings.sent);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 2);
    defer responses.deinit();
    var streaming = StreamingResponseSet.init(
        allocator,
        2,
        1024,
        local_settings,
        .response,
    );
    defer streaming.deinit();

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "response");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-blocked", .value = "response" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try responses.insert(from, .{
        .stream_id = 0,
        .data = message.items,
        .fin = true,
    });
    _ = try streaming.activateResponse(&responses, 0);

    var state: response_routing.State = .{
        .allocator = allocator,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = local_settings.qpack_blocked_streams,
        .response_streams = &responses,
        .streaming_responses = &streaming,
        .push_streams = null,
        .request_lifecycle = null,
    };
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        response_routing.routePacket(&state, from, &.{.{ .stream = .{
            .stream_id = 4,
            .data = message.items,
            .fin = true,
        } }}),
    );
    try std.testing.expect(streaming.find(0) != null);
    try std.testing.expect(responses.contains(4));
}

test "HTTP/3 response router distinguishes allocated extension and future IDs" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var responses = ResponseStreamSet.init(allocator, 1024, 3);
    defer responses.deinit();
    var lifecycle = ClientRequestLifecycle.init(allocator, 1);
    defer lifecycle.deinit();

    // Stream 0 was allocated to WebTransport, while stream 4 is a live HTTP
    // request. The high-water mark represents both without retaining one
    // tombstone per completed request or extension stream.
    lifecycle.markAllocated(0);
    try lifecycle.open(4, "GET", false);
    lifecycle.markAllocated(4);
    var state: response_routing.State = .{
        .allocator = allocator,
        .control = &control,
        .qpack_decode = &qpack_decode,
        .qpack_encode = &qpack_encode,
        .max_blocked_streams = 0,
        .response_streams = &responses,
        .streaming_responses = null,
        .push_streams = null,
        .request_lifecycle = &lifecycle,
    };
    const data_frame = [_]u8{ 0x00, 0x01, 'x' };

    _ = try response_routing.routePacket(&state, from, &.{.{ .stream = .{
        .stream_id = 0,
        .data = &data_frame,
    } }});
    try std.testing.expect(!responses.contains(0));

    _ = try response_routing.routePacket(&state, from, &.{.{ .stream = .{
        .stream_id = 4,
        .data = &data_frame,
    } }});
    try std.testing.expect(responses.contains(4));

    try std.testing.expectError(
        error.UnexpectedStream,
        response_routing.routePacket(&state, from, &.{.{ .stream = .{
            .stream_id = 8,
            .data = &data_frame,
        } }}),
    );
    try std.testing.expect(!responses.contains(8));
}
