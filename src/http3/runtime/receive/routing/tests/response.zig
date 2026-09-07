const std = @import("std");
const http3 = @import("../../../../mod.zig");
const quic = @import("../../../../../quic/mod.zig");
const response_routing = @import("../response.zig");
const qpack_state = @import("../../../qpack/state.zig");
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

test "HTTP/3 push reset requests QUIC stream retirement" {
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
    const stream_frame = quic.Frame{ .stream = .{
        .stream_id = 3,
        .data = prefix.items,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{stream_frame},
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
        &.{stream_frame},
    );
    try std.testing.expect(pushes.containsStream(3));

    const reset = quic.Frame{ .reset_stream = .{
        .stream_id = 3,
        .application_error_code = http3.ApplicationErrorCode.request_cancelled,
        .final_size = prefix.items.len,
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
