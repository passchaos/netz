const std = @import("std");
const http3 = @import("../../../../mod.zig");
const quic = @import("../../../../../quic/mod.zig");
const request_routing = @import("../request.zig");
const qpack_state = @import("../../../qpack/state.zig");
const buffered_request = @import("../../../stream/buffered/request.zig");
const stream_lifecycle = @import("../../../stream/lifecycle.zig");
const streaming_set = @import("../../../stream/set.zig");

const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const RequestStreamSet = buffered_request.Set;
const ServerRequestLifecycle = stream_lifecycle.Server;
const StreamingRequestSet = streaming_set.Set;

test "HTTP/3 server request priorities move into active lifecycle" {
    const allocator = std.testing.allocator;
    var control = try http3.ControlState.init(.{
        .max_priority_updates = 2,
    });
    defer control.deinit(allocator);
    control.settings.received = true;
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1, .incremental = true },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        0,
        .{ .urgency = 6 },
    );
    try std.testing.expectEqual(@as(u3, 1), lifecycle.priority(0).urgency);
    try std.testing.expect(lifecycle.priority(0).incremental);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        4,
        .{ .urgency = 5 },
    );
    request_routing.finishServerRequest(&control, &lifecycle, 4);
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(!lifecycle.contains(4));

    encoded.clearRetainingCapacity();
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 4 },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    request_routing.reconcileServerRequestPriorities(&control, &lifecycle);
    try std.testing.expectEqual(@as(u3, 4), lifecycle.priority(0).urgency);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);

    request_routing.finishServerRequest(&control, &lifecycle, 0);
    try std.testing.expect(!lifecycle.contains(0));

    encoded.clearRetainingCapacity();
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 7 },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
}

test "HTTP/3 request router handles duplicate reset idempotently" {
    const allocator = std.testing.allocator;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    const code = http3.ApplicationErrorCode.request_cancelled;
    const frames = [_]quic.Frame{.{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = code,
        .final_size = 0,
    } }};

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 2);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(
        allocator,
        2,
        1024,
        .{},
        .request,
    );
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        0,
        .{},
    );

    const first = (try request_routing.applyServerRequestPacketFrames(
        from,
        &frames,
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 1 },
        &.{},
        null,
        null,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqual(@as(usize, 1), streaming.resetCount());
    try std.testing.expect(!lifecycle.contains(0));

    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &frames,
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 1 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expectEqual(@as(usize, 1), streaming.resetCount());
    const queued = streaming.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), queued.stream_id);
    try std.testing.expectEqual(code, queued.application_error_code);
}

test "HTTP/3 request router classifies reordered peer uni streams by prefix" {
    const allocator = std.testing.allocator;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 2);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(
        allocator,
        2,
        1024,
        .{},
        .request,
    );
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &.{.{ .stream = .{
            .stream_id = 6,
            .offset = 1,
            .data = &.{0xbb},
        } }},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 2 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &.{.{ .stream = .{
            .stream_id = 6,
            .offset = 0,
            .data = &.{0x21},
        } }},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 2 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expect(control.peer_qpack_encoder_stream_id == null);
    try std.testing.expect(qpack_decode.encoder_stream == null);

    try qpack_decode.table.setCapacity(256);
    var encoder: std.ArrayList(u8) = .empty;
    defer encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder,
        allocator,
        .{ .insert_literal = .{ .name = "x-request", .value = "yes" } },
    );
    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &.{.{ .stream = .{
            .stream_id = 14,
            .offset = 1,
            .data = encoder.items[1..],
        } }},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 2 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &.{.{ .stream = .{
            .stream_id = 14,
            .offset = 0,
            .data = encoder.items[0..1],
        } }},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 2 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expectEqual(
        @as(?u64, 14),
        control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(@as(u64, 1), qpack_decode.table.insert_count);
}

test "HTTP/3 request router ignores late STREAM after QUIC reclamation" {
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
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "route-server",
        .peer_connection_id = "route-client",
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 0, .data = "x", .fin = true } }},
        null,
        .not_ect,
    );
    try connection.releaseReceivedCapacity(0, 1);
    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "response",
        .fin = true,
    } }});
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expect(try connection.releaseCompletedPeerStream(0));
    try std.testing.expect(connection.peerStreamClosed(0));

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(allocator, 1024);
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 1);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(allocator, 1, 1024, .{}, .request);
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        .{ .ip4 = .loopback(443) },
        &.{.{ .stream = .{ .stream_id = 0, .data = "late", .fin = true } }},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .connection = &connection },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expect(buffered.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), streaming.entryCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.count());
}

test "HTTP/3 request reset automatically registers QUIC retirement" {
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
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-route-server",
        .peer_connection_id = "reset-route-client",
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const reset = quic.Frame{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = http3.ApplicationErrorCode.request_cancelled,
        .final_size = 0,
    } };
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{reset},
        null,
        .not_ect,
    );

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(allocator, 1024);
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 1);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(allocator, 1, 1024, .{}, .request);
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    const routed = (try request_routing.applyServerRequestPacketFrames(
        .{ .ip4 = .loopback(443) },
        &.{reset},
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .connection = &connection },
        &.{},
        null,
        null,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), routed.stream_id);
    try std.testing.expect(!connection.peerStreamClosed(0));

    try connection.resetStream(0, http3.ApplicationErrorCode.request_cancelled);
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.peerStreamClosed(0));
}

test "HTTP/3 request router enforces blocked budget across buffered and streaming sets" {
    const allocator = std.testing.allocator;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    control.settings.local = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    };
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 2);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(
        allocator,
        2,
        1024,
        control.settings.local,
        .request,
    );
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "request");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = "x-blocked", .value = "request" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try buffered.insert(from, .{
        .stream_id = 0,
        .data = message.items,
        .fin = true,
    });
    _ = try streaming.activateRequest(&buffered, 0);

    try std.testing.expectError(
        error.QpackDecompressionFailed,
        request_routing.applyServerRequestPacketFrames(
            from,
            &.{.{ .stream = .{
                .stream_id = 4,
                .data = message.items,
                .fin = true,
            } }},
            allocator,
            &control,
            &qpack_decode,
            &qpack_encode,
            1,
            &buffered,
            &streaming,
            &lifecycle,
            .{ .static_limit = 2 },
            &.{},
            null,
            null,
        ),
    );
    try std.testing.expect(streaming.find(0) != null);
    try std.testing.expect(buffered.contains(4));
}
