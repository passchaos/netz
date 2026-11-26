//! Dispatcher control frames retain exact state across pacing refusal.
const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");
const FixedClockIo = @import("../../../internal/testing/deadline_send_io.zig").Native;
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");

test "HTTP/3 dispatcher client control frames retry transactionally" {
    try native_protocol_io.run(dispatcherClientControlFramesRetryTransactionally);
}

fn dispatcherClientControlFramesRetryTransactionally(io: std.Io) !void {
    const allocator = std.testing.allocator;

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
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var client = try runtime.HandshakeClient.initEstablished(
        &endpoint,
        peer_endpoint.address(),
        try quic.handshake.establishPreconfigured(
            &endpoint,
            peer_endpoint.address(),
            .client,
            .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = "control-client",
                .peer_connection_id = "control-server",
                .one_rtt = .{
                    .max_datagram_size = 1200,
                    .pacing_max_burst_packets = 1,
                },
            },
        ),
        .{},
    );
    defer client.deinit();
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = "control-server",
        .peer_connection_id = "control-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer peer.deinit();

    try client.ensureSettingsSentOnce();
    var settings_packet = try peer.receivePacket();
    settings_packet.deinit(allocator);
    try client.bindDispatcher();
    var fixed_io: FixedClockIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = endpoint.io,
        .now_ns = .init(9_000_000),
    };
    defer fixed_io.backend.deinit();
    endpoint.io = fixed_io.io();
    defer endpoint.io = fixed_io.baseIo();

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    var packet_number = client.established.connection.next_packet_number;
    var control_offset = runtime.testing.clientControlSendOffset(&client);
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendGoAway(9),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        runtime.testing.clientLocalGoAwayId(&client),
    );
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.clientControlSendOffset(&client),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );

    var timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.trySendGoAway(9);

    var received = try peer.receivePacket();
    defer received.deinit(allocator);
    var control_bytes: []const u8 = &.{};
    for (received.frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == 2) {
            control_bytes = stream.data;
        },
        else => {},
    };
    const goaway = try http3.Frame.parse(control_bytes);
    try std.testing.expectEqual(http3.FrameType.goaway, goaway.frame_type);
    try std.testing.expectEqual(
        @as(u64, 9),
        (try quic.varint.decodeSlice(goaway.payload)).value,
    );

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    packet_number = client.established.connection.next_packet_number;
    control_offset = runtime.testing.clientControlSendOffset(&client);
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendMaxPushId(4),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        runtime.testing.clientLocalMaxPushId(&client),
    );
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.clientControlSendOffset(&client),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );

    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.trySendMaxPushId(4);
    received.deinit(allocator);
    received = try peer.receivePacket();
    control_bytes = &.{};
    for (received.frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == 2) {
            control_bytes = stream.data;
        },
        else => {},
    };
    const max_push_id = try http3.Frame.parse(control_bytes);
    try std.testing.expectEqual(
        http3.FrameType.max_push_id,
        max_push_id.frame_type,
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        (try quic.varint.decodeSlice(max_push_id.payload)).value,
    );
    try client.push_streams.registerPromise(3, 0);
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    packet_number = client.established.connection.next_packet_number;
    control_offset = runtime.testing.clientControlSendOffset(&client);
    try std.testing.expectError(
        error.PacingLimited,
        client.tryCancelPush(3),
    );
    try std.testing.expect(runtime.testing.clientHasPushPromise(&client, 3));
    try std.testing.expectEqual(
        @as(usize, 1),
        runtime.testing.clientPushPromiseCount(&client),
    );
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.clientControlSendOffset(&client),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );

    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.tryCancelPush(3);
    // Completed/cancelled IDs remain in compact lifetime history, while the
    // active promise slot itself is retired.
    try std.testing.expect(runtime.testing.clientHasPushPromise(&client, 3));
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.clientPushPromiseCount(&client),
    );
    received.deinit(allocator);
    received = try peer.receivePacket();
    control_bytes = &.{};
    for (received.frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == 2) {
            control_bytes = stream.data;
        },
        else => {},
    };
    const cancel_push = try http3.Frame.parse(control_bytes);
    try std.testing.expectEqual(
        http3.FrameType.cancel_push,
        cancel_push.frame_type,
    );
    try std.testing.expectEqual(
        @as(u64, 3),
        (try quic.varint.decodeSlice(cancel_push.payload)).value,
    );

    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    packet_number = client.established.connection.next_packet_number;
    control_offset = runtime.testing.clientControlSendOffset(&client);
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendPriorityUpdate(0, .{ .urgency = 2, .incremental = true }),
    );
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.clientControlSendOffset(&client),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );

    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.trySendPriorityUpdate(0, .{
        .urgency = 2,
        .incremental = true,
    });
    received.deinit(allocator);
    received = try peer.receivePacket();
    control_bytes = &.{};
    for (received.frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == 2) {
            control_bytes = stream.data;
        },
        else => {},
    };
    const priority_frame = try http3.Frame.parse(control_bytes);
    try std.testing.expectEqual(
        http3.FrameType.priority_update_request,
        priority_frame.frame_type,
    );
    const priority = try http3.parsePriorityUpdatePayload(
        priority_frame.payload,
    );
    try std.testing.expectEqual(@as(u64, 0), priority.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 2), priority.priority().urgency);
    try std.testing.expect(priority.priority().incremental);

    try client.push_streams.registerPromise(4, 0);
    quic.one_rtt.testing.exhaustPacingAt(
        &client.established.connection,
        @intCast(fixed_io.now_ns.load(.acquire)),
    );
    packet_number = client.established.connection.next_packet_number;
    control_offset = runtime.testing.clientControlSendOffset(&client);
    try std.testing.expectError(
        error.PacingLimited,
        client.trySendPushPriorityUpdate(4, .{ .urgency = 5 }),
    );
    try std.testing.expectEqual(
        control_offset,
        runtime.testing.clientControlSendOffset(&client),
    );
    try std.testing.expectEqual(
        packet_number,
        client.established.connection.next_packet_number,
    );

    timer = client.established.connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    fixed_io.setNow(@intCast(timer.deadline_ns));
    _ = (try client.established.connection.serviceNextTimerAt(
        timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try client.trySendPushPriorityUpdate(4, .{ .urgency = 5 });
    received.deinit(allocator);
    received = try peer.receivePacket();
    control_bytes = &.{};
    for (received.frames) |frame| switch (frame) {
        .stream => |stream| if (stream.stream_id == 2) {
            control_bytes = stream.data;
        },
        else => {},
    };
    const push_priority_frame = try http3.Frame.parse(control_bytes);
    try std.testing.expectEqual(
        http3.FrameType.priority_update_push,
        push_priority_frame.frame_type,
    );
    const push_priority = try http3.parsePriorityUpdatePayload(
        push_priority_frame.payload,
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        push_priority.prioritized_element_id,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        push_priority.priority().urgency,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.duration_sleep_calls.load(.acquire));
}
