const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const receive = @import("receive.zig");

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;

const applyControlStreamFrame = receive.applyControlStreamFrame;
const applyControlStreamFrameForRole = receive.applyControlStreamFrameForRole;
const applyControlStreamFrameForRoleWithPushes =
    receive.applyControlStreamFrameForRoleWithPushes;
const rejectCriticalStreamClosureFrame =
    receive.rejectCriticalStreamClosureFrame;

test "HTTP/3 promised push ID set preserves sparse membership compactly" {
    const allocator = std.testing.allocator;
    var ids = receive.ServerPushIdSet{};
    defer ids.deinit(allocator);

    try ids.prepareInsert(allocator, 8);
    for (0..1024) |push_id| {
        ids.insertAssumeCapacity(@intCast(push_id));
    }
    try std.testing.expectEqual(@as(usize, 1), ids.rangeCount());
    try std.testing.expectEqual(@as(usize, 0), ids.sparseRangeCount());
    try std.testing.expect(ids.contains(0));
    try std.testing.expect(ids.contains(1023));
    try std.testing.expect(!ids.contains(1024));

    ids.insertAssumeCapacity(2048);
    ids.insertAssumeCapacity(2050);
    ids.insertAssumeCapacity(2049);
    ids.insertAssumeCapacity(2048);
    try std.testing.expectEqual(@as(usize, 2), ids.rangeCount());
    try std.testing.expectEqual(@as(usize, 1), ids.sparseRangeCount());
    try std.testing.expect(ids.contains(2048));
    try std.testing.expect(ids.contains(2049));
    try std.testing.expect(ids.contains(2050));
    try std.testing.expect(!ids.contains(2047));
    try std.testing.expect(!ids.contains(2051));
    try std.testing.expectError(
        error.DuplicatePushId,
        receive.validateNewServerPush(.{}, ids, 1023),
    );
    try receive.validateNewServerPush(.{}, ids, 1024);

    const promised: receive.PromisedPushIds = .{ .set = &ids };
    try std.testing.expect(promised.contains(1023));
    try std.testing.expect(promised.contains(2049));
    try std.testing.expect(!promised.contains(1024));
}

test "HTTP/3 GOAWAY validates role-specific identifiers" {
    try receive.validateServerGoAwayStreamId(0);
    try receive.validateServerGoAwayStreamId(4);
    try receive.validateServerGoAwayStreamId(128);
    try std.testing.expectError(
        error.IdError,
        receive.validateServerGoAwayStreamId(1),
    );
    try std.testing.expectError(
        error.IdError,
        receive.validateServerGoAwayStreamId(2),
    );
    try std.testing.expectError(
        error.IdError,
        receive.validateServerGoAwayStreamId(3),
    );
    try receive.validateClientGoAwayPushId(0);
    try receive.validateClientGoAwayPushId(1);
    try receive.validateClientGoAwayPushId(quic.varint.max_value);

    try std.testing.expect(!receive.rejectByLocalGoAway(
        .{ .local_goaway_id = 0 },
        .client,
        0,
    ));
    try std.testing.expect(!receive.rejectByLocalGoAway(
        .{ .local_goaway_id = 0 },
        .client,
        4,
    ));
    try std.testing.expect(!receive.rejectByLocalGoAway(
        .{ .local_goaway_id = 4 },
        .server,
        0,
    ));
    try std.testing.expect(receive.rejectByLocalGoAway(
        .{ .local_goaway_id = 4 },
        .server,
        4,
    ));
}

test "HTTP/3 client rejects server-only control frames" {
    const allocator = std.testing.allocator;

    var ignored_message_control = http3.ControlState{};
    defer ignored_message_control.deinit(allocator);
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_message_control,
        allocator,
        .{
            .stream_id = 0,
            .offset = 0,
            .fin = false,
            // On bidirectional request/response streams this is a DATA frame,
            // not a unidirectional stream-type prefix.  Keep role validation
            // from interpreting the DATA length as MAX_PUSH_ID and rejecting a
            // message stream before the message decoder sees it.
            .data = &.{ 0x00, 0x0d, 0x00 },
        },
        .client,
    ));

    var ignored_extension_control = http3.ControlState{};
    defer ignored_extension_control.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_extension_control,
        no_alloc.allocator(),
        .{
            .stream_id = 3,
            .offset = 0,
            .fin = false,
            // Unknown unidirectional streams are extension-owned.  Role
            // validation should ignore them without cloning control state.
            .data = &.{ 0x21, 0x00 },
        },
        .client,
    ));
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_extension_control,
        no_alloc.allocator(),
        .{
            .stream_id = 3,
            .offset = 2,
            .fin = false,
            .data = &.{0x0d},
        },
        .client,
    ));
    try std.testing.expect(!no_alloc.has_induced_failure);

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);

    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var client_control = http3.ControlState{};
    defer client_control.deinit(allocator);
    try std.testing.expectError(error.IdError, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_goaway_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&stream_bytes, allocator, 4);

    client_control.deinit(allocator);
    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_max_push_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });
    client_control.deinit(allocator);
    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.latest_priority_update == null);

    // A second server PRIORITY_UPDATE must be rejected too. Comparing only
    // optional presence let this bypass role validation once one update had
    // already populated connection state.
    var repeated_client_control = http3.ControlState{};
    defer repeated_client_control.deinit(allocator);
    repeated_client_control.settings.received = true;
    var first_illegal: std.ArrayList(u8) = .empty;
    defer first_illegal.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &first_illegal,
        allocator,
        0,
        .{ .urgency = 1 },
    );
    try repeated_client_control.applyFrame(
        allocator,
        try http3.Frame.parse(first_illegal.items),
    );
    const generation =
        repeated_client_control.priority_update_generation;
    var second_illegal: std.ArrayList(u8) = .empty;
    defer second_illegal.deinit(allocator);
    try http3.writeControlStreamPrefix(&second_illegal, allocator);
    try http3.writePriorityUpdateFrame(
        &second_illegal,
        allocator,
        4,
        .{ .urgency = 2 },
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        applyControlStreamFrameForRole(
            &repeated_client_control,
            allocator,
            .{
                .stream_id = 3,
                .offset = 0,
                .data = second_illegal.items,
            },
            .client,
        ),
    );
    try std.testing.expectEqual(
        generation,
        repeated_client_control.priority_update_generation,
    );
    try std.testing.expect(
        repeated_client_control.requestPriorityUpdate(4) == null,
    );

    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var server_control = http3.ControlState{};
    defer server_control.deinit(allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expectEqual(@as(?u64, 1), server_control.peer_goaway_id);

    const next_control_offset = stream_bytes.items.len;
    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = next_control_offset,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expectEqual(@as(?u64, 0), server_control.peer_goaway_id);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });

    server_control.deinit(allocator);
    server_control = .{};
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expect(server_control.latest_priority_update != null);

    stream_bytes.clearRetainingCapacity();
    try quic.varint.encode(&stream_bytes, allocator, @intFromEnum(http3.StreamType.push));
    server_control.deinit(allocator);
    server_control = .{};
    try std.testing.expectError(error.StreamCreationError, applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));

    var client_control_for_push = http3.ControlState{};
    try std.testing.expect(!try applyControlStreamFrameForRole(&client_control_for_push, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));

    var origin_payload: std.ArrayList(u8) = .empty;
    defer origin_payload.deinit(allocator);
    try http3.writeControlStreamPrefix(&origin_payload, allocator);
    try http3.writeSettingsFrame(&origin_payload, allocator, .{});
    try http3.OriginPayload.write(
        &origin_payload,
        allocator,
        &.{"https://illegal-client.example"},
    );
    var origin_server_control = http3.ControlState{};
    defer origin_server_control.deinit(allocator);
    try std.testing.expectError(
        error.UnexpectedFrame,
        applyControlStreamFrameForRole(
            &origin_server_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = origin_payload.items,
            },
            .server,
        ),
    );
    try std.testing.expect(
        !origin_server_control.peerOriginSetInitialized(),
    );
}

test "HTTP/3 role-aware control extensions avoid state snapshots" {
    const allocator = std.testing.allocator;
    var control = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer control.deinit(allocator);

    var priority: std.ArrayList(u8) = .empty;
    defer priority.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &priority,
        allocator,
        0,
        .{ .urgency = 3 },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(priority.items));
    try control.peer_control_stream_buffer.ensureTotalCapacity(allocator, 8);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(try applyControlStreamFrameForRole(
        &control,
        no_alloc.allocator(),
        .{
            .stream_id = server_control_stream_id,
            .offset = 0,
            // Control-stream prefix followed by one complete unknown
            // extension frame with a one-byte payload.
            .data = &.{ 0x00, 0x21, 0x01, 0xaa },
        },
        .client,
    ));
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(u3, 3),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        control.peer_control_stream_consumed_offset,
    );
}

test "HTTP/3 role-aware control rejects oversized priority declaration transactionally" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&bytes, allocator);
    try http3.writeSettingsFrame(&bytes, allocator, .{});
    try quic.varint.encode(
        &bytes,
        allocator,
        http3.FrameType.priority_update_request,
    );
    try quic.varint.encode(
        &bytes,
        allocator,
        http3.max_priority_update_payload_size + 1,
    );

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    try std.testing.expectError(
        error.InvalidFrame,
        applyControlStreamFrameForRole(
            &control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = bytes.items,
            },
            .server,
        ),
    );
    try std.testing.expect(!control.settings.received);
    try std.testing.expect(control.peer_control_stream_id == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_consumed_offset,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        control.priorityUpdates().len,
    );
}

test "HTTP/3 client rejects split server-only control frame transactionally" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&bytes, allocator);
    try http3.writeSettingsFrame(&bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&bytes, allocator, 64);
    const split = bytes.items.len - 1;

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(
        &control,
        allocator,
        .{
            .stream_id = server_control_stream_id,
            .offset = 0,
            .data = bytes.items[0..split],
        },
        .client,
    ));
    try std.testing.expect(control.settings.received);
    try std.testing.expect(control.peer_max_push_id == null);
    const retained = try allocator.dupe(
        u8,
        control.peer_control_stream_buffer.items,
    );
    defer allocator.free(retained);
    try std.testing.expect(retained.len != 0);
    try std.testing.expectEqual(split, control.peer_control_stream_consumed_offset);

    try std.testing.expectError(
        error.UnexpectedFrame,
        applyControlStreamFrameForRole(
            &control,
            allocator,
            .{
                .stream_id = server_control_stream_id,
                .offset = split,
                .data = bytes.items[split..],
            },
            .client,
        ),
    );
    try std.testing.expect(control.settings.received);
    try std.testing.expect(control.peer_max_push_id == null);
    try std.testing.expectEqualSlices(
        u8,
        retained,
        control.peer_control_stream_buffer.items,
    );
    try std.testing.expectEqual(split, control.peer_control_stream_consumed_offset);
}

test "HTTP/3 server validates every batched priority update transactionally" {
    const allocator = std.testing.allocator;

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&request_bytes, allocator);
    try http3.writeSettingsFrame(&request_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(
        &request_bytes,
        allocator,
        8,
        .{ .urgency = 6 },
    );
    try http3.writePriorityUpdateFrame(
        &request_bytes,
        allocator,
        4,
        .{ .urgency = 1 },
    );

    var request_control = http3.ControlState{};
    defer request_control.deinit(allocator);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRoleWithPushes(
            &request_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = request_bytes.items,
            },
            .server,
            .{ .slice = &.{} },
            .{ .static_limit = 2 },
            null,
        ),
    );
    try std.testing.expect(!request_control.settings.received);
    try std.testing.expectEqual(
        @as(usize, 0),
        request_control.priorityUpdates().len,
    );

    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&push_bytes, allocator);
    try http3.writeSettingsFrame(&push_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&push_bytes, allocator, 3);
    try http3.writePushPriorityUpdateFrame(
        &push_bytes,
        allocator,
        2,
        .{ .urgency = 6 },
    );
    try http3.writePushPriorityUpdateFrame(
        &push_bytes,
        allocator,
        1,
        .{ .urgency = 1 },
    );

    var push_control = http3.ControlState{};
    defer push_control.deinit(allocator);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRoleWithPushes(
            &push_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = push_bytes.items,
            },
            .server,
            .{ .slice = &.{1} },
            .{ .static_limit = quic.max_stream_count },
            null,
        ),
    );
    try std.testing.expect(!push_control.settings.received);
    try std.testing.expectEqual(
        @as(usize, 0),
        push_control.priorityUpdates().len,
    );

    // Validation runs before a later frame can trigger any bounded-state
    // housekeeping. An invalid retired-prefix ID therefore remains an error
    // rather than being hidden by the valid update that follows it.
    var retired_bytes: std.ArrayList(u8) = .empty;
    defer retired_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&retired_bytes, allocator);
    try http3.writeSettingsFrame(&retired_bytes, allocator, .{});
    try http3.writePriorityUpdateFrameRaw(
        &retired_bytes,
        allocator,
        http3.FrameType.priority_update_request,
        1,
        "u=7",
    );
    try http3.writePriorityUpdateFrame(
        &retired_bytes,
        allocator,
        4,
        .{ .urgency = 2 },
    );
    try http3.writePriorityUpdateFrame(
        &retired_bytes,
        allocator,
        8,
        .{ .urgency = 3 },
    );
    var retired_control = try http3.ControlState.init(.{
        .max_priority_updates = 2,
    });
    defer retired_control.deinit(allocator);
    retired_control.retireRequestPriority(allocator, 4);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRoleWithPushes(
            &retired_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = retired_bytes.items,
            },
            .server,
            .{ .slice = &.{} },
            .{ .static_limit = 2 },
            null,
        ),
    );
    try std.testing.expect(!retired_control.settings.received);
}

test "HTTP/3 ignored priority update cannot precede SETTINGS" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&bytes, allocator);
    try http3.writePriorityUpdateFrame(
        &bytes,
        allocator,
        0,
        .{ .urgency = 7 },
    );

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    control.retireRequestPriority(allocator, 0);
    try std.testing.expectError(
        error.MissingSettings,
        applyControlStreamFrameForRoleWithPushes(
            &control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = bytes.items,
            },
            .server,
            .{ .slice = &.{} },
            .{ .static_limit = 1 },
            null,
        ),
    );
    try std.testing.expect(!control.settings.received);
    try std.testing.expect(control.peer_control_stream_id == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
}

test "HTTP/3 server rejects unpromised CANCEL_PUSH transactionally" {
    const allocator = std.testing.allocator;

    var invalid_bytes: std.ArrayList(u8) = .empty;
    defer invalid_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&invalid_bytes, allocator);
    try http3.writeSettingsFrame(&invalid_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&invalid_bytes, allocator, 8);
    try http3.writeCancelPushFrame(&invalid_bytes, allocator, 3);

    var invalid_control = http3.ControlState{};
    defer invalid_control.deinit(allocator);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRoleWithPushes(
            &invalid_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = invalid_bytes.items,
            },
            .server,
            .{ .slice = &.{7} },
            .{ .static_limit = quic.max_stream_count },
            null,
        ),
    );
    try std.testing.expect(!invalid_control.settings.received);
    try std.testing.expectEqual(
        @as(?u64, null),
        invalid_control.peer_max_push_id,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        invalid_control.push_cancellation_generation,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_control.cancelledPushRangeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_control.peer_control_stream_consumed_offset,
    );

    var missing_metadata_control = http3.ControlState{};
    defer missing_metadata_control.deinit(allocator);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRole(
            &missing_metadata_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = invalid_bytes.items,
            },
            .server,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        missing_metadata_control.cancelledPushRangeCount(),
    );

    var batched_bytes: std.ArrayList(u8) = .empty;
    defer batched_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&batched_bytes, allocator);
    try http3.writeSettingsFrame(&batched_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&batched_bytes, allocator, 8);
    try http3.writeCancelPushFrame(&batched_bytes, allocator, 7);
    try http3.writeCancelPushFrame(&batched_bytes, allocator, 3);

    var batched_control = http3.ControlState{};
    defer batched_control.deinit(allocator);
    try std.testing.expectError(
        error.IdError,
        applyControlStreamFrameForRoleWithPushes(
            &batched_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = batched_bytes.items,
            },
            .server,
            .{ .slice = &.{7} },
            .{ .static_limit = quic.max_stream_count },
            null,
        ),
    );
    try std.testing.expect(!batched_control.settings.received);
    try std.testing.expectEqual(
        @as(u64, 0),
        batched_control.push_cancellation_generation,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        batched_control.cancelledPushRangeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        batched_control.peer_control_stream_consumed_offset,
    );

    var valid_bytes: std.ArrayList(u8) = .empty;
    defer valid_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&valid_bytes, allocator);
    try http3.writeSettingsFrame(&valid_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&valid_bytes, allocator, 8);
    try http3.writeCancelPushFrame(&valid_bytes, allocator, 7);
    var valid_control = http3.ControlState{};
    defer valid_control.deinit(allocator);
    try std.testing.expect(try applyControlStreamFrameForRoleWithPushes(
        &valid_control,
        allocator,
        .{
            .stream_id = client_control_stream_id,
            .offset = 0,
            .data = valid_bytes.items,
        },
        .server,
        .{ .slice = &.{7} },
        .{ .static_limit = quic.max_stream_count },
        null,
    ));
    try std.testing.expect(valid_control.pushCancelled(7));
    try std.testing.expectEqual(
        @as(u64, 1),
        valid_control.push_cancellation_generation,
    );
}

test "HTTP/3 runtime rejects closed critical streams" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = true,
        .data = control_bytes.items,
    }));
    try std.testing.expect(control.peer_control_stream_id == null);

    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = false,
        .data = control_bytes.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = control_bytes.items.len,
        .fin = true,
        .data = &.{},
    }));

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, allocator);

    var qpack_control = http3.ControlState{};
    defer qpack_control.deinit(allocator);
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = true,
        .data = qpack_encoder.items,
    }));

    try std.testing.expect(try applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = false,
        .data = qpack_encoder.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = qpack_encoder.items.len,
        .fin = true,
        .data = &.{},
    }));
}

test "HTTP/3 runtime rejects non-empty QPACK critical streams" {
    const allocator = std.testing.allocator;
    var control = http3.ControlState{};
    defer control.deinit(allocator);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&payload, allocator);
    // Set Dynamic Table Capacity instruction byte. The compact control-layer
    // compatibility path permits only the critical stream prefix itself.
    try payload.append(allocator, 0x3f);

    try std.testing.expectError(
        error.QpackDynamicTableUnsupported,
        applyControlStreamFrame(&control, allocator, .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = payload.items,
        }),
    );
    try std.testing.expectEqual(
        @as(?u64, client_qpack_encoder_stream_id),
        control.peer_qpack_encoder_stream_id,
    );
}

test "HTTP/3 runtime rejects critical stream reset requests" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .data = control_bytes.items,
    }));

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = client_control_stream_id,
        .application_error_code = 0,
        .final_size = control_bytes.items.len,
    } }, .server));

    try rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 0,
        .final_size = 0,
    } }, .server);

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = client_qpack_encoder_stream_id,
        .application_error_code = 0,
    } }, .client));
    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = server_control_stream_id,
        .application_error_code = 0,
    } }, .server));

    try rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 0,
    } }, .client);
}
