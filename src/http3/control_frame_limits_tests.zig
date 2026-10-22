const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");

test "HTTP/3 control stream rejects invalid declarations before payload" {
    const allocator = std.testing.allocator;
    const Case = struct {
        settings_received: bool,
        frame_type: u64,
        payload_length: u64,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{ .settings_received = false, .frame_type = 0x21, .payload_length = 4096, .expected = error.MissingSettings },
        .{ .settings_received = true, .frame_type = http3.FrameType.settings, .payload_length = 0, .expected = error.DuplicateSettings },
        .{ .settings_received = false, .frame_type = http3.FrameType.settings, .payload_length = http3.max_settings_payload_size + 1, .expected = error.InvalidSetting },
        .{ .settings_received = true, .frame_type = http3.FrameType.goaway, .payload_length = 0, .expected = error.InvalidFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.goaway, .payload_length = 9, .expected = error.InvalidFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.cancel_push, .payload_length = 0, .expected = error.InvalidFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.max_push_id, .payload_length = 9, .expected = error.InvalidFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.priority_update_request, .payload_length = 0, .expected = error.InvalidFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.priority_update_push, .payload_length = http3.max_priority_update_payload_size + 1, .expected = error.ExcessiveLoad },
        .{ .settings_received = true, .frame_type = http3.FrameType.data, .payload_length = 4096, .expected = error.UnexpectedFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.headers, .payload_length = 4096, .expected = error.UnexpectedFrame },
        .{ .settings_received = true, .frame_type = http3.FrameType.push_promise, .payload_length = 4096, .expected = error.UnexpectedFrame },
    };

    for (cases) |case| {
        var control = http3.ControlState{};
        defer control.deinit(allocator);
        control.settings.received = case.settings_received;
        var header: std.ArrayList(u8) = .empty;
        defer header.deinit(allocator);
        try quic.varint.encode(&header, allocator, case.frame_type);
        try quic.varint.encode(&header, allocator, case.payload_length);
        try std.testing.expectError(
            case.expected,
            control.appendControlPayload(allocator, header.items),
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            control.peer_control_stream_buffer.items.len,
        );
        try std.testing.expectEqual(
            case.settings_received,
            control.settings.received,
        );
    }

    var allowed = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer allowed.deinit(allocator);
    var header: std.ArrayList(u8) = .empty;
    defer header.deinit(allocator);
    try quic.varint.encode(
        &header,
        allocator,
        http3.FrameType.priority_update_request,
    );
    try quic.varint.encode(
        &header,
        allocator,
        http3.max_priority_update_payload_size,
    );
    try allowed.appendControlPayload(allocator, header.items);
    try std.testing.expectEqualSlices(
        u8,
        header.items,
        allowed.peer_control_stream_buffer.items,
    );
}

test "HTTP/3 PRIORITY_UPDATE payload cap is configurable and transactional" {
    const allocator = std.testing.allocator;
    var expanded_payload =
        [_]u8{'a'} ** (http3.max_priority_update_payload_size + 1);
    expanded_payload[0] = 0;
    const parsed = try http3.parsePriorityUpdatePayload(&expanded_payload);
    try std.testing.expectEqual(@as(u64, 0), parsed.prioritized_element_id);
    try std.testing.expectEqual(
        http3.max_priority_update_payload_size,
        parsed.field_value.len,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writePriorityUpdateFrameRaw(
        &encoded,
        allocator,
        http3.FrameType.priority_update_request,
        0,
        expanded_payload[1..],
    );
    const expanded_frame = try http3.Frame.parse(encoded.items);
    try std.testing.expectEqual(
        expanded_payload.len,
        expanded_frame.payload.len,
    );

    var default_control = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer default_control.deinit(allocator);
    try std.testing.expectError(
        error.ExcessiveLoad,
        default_control.applyFrame(allocator, .{
            .frame_type = http3.FrameType.priority_update_request,
            .payload = &expanded_payload,
            .consumed = 0,
        }),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        default_control.priorityUpdates().len,
    );

    var expanded = try http3.ControlState.init(.{
        .max_priority_update_payload_size = expanded_payload.len,
    });
    defer expanded.deinit(allocator);
    expanded.settings.received = true;
    try expanded.applyFrame(allocator, .{
        .frame_type = http3.FrameType.priority_update_request,
        .payload = &expanded_payload,
        .consumed = 0,
    });
    try std.testing.expectEqual(
        expanded_payload.len,
        expanded.priorityUpdates()[0].payload.field_value.len + 1,
    );
    var cloned = try expanded.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        expanded_payload.len,
        cloned.max_priority_update_payload_size,
    );

    var strict = try http3.ControlState.init(.{
        .max_priority_update_payload_size = 4,
    });
    defer strict.deinit(allocator);
    strict.settings.received = true;
    var declaration: std.ArrayList(u8) = .empty;
    defer declaration.deinit(allocator);
    try quic.varint.encode(
        &declaration,
        allocator,
        http3.FrameType.priority_update_request,
    );
    try quic.varint.encode(&declaration, allocator, 5);
    try std.testing.expectError(
        error.ExcessiveLoad,
        strict.appendControlPayload(
            allocator,
            declaration.items,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        strict.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(@as(usize, 0), strict.priorityUpdates().len);
    try strict.applyFrame(allocator, .{
        .frame_type = http3.FrameType.priority_update_request,
        .payload = &.{ 0, 'u', '=', '1' },
        .consumed = 0,
    });
    try std.testing.expectEqual(
        @as(u3, 1),
        strict.requestPriorityUpdate(0).?.priority().urgency,
    );

    var disabled = try http3.ControlState.init(.{
        .max_priority_update_payload_size = 0,
    });
    defer disabled.deinit(allocator);
    disabled.settings.received = true;
    try std.testing.expectError(
        error.ExcessiveLoad,
        disabled.applyFrame(allocator, .{
            .frame_type = http3.FrameType.priority_update_request,
            .payload = &.{0},
            .consumed = 0,
        }),
    );
}

test "HTTP/3 unknown control payload skips without allocation" {
    const allocator = std.testing.allocator;
    const payload_len = http3.max_control_stream_buffer_size + 1;
    var control = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer control.deinit(allocator);
    try control.peer_control_stream_buffer.ensureTotalCapacity(
        allocator,
        16,
    );
    try control.appendControlPayload(allocator, &.{0x21});

    var length_storage: [8]u8 = undefined;
    const encoded_length = try quic.varint.encodeInto(
        &length_storage,
        payload_len,
    );
    var suffix_storage: [11]u8 = undefined;
    @memcpy(suffix_storage[0..encoded_length.len], encoded_length);
    @memset(suffix_storage[encoded_length.len..][0..3], 0xaa);
    const suffix = suffix_storage[0 .. encoded_length.len + 3];
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try control.appendControlPayload(no_alloc.allocator(), suffix);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        payload_len - 3,
        control.peer_control_stream_skip_remaining,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );

    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        control.peer_control_stream_skip_remaining,
        cloned.peer_control_stream_skip_remaining,
    );

    const remaining = try allocator.alloc(
        u8,
        control.peer_control_stream_skip_remaining,
    );
    defer allocator.free(remaining);
    @memset(remaining, 0xbb);
    try control.appendControlPayload(no_alloc.allocator(), remaining);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_skip_remaining,
    );

    try control.appendControlPayload(allocator, &.{ 0x07, 0x01, 0x05 });
    try std.testing.expectEqual(@as(?u64, 5), control.peer_goaway_id);
}

test "HTTP/3 unknown control skipping rolls back with batched errors" {
    const allocator = std.testing.allocator;
    var semantic = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer semantic.deinit(allocator);
    try std.testing.expectError(
        error.UnexpectedFrame,
        semantic.appendControlPayload(
            allocator,
            &.{
                0x21, 0x02, 0xaa, 0xbb,
                0x07, 0x01, 0x05, 0x00,
                0x00,
            },
        ),
    );
    try std.testing.expectEqual(@as(?u64, null), semantic.peer_goaway_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        semantic.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        semantic.peer_control_stream_skip_remaining,
    );

    var parser = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer parser.deinit(allocator);
    try parser.appendControlPayload(allocator, &.{0x21});
    try std.testing.expectError(
        error.UnexpectedFrame,
        parser.appendControlPayload(
            allocator,
            &.{ 0x01, 0xaa, 0x00, 0x00 },
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{0x21},
        parser.peer_control_stream_buffer.items,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        parser.peer_control_stream_skip_remaining,
    );
}

fn checkSkippedControlBatchAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var control = http3.ControlState{
        .settings = .{ .received = true },
    };
    defer control.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        8,
        .{ .urgency = 3 },
    );
    try control.applyFrame(
        allocator,
        try http3.Frame.parse(encoded.items),
    );
    encoded.clearRetainingCapacity();
    try encoded.appendSlice(allocator, &.{ 0x21, 0x02, 0xaa, 0xbb });
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1 },
    );
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        4,
        .{ .urgency = 2, .incremental = true },
    );
    control.appendControlPayload(allocator, encoded.items) catch |err| {
        try std.testing.expectEqual(
            @as(usize, 1),
            control.priorityUpdates().len,
        );
        try std.testing.expectEqual(
            @as(u3, 3),
            control.requestPriorityUpdate(8).?.priority().urgency,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            control.peer_control_stream_buffer.items.len,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            control.peer_control_stream_skip_remaining,
        );
        return err;
    };
    try std.testing.expectEqual(
        @as(usize, 3),
        control.priorityUpdates().len,
    );
}

test "HTTP/3 skipped control batch is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkSkippedControlBatchAllocationFailure,
        .{},
    );
}
