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
        .{ .settings_received = true, .frame_type = http3.FrameType.priority_update_push, .payload_length = http3.max_priority_update_payload_size + 1, .expected = error.InvalidFrame },
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

test "HTTP/3 PRIORITY_UPDATE payload is bounded transactionally" {
    const allocator = std.testing.allocator;
    var maximum = [_]u8{'a'} ** http3.max_priority_update_payload_size;
    maximum[0] = 0;
    const parsed = try http3.parsePriorityUpdatePayload(&maximum);
    try std.testing.expectEqual(@as(u64, 0), parsed.prioritized_element_id);
    try std.testing.expectEqual(
        http3.max_priority_update_payload_size - 1,
        parsed.field_value.len,
    );

    var oversized =
        [_]u8{'a'} ** (http3.max_priority_update_payload_size + 1);
    oversized[0] = 0;
    try std.testing.expectError(
        error.InvalidFrame,
        http3.parsePriorityUpdatePayload(&oversized),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const original = "stable-prefix";
    try encoded.appendSlice(allocator, original);
    try std.testing.expectError(
        error.InvalidPriorityUpdate,
        http3.writePriorityUpdateFrameRaw(
            &encoded,
            allocator,
            http3.FrameType.priority_update_request,
            0,
            oversized[1..],
        ),
    );
    try std.testing.expectEqualStrings(original, encoded.items);

    try std.testing.expectError(
        error.InvalidFrame,
        (http3.Frame{
            .frame_type = http3.FrameType.priority_update_request,
            .payload = &oversized,
            .consumed = 0,
        }).write(&encoded, allocator),
    );
    try std.testing.expectEqualStrings(original, encoded.items);
}
