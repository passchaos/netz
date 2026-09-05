const std = @import("std");
const http2 = @import("../../../mod.zig");
const wire = @import("../wire.zig");

test "HTTP/2 frame wire validates envelope rules" {
    try wire.validateEnvelope(frame(.data, 1, 0x1, &.{}));
    try wire.validateEnvelope(frame(.settings, 0, 0x1, &.{}));
    try wire.validateEnvelope(frame(
        .settings,
        0,
        0,
        &.{ 0, 1, 0, 0, 0, 0 },
    ));
    try wire.validateEnvelope(frame(
        .rst_stream,
        1,
        0,
        &.{ 0, 0, 0, 8 },
    ));

    const invalid = [_]http2.Frame{
        .{
            .header = .{
                .length = 1,
                .frame_type = .data,
                .flags = 0,
                .stream_id = 1,
            },
            .payload = &.{},
        },
        frame(.data, 0, 0, &.{}),
        frame(.settings, 0, 0x1, &.{0}),
        frame(.settings, 0, 0, &.{ 0, 1, 0, 0, 0 }),
        frame(.settings, 1, 0, &.{}),
        frame(.rst_stream, 1, 0, &.{ 0, 0, 0 }),
        frame(.ping, 0, 0, &.{ 0, 1, 2, 3, 4, 5, 6 }),
        frame(.ping, 1, 0, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }),
        frame(.window_update, 1, 0, &.{ 0, 0, 0, 0 }),
        frame(.priority, 1, 0, &.{ 0, 0, 0, 0 }),
        frame(.goaway, 1, 0, &.{ 0, 0, 0, 0, 0, 0, 0, 0 }),
        frame(.push_promise, 0, 0, &.{ 0, 0, 0, 2 }),
        frame(.priority_update, 1, 0, &.{ 0, 0, 0, 1 }),
    };
    for (invalid) |value| {
        try std.testing.expectError(
            error.InvalidFrame,
            wire.validateEnvelope(value),
        );
    }
}

test "HTTP/2 frame wire appends HEADERS and CONTINUATION transactionally" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try wire.appendHeaderBlock(
        &encoded,
        allocator,
        3,
        "abcdefgh",
        true,
        3,
    );

    var cursor: usize = 0;
    const expected_types = [_]http2.FrameType{
        .headers,
        .continuation,
        .continuation,
    };
    const expected_payloads = [_][]const u8{ "abc", "def", "gh" };
    for (expected_types, expected_payloads, 0..) |expected_type, payload, index| {
        const parsed = try http2.Frame.parse(encoded.items[cursor..]);
        try std.testing.expectEqual(expected_type, parsed.header.frame_type);
        try std.testing.expectEqual(@as(u31, 3), parsed.header.stream_id);
        try std.testing.expectEqualSlices(u8, payload, parsed.payload);
        try std.testing.expectEqual(index == 0, (parsed.header.flags & 0x1) != 0);
        try std.testing.expectEqual(index == 2, (parsed.header.flags & 0x4) != 0);
        cursor += parsed.consumed();
    }
    try std.testing.expectEqual(encoded.items.len, cursor);

    const retained = try allocator.dupe(u8, encoded.items);
    defer allocator.free(retained);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    encoded.clearRetainingCapacity();
    try wire.appendHeaderBlock(
        &encoded,
        no_alloc.allocator(),
        3,
        "abcdefgh",
        true,
        3,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, retained, encoded.items);

    var transactional: std.ArrayList(u8) = .empty;
    defer transactional.deinit(allocator);
    try transactional.ensureTotalCapacityPrecise(allocator, "prefix".len);
    transactional.appendSliceAssumeCapacity("prefix");
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        wire.appendHeaderBlock(
            &transactional,
            fail_first.allocator(),
            3,
            "abcdefgh",
            true,
            3,
        ),
    );
    try std.testing.expectEqualStrings("prefix", transactional.items);

    try std.testing.expectError(
        error.InvalidFrameSize,
        wire.appendHeaderBlock(
            &transactional,
            allocator,
            3,
            "abcdefgh",
            true,
            0,
        ),
    );
    try std.testing.expectEqualStrings("prefix", transactional.items);
}

test "HTTP/2 frame wire encodes bounded fixed frames" {
    var header: [http2.FrameHeader.encoded_len]u8 = undefined;
    try wire.encodeHeader(&header, .data, 0x1, 7, 65_535);
    const parsed = try http2.FrameHeader.parse(&header);
    try std.testing.expectEqual(@as(u24, 65_535), parsed.length);
    try std.testing.expectEqual(http2.FrameType.data, parsed.frame_type);
    try std.testing.expectEqual(@as(u31, 7), parsed.stream_id);
    try std.testing.expectError(
        error.InvalidFrameSize,
        wire.encodeHeader(
            &header,
            .data,
            0,
            1,
            @as(usize, std.math.maxInt(u24)) + 1,
        ),
    );

    var update: [http2.FrameHeader.encoded_len + 4]u8 = undefined;
    try wire.encodeWindowUpdate(&update, 5, 1024);
    const update_frame = try http2.Frame.parse(&update);
    try wire.validateEnvelope(update_frame);
    try std.testing.expectEqual(
        @as(u32, 1024),
        std.mem.readInt(u32, update_frame.payload[0..4], .big),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        wire.encodeWindowUpdate(&update, 5, 0),
    );
}

test "HTTP/2 frame wire identifies client streams" {
    try std.testing.expect(!wire.clientInitiatedStreamId(0));
    try std.testing.expect(wire.clientInitiatedStreamId(1));
    try std.testing.expect(!wire.clientInitiatedStreamId(2));
    try std.testing.expect(wire.clientInitiatedStreamId(3));
}

fn frame(
    frame_type: http2.FrameType,
    stream_id: u31,
    flags: u8,
    payload: []const u8,
) http2.Frame {
    return .{
        .header = .{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        },
        .payload = payload,
    };
}
