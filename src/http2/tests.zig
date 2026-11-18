const std = @import("std");
const http2_root = @import("mod.zig");

const wire = @import("../internal/wire.zig");

const AltSvcPayload = http2_root.AltSvcPayload;
const DataPayload = http2_root.DataPayload;
const ErrorCode = http2_root.ErrorCode;
const Flags = http2_root.Flags;
const Frame = http2_root.Frame;
const FrameType = http2_root.FrameType;
const GoAwayPayload = http2_root.GoAwayPayload;
const HeadersPayload = http2_root.HeadersPayload;
const Hpack = http2_root.Hpack;
const OriginPayload = http2_root.OriginPayload;
const PingPayload = http2_root.PingPayload;
const PriorityPayload = http2_root.PriorityPayload;
const PriorityUpdatePayload = http2_root.PriorityUpdatePayload;
const PushPromisePayload = http2_root.PushPromisePayload;
const ResetStreamPayload = http2_root.ResetStreamPayload;
const Setting = http2_root.Setting;
const SettingId = http2_root.SettingId;
const WindowUpdatePayload = http2_root.WindowUpdatePayload;
const checkHpackContiguousDynamicStorage = http2_root.checkHpackContiguousDynamicStorage;
const checkHpackDecoderTableWithoutLookupIndexes = http2_root.checkHpackDecoderTableWithoutLookupIndexes;
const checkHpackOwnedDecode = http2_root.checkHpackOwnedDecode;
const checkHpackOwnedDecodeScratchFallback = http2_root.checkHpackOwnedDecodeScratchFallback;
const connection_preface = http2_root.connection_preface;
const parseSettings = http2_root.parseSettings;
const validateClientPreface = http2_root.validateClientPreface;
const writeSettings = http2_root.writeSettings;

test "HTTP/2 HPACK prefix integer covers the complete u64 range" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Hpack.encodeInteger(
        &encoded,
        allocator,
        5,
        0,
        std.math.maxInt(u64),
    );

    var cursor = wire.Cursor.init(encoded.items[1..]);
    try std.testing.expectEqual(
        std.math.maxInt(u64),
        try Hpack.decodeInteger(encoded.items[0], &cursor, 5),
    );
    try std.testing.expect(cursor.eof());
}

test "HTTP/2 HPACK prefix integer rejects values wider than u64" {
    const continued = [_]u8{0x80} ** 10;
    var unterminated = wire.Cursor.init(&continued);
    try std.testing.expectError(
        error.IntegerOverflow,
        Hpack.decodeInteger(0x1f, &unterminated, 5),
    );

    const terminal_overflow = [_]u8{0x80} ** 9 ++ [_]u8{0x02};
    var terminated = wire.Cursor.init(&terminal_overflow);
    try std.testing.expectError(
        error.IntegerOverflow,
        Hpack.decodeInteger(0x1f, &terminated, 5),
    );
}

test "HTTP/2 frame and settings roundtrip" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = .max_concurrent_streams, .value = 100 },
        .{ .id = .initial_window_size, .value = 65535 },
    };
    try writeSettings(&payload, allocator, &settings);
    var no_alloc_payload: std.ArrayList(u8) = .empty;
    defer no_alloc_payload.deinit(allocator);
    try no_alloc_payload.ensureTotalCapacity(allocator, payload.items.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeSettings(&no_alloc_payload, no_alloc.allocator(), &settings);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, payload.items, no_alloc_payload.items);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Frame{ .header = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 }, .payload = payload.items }).write(&encoded, allocator);
    var no_alloc_frame: std.ArrayList(u8) = .empty;
    defer no_alloc_frame.deinit(allocator);
    try no_alloc_frame.ensureTotalCapacity(allocator, encoded.items.len);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try (Frame{ .header = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 }, .payload = payload.items }).write(&no_alloc_frame, no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_frame.items);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.settings, frame.header.frame_type);
    const parsed = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(u32, 100), parsed[0].value);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const no_alloc_parsed_allocator = no_alloc.allocator();
    const no_alloc_parsed = try parseSettings(no_alloc_parsed_allocator, frame.payload);
    defer no_alloc_parsed_allocator.free(no_alloc_parsed);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(parsed[1].value, no_alloc_parsed[1].value);

    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const empty_settings = try parseSettings(no_alloc.allocator(), &.{});
    defer no_alloc.allocator().free(empty_settings);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), empty_settings.len);
}

test "HTTP/2 payload helpers" {
    const frame = Frame{
        .header = .{ .length = 6, .frame_type = .data, .flags = (@as(Flags, .{ .padded = true })).byte(), .stream_id = 1 },
        .payload = &.{ 2, 'o', 'k', 0, 0 },
    };
    const data = try DataPayload.parse(frame);
    try std.testing.expectEqualStrings("ok", data.data);
    try std.testing.expectError(error.InvalidFrameSize, DataPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidStreamId, DataPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 0 },
        .payload = &.{},
    }));

    try std.testing.expectError(error.InvalidStreamId, HeadersPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_id = 0 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidFrameSize, HeadersPayload.parse(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidStreamId, HeadersPayload.parse(.{
        .header = .{ .length = 5, .frame_type = .headers, .flags = (@as(Flags, .{ .priority = true })).byte(), .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 1, 16 },
    }));
    try validateClientPreface(connection_preface ++ "rest");
}

test "HTTP/2 PRIORITY payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try PriorityPayload.write(&encoded, allocator, 5, true, 3, 200);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 5, @intFromEnum(FrameType.priority), 0, 0, 0, 0, 5 }, encoded.items[0..9]);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.priority, frame.header.frame_type);
    const priority = try PriorityPayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 5), priority.stream_id);
    try std.testing.expect(priority.exclusive);
    try std.testing.expectEqual(@as(u31, 3), priority.stream_dependency);
    try std.testing.expectEqual(@as(u8, 200), priority.weight);

    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.write(&encoded, allocator, 0, false, 0, 1));
    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.write(&encoded, allocator, 5, false, 5, 1));
    try std.testing.expectError(error.InvalidFrameSize, PriorityPayload.parse(.{
        .header = .{ .length = 4, .frame_type = .priority, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidStreamId, PriorityPayload.parse(.{
        .header = .{ .length = 5, .frame_type = .priority, .flags = 0, .stream_id = 5 },
        .payload = &.{ 0, 0, 0, 5, 1 },
    }));
}

test "HTTP/2 PRIORITY_UPDATE payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try PriorityUpdatePayload.writePriority(
        &encoded,
        allocator,
        5,
        .{ .urgency = 1, .incremental = true },
    );
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(
        FrameType.priority_update,
        frame.header.frame_type,
    );
    try std.testing.expectEqual(@as(u31, 0), frame.header.stream_id);
    const update = try PriorityUpdatePayload.parse(frame);
    try std.testing.expectEqual(
        @as(u31, 5),
        update.prioritized_stream_id,
    );
    try std.testing.expectEqualStrings("u=1, i", update.field_value);
    try std.testing.expectEqual(
        @as(u3, 1),
        update.priorityValue().urgency,
    );
    try std.testing.expect(update.priorityValue().incremental);

    var no_alloc_update: std.ArrayList(u8) = .empty;
    defer no_alloc_update.deinit(allocator);
    try no_alloc_update.ensureTotalCapacity(allocator, 32);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try PriorityUpdatePayload.write(&no_alloc_update, no_alloc.allocator(), 5, "u=1, i");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_update.items);

    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.write(&encoded, allocator, 0, "u=1"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.write(&encoded, allocator, 1, "u=1\n"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.write(&encoded, allocator, 1, "u=1,"),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 3,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 0, 1 },
        }),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 4,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 0, 0, 0 },
        }),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        PriorityUpdatePayload.parse(.{
            .header = .{
                .length = 4,
                .frame_type = .priority_update,
                .flags = 0,
                .stream_id = 1,
            },
            .payload = &.{ 0, 0, 0, 1 },
        }),
    );
}

test "HTTP/2 PUSH_PROMISE payload helper" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/pushed.css" },
        .{ .name = ":scheme", .value = "https" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try PushPromisePayload.write(&encoded, allocator, 1, 2, block.items, .{ .padding_len = 3 });
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.header.frame_type);
    try std.testing.expect((frame.header.flags & (@as(Flags, .{ .padded = true })).byte()) != 0);
    const promise = try PushPromisePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 1), promise.stream_id);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);
    try std.testing.expectEqual(@as(u8, 3), promise.padding_len);

    const fields = try Hpack.decodeLiteralBlock(allocator, promise.header_block);
    defer Hpack.freeDecodedFields(allocator, fields);
    try std.testing.expectEqualStrings("/pushed.css", fields[1].value);

    var no_alloc_encoded: std.ArrayList(u8) = .empty;
    defer no_alloc_encoded.deinit(allocator);
    try no_alloc_encoded.ensureTotalCapacity(allocator, encoded.items.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try PushPromisePayload.write(&no_alloc_encoded, no_alloc.allocator(), 1, 2, block.items, .{ .padding_len = 3 });
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_encoded.items);

    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.write(&encoded, allocator, 0, 2, block.items, .{}));
    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.write(&encoded, allocator, 1, 0, block.items, .{}));
    try std.testing.expectError(error.InvalidStreamId, PushPromisePayload.parse(.{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrameSize, PushPromisePayload.parse(.{
        .header = .{ .length = 2, .frame_type = .push_promise, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0 },
    }));
}

test "HTTP/2 ORIGIN frame round trips and validates ASCII entries" {
    const allocator = std.testing.allocator;
    const expected = [_][]const u8{
        "https://example.com",
        "https://cdn.example.com:8443",
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(&encoded, allocator, &expected);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.origin, frame.header.frame_type);
    try std.testing.expectEqual(@as(u31, 0), frame.header.stream_id);
    var parsed = try OriginPayload.parse(allocator, frame);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.origins.len);
    try std.testing.expectEqualStrings(expected[0], parsed.origins[0]);
    try std.testing.expectEqualStrings(expected[1], parsed.origins[1]);
    var parse_no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    var parsed_once = try OriginPayload.parse(parse_no_alloc.allocator(), frame);
    defer parsed_once.deinit(parse_no_alloc.allocator());
    try std.testing.expect(!parse_no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(expected[1], parsed_once.origins[1]);
    const origin_encoded = try allocator.dupe(u8, encoded.items);
    defer allocator.free(origin_encoded);
    var no_alloc_origin: std.ArrayList(u8) = .empty;
    defer no_alloc_origin.deinit(allocator);
    try no_alloc_origin.ensureTotalCapacity(allocator, origin_encoded.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try OriginPayload.write(&no_alloc_origin, no_alloc.allocator(), &expected);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, origin_encoded, no_alloc_origin.items);

    var empty: std.ArrayList(u8) = .empty;
    defer empty.deinit(allocator);
    try OriginPayload.write(&empty, allocator, &.{});
    var empty_parsed = try OriginPayload.parse(
        allocator,
        try Frame.parse(empty.items),
    );
    defer empty_parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), empty_parsed.origins.len);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var no_alloc_empty = try OriginPayload.parse(no_alloc.allocator(), try Frame.parse(empty.items));
    defer no_alloc_empty.deinit(no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), no_alloc_empty.origins.len);

    try std.testing.expectError(
        error.InvalidFrameSize,
        OriginPayload.write(&encoded, allocator, &.{"https://bad host"}),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        OriginPayload.parse(allocator, .{
            .header = .{
                .length = 3,
                .frame_type = .origin,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 2, 'x' },
        }),
    );
}

test "HTTP/2 ALTSVC frame validates connection and stream forms" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try AltSvcPayload.write(
        &encoded,
        allocator,
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    const connection_frame = try Frame.parse(encoded.items);
    const connection_alt = try AltSvcPayload.parse(connection_frame);
    try std.testing.expectEqualStrings(
        "https://example.com",
        connection_alt.origin,
    );
    try std.testing.expectEqualStrings(
        "h3=\":443\"; ma=3600",
        connection_alt.field_value,
    );
    const connection_encoded = try allocator.dupe(u8, encoded.items);
    defer allocator.free(connection_encoded);
    var no_alloc_connection: std.ArrayList(u8) = .empty;
    defer no_alloc_connection.deinit(allocator);
    try no_alloc_connection.ensureTotalCapacity(allocator, connection_encoded.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try AltSvcPayload.write(
        &no_alloc_connection,
        no_alloc.allocator(),
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, connection_encoded, no_alloc_connection.items);

    encoded.clearRetainingCapacity();
    try AltSvcPayload.write(
        &encoded,
        allocator,
        1,
        "",
        "h2=\"alt.example.com:443\"",
    );
    const stream_alt = try AltSvcPayload.parse(try Frame.parse(encoded.items));
    try std.testing.expectEqual(@as(usize, 0), stream_alt.origin.len);
    try std.testing.expectEqualStrings(
        "h2=\"alt.example.com:443\"",
        stream_alt.field_value,
    );

    try std.testing.expectError(
        error.InvalidStreamId,
        AltSvcPayload.write(
            &encoded,
            allocator,
            0,
            "",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        AltSvcPayload.write(
            &encoded,
            allocator,
            1,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        AltSvcPayload.parse(.{
            .header = .{
                .length = 3,
                .frame_type = .altsvc,
                .flags = 0,
                .stream_id = 0,
            },
            .payload = &.{ 0, 4, 'x' },
        }),
    );
}

test "HTTP/2 SETTINGS validates RFC value bounds" {
    const allocator = std.testing.allocator;

    var invalid_write: std.ArrayList(u8) = .empty;
    defer invalid_write.deinit(allocator);
    try std.testing.expectError(error.InvalidSetting, writeSettings(&invalid_write, allocator, &.{
        .{ .id = .enable_push, .value = 2 },
    }));

    var invalid_enable_push: std.ArrayList(u8) = .empty;
    defer invalid_enable_push.deinit(allocator);
    try wire.appendInt(&invalid_enable_push, allocator, u16, @intFromEnum(SettingId.enable_push), .big);
    try wire.appendInt(&invalid_enable_push, allocator, u32, 2, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_enable_push.items));

    var invalid_no_rfc7540_priorities: std.ArrayList(u8) = .empty;
    defer invalid_no_rfc7540_priorities.deinit(allocator);
    try wire.appendInt(
        &invalid_no_rfc7540_priorities,
        allocator,
        u16,
        @intFromEnum(SettingId.no_rfc7540_priorities),
        .big,
    );
    try wire.appendInt(
        &invalid_no_rfc7540_priorities,
        allocator,
        u32,
        2,
        .big,
    );
    try std.testing.expectError(
        error.InvalidSetting,
        parseSettings(allocator, invalid_no_rfc7540_priorities.items),
    );

    var invalid_window: std.ArrayList(u8) = .empty;
    defer invalid_window.deinit(allocator);
    try wire.appendInt(&invalid_window, allocator, u16, @intFromEnum(SettingId.initial_window_size), .big);
    try wire.appendInt(&invalid_window, allocator, u32, @as(u32, std.math.maxInt(i31)) + 1, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_window.items));

    var invalid_frame: std.ArrayList(u8) = .empty;
    defer invalid_frame.deinit(allocator);
    try wire.appendInt(&invalid_frame, allocator, u16, @intFromEnum(SettingId.max_frame_size), .big);
    try wire.appendInt(&invalid_frame, allocator, u32, 16_383, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_frame.items));

    var valid: std.ArrayList(u8) = .empty;
    defer valid.deinit(allocator);
    try writeSettings(&valid, allocator, &.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .enable_connect_protocol, .value = 1 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
        .{ .id = .max_frame_size, .value = 16_777_215 },
    });
    const parsed = try parseSettings(allocator, valid.items);
    defer allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 5), parsed.len);

    var invalid_connect_protocol: std.ArrayList(u8) = .empty;
    defer invalid_connect_protocol.deinit(allocator);
    try wire.appendInt(&invalid_connect_protocol, allocator, u16, @intFromEnum(SettingId.enable_connect_protocol), .big);
    try wire.appendInt(&invalid_connect_protocol, allocator, u32, 2, .big);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, invalid_connect_protocol.items));
}

test "HTTP/2 ping and goaway payload helpers" {
    const allocator = std.testing.allocator;

    var ping_bytes: std.ArrayList(u8) = .empty;
    defer ping_bytes.deinit(allocator);
    const ping_data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    try PingPayload.write(&ping_bytes, allocator, ping_data, true);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 8, @intFromEnum(FrameType.ping), 1, 0, 0, 0, 0 }, ping_bytes.items[0..9]);
    const ping_frame = try Frame.parse(ping_bytes.items);
    try std.testing.expectEqual(FrameType.ping, ping_frame.header.frame_type);
    try std.testing.expectEqual(@as(u8, 1), ping_frame.header.flags);
    const ping = try PingPayload.parse(ping_frame);
    try std.testing.expectEqualSlices(u8, &ping_data, &ping.data);
    var ping_storage: [PingPayload.encoded_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        ping_bytes.items,
        PingPayload.writeInto(&ping_storage, ping_data, true),
    );

    var goaway_bytes: std.ArrayList(u8) = .empty;
    defer goaway_bytes.deinit(allocator);
    try GoAwayPayload.write(&goaway_bytes, allocator, 7, .no_error, "bye");
    const goaway_frame = try Frame.parse(goaway_bytes.items);
    const goaway = try GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 7), goaway.last_stream_id);
    try std.testing.expectEqual(ErrorCode.no_error, goaway.error_code);
    try std.testing.expectEqualStrings("bye", goaway.debug_data);
    var goaway_storage: [64]u8 = undefined;
    const direct_goaway = try GoAwayPayload.writeInto(
        &goaway_storage,
        7,
        .no_error,
        "bye",
    );
    try std.testing.expectEqualSlices(
        u8,
        goaway_bytes.items,
        direct_goaway,
    );
    var short_storage: [10]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        GoAwayPayload.writeInto(
            &short_storage,
            7,
            .no_error,
            "bye",
        ),
    );

    var no_alloc_goaway: std.ArrayList(u8) = .empty;
    defer no_alloc_goaway.deinit(allocator);
    try no_alloc_goaway.ensureTotalCapacity(allocator, goaway_bytes.items.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try GoAwayPayload.write(&no_alloc_goaway, no_alloc.allocator(), 7, .no_error, "bye");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, goaway_bytes.items, no_alloc_goaway.items);
}

test "HTTP/2 window update payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try WindowUpdatePayload.write(&encoded, allocator, 3, 1024);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 4, @intFromEnum(FrameType.window_update), 0, 0, 0, 0, 3 }, encoded.items[0..9]);
    const frame = try Frame.parse(encoded.items);
    const update = try WindowUpdatePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 3), update.stream_id);
    try std.testing.expectEqual(@as(u31, 1024), update.increment);
    try std.testing.expectError(error.InvalidFrameSize, WindowUpdatePayload.write(&encoded, allocator, 0, 0));
    var storage: [WindowUpdatePayload.encoded_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        encoded.items,
        try WindowUpdatePayload.writeInto(&storage, 3, 1024),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        WindowUpdatePayload.writeInto(&storage, 0, 0),
    );
}

test "HTTP/2 RST_STREAM payload helper" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try ResetStreamPayload.write(&encoded, allocator, 3, .cancel);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 4, @intFromEnum(FrameType.rst_stream), 0, 0, 0, 0, 3 }, encoded.items[0..9]);
    const frame = try Frame.parse(encoded.items);
    const reset = try ResetStreamPayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 3), reset.stream_id);
    try std.testing.expectEqual(ErrorCode.cancel, reset.error_code);
    try std.testing.expectError(error.InvalidStreamId, ResetStreamPayload.write(&encoded, allocator, 0, .cancel));

    var storage: [ResetStreamPayload.encoded_len]u8 = undefined;
    const direct = try ResetStreamPayload.writeInto(
        &storage,
        3,
        .cancel,
    );
    try std.testing.expectEqualSlices(u8, encoded.items, direct);
}

test "HTTP/2 HPACK static table decode" {
    const allocator = std.testing.allocator;
    // RFC 7541 Appendix C.3: :method GET, :scheme http, :path /,
    // :authority www.example.com.  The literal authority field is accepted but
    // not inserted because this bootstrap decoder has no dynamic table.
    const block = "\x82\x86\x84\x41\x0fwww.example.com";
    const fields = try Hpack.decodeLiteralBlock(allocator, block);
    defer Hpack.freeDecodedFields(allocator, fields);

    try std.testing.expectEqual(@as(usize, 4), fields.len);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("GET", fields[0].value);
    try std.testing.expectEqualStrings(":scheme", fields[1].name);
    try std.testing.expectEqualStrings("http", fields[1].value);
    try std.testing.expectEqualStrings(":authority", fields[3].name);
    try std.testing.expectEqualStrings("www.example.com", fields[3].value);
}

test "HTTP/2 HPACK static-only encode roundtrip" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const fields_in = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/resource" },
        .{ .name = "authorization", .value = "Bearer token", .never_index = true },
        .{ .name = "x-long", .value = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz" },
    };

    try Hpack.encodeLiteralBlock(&encoded, allocator, &fields_in);
    const decoded = try Hpack.decodeLiteralBlock(allocator, encoded.items);
    defer Hpack.freeDecodedFields(allocator, decoded);

    try std.testing.expectEqual(fields_in.len, decoded.len);
    for (fields_in, decoded) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
        try std.testing.expectEqual(expected.never_index, actual.never_index);
    }
}

test "HTTP/2 HPACK static lookup index preserves one-indexed table order" {
    for (Hpack.static_table, 0..) |entry, zero_index| {
        const wire_index: u64 = @intCast(zero_index + 1);
        try std.testing.expectEqual(wire_index, Hpack.findStaticIndex(entry.name, entry.value).?);
        try std.testing.expectEqual(
            Hpack.findStaticNameIndex(entry.name).?,
            (blk: {
                for (Hpack.static_table, 0..) |candidate, first_zero_index| {
                    if (std.mem.eql(u8, candidate.name, entry.name)) {
                        break :blk @as(u64, @intCast(first_zero_index + 1));
                    }
                }
                unreachable;
            }),
        );
    }

    try std.testing.expectEqual(@as(?u64, 2), Hpack.findStaticNameIndex(":method"));
    try std.testing.expectEqual(@as(?u64, 8), Hpack.findStaticNameIndex(":status"));
    try std.testing.expectEqual(@as(?u64, 31), Hpack.findStaticNameIndex("content-type"));
    try std.testing.expectEqual(@as(?u64, 2), Hpack.findStaticIndex(":method", "GET"));
    try std.testing.expectEqual(@as(?u64, 3), Hpack.findStaticIndex(":method", "POST"));
    try std.testing.expectEqual(@as(?u64, 4), Hpack.findStaticIndex(":path", "/"));
    try std.testing.expectEqual(@as(?u64, 7), Hpack.findStaticIndex(":scheme", "https"));
    try std.testing.expectEqual(@as(?u64, 9), Hpack.findStaticIndex(":status", "204"));
    try std.testing.expectEqual(@as(?u64, 16), Hpack.findStaticIndex("accept-encoding", "gzip, deflate"));
    try std.testing.expectEqual(@as(?u64, 19), Hpack.findStaticIndex("accept", ""));
    try std.testing.expectEqual(@as(?u64, 24), Hpack.findStaticIndex("cache-control", ""));
    try std.testing.expectEqual(@as(?u64, 28), Hpack.findStaticIndex("content-length", ""));
    try std.testing.expectEqual(@as(?u64, 31), Hpack.findStaticIndex("content-type", ""));
    try std.testing.expectEqual(@as(?u64, 54), Hpack.findStaticIndex("server", ""));
    try std.testing.expectEqual(@as(?u64, 58), Hpack.findStaticIndex("user-agent", ""));
    try std.testing.expectEqual(@as(?u64, 59), Hpack.findStaticIndex("vary", ""));
    try std.testing.expectEqual(@as(?u64, 19), Hpack.findStaticNameIndex("accept"));
    try std.testing.expectEqual(@as(?u64, 16), Hpack.findStaticNameIndex("accept-encoding"));
    try std.testing.expectEqual(@as(?u64, 54), Hpack.findStaticNameIndex("server"));
    try std.testing.expect(Hpack.findStaticIndex(":status", "418") == null);
    try std.testing.expect(Hpack.findStaticNameIndex("x-not-static") == null);
}

test "HTTP/2 HPACK dynamic table keeps newest-index order without shifts" {
    const allocator = std.testing.allocator;
    var table = Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 80);

    try table.add(allocator, "x-a", "1");
    try table.add(allocator, "x-b", "2");
    try table.add(allocator, "x-c", "3");

    try std.testing.expectEqual(@as(usize, 2), table.entries.items.len);
    try std.testing.expectEqualStrings("x-c", table.get(0).?.name);
    try std.testing.expectEqualStrings("x-b", table.get(1).?.name);
    for (table.entries.items) |entry| {
        const storage = entry.block_storage orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(storage.ptr, entry.name.ptr);
        try std.testing.expectEqual(
            storage.ptr + entry.name.len,
            entry.value.ptr,
        );
        try std.testing.expectEqual(
            storage.len,
            entry.name.len + entry.value.len,
        );
    }
    try std.testing.expectEqual(@as(?u64, Hpack.static_table.len + 1), table.findIndex("x-c", "3"));
    try std.testing.expectEqual(@as(?u64, Hpack.static_table.len + 2), table.findNameIndex("x-b"));
    try std.testing.expect(table.findNameIndex("x-a") == null);
}

test "HTTP/2 HPACK dynamic insertion uses one string allocation" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var table = Hpack.DynamicTable{};
    defer table.deinit(tracked);
    table.setLimit(tracked, 512);

    // Warm all container capacities, then clear only logical state so the next
    // insertion isolates ownership of its name/value bytes.
    for (0..8) |index| {
        var value_buffer: [16]u8 = undefined;
        const value = try std.fmt.bufPrint(
            &value_buffer,
            "value-{d}",
            .{index},
        );
        try table.add(tracked, "x-field", value);
    }
    table.clear(tracked);
    const before = tracking.allocations;
    try table.add(tracked, "x-field", "value");
    try std.testing.expectEqual(before + 1, tracking.allocations);

    const entry = table.get(0).?;
    const storage = entry.block_storage orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(storage.ptr, entry.name.ptr);
    try std.testing.expectEqual(
        storage.ptr + entry.name.len,
        entry.value.ptr,
    );
    try std.testing.expectEqual(
        storage.len,
        entry.name.len + entry.value.len,
    );
}

test "HTTP/2 HPACK decoder omits encoder lookup indexes" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(tracked);
    var output: [1]Hpack.HeaderField = undefined;

    // A raw incremental literal needs only the entry-vector allocation and
    // the entry's contiguous string block. The decoder never performs reverse
    // lookup, so it must not allocate either of the encoder-only hash maps.
    const literal = "\x40\x09x-inbound\x05value";
    const before = tracking.allocations;
    const first = try decoder.decodeBlockInto(tracked, literal, &output);
    defer Hpack.freeDecodedFieldStorages(tracked, first);
    try std.testing.expectEqual(before + 2, tracking.allocations);
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_name.count());
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_exact.count());
    try std.testing.expectEqualStrings("x-inbound", decoder.dynamic_table.get(0).?.name);

    // Wire index 62 is the newest dynamic entry. Reading it remains O(1) from
    // the entry vector and only allocates the application-owned field block.
    const before_indexed = tracking.allocations;
    const indexed = try decoder.decodeBlockInto(tracked, &.{0xbe}, &output);
    defer Hpack.freeDecodedFieldStorages(tracked, indexed);
    try std.testing.expectEqual(before_indexed + 1, tracking.allocations);
    try std.testing.expectEqualStrings("value", indexed[0].value);

    decoder.dynamic_table.setLimit(tracked, 0);
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_name.count());
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.latest_exact.count());
}

test "HTTP/2 HPACK decoder table without lookup indexes is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkHpackDecoderTableWithoutLookupIndexes,
        .{},
    );
}

test "HTTP/2 HPACK contiguous dynamic storage is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkHpackContiguousDynamicStorage,
        .{},
    );
}

test "HTTP/2 HPACK dynamic lookup indexes survive eviction and clear" {
    const allocator = std.testing.allocator;
    var table = Hpack.DynamicTable{};
    defer table.deinit(allocator);
    table.setLimit(allocator, 68);

    try std.testing.expect(table.findNameIndex("x") == null);
    try std.testing.expect(table.findIndex("x", "a") == null);

    try table.add(allocator, "x", "a");
    try table.add(allocator, "x", "b");
    try table.add(allocator, "y", "c");
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 2),
        table.findNameIndex("x"),
    );
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 2),
        table.findIndex("x", "b"),
    );
    try std.testing.expectEqual(@as(?usize, 0), table.latest_name.get("x"));
    try std.testing.expectEqual(@as(?usize, 0), table.latest_exact.get(.{ .name = "x", .value = "b" }));
    try std.testing.expect(table.findIndex("x", "a") == null);

    try table.add(allocator, "z", "d");
    try std.testing.expect(table.findNameIndex("x") == null);
    try std.testing.expect(table.findIndex("x", "b") == null);
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 1),
        table.findIndex("z", "d"),
    );

    try table.add(allocator, "too-large", "012345678901234567890123456789");
    try std.testing.expectEqual(@as(usize, 0), table.entryCount());
    try std.testing.expect(table.findNameIndex("z") == null);
    try std.testing.expect(table.findIndex("z", "d") == null);

    try table.add(allocator, "n", "v");
    try std.testing.expectEqual(
        @as(?u64, Hpack.static_table.len + 1),
        table.findIndex("n", "v"),
    );
}

test "HTTP/2 HPACK never-indexes sensitive fields automatically" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoder.encodeBlock(&encoded, allocator, &.{
        .{ .name = "authorization", .value = "Bearer secret" },
        .{ .name = "cookie", .value = "sid=secret" },
        .{ .name = "set-cookie", .value = "sid=secret; HttpOnly" },
    });

    const decoded = try Hpack.decodeLiteralBlock(allocator, encoded.items);
    defer Hpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    for (decoded) |field| try std.testing.expect(field.never_index);
    try std.testing.expectEqual(@as(usize, 0), encoder.dynamic_table.entries.items.len);

    try std.testing.expect(Hpack.sensitiveHeaderName("Authorization"));
    try std.testing.expect(Hpack.sensitiveHeaderName("proxy-authorization"));
    try std.testing.expect(Hpack.sensitiveHeaderName("cookie"));
    try std.testing.expect(Hpack.sensitiveHeaderName("set-cookie"));
    try std.testing.expect(!Hpack.sensitiveHeaderName("x-token"));
}

test "HTTP/2 HPACK Huffman and dynamic table state" {
    const allocator = std.testing.allocator;

    const huffman = try Hpack.encodeHuffman(allocator, "www.example.com");
    defer allocator.free(huffman);
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huffman);
    try std.testing.expectEqual(huffman.len, try Hpack.huffmanEncodedLen("www.example.com"));
    try std.testing.expectError(
        error.InvalidEncoding,
        Hpack.encodeHuffmanWithLen(
            allocator,
            "www.example.com",
            huffman.len - 1,
        ),
    );
    const decoded_huffman = try Hpack.decodeHuffman(allocator, huffman);
    defer allocator.free(decoded_huffman);
    try std.testing.expectEqualStrings("www.example.com", decoded_huffman);
    try std.testing.expectEqual(decoded_huffman.len, try Hpack.huffmanDecodedLen(huffman));
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const no_alloc_allocator = no_alloc.allocator();
    const no_alloc_decoded = try Hpack.decodeHuffman(no_alloc_allocator, huffman);
    defer no_alloc_allocator.free(no_alloc_decoded);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("www.example.com", no_alloc_decoded);

    var no_alloc_block: std.ArrayList(u8) = .empty;
    defer no_alloc_block.deinit(allocator);
    try no_alloc_block.ensureTotalCapacity(allocator, 96);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const raw_preferred = [_]u8{ 0xff, 0xff, 0xff };
    try Hpack.encodeLiteralBlock(&no_alloc_block, no_alloc.allocator(), &.{
        .{ .name = "accept-encoding", .value = "", .never_index = true },
        .{ .name = "accept-encoding", .value = "ok", .never_index = true },
        .{ .name = "accept-encoding", .value = &raw_preferred, .never_index = true },
    });
    try std.testing.expect(!no_alloc.has_induced_failure);
    const fast_decoded = try Hpack.decodeLiteralBlock(allocator, no_alloc_block.items);
    defer Hpack.freeDecodedFields(allocator, fast_decoded);
    try std.testing.expectEqualStrings("", fast_decoded[0].value);
    try std.testing.expectEqualStrings("ok", fast_decoded[1].value);
    try std.testing.expectEqualSlices(u8, &raw_preferred, fast_decoded[2].value);

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var first_block: std.ArrayList(u8) = .empty;
    defer first_block.deinit(allocator);
    try encoder.encodeBlock(&first_block, allocator, &.{.{ .name = "x-dynamic", .value = "one" }});
    try std.testing.expect((first_block.items[0] & 0x40) != 0);

    var second_block: std.ArrayList(u8) = .empty;
    defer second_block.deinit(allocator);
    try encoder.encodeBlock(&second_block, allocator, &.{.{ .name = "x-dynamic", .value = "one" }});
    try std.testing.expect((second_block.items[0] & 0x80) != 0);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const first_fields = try decoder.decodeBlock(allocator, first_block.items);
    defer Hpack.freeDecodedFields(allocator, first_fields);
    try std.testing.expectEqualStrings("x-dynamic", first_fields[0].name);
    try std.testing.expectEqualStrings("one", first_fields[0].value);

    const second_fields = try decoder.decodeBlock(allocator, second_block.items);
    defer Hpack.freeDecodedFields(allocator, second_fields);
    try std.testing.expectEqualStrings("x-dynamic", second_fields[0].name);
    try std.testing.expectEqualStrings("one", second_fields[0].value);
}

test "HTTP/2 HPACK retained encoder scratch reuses capacity" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);

    const first = try encoder.encodeBlockRetained(
        allocator,
        &.{.{ .name = ":status", .value = "200" }},
    );
    try std.testing.expectEqualSlices(u8, &.{0x88}, first);
    const first_ptr = first.ptr;

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const second = try encoder.encodeBlockRetained(
        failing.allocator(),
        &.{.{ .name = ":status", .value = "204" }},
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(first_ptr, second.ptr);
    try std.testing.expectEqualSlices(u8, &.{0x89}, second);
}

test "HTTP/2 HPACK retained Huffman encode uses only warmed scratch" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    const fields = [_]Hpack.HeaderField{
        .{ .name = "authorization", .value = "compressible-value" },
    };

    const first = try encoder.encodeBlockRetained(allocator, &fields);
    try std.testing.expect((first[2] & 0x80) != 0);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const second = try encoder.encodeBlockRetained(
        no_alloc.allocator(),
        &fields,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, first, second);
}

test "HTTP/2 HPACK encoder clone isolates transactional state" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);

    _ = try encoder.encodeBlockRetained(
        allocator,
        &.{.{ .name = "x-original", .value = "one" }},
    );
    var staged = try encoder.clone(allocator);
    defer staged.deinit(allocator);

    const staged_existing = try staged.encodeBlockRetained(
        allocator,
        &.{.{ .name = "x-original", .value = "one" }},
    );
    try std.testing.expect((staged_existing[0] & 0x80) != 0);
    _ = try staged.encodeBlockRetained(
        allocator,
        &.{.{ .name = "x-staged", .value = "two" }},
    );

    const original_new = try encoder.encodeBlockRetained(
        allocator,
        &.{.{ .name = "x-staged", .value = "two" }},
    );
    try std.testing.expect((original_new[0] & 0x80) == 0);
}

test "HTTP/2 HPACK encoder staging reuses cloned state capacity" {
    const allocator = std.testing.allocator;
    const fields = [_]Hpack.HeaderField{
        .{ .name = "x-first", .value = "one" },
        .{ .name = "x-second", .value = "two" },
    };
    var live = Hpack.Encoder{};
    defer live.deinit(allocator);
    _ = try live.encodeBlockRetained(allocator, &fields);

    var staging = Hpack.Encoder{};
    defer staging.deinit(allocator);
    try staging.copyFromRetainingCapacity(allocator, &live);
    _ = try staging.encodeBlockRetained(allocator, &fields);
    std.mem.swap(Hpack.Encoder, &live, &staging);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try staging.copyFromRetainingCapacity(no_alloc.allocator(), &live);
    const block = try staging.encodeBlockRetained(
        no_alloc.allocator(),
        &fields,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &.{ 0xbf, 0xbe }, block);
}

test "HTTP/2 HPACK decoder writes into caller storage" {
    const allocator = std.testing.allocator;

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{
        .{ .name = "x-dynamic", .value = "one" },
        .{ .name = ":method", .value = "GET" },
    });

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var storage: [2]Hpack.HeaderField = undefined;
    const fields = try decoder.decodeBlockInto(allocator, block.items, &storage);
    defer Hpack.freeDecodedFieldStorages(allocator, fields);
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("x-dynamic", fields[0].name);
    try std.testing.expectEqualStrings("one", fields[0].value);
    try std.testing.expectEqualStrings(":method", fields[1].name);
    try std.testing.expectEqualStrings("GET", fields[1].value);

    var too_small_decoder = Hpack.Decoder{};
    defer too_small_decoder.deinit(allocator);
    var too_small: [1]Hpack.HeaderField = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        too_small_decoder.decodeBlockInto(allocator, block.items, &too_small),
    );
}

test "HTTP/2 HPACK bounded decoder avoids output allocation after limit" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{
        .{ .name = "authorization", .value = "compressible-value" },
    });

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var storage: [1]Hpack.HeaderField = undefined;
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.HeaderListTooLarge,
        decoder.decodeBlockIntoWithLimit(
            no_alloc.allocator(),
            block.items,
            &storage,
            32,
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/2 HPACK oversized block preserves incremental indexing state" {
    const allocator = std.testing.allocator;
    const fields = [_]Hpack.HeaderField{
        .{ .name = "x-indexed", .value = "compressible-value" },
        .{ .name = "x-too-large", .value = "also-compressible-value" },
    };
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &fields);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var storage: [2]Hpack.HeaderField = undefined;
    try std.testing.expectError(
        error.HeaderListTooLarge,
        decoder.decodeBlockIntoWithLimit(
            allocator,
            block.items,
            &storage,
            1,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), decoder.dynamic_table.entryCount());

    block.clearRetainingCapacity();
    try encoder.encodeBlock(&block, allocator, &fields);
    const decoded = try decoder.decodeBlockIntoWithLimit(
        allocator,
        block.items,
        &storage,
        512,
    );
    defer Hpack.freeDecodedFieldStorages(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings("x-indexed", decoded[0].name);
    try std.testing.expectEqualStrings("compressible-value", decoded[0].value);
}

test "HTTP/2 HPACK owned decode uses one allocation and is failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkHpackOwnedDecode,
        .{},
    );
}

test "HTTP/2 HPACK owned decode preserves table state after output limits" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Hpack.HeaderField{
        .{ .name = "x-first", .value = "compressible-value" },
        .{ .name = "x-second", .value = "another-compressible-value" },
    };
    try encoder.encodeBlock(&block, allocator, &fields);
    try std.testing.expectError(
        error.HeaderListTooLarge,
        decoder.decodeBlockOwnedWithLimit(
            allocator,
            block.items,
            8,
            1,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        decoder.dynamic_table.entryCount(),
    );

    block.clearRetainingCapacity();
    try encoder.encodeBlock(&block, allocator, &fields);
    const decoded = try decoder.decodeBlockOwnedWithLimit(
        allocator,
        block.items,
        8,
        1024,
    );
    defer Hpack.freeOwnedFields(allocator, decoded);
    try std.testing.expectEqualStrings("compressible-value", decoded[0].value);
    try std.testing.expectEqualStrings("another-compressible-value", decoded[1].value);
}

test "HTTP/2 HPACK compaction rebinds duplicate lookup keys" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    // Fill the table with repeated names and distinct values, then shrink it
    // far enough to evict at least half the physical entries. Compaction must
    // make every hash-map key borrow from the newest surviving entry.
    for (0..12) |index| {
        var value_storage: [2]u8 = .{
            'a' + @as(u8, @intCast(index)),
            '0' + @as(u8, @intCast(index % 10)),
        };
        encoded.clearRetainingCapacity();
        try encoder.encodeBlock(&encoded, allocator, &.{.{
            .name = "x-repeated",
            .value = &value_storage,
        }});
    }
    encoder.setMaxDynamicTableSize(allocator, 160);

    // A second shrink frees the entry that supplied the pre-compaction key.
    // The next encode performs lookups and would read freed memory if the key
    // had not been rebound during rebuildIndexes.
    encoder.setMaxDynamicTableSize(allocator, 0);
    encoded.clearRetainingCapacity();
    try encoder.encodeBlock(&encoded, allocator, &.{.{
        .name = "x-repeated",
        .value = "after-clear",
    }});
    try std.testing.expectEqual(@as(usize, 0), encoder.dynamic_table.used);
}

test "HTTP/2 HPACK owned decoder distinguishes truncation from field limit" {
    const allocator = std.testing.allocator;
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);

    try std.testing.expectError(
        error.BufferTooShort,
        decoder.decodeBlockOwnedWithLimit(
            allocator,
            &.{0xff},
            8,
            1024,
        ),
    );
    try std.testing.expect(decoder.lastDecodeWasCompressionError());

    const block = [_]u8{ 0x82, 0x84 };
    try std.testing.expectError(
        error.BufferTooShort,
        decoder.decodeBlockOwnedWithLimit(
            allocator,
            &block,
            1,
            1024,
        ),
    );
    try std.testing.expect(!decoder.lastDecodeWasCompressionError());
}

test "HTTP/2 HPACK owned decode scratch fallback is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkHpackOwnedDecodeScratchFallback,
        .{},
    );
}

test "HTTP/2 HPACK incremental name index does not set never-indexed" {
    const allocator = std.testing.allocator;
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var storage: [1]Hpack.HeaderField = undefined;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    // Populate dynamic index 62, then reuse its name with a different value.
    // The resulting 01xxxxxx representation has bit 0x10 set as part of that
    // 6-bit index, not as the Never Indexed marker used by 0001xxxx.
    try encoder.encodeBlock(&block, allocator, &.{.{
        .name = "x-dynamic-name",
        .value = "first-value",
    }});
    const first = try decoder.decodeBlockInto(allocator, block.items, &storage);
    Hpack.freeDecodedFieldStorages(allocator, first);

    block.clearRetainingCapacity();
    try encoder.encodeBlock(&block, allocator, &.{.{
        .name = "x-dynamic-name",
        .value = "second-value",
    }});
    try std.testing.expectEqual(@as(u8, 0x7e), block.items[0]);
    const second = try decoder.decodeBlockInto(allocator, block.items, &storage);
    defer Hpack.freeDecodedFieldStorages(allocator, second);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expect(!second[0].never_index);
    try std.testing.expectEqualStrings("x-dynamic-name", second[0].name);
    try std.testing.expectEqualStrings("second-value", second[0].value);
}

test "HTTP/2 HPACK encoder emits table size updates and avoids low-value indexing" {
    const allocator = std.testing.allocator;

    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    encoder.setMaxDynamicTableSize(allocator, 128);
    encoder.setMaxDynamicTableSize(allocator, 512);

    var sized_block: std.ArrayList(u8) = .empty;
    defer sized_block.deinit(allocator);
    try encoder.encodeBlock(&sized_block, allocator, &.{.{ .name = "x-small", .value = "one" }});

    // RFC 7541 requires dynamic table-size updates before any header field when
    // the peer's SETTINGS_HEADER_TABLE_SIZE changes.  h2/hyper emits both the
    // temporary minimum and final value if the limit was lowered then raised
    // before the next HEADERS frame.
    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0x61, 0x3f, 0xe1, 0x03 }, sized_block.items[0..5]);
    try std.testing.expectEqual(@as(usize, 512), encoder.last_emitted_dynamic_table_size);

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const sized_fields = try decoder.decodeBlock(allocator, sized_block.items);
    defer Hpack.freeDecodedFields(allocator, sized_fields);
    try std.testing.expectEqual(@as(usize, 512), decoder.dynamic_table.size_limit);
    try std.testing.expectEqualStrings("x-small", sized_fields[0].name);

    var indexed_again: std.ArrayList(u8) = .empty;
    defer indexed_again.deinit(allocator);
    try encoder.encodeBlock(&indexed_again, allocator, &.{.{ .name = "x-small", .value = "one" }});
    try std.testing.expect((indexed_again.items[0] & 0x80) != 0);

    var small_table_encoder = Hpack.Encoder{};
    defer small_table_encoder.deinit(allocator);
    small_table_encoder.setMaxDynamicTableSize(allocator, 128);
    var large_block: std.ArrayList(u8) = .empty;
    defer large_block.deinit(allocator);
    try small_table_encoder.encodeBlock(&large_block, allocator, &.{.{ .name = "x-large", .value = "01234567890123456789012345678901234567890123456789012345678901234567890123456789" }});
    try std.testing.expectEqual(@as(usize, 0), small_table_encoder.dynamic_table.entries.items.len);
    try std.testing.expect((large_block.items[2] & 0xc0) == 0x00);

    var content_length_block: std.ArrayList(u8) = .empty;
    defer content_length_block.deinit(allocator);
    try encoder.encodeBlock(&content_length_block, allocator, &.{.{ .name = "content-length", .value = "1234" }});
    try std.testing.expectEqualSlices(u8, &.{ 0x0f, 0x0d }, content_length_block.items[0..2]);
    try std.testing.expect(encoder.dynamic_table.findNameIndex("content-length") == null);
}

test "HTTP/2 HPACK accepts legal size updates and rejects bad dynamic use" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.HpackDynamicTableUnsupported, Hpack.decodeLiteralBlock(allocator, &.{0xfe}));

    // A dynamic table-size update is legal only at the beginning of a header
    // block.  Go's x/net/http2 and Rust h2 both accept such updates before the
    // first representation; keep the stateless helper compatible with peers
    // that emit a size update followed only by static-indexed fields.
    const sized_static = try Hpack.decodeLiteralBlock(allocator, &.{ 0x20, 0x82 });
    defer Hpack.freeDecodedFields(allocator, sized_static);
    try std.testing.expectEqual(@as(usize, 1), sized_static.len);
    try std.testing.expectEqualStrings(":method", sized_static[0].name);
    try std.testing.expectEqualStrings("GET", sized_static[0].value);
    try std.testing.expectError(error.InvalidEncoding, Hpack.decodeLiteralBlock(allocator, &.{ 0x82, 0x20 }));

    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    decoder.setMaxDynamicTableSize(allocator, 32);
    try std.testing.expectError(error.InvalidEncoding, decoder.decodeBlock(allocator, &.{ 0x3f, 0x02 }));
}
