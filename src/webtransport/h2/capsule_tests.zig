const std = @import("std");
const mod = @import("capsule.zig");
const Capsule = mod.Capsule;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 capsules match independent stream and reset wire vectors" {
    const cases = [_]struct { capsule: Capsule, bytes: []const u8 }{
        .{ .capsule = .{ .stream = .{ .id = 4, .data = "abc" } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3c, 4, 4, 'a', 'b', 'c' } },
        .{ .capsule = .{ .stream = .{ .id = 4, .data = "abc", .fin = true } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3b, 4, 4, 'a', 'b', 'c' } },
        .{ .capsule = .{ .reset_stream = .{ .id = 4, .code = 200, .reliable_size = 129 } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x39, 5, 4, 0x40, 0xc8, 0x40, 0x81 } },
        .{ .capsule = .{ .stop_sending = .{ .id = 4, .code = 200 } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3a, 3, 4, 0x40, 0xc8 } },
        .{ .capsule = .{ .max_stream_data = .{ .id = 4, .limit = 129 } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3e, 3, 4, 0x40, 0x81 } },
        .{ .capsule = .{ .stream_data_blocked = .{ .id = 4, .limit = 129 } }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x42, 3, 4, 0x40, 0x81 } },
    };
    for (cases) |case| {
        var out: [64]u8 = undefined;
        try std.testing.expectEqualSlices(u8, case.bytes, try case.capsule.writeInto(&out));
        const parsed = try Capsule.parse(case.bytes);
        try std.testing.expectEqualDeep(case.capsule, parsed.capsule);
        try std.testing.expectEqual(case.bytes.len, parsed.consumed);
        var allocating: std.ArrayList(u8) = .empty;
        defer allocating.deinit(allocator);
        try case.capsule.write(&allocating, allocator);
        try std.testing.expectEqualSlices(u8, case.bytes, allocating.items);
    }
}

test "WebTransport HTTP2 capsule errors distinguish incomplete envelopes from malformed payloads" {
    for ([_]u8{ 0x39, 0x3a, 0x3b, 0x3c, 0x3e, 0x42 }) |kind| {
        const incomplete = [_]u8{ 0x99, 0x0b, 0x4d, kind, 1 };
        const empty = [_]u8{ 0x99, 0x0b, 0x4d, kind, 0 };
        try std.testing.expectError(error.BufferTooShort, Capsule.parse(&incomplete));
        try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&empty));
    }
    try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&.{ 0x99, 0x0b, 0x4d, 0x3a, 3, 0, 1, 0 }));
    try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&.{ 0x99, 0x0b, 0x4d, 0x3e, 3, 0, 1, 0 }));
    const too_large_code = [_]u8{ 0x99, 0x0b, 0x4d, 0x3a, 9, 0, 0xc0, 0, 0, 1, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&too_large_code));
}

test "WebTransport HTTP2 capsule writers retain caller storage on invalid input and OOM" {
    var bytes = [_]u8{0xaa} ** 64;
    const original = bytes;
    const valid = Capsule{ .reset_stream = .{ .id = 4, .code = 1, .reliable_size = 0 } };
    try std.testing.expectError(error.BufferTooShort, valid.writeInto(bytes[0..3]));
    try std.testing.expectEqualSlices(u8, &original, &bytes);
    try std.testing.expectError(error.InvalidCapsule, (Capsule{ .padding = "bad" }).writeInto(&bytes));
    try std.testing.expectError(error.InvalidCapsule, (Capsule{ .unknown = .{ .capsule_type = mod.CapsuleType.stream, .payload = "raw" } }).writeInto(&bytes));
    try std.testing.expectEqualSlices(u8, &original, &bytes);
    var list = try std.ArrayList(u8).initCapacity(allocator, 4);
    defer list.deinit(allocator);
    list.appendSliceAssumeCapacity("keep");
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, valid.write(&list, failing.allocator()));
    try std.testing.expectEqualStrings("keep", list.items);
}

test "WebTransport HTTP2 capsule stream identifiers and application errors retain all wire bits" {
    const values = [_]u62{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, std.math.maxInt(u62) };
    for (values) |id| {
        const cases = [_]Capsule{
            .{ .stream = .{ .id = id, .data = &.{}, .fin = true } },
            .{ .reset_stream = .{ .id = id, .code = std.math.maxInt(u32), .reliable_size = id } },
            .{ .max_stream_data = .{ .id = id, .limit = id } },
        };
        for (cases) |case| {
            var bytes: [64]u8 = undefined;
            const encoded = try case.writeInto(&bytes);
            try std.testing.expectEqualDeep(case, (try Capsule.parse(encoded)).capsule);
        }
    }
}

test "WebTransport HTTP2 common capsule kinds retain standard DATAGRAM CLOSE and flow encoding" {
    const cases = [_]Capsule{
        .{ .datagram = "data" },        .{ .close_session = .{ .code = 77, .reason = "done" } },           .drain_session,
        .{ .padding = &.{ 0, 0, 0 } },  .{ .max_data = 129 },                                              .{ .max_streams_bidi = 7 },
        .{ .max_streams_uni = 8 },      .{ .data_blocked = 9 },                                            .{ .streams_blocked_bidi = 10 },
        .{ .streams_blocked_uni = 11 }, .{ .unknown = .{ .capsule_type = 0x21, .payload = "extension" } },
    };
    for (cases) |case| {
        var bytes: [128]u8 = undefined;
        const encoded = try case.writeInto(&bytes);
        try std.testing.expectEqualDeep(case, (try Capsule.parse(encoded)).capsule);
    }
}
