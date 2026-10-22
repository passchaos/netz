const std = @import("std");
const quic = @import("../../quic/mod.zig");
const capsule_mod = @import("../capsule.zig");
const Capsule = capsule_mod.Capsule;

fn flow(index: usize, value: u64) Capsule {
    return switch (index) {
        0 => .{ .max_data = value },
        1 => .{ .max_streams_bidi = value },
        2 => .{ .max_streams_uni = value },
        3 => .{ .data_blocked = value },
        4 => .{ .streams_blocked_bidi = value },
        5 => .{ .streams_blocked_uni = value },
        else => unreachable,
    };
}

test "WebTransport flow capsules match independent fixed wire vectors" {
    const endings = [_]u8{ 0x3d, 0x3f, 0x40, 0x41, 0x43, 0x44 };
    for (endings, 0..) |ending, index| {
        const expected = [_]u8{ 0x99, 0x0b, 0x4d, ending, 1, 42 };
        var output: [32]u8 = undefined;
        const value = flow(index, 42);
        try std.testing.expectEqualSlices(u8, &expected, try value.writeInto(&output));
        const parsed = try Capsule.parse(&expected);
        try std.testing.expectEqual(@as(usize, expected.len), parsed.consumed);
        try std.testing.expectEqualDeep(value, parsed.capsule);
    }
}

test "WebTransport flow capsules round trip every QUIC varint boundary" {
    const values = [_]u64{ 0, 63, 64, 16383, 16384, (@as(u64, 1) << 30) - 1, @as(u64, 1) << 30, quic.varint.max_value };
    for (0..6) |index| for (values) |value| {
        const original = flow(index, value);
        var output: [32]u8 = undefined;
        const encoded = try original.writeInto(&output);
        try std.testing.expectEqual(try original.encodedLen(), encoded.len);
        const parsed = try Capsule.parse(encoded);
        try std.testing.expectEqualDeep(original, parsed.capsule);
        var allocating: std.ArrayList(u8) = .empty;
        defer allocating.deinit(std.testing.allocator);
        try original.write(&allocating, std.testing.allocator);
        try std.testing.expectEqualSlices(u8, encoded, allocating.items);
    };
}

test "WebTransport flow capsules reject incomplete values and trailing fields" {
    const endings = [_]u8{ 0x3d, 0x3f, 0x40, 0x41, 0x43, 0x44 };
    for (endings) |ending| {
        const empty = [_]u8{ 0x99, 0x0b, 0x4d, ending, 0 };
        const partial = [_]u8{ 0x99, 0x0b, 0x4d, ending, 1, 0x40 };
        const trailing = [_]u8{ 0x99, 0x0b, 0x4d, ending, 2, 1, 2 };
        try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&empty));
        try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&partial));
        try std.testing.expectError(error.InvalidCapsule, Capsule.parse(&trailing));
    }
}

test "WebTransport capsule writers preflight complete caller output" {
    var output = [_]u8{0xaa} ** 32;
    const original = output;
    const value = Capsule{ .max_data = quic.varint.max_value };
    try std.testing.expectError(error.BufferTooShort, value.writeInto(output[0 .. (try value.encodedLen()) - 1]));
    try std.testing.expectEqualSlices(u8, &original, &output);
    try std.testing.expectError(error.VarIntTooLarge, (Capsule{ .max_data = @as(u64, quic.varint.max_value) + 1 }).writeInto(&output));
    try std.testing.expectEqualSlices(u8, &original, &output);
    var list = try std.ArrayList(u8).initCapacity(std.testing.allocator, 4);
    defer list.deinit(std.testing.allocator);
    list.appendSliceAssumeCapacity("keep");
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, value.write(&list, failing.allocator()));
    try std.testing.expectEqualStrings("keep", list.items);
}

test "WebTransport caller-buffer capsule encoding preserves existing capsule kinds" {
    const values = [_]Capsule{
        .{ .datagram = "data" },
        .{ .close_session = .{ .code = 77, .reason = "done" } },
        .{ .drain_session = {} },
        .{ .unknown = .{ .capsule_type = 0x21, .payload = "extension" } },
    };
    for (values) |value| {
        var output: [64]u8 = undefined;
        const encoded = try value.writeInto(&output);
        const parsed = try Capsule.parse(encoded);
        try std.testing.expectEqualDeep(value, parsed.capsule);
    }
}
