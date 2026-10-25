//! Tests for RFC 9218 priority values and complete field-section parsing.
const std = @import("std");
const priority = @import("../priority.zig");
const Priority = priority.Priority;
const isAsciiFieldValue = priority.isAsciiFieldValue;

test "priority parameters parse and serialize across HTTP versions" {
    const parsed = Priority.parse("u=1, foo=bar, i=?1");
    try std.testing.expectEqual(@as(u3, 1), parsed.urgency);
    try std.testing.expect(parsed.incremental);

    var field_buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings(
        "u=1, i",
        parsed.serialize(&field_buf),
    );
    try std.testing.expectEqual(
        @as(u3, 3),
        Priority.parse("u=9, i=?0").urgency,
    );
    try std.testing.expectEqualStrings(
        "",
        (Priority{}).serialize(&field_buf),
    );
}

test "priority field values permit ASCII Dictionary OWS and reject other controls" {
    try std.testing.expect(isAsciiFieldValue(""));
    try std.testing.expect(isAsciiFieldValue("u=0, i"));
    try std.testing.expect(isAsciiFieldValue("u=0,\ti"));
    try std.testing.expect(!isAsciiFieldValue("u=0\n"));
    try std.testing.expect(!isAsciiFieldValue(&.{0xff}));
    try std.testing.expect(!isAsciiFieldValue(&.{0}));
    for ([_][]const u8{ "\ti", "u=\t1", "custom=\"a\tb\"", "custom=(1\t2)" }) |value| {
        try std.testing.expectError(error.InvalidPriority, Priority.parseStrict(value));
    }
}

test "strict priority parsing rejects malformed dictionaries" {
    const parsed = try Priority.parseStrict(
        "u=1, i, custom=(token \"ok\");p=?1",
    );
    try std.testing.expectEqual(@as(u3, 1), parsed.urgency);
    try std.testing.expect(parsed.incremental);
    const parameterized = try Priority.parseStrict("u=2;source=client, i");
    try std.testing.expectEqual(@as(u3, 2), parameterized.urgency);
    try std.testing.expect(parameterized.incremental);
    const duplicate = try Priority.parseStrict("u=1, u=9, i, i=?0");
    try std.testing.expectEqual(@as(u3, 3), duplicate.urgency);
    try std.testing.expect(!duplicate.incremental);
    const inner_list = try Priority.parseStrict("i=(?1)");
    try std.testing.expect(!inner_list.incremental);
    _ = try Priority.parseStrict("custom=:AQI=:");
    try std.testing.expectError(
        error.InvalidPriority,
        Priority.parseStrict("u=1,"),
    );
    try std.testing.expectError(
        error.InvalidPriority,
        Priority.parseStrict("=1"),
    );
    try std.testing.expectError(
        error.InvalidPriority,
        Priority.parseStrict("u=\"unterminated"),
    );
    try std.testing.expectError(
        error.InvalidPriority,
        Priority.parseStrict("custom=:A=:"),
    );
}

test "priority structured dictionaries isolate extensions and use final typed member values" {
    const Case = struct { value: []const u8, expected: Priority };
    const cases = [_]Case{
        .{ .value = "custom=\"noise, i, tail\", u=2", .expected = .{ .urgency = 2 } },
        .{ .value = "custom=(\"noise, i, tail\" ?1);p=\"u=0\", u=2", .expected = .{ .urgency = 2 } },
        .{ .value = "u=1;note=\"noise, i, tail\"", .expected = .{ .urgency = 1 } },
        .{ .value = "u=0, u=9, i, i=token", .expected = .{} },
        .{ .value = "u=1, i, u=(0), i=(?1)", .expected = .{} },
        .{ .value = "u=01, i=?1", .expected = .{ .urgency = 1, .incremental = true } },
        .{ .value = "u=-0", .expected = .{ .urgency = 0 } },
        .{ .value = "u=000000000000007", .expected = .{ .urgency = 7 } },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.expected, try Priority.parseStrict(case.value));
        try std.testing.expectEqual(case.expected, Priority.parse(case.value));
    }
    try std.testing.expectEqual(Priority{}, Priority.parse("u=0, custom=\"unterminated"));
}

test "priority repeated fields form one Dictionary with transactional invalidation" {
    const vectors = @import("test_vectors.zig");
    const Field = struct { name: []const u8, value: []const u8 };
    for (vectors.field_sections) |case| {
        var fields: [10]Field = undefined;
        var count: usize = 0;
        var combined: std.ArrayList(u8) = .empty;
        defer combined.deinit(std.testing.allocator);
        for (case.values, 0..) |value, index| {
            // Case-insensitive matching and intervening unrelated fields.
            fields[count] = .{ .name = if (index % 2 == 0) "Priority" else "priority", .value = value };
            count += 1;
            fields[count] = .{ .name = "unrelated", .value = "i, u=0" };
            count += 1;
            if (index != 0) try combined.appendSlice(std.testing.allocator, ", ");
            try combined.appendSlice(std.testing.allocator, value);
        }
        const expected = Priority{ .urgency = case.urgency, .incremental = case.incremental };
        try std.testing.expectEqual(expected, Priority.parseFields(fields[0..count]));
        try std.testing.expectEqual(Priority.parse(combined.items), Priority.parseFields(fields[0..count]));
    }
    try std.testing.expectEqual(Priority{}, Priority.parseFields(&[_]Field{}));
}
