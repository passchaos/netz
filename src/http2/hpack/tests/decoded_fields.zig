const std = @import("std");
const Hpack = @import("../../mod.zig").Hpack;

// RFC 7541 C.4.1's Huffman encoding of www.example.com, used for
// independently encoded names/values rather than a paired encoder oracle.
const huffman_string = "\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
const literal = "\x00" ++ huffman_string ++ huffman_string;
const inserted = "\x40" ++ huffman_string ++ huffman_string;
const dynamic_name = "\x0f\x2f" ++ huffman_string;
const indexed = "\xbe";

test "HTTP/2 HPACK discard preserves dynamic state and malformed input errors" {
    const allocator = std.testing.allocator;
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try decoder.discardBlock(allocator, inserted);
    const fields = try decoder.decodeBlockOwnedWithLimit(allocator, indexed, 1, 4096);
    defer Hpack.freeOwnedFields(allocator, fields);
    try std.testing.expectEqualStrings("www.example.com", fields[0].value);
    try std.testing.expectError(error.InvalidEncoding, decoder.discardBlock(allocator, inserted ++ "\x80"));
    try std.testing.expect(decoder.lastDecodeWasCompressionError());
    try std.testing.expectError(error.BufferTooShort, decoder.discardBlock(allocator, inserted ++ "\x40"));
    try std.testing.expect(decoder.lastDecodeWasCompressionError());
    try decoder.discardBlock(allocator, "\x20");
    try std.testing.expectEqual(@as(usize, 0), decoder.dynamic_table.used);
}

fn discardLargeEntry(allocator: std.mem.Allocator) !void {
    var encoder = Hpack.Encoder{};
    defer encoder.deinit(allocator);
    encoder.setMaxDynamicTableSize(allocator, 16 * 1024);
    var decoder = Hpack.Decoder{ .max_dynamic_table_size = 16 * 1024 };
    defer decoder.deinit(allocator);
    const block = try encoder.encodeBlockRetained(allocator, &.{.{ .name = "large", .value = "a" ** 6000 }});
    try decoder.discardBlock(allocator, block);
    const fields = try decoder.decodeBlockOwnedWithLimit(allocator, indexed, 1, 16 * 1024);
    defer Hpack.freeOwnedFields(allocator, fields);
    try std.testing.expectEqualStrings("large", fields[0].name);
    try std.testing.expectEqualStrings("a" ** 6000, fields[0].value);
}

test "HTTP/2 HPACK discard releases large dynamic-entry scratch on all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, discardLargeEntry, .{});
}

fn decodeAllocationLifecycle(allocator: std.mem.Allocator, standalone: bool) !void {
    const block = inserted ++ dynamic_name ++ indexed ++ literal ** 16;
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const fields = if (standalone)
        try Hpack.decodeLiteralBlock(allocator, block)
    else
        try decoder.decodeBlock(allocator, block);
    defer Hpack.freeDecodedFields(allocator, fields);
    try std.testing.expectEqual(@as(usize, 19), fields.len);
    for (fields) |field| {
        try std.testing.expectEqualStrings("www.example.com", field.name);
        try std.testing.expectEqualStrings("www.example.com", field.value);
    }
}

test "HTTP/2 HPACK decoded fields release all partial allocations" {
    for ([_]bool{ false, true }) |standalone| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeAllocationLifecycle, .{standalone});
    }
}

fn decodeDynamicFieldLifecycle(allocator: std.mem.Allocator, name_only: bool) !void {
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try decoder.dynamic_table.add(allocator, "www.example.com", "www.example.com");
    // An indexed field must own its copy even when the first output-array
    // allocation fails. Repetition also crosses output growth boundaries.
    const fields = try decoder.decodeBlock(allocator, if (name_only) dynamic_name else indexed ** 17);
    defer Hpack.freeDecodedFields(allocator, fields);
    try std.testing.expectEqual(@as(usize, if (name_only) 1 else 17), fields.len);
    for (fields) |field| {
        try std.testing.expectEqualStrings("www.example.com", field.name);
        try std.testing.expectEqualStrings("www.example.com", field.value);
    }
}

test "HTTP/2 HPACK decoded dynamic fields release copies on output growth failure" {
    for ([_]bool{ false, true }) |name_only| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeDynamicFieldLifecycle, .{name_only});
    }
}

test "HTTP/2 HPACK truncated literal releases its decoded name" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |standalone| {
        var decoder = Hpack.Decoder{};
        defer decoder.deinit(allocator);
        const result = if (standalone)
            Hpack.decodeLiteralBlock(allocator, "\x00" ++ huffman_string)
        else
            decoder.decodeBlock(allocator, "\x00" ++ huffman_string);
        try std.testing.expectError(error.BufferTooShort, result);
    }
}

test "HTTP/2 HPACK decoded field cleanup covers every literal and index truncation" {
    const allocator = std.testing.allocator;
    const block = inserted ++ dynamic_name ++ indexed ++ literal;
    for ([_]bool{ false, true }) |standalone| {
        for (0..block.len) |length| {
            var decoder = Hpack.Decoder{};
            defer decoder.deinit(allocator);
            const result = if (standalone)
                Hpack.decodeLiteralBlock(allocator, block[0..length])
            else
                decoder.decodeBlock(allocator, block[0..length]);
            if (result) |fields| {
                // A prefix ending at a field boundary is a complete block.
                Hpack.freeDecodedFields(allocator, fields);
            } else |err| try std.testing.expectEqual(error.BufferTooShort, err);
        }
    }
}

test "HTTP/2 HPACK decoded field cleanup preserves independent dynamic table storage" {
    const allocator = std.testing.allocator;
    var decoder = Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try std.testing.expectError(error.BufferTooShort, decoder.decodeBlock(allocator, inserted ++ "\x0f\x2f"));
    try std.testing.expectEqual(@as(usize, 1), decoder.dynamic_table.entries.items.len - decoder.dynamic_table.head);
    const entry = decoder.dynamic_table.entries.items[decoder.dynamic_table.head];
    try std.testing.expectEqualStrings("www.example.com", entry.name);
    try std.testing.expectEqualStrings("www.example.com", entry.value);
    try std.testing.expectEqual(@as(usize, 62), decoder.dynamic_table.used);
}
