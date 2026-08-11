const std = @import("std");
const Qpack = @import("mod.zig");
const static_table = @import("static_table.zig");

test "HTTP/3 QPACK static name references and literal fallback" {
    const allocator = std.testing.allocator;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const huffman = try Qpack.encodeHuffman(allocator, "www.example.com");
    defer allocator.free(huffman);
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huffman);
    try std.testing.expectEqual(huffman.len, try Qpack.huffmanEncodedLen("www.example.com"));
    const decoded_huffman = try Qpack.decodeHuffman(allocator, huffman);
    defer allocator.free(decoded_huffman);
    try std.testing.expectEqualStrings("www.example.com", decoded_huffman);

    const fields = [_]Qpack.HeaderField{
        .{ .name = "content-type", .value = "application/problem+json" },
        .{ .name = "x-custom", .value = "value" },
    };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, block.items[0..2]);
    try std.testing.expectEqual(@as(u8, 0x5f), block.items[2]); // static name ref with extended index, content-type

    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings("content-type", decoded[0].name);
    try std.testing.expectEqualStrings("application/problem+json", decoded[0].value);
    try std.testing.expectEqualStrings("x-custom", decoded[1].name);
    try std.testing.expectEqualStrings("value", decoded[1].value);
    try std.testing.expectEqualStrings(":status", Qpack.staticEntry(25).?.name);
    try std.testing.expectEqualStrings("200", Qpack.staticEntry(25).?.value);

    block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":StatuS", .value = "200" },
        .{ .name = "X-Proto", .value = "QUIC" },
    });
    const lower_decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, lower_decoded);
    try std.testing.expectEqualStrings(":status", lower_decoded[0].name);
    try std.testing.expectEqualStrings("200", lower_decoded[0].value);
    try std.testing.expectEqualStrings("x-proto", lower_decoded[1].name);
    try std.testing.expectEqualStrings("QUIC", lower_decoded[1].value);

    block.clearRetainingCapacity();
    try block.ensureTotalCapacity(allocator, 8);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Qpack.encodeLiteralBlock(&block, no_alloc.allocator(), &.{.{ .name = "x-empty", .value = "" }});
    try std.testing.expect(!no_alloc.has_induced_failure);
    const empty_decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, empty_decoded);
    try std.testing.expectEqualStrings("x-empty", empty_decoded[0].name);
    try std.testing.expectEqualStrings("", empty_decoded[0].value);

    block.clearRetainingCapacity();
    try block.ensureTotalCapacity(allocator, 16);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Qpack.encodeLiteralBlock(&block, no_alloc.allocator(), &.{.{ .name = "x-short", .value = "ok" }});
    try std.testing.expect(!no_alloc.has_induced_failure);
    const short_decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, short_decoded);
    try std.testing.expectEqualStrings("x-short", short_decoded[0].name);
    try std.testing.expectEqualStrings("ok", short_decoded[0].value);

    block.clearRetainingCapacity();
    try block.ensureTotalCapacity(allocator, 32);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const raw_preferred = [_]u8{ 0xff, 0xff, 0xff };
    try Qpack.encodeLiteralBlock(&block, no_alloc.allocator(), &.{.{ .name = "x-raw", .value = &raw_preferred }});
    try std.testing.expect(!no_alloc.has_induced_failure);
    const raw_decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, raw_decoded);
    try std.testing.expectEqualStrings("x-raw", raw_decoded[0].name);
    try std.testing.expectEqualSlices(u8, &raw_preferred, raw_decoded[0].value);
}

test "HTTP/3 QPACK static table name index preserves RFC lookup order" {
    for (static_table.entries, 0..) |entry, index| {
        const match = static_table.findMatch(entry.name, entry.value) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(match.full_match);
        try std.testing.expectEqual(@as(u64, @intCast(index)), match.index);
    }

    var first_indexes = std.StaticStringMap(u64).initComptime(.{
        .{ ":status", 24 },
        .{ "access-control-allow-headers", 33 },
        .{ "content-type", 44 },
    });
    inline for (.{ ":status", "access-control-allow-headers", "content-type" }) |name| {
        const match = static_table.findMatch(name, "not in the static table") orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(!match.full_match);
        // Name-only matches must keep RFC table-order tie breaking because the
        // encoded index becomes observable wire output.
        try std.testing.expectEqual(first_indexes.get(name).?, match.index);
    }
    try std.testing.expectEqual(@as(?u64, 24), Qpack.findStaticName(":status"));
    try std.testing.expectEqual(
        @as(?u64, 33),
        Qpack.findStaticName("access-control-allow-headers"),
    );
    try std.testing.expect(Qpack.findStaticName("x-not-static") == null);
}

test "HTTP/3 QPACK static table fast-matches pseudo headers" {
    const pseudo = [_]struct {
        name: []const u8,
        value: []const u8,
        index: u64,
    }{
        .{ .name = ":method", .value = "GET", .index = 17 },
        .{ .name = ":method", .value = "POST", .index = 20 },
        .{ .name = ":scheme", .value = "https", .index = 23 },
        .{ .name = ":status", .value = "200", .index = 25 },
        .{ .name = ":status", .value = "204", .index = 64 },
        .{ .name = ":path", .value = "/", .index = 1 },
        .{ .name = ":authority", .value = "", .index = 0 },
    };
    for (pseudo) |field| {
        const match = static_table.findMatch(field.name, field.value) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(match.full_match);
        try std.testing.expectEqual(field.index, match.index);
    }

    const unmatched_status = static_table.findMatch(":status", "201") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!unmatched_status.full_match);
    try std.testing.expectEqual(@as(u64, 24), unmatched_status.index);
    try std.testing.expectEqual(@as(?u64, 15), static_table.findName(":method"));
    try std.testing.expectEqual(@as(?u64, 22), static_table.findName(":scheme"));
}

test "HTTP/3 QPACK static table fast-matches common request headers" {
    const common = [_]struct {
        name: []const u8,
        value: []const u8,
        index: u64,
    }{
        .{ .name = "content-length", .value = "0", .index = 4 },
        .{ .name = "accept", .value = "*/*", .index = 29 },
        .{ .name = "accept", .value = "application/dns-message", .index = 30 },
        .{ .name = "accept-encoding", .value = "gzip, deflate, br", .index = 31 },
    };
    for (common) |field| {
        const match = static_table.findMatch(field.name, field.value) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(match.full_match);
        try std.testing.expectEqual(field.index, match.index);
    }

    const unmatched_length = static_table.findMatch("content-length", "42") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!unmatched_length.full_match);
    try std.testing.expectEqual(@as(u64, 4), unmatched_length.index);
    try std.testing.expectEqual(@as(?u64, 29), Qpack.findStaticName("accept"));
    try std.testing.expectEqual(@as(?u64, 31), Qpack.findStaticName("accept-encoding"));
}

test "HTTP/3 QPACK static table fast-matches common response headers" {
    const common = [_]struct {
        name: []const u8,
        value: []const u8,
        index: u64,
    }{
        .{ .name = "cache-control", .value = "max-age=0", .index = 36 },
        .{ .name = "cache-control", .value = "no-cache", .index = 39 },
        .{ .name = "cache-control", .value = "no-store", .index = 40 },
        .{ .name = "content-type", .value = "application/json", .index = 46 },
        .{ .name = "content-type", .value = "text/html; charset=utf-8", .index = 52 },
        .{ .name = "content-type", .value = "text/plain", .index = 53 },
        .{ .name = "content-encoding", .value = "br", .index = 42 },
        .{ .name = "content-encoding", .value = "gzip", .index = 43 },
        .{ .name = "vary", .value = "accept-encoding", .index = 59 },
        .{ .name = "vary", .value = "origin", .index = 60 },
        .{ .name = "x-content-type-options", .value = "nosniff", .index = 61 },
    };
    for (common) |field| {
        const match = static_table.findMatch(field.name, field.value) orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(match.full_match);
        try std.testing.expectEqual(field.index, match.index);
    }

    const unmatched_type = static_table.findMatch("content-type", "application/problem+json") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(!unmatched_type.full_match);
    try std.testing.expectEqual(@as(u64, 44), unmatched_type.index);
    try std.testing.expectEqual(@as(?u64, 36), Qpack.findStaticName("cache-control"));
    try std.testing.expectEqual(@as(?u64, 44), Qpack.findStaticName("content-type"));
    try std.testing.expectEqual(@as(?u64, 42), Qpack.findStaticName("content-encoding"));
    try std.testing.expectEqual(@as(?u64, 59), Qpack.findStaticName("vary"));
    try std.testing.expectEqual(@as(?u64, 61), Qpack.findStaticName("x-content-type-options"));
}

test "HTTP/3 QPACK dynamic table applies RFC 9204 Appendix B encoder stream" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 220);
    defer table.deinit();

    const appendix_b2 = [_]u8{
        0x3f, 0xbd, 0x01, // Set Dynamic Table Capacity = 220.
        0xc0, 0x0f, // Insert static name index 0, value length 15.
        'w',  'w',
        'w',  '.',
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  '.',
        'c',  'o',
        'm',
        0xc1, 0x0c, // Insert static name index 1, value length 12.
        '/',  's',
        'a',  'm',
        'p',  'l',
        'e',  '/',
        'p',  'a',
        't',  'h',
    };
    try std.testing.expectEqual(
        appendix_b2.len,
        try Qpack.applyEncoderInstructions(&table, allocator, &appendix_b2),
    );
    try std.testing.expectEqual(@as(usize, 220), table.capacity);
    try std.testing.expectEqual(@as(usize, 106), table.current_size);
    try std.testing.expectEqual(@as(u64, 2), table.insert_count);
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expectEqualStrings(":authority", table.absolute(0).?.name);
    try std.testing.expectEqualStrings("www.example.com", table.absolute(0).?.value);
    try std.testing.expectEqualStrings(":path", table.relative(0).?.name);
    try std.testing.expectEqualStrings("/sample/path", table.relative(0).?.value);

    const appendix_b3 = [_]u8{
        0x4a, // Insert literal name, length 10.
        'c',
        'u',
        's',
        't',
        'o',
        'm',
        '-',
        'k',
        'e',
        'y',
        0x0c, // Value length 12.
        'c',
        'u',
        's',
        't',
        'o',
        'm',
        '-',
        'v',
        'a',
        'l',
        'u',
        'e',
    };
    try std.testing.expectEqual(
        appendix_b3.len,
        try Qpack.applyEncoderInstructions(&table, allocator, &appendix_b3),
    );
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);
    try std.testing.expectEqual(@as(usize, 160), table.current_size);
    try std.testing.expectEqualStrings("custom-key", table.relative(0).?.name);
    try std.testing.expectEqualStrings("custom-value", table.relative(0).?.value);

    // Duplicate index zero must stabilize the source before insertion because
    // the insertion can evict an older entry.
    try std.testing.expectEqual(
        @as(usize, 1),
        try Qpack.applyEncoderInstructions(&table, allocator, &.{0x00}),
    );
    try std.testing.expectEqual(@as(u64, 4), table.insert_count);
    try std.testing.expectEqual(@as(usize, 214), table.current_size);
    try std.testing.expectEqualStrings("custom-key", table.absolute(3).?.name);
}

test "HTTP/3 QPACK dynamic match prefers exact then newest name before limit" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);

    _ = try table.insert("x-match", "old-exact");
    _ = try table.insert("x-match", "name-only");
    _ = try table.insert("x-other", "unrelated");
    _ = try table.insert("x-match", "new-exact");

    const exact = table.findMatchBefore(
        "x-match",
        "new-exact",
        table.insert_count,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(exact.full_match);
    try std.testing.expectEqual(@as(u64, 3), exact.absolute_index);
    try std.testing.expectEqual(
        @as(?u64, 3),
        table.findExact("x-match", "new-exact"),
    );

    const name_only = table.findMatchBefore(
        "x-match",
        "missing",
        table.insert_count,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!name_only.full_match);
    try std.testing.expectEqual(@as(u64, 3), name_only.absolute_index);
    try std.testing.expect(
        table.findExact("x-match", "missing") == null,
    );

    // Excluding absolute index 3 must reveal the newest eligible name match,
    // while an older exact value still outranks that newer name-only entry.
    const limited_name = table.findMatchBefore(
        "x-match",
        "missing",
        3,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!limited_name.full_match);
    try std.testing.expectEqual(@as(u64, 1), limited_name.absolute_index);
    const limited_exact = table.findMatchBefore(
        "x-match",
        "old-exact",
        3,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(limited_exact.full_match);
    try std.testing.expectEqual(@as(u64, 0), limited_exact.absolute_index);
}

test "HTTP/3 QPACK lookup indexes remain coherent across eviction and clear" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 68);
    defer table.deinit();
    try table.setCapacity(68);

    _ = try table.insert("x", "a");
    _ = try table.insert("x", "b");
    _ = try table.insert("y", "c");

    // Inserting y evicts only the older x entry. Removing that entry must not
    // discard the index for the newer entry sharing its name.
    try std.testing.expectEqual(@as(?u64, 1), table.findName("x"));
    try std.testing.expectEqual(@as(?u64, 1), table.findExact("x", "b"));
    try std.testing.expect(table.findExact("x", "a") == null);
    const name_only = table.findMatchBefore(
        "x",
        "missing",
        table.insert_count,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!name_only.full_match);
    try std.testing.expectEqual(@as(u64, 1), name_only.absolute_index);

    _ = try table.insert("z", "d");
    try std.testing.expect(table.findName("x") == null);
    try std.testing.expect(table.findExact("x", "b") == null);
    try std.testing.expectEqual(@as(?u64, 3), table.findExact("z", "d"));

    // RFC 9204 requires an over-capacity insertion to empty the dynamic
    // table. Retained hash-map allocations must not retain logical entries.
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        table.insert("too-large", "0123456789012345678901234567890123456789"),
    );
    try std.testing.expectEqual(@as(usize, 0), table.entryCount());
    try std.testing.expect(table.findName("z") == null);
    try std.testing.expect(table.findExact("z", "d") == null);

    _ = try table.insert("n", "v");
    try std.testing.expectEqual(@as(?u64, 4), table.findExact("n", "v"));
}

fn checkDynamicQpackIndexAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var table = Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-first", "one");
    _ = try table.insert("x-second", "two");
    try std.testing.expectEqual(
        @as(?u64, 0),
        table.findExact("x-first", "one"),
    );
    try std.testing.expectEqual(
        @as(?u64, 1),
        table.findName("x-second"),
    );
}

test "HTTP/3 QPACK lookup indexes are allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackIndexAllocationFailure,
        .{},
    );
}

fn checkLargeDynamicQpackEncodeAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var table = Qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    _ = try table.insert("x-large-block", "repeated");
    var fields: [65]Qpack.HeaderField = undefined;
    for (&fields) |*field| {
        field.* = .{ .name = "x-large-block", .value = "repeated" };
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var references: std.ArrayList(u64) = .empty;
    defer references.deinit(allocator);
    try Qpack.encodeDynamicBlockKnownReceived(
        &encoded,
        allocator,
        &fields,
        table,
        table.insert_count,
        &references,
    );
    try std.testing.expectEqual(@as(usize, 1), references.items.len);
}

test "HTTP/3 QPACK large encode scratch is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkLargeDynamicQpackEncodeAllocationFailure,
        .{},
    );
}

test "HTTP/3 QPACK dynamic table evicts by capacity and rejects invalid instructions" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 96);
    defer table.deinit();
    try table.setCapacity(96);

    try std.testing.expectEqual(@as(u64, 0), try table.insert("a", "1"));
    try std.testing.expectEqual(@as(u64, 1), try table.insert("b", "2"));
    try std.testing.expectEqual(@as(u64, 2), try table.insert("c", "3"));
    try std.testing.expectEqual(@as(usize, 2), table.entryCount());
    try std.testing.expect(table.absolute(0) == null);
    try std.testing.expectEqualStrings("b", table.absolute(1).?.name);
    try std.testing.expectEqualStrings("c", table.relative(0).?.name);

    try table.setCapacity(34);
    try std.testing.expectEqual(@as(usize, 1), table.entryCount());
    try std.testing.expectEqualStrings("c", table.relative(0).?.name);
    try std.testing.expectError(error.QpackEncoderStreamError, table.setCapacity(97));

    // An entry larger than the current capacity is a connection error and
    // clears the decoder's table per RFC 9204 Section 3.2.2.
    try std.testing.expectError(error.QpackEncoderStreamError, table.insert("too", "large"));
    try std.testing.expectEqual(@as(usize, 0), table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), table.current_size);
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);

    try std.testing.expectError(
        error.QpackEncoderStreamError,
        Qpack.applyEncoderInstructions(&table, allocator, &.{0x80}),
    );
}

test "HTTP/3 QPACK encoder instructions round trip Huffman strings" {
    const allocator = std.testing.allocator;
    const instructions = [_]Qpack.EncoderInstruction{
        .{ .set_capacity = 4096 },
        .{ .insert_name_reference = .{
            .static = true,
            .name_index = 95,
            .value = "netz/1.0",
        } },
        .{ .insert_literal = .{
            .name = "x-long-custom-header-name",
            .value = "compressible compressible compressible",
        } },
        .{ .duplicate = 127 },
    };

    for (instructions) |instruction| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try Qpack.writeEncoderInstruction(&encoded, allocator, instruction);
        var decoded = try Qpack.decodeEncoderInstruction(allocator, encoded.items);
        defer decoded.deinit(allocator);
        try std.testing.expectEqual(encoded.items.len, decoded.consumed);

        switch (instruction) {
            .set_capacity => |expected| try std.testing.expectEqual(expected, decoded.instruction.set_capacity),
            .duplicate => |expected| try std.testing.expectEqual(expected, decoded.instruction.duplicate),
            .insert_name_reference => |expected| {
                const actual = decoded.instruction.insert_name_reference;
                try std.testing.expectEqual(expected.static, actual.static);
                try std.testing.expectEqual(expected.name_index, actual.name_index);
                try std.testing.expectEqualStrings(expected.value, actual.value);
            },
            .insert_literal => |expected| {
                const actual = decoded.instruction.insert_literal;
                try std.testing.expectEqualStrings(expected.name, actual.name);
                try std.testing.expectEqualStrings(expected.value, actual.value);
            },
        }
    }
}

test "HTTP/3 QPACK Required Insert Count wraps per RFC 9204" {
    try std.testing.expectEqual(@as(u64, 0), try Qpack.encodeRequiredInsertCount(0, 3));
    try std.testing.expectEqual(@as(u64, 3), try Qpack.encodeRequiredInsertCount(2, 6));
    try std.testing.expectEqual(@as(u64, 9), try Qpack.decodeRequiredInsertCount(4, 3, 10));
    try std.testing.expectEqual(@as(u64, 2), try Qpack.decodeRequiredInsertCount(3, 6, 2));
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.encodeRequiredInsertCount(1, 0),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(7, 3, 10),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(1, 0, 0),
    );
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeRequiredInsertCount(
            1,
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        ),
    );
}

test "HTTP/3 QPACK field section prefix detects blocking without allocation" {
    const allocator = std.testing.allocator;
    var encoder_table = Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-prefix", "blocked");

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = "x-prefix", .value = "blocked" },
    }, encoder_table);

    var decoder_table = Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    // The prefix parser intentionally accepts no allocator, keeping this
    // receive-scheduling probe independent of heap availability.
    const prefix = try Qpack.decodeFieldSectionPrefix(
        block.items,
        decoder_table,
    );
    try std.testing.expectEqual(@as(u64, 1), prefix.required_insert_count);
    try std.testing.expect(prefix.required_insert_count > decoder_table.insert_count);
    try std.testing.expectEqual(@as(u64, 1), prefix.base);
    try std.testing.expect(prefix.consumed >= 2);
}

test "HTTP/3 QPACK dynamic block decodes RFC 9204 Appendix B post-base fields" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 220);
    defer table.deinit();
    try std.testing.expectEqual(
        @as(usize, 34),
        try Qpack.applyEncoderInstructions(&table, allocator, &.{
            0x3f, 0xbd, 0x01,
            0xc0, 0x0f, 'w',
            'w',  'w',  '.',
            'e',  'x',  'a',
            'm',  'p',  'l',
            'e',  '.',  'c',
            'o',  'm',  0xc1,
            0x0c, '/',  's',
            'a',  'm',  'p',
            'l',  'e',  '/',
            'p',  'a',  't',
            'h',
        }),
    );

    // RFC 9204 Appendix B.2, stream 4:
    // Encoded RIC=3 => Required Insert Count=2, S=1/DeltaBase=1 => Base=0.
    const appendix_b_field_section = [_]u8{ 0x03, 0x81, 0x10, 0x11 };
    var decoded = try Qpack.decodeDynamicBlock(allocator, &appendix_b_field_section, table);
    defer Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.required_insert_count);
    try std.testing.expectEqual(@as(u64, 0), decoded.base);
    try std.testing.expectEqual(@as(usize, 2), decoded.fields.len);
    try std.testing.expectEqualStrings(":authority", decoded.fields[0].name);
    try std.testing.expectEqualStrings("www.example.com", decoded.fields[0].value);
    try std.testing.expectEqualStrings(":path", decoded.fields[1].name);
    try std.testing.expectEqualStrings("/sample/path", decoded.fields[1].value);
}

test "HTTP/3 QPACK dynamic block round trips and reduces wire size" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-service-version", "2026.08.09-release-candidate");
    _ = try table.insert("x-region", "cn-north-1");

    const fields = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-service-version", .value = "2026.08.09-release-candidate" },
        .{ .name = "x-region", .value = "cn-north-2" },
        .{ .name = "authorization", .value = "secret", .never_indexed = true },
    };
    var dynamic: std.ArrayList(u8) = .empty;
    defer dynamic.deinit(allocator);
    try Qpack.encodeDynamicBlock(&dynamic, allocator, &fields, table);

    var literal: std.ArrayList(u8) = .empty;
    defer literal.deinit(allocator);
    try Qpack.encodeLiteralBlock(&literal, allocator, &fields);
    try std.testing.expect(dynamic.items.len < literal.items.len);

    var decoded = try Qpack.decodeDynamicBlock(allocator, dynamic.items, table);
    defer Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(fields.len, decoded.fields.len);
    for (fields, decoded.fields) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
        try std.testing.expectEqual(expected.never_indexed, actual.never_indexed);
    }
}

test "HTTP/3 QPACK dynamic block distinguishes blocked and evicted references" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 96);
    defer table.deinit();
    try table.setCapacity(96);
    _ = try table.insert("a", "1");

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Qpack.encodeDynamicBlock(&encoded, allocator, &.{
        .{ .name = "a", .value = "1" },
    }, table);

    var behind = Qpack.DynamicTable.init(allocator, 96);
    defer behind.deinit();
    try behind.setCapacity(96);
    try std.testing.expectError(
        error.QpackBlocked,
        Qpack.decodeDynamicBlock(allocator, encoded.items, behind),
    );

    _ = try table.insert("b", "2");
    _ = try table.insert("c", "3"); // Evicts absolute index zero.
    try std.testing.expect(table.absolute(0) == null);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        Qpack.decodeDynamicBlock(allocator, encoded.items, table),
    );
}

test "HTTP/3 QPACK decoder instructions round trip and reject zero increment" {
    const allocator = std.testing.allocator;
    const instructions = [_]Qpack.DecoderInstruction{
        .{ .section_acknowledgment = 1337 },
        .{ .stream_cancellation = 1024 },
        .{ .insert_count_increment = 65 },
    };
    for (instructions) |instruction| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try Qpack.writeDecoderInstruction(&encoded, allocator, instruction);
        const decoded = try Qpack.decodeDecoderInstruction(encoded.items);
        try std.testing.expectEqual(encoded.items.len, decoded.consumed);
        switch (instruction) {
            .section_acknowledgment => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.section_acknowledgment,
            ),
            .stream_cancellation => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.stream_cancellation,
            ),
            .insert_count_increment => |expected| try std.testing.expectEqual(
                expected,
                decoded.instruction.insert_count_increment,
            ),
        }
    }
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        Qpack.decodeDecoderInstruction(&.{0x00}),
    );
    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        Qpack.writeDecoderInstruction(&invalid, allocator, .{ .insert_count_increment = 0 }),
    );
}

fn checkQpackDynamicDecodeAllocationFailure(allocator: std.mem.Allocator) !void {
    var table = Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-name", "x-value");

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Qpack.encodeDynamicBlock(&encoded, allocator, &.{
        .{ .name = "x-name", .value = "x-value" },
        .{ .name = "x-name", .value = "different" },
        .{ .name = "x-literal", .value = "materialized" },
    }, table);
    var decoded = try Qpack.decodeDynamicBlock(allocator, encoded.items, table);
    Qpack.freeDynamicBlock(allocator, &decoded);
}

test "HTTP/3 QPACK dynamic decode is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackDynamicDecodeAllocationFailure,
        .{},
    );
}
