//! Bounded `application/x-www-form-urlencoded` encoding and decoding.
//!
//! Encoding writes into caller storage. Decoding owns one contiguous byte
//! buffer for all decoded names and values, so a form with many fields does
//! not allocate once per component.

const std = @import("std");

pub const Pair = struct {
    name: []const u8,
    value: []const u8,
};

pub const Error = std.mem.Allocator.Error || error{
    BufferTooSmall,
    InvalidPercentEncoding,
    TooManyPairs,
    ComponentTooLarge,
    BodyTooLarge,
    Overflow,
};

pub const DecodeOptions = struct {
    max_pairs: usize = 64,
    max_component_bytes: usize = 64 * 1024,
    max_body_bytes: usize = 1024 * 1024,
};

pub const Decoded = struct {
    allocator: std.mem.Allocator,
    pairs: []Pair,
    storage: []u8,

    pub fn deinit(self: *Decoded) void {
        self.allocator.free(self.pairs);
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn encodedByteLen(byte: u8) usize {
    if (byte == ' ') return 1;
    return if (isUnreserved(byte)) 1 else 3;
}

/// Exact encoded length, including `&` separators.
pub fn encodedLen(pairs: []const Pair) Error!usize {
    var total: usize = 0;
    for (pairs, 0..) |pair, index| {
        if (index != 0) total = try std.math.add(usize, total, 1);
        for (pair.name) |byte| {
            total = try std.math.add(usize, total, encodedByteLen(byte));
        }
        total = try std.math.add(usize, total, 1);
        for (pair.value) |byte| {
            total = try std.math.add(usize, total, encodedByteLen(byte));
        }
    }
    return total;
}

/// Encode into `out` and return the written slice.
pub fn encode(out: []u8, pairs: []const Pair) Error![]const u8 {
    const required = try encodedLen(pairs);
    if (out.len < required) return error.BufferTooSmall;

    const hex = "0123456789ABCDEF";
    var cursor: usize = 0;
    for (pairs, 0..) |pair, index| {
        if (index != 0) {
            out[cursor] = '&';
            cursor += 1;
        }
        for (pair.name) |byte| {
            cursor = encodeByte(out, cursor, byte, hex);
        }
        out[cursor] = '=';
        cursor += 1;
        for (pair.value) |byte| {
            cursor = encodeByte(out, cursor, byte, hex);
        }
    }
    return out[0..cursor];
}

fn encodeByte(out: []u8, cursor: usize, byte: u8, hex: *const [16]u8) usize {
    if (byte == ' ') {
        out[cursor] = '+';
        return cursor + 1;
    }
    if (isUnreserved(byte)) {
        out[cursor] = byte;
        return cursor + 1;
    }
    out[cursor] = '%';
    out[cursor + 1] = hex[byte >> 4];
    out[cursor + 2] = hex[byte & 0x0f];
    return cursor + 3;
}

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    pairs: []const Pair,
) Error![]u8 {
    const required = try encodedLen(pairs);
    const buffer = try allocator.alloc(u8, required);
    errdefer allocator.free(buffer);
    _ = try encode(buffer, pairs);
    return buffer;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

/// Decode one name or value component into `out`.
pub fn decodeComponentInto(out: []u8, input: []const u8) Error![]const u8 {
    var written: usize = 0;
    var index: usize = 0;
    while (index < input.len) {
        const byte = input[index];
        if (byte == '+') {
            if (written == out.len) return error.BufferTooSmall;
            out[written] = ' ';
            written += 1;
            index += 1;
            continue;
        }
        if (byte == '%') {
            if (index + 2 >= input.len) return error.InvalidPercentEncoding;
            const high = hexValue(input[index + 1]) orelse
                return error.InvalidPercentEncoding;
            const low = hexValue(input[index + 2]) orelse
                return error.InvalidPercentEncoding;
            if (written == out.len) return error.BufferTooSmall;
            out[written] = (high << 4) | low;
            written += 1;
            index += 3;
            continue;
        }
        if (written == out.len) return error.BufferTooSmall;
        out[written] = byte;
        written += 1;
        index += 1;
    }
    return out[0..written];
}

/// Decode an entire form. Empty segments between `&` separators are skipped.
/// A segment without `=` is a name with an empty value.
pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
    options: DecodeOptions,
) Error!Decoded {
    if (input.len > options.max_body_bytes) return error.BodyTooLarge;

    var pair_count: usize = 0;
    var counter = std.mem.splitScalar(u8, input, '&');
    while (counter.next()) |segment| {
        if (segment.len == 0) continue;
        pair_count += 1;
        if (pair_count > options.max_pairs) return error.TooManyPairs;
    }

    const pairs = try allocator.alloc(Pair, pair_count);
    errdefer allocator.free(pairs);
    const storage = try allocator.alloc(u8, input.len);
    errdefer allocator.free(storage);

    var pair_index: usize = 0;
    var cursor: usize = 0;
    var iterator = std.mem.splitScalar(u8, input, '&');
    while (iterator.next()) |segment| {
        if (segment.len == 0) continue;
        const equals = std.mem.indexOfScalar(u8, segment, '=') orelse
            segment.len;
        const raw_name = segment[0..equals];
        const raw_value = if (equals < segment.len)
            segment[equals + 1 ..]
        else
            "";

        const name = try decodeComponentInto(storage[cursor..], raw_name);
        if (name.len > options.max_component_bytes) {
            return error.ComponentTooLarge;
        }
        cursor += name.len;

        const value = try decodeComponentInto(storage[cursor..], raw_value);
        if (value.len > options.max_component_bytes) {
            return error.ComponentTooLarge;
        }
        cursor += value.len;

        pairs[pair_index] = .{ .name = name, .value = value };
        pair_index += 1;
    }

    return .{
        .allocator = allocator,
        .pairs = pairs,
        .storage = storage,
    };
}

test "form encoding round trips reserved and non-ASCII bytes" {
    const allocator = std.testing.allocator;
    const pairs = [_]Pair{
        .{ .name = "name", .value = "a b" },
        .{ .name = "plus", .value = "+&=%" },
        .{ .name = "unicode", .value = "你 好" },
        .{ .name = "empty", .value = "" },
    };

    const encoded = try encodeAlloc(allocator, &pairs);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(
        "name=a+b&plus=%2B%26%3D%25&unicode=%E4%BD%A0+%E5%A5%BD&empty=",
        encoded,
    );

    var decoded = try decodeAlloc(allocator, encoded, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, pairs.len), decoded.pairs.len);
    for (pairs, decoded.pairs) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
    }
}

test "form encoding rejects a short output buffer" {
    var buffer: [2]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        encode(&buffer, &.{.{ .name = "a", .value = "b" }}),
    );
}

test "form decoding skips empty segments and accepts a missing equals" {
    const allocator = std.testing.allocator;
    var decoded = try decodeAlloc(
        allocator,
        "a=1&&b&=x",
        .{},
    );
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 3), decoded.pairs.len);
    try std.testing.expectEqualStrings("a", decoded.pairs[0].name);
    try std.testing.expectEqualStrings("1", decoded.pairs[0].value);
    try std.testing.expectEqualStrings("b", decoded.pairs[1].name);
    try std.testing.expectEqualStrings("", decoded.pairs[1].value);
    try std.testing.expectEqualStrings("", decoded.pairs[2].name);
    try std.testing.expectEqualStrings("x", decoded.pairs[2].value);
}

test "form decoding rejects malformed percent escapes and limits" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidPercentEncoding,
        decodeAlloc(allocator, "a=%", .{}),
    );
    try std.testing.expectError(
        error.InvalidPercentEncoding,
        decodeAlloc(allocator, "a=%GG", .{}),
    );
    try std.testing.expectError(
        error.TooManyPairs,
        decodeAlloc(allocator, "a=1&b=2", .{ .max_pairs = 1 }),
    );
    try std.testing.expectError(
        error.BodyTooLarge,
        decodeAlloc(allocator, "a=1", .{ .max_body_bytes = 1 }),
    );
}
