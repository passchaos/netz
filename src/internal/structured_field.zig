//! Small RFC 8941 Structured Field helpers shared by protocol modules.
//!
//! This is intentionally not a complete value model.  Callers that only need a
//! specific field type can validate the surrounding syntax without allocating or
//! accepting HTTP-list fallbacks that would be invalid for Structured Fields.

const std = @import("std");

pub const Error = error{InvalidStructuredField};

/// Borrowed, validated RFC 9651 String content. Escapes stay in the source;
/// comparisons and caller-buffer decoding use its actual string value.
pub const String = struct {
    raw: []const u8,

    pub fn decodedLen(self: String) usize {
        var count: usize = 0;
        var cursor: usize = 0;
        while (cursor < self.raw.len) : (count += 1) {
            if (self.raw[cursor] == '\\') cursor += 1;
            cursor += 1;
        }
        return count;
    }

    pub fn eql(self: String, value: []const u8) bool {
        var cursor: usize = 0;
        var index: usize = 0;
        while (cursor < self.raw.len) {
            if (self.raw[cursor] == '\\') cursor += 1;
            if (index == value.len or self.raw[cursor] != value[index]) return false;
            cursor += 1;
            index += 1;
        }
        return index == value.len;
    }

    pub fn eqlString(self: String, other: String) bool {
        var left: usize = 0;
        var right: usize = 0;
        while (left < self.raw.len and right < other.raw.len) {
            if (self.raw[left] == '\\') left += 1;
            if (other.raw[right] == '\\') right += 1;
            if (self.raw[left] != other.raw[right]) return false;
            left += 1;
            right += 1;
        }
        return left == self.raw.len and right == other.raw.len;
    }

    pub fn decodeInto(self: String, output: []u8) error{BufferTooSmall}![]u8 {
        const length = self.decodedLen();
        if (output.len < length) return error.BufferTooSmall;
        var cursor: usize = 0;
        var index: usize = 0;
        while (cursor < self.raw.len) {
            if (self.raw[cursor] == '\\') cursor += 1;
            output[index] = self.raw[cursor];
            cursor += 1;
            index += 1;
        }
        return output[0..length];
    }
};

pub fn parseString(value: []const u8, cursor: *usize) Error!String {
    if (cursor.* >= value.len or value[cursor.*] != '"') return error.InvalidStructuredField;
    const first = cursor.* + 1;
    try consumeString(value, cursor);
    return .{ .raw = value[first .. cursor.* - 1] };
}

pub fn parseBooleanItem(value: []const u8) Error!bool {
    var cursor: usize = 0;
    skipOptionalWhitespace(value, &cursor);
    if (cursor + 2 > value.len or value[cursor] != '?') {
        return error.InvalidStructuredField;
    }
    const result = switch (value[cursor + 1]) {
        '0' => false,
        '1' => true,
        else => return error.InvalidStructuredField,
    };
    cursor += 2;
    try consumeParameters(value, &cursor);
    skipOptionalWhitespace(value, &cursor);
    if (cursor != value.len) return error.InvalidStructuredField;
    return result;
}

pub fn skipOptionalWhitespace(value: []const u8, cursor: *usize) void {
    while (cursor.* < value.len and
        (value[cursor.*] == ' ' or value[cursor.*] == '\t'))
    {
        cursor.* += 1;
    }
}

pub fn consumeParameters(value: []const u8, cursor: *usize) Error!void {
    while (cursor.* < value.len and value[cursor.*] == ';') {
        cursor.* += 1;
        while (cursor.* < value.len and value[cursor.*] == ' ') {
            cursor.* += 1;
        }
        try consumeKey(value, cursor);
        if (cursor.* < value.len and value[cursor.*] == '=') {
            cursor.* += 1;
            try consumeBareItem(value, cursor);
        }
    }
}

fn consumeKey(value: []const u8, cursor: *usize) Error!void {
    if (cursor.* >= value.len or !isKeyStart(value[cursor.*])) {
        return error.InvalidStructuredField;
    }
    cursor.* += 1;
    while (cursor.* < value.len and isKeyChar(value[cursor.*])) {
        cursor.* += 1;
    }
}

fn isKeyStart(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or byte == '*';
}

fn isKeyChar(byte: u8) bool {
    return isKeyStart(byte) or
        (byte >= '0' and byte <= '9') or
        byte == '_' or
        byte == '-' or
        byte == '.';
}

fn consumeBareItem(value: []const u8, cursor: *usize) Error!void {
    if (cursor.* >= value.len) return error.InvalidStructuredField;
    return switch (value[cursor.*]) {
        '"' => consumeString(value, cursor),
        ':' => consumeByteSequence(value, cursor),
        '?' => consumeBoolean(value, cursor),
        '-', '0'...'9' => consumeNumber(value, cursor),
        '@' => consumeDate(value, cursor),
        '%' => consumeDisplayString(value, cursor),
        'A'...'Z', 'a'...'z', '*' => consumeToken(value, cursor),
        else => error.InvalidStructuredField,
    };
}

fn consumeString(value: []const u8, cursor: *usize) Error!void {
    cursor.* += 1;
    while (cursor.* < value.len) {
        const byte = value[cursor.*];
        cursor.* += 1;
        if (byte == '"') return;
        if (byte == '\\') {
            if (cursor.* >= value.len) return error.InvalidStructuredField;
            const escaped = value[cursor.*];
            if (escaped != '"' and escaped != '\\') {
                return error.InvalidStructuredField;
            }
            cursor.* += 1;
        } else if (byte < 0x20 or byte > 0x7e) {
            return error.InvalidStructuredField;
        }
    }
    return error.InvalidStructuredField;
}

fn consumeByteSequence(value: []const u8, cursor: *usize) Error!void {
    cursor.* += 1;
    const content_start = cursor.*;
    while (cursor.* < value.len and value[cursor.*] != ':') {
        if (!isBase64(value[cursor.*])) return error.InvalidStructuredField;
        cursor.* += 1;
    }
    if (cursor.* >= value.len) return error.InvalidStructuredField;
    const content = value[content_start..cursor.*];
    cursor.* += 1;

    var padding: usize = 0;
    while (padding < content.len and
        content[content.len - 1 - padding] == '=') : (padding += 1)
    {}
    if (padding > 2) return error.InvalidStructuredField;
    for (content[0 .. content.len - padding]) |byte| {
        if (byte == '=') return error.InvalidStructuredField;
    }
    const unpadded_len = content.len - padding;
    if (unpadded_len % 4 == 1) return error.InvalidStructuredField;
    if (padding != 0 and content.len % 4 != 0) {
        return error.InvalidStructuredField;
    }
}

fn consumeBoolean(value: []const u8, cursor: *usize) Error!void {
    if (cursor.* + 1 >= value.len or
        (value[cursor.* + 1] != '0' and value[cursor.* + 1] != '1'))
    {
        return error.InvalidStructuredField;
    }
    cursor.* += 2;
}

fn consumeNumber(value: []const u8, cursor: *usize) Error!void {
    if (value[cursor.*] == '-') cursor.* += 1;
    const integer_start = cursor.*;
    while (cursor.* < value.len and
        std.ascii.isDigit(value[cursor.*])) : (cursor.* += 1)
    {}
    const integer_len = cursor.* - integer_start;
    if (integer_len == 0 or integer_len > 15) return error.InvalidStructuredField;

    if (cursor.* < value.len and value[cursor.*] == '.') {
        if (integer_len > 12) return error.InvalidStructuredField;
        cursor.* += 1;
        const fraction_start = cursor.*;
        while (cursor.* < value.len and
            std.ascii.isDigit(value[cursor.*])) : (cursor.* += 1)
        {}
        const fraction_len = cursor.* - fraction_start;
        if (fraction_len == 0 or fraction_len > 3) {
            return error.InvalidStructuredField;
        }
    }
}

fn consumeDate(value: []const u8, cursor: *usize) Error!void {
    cursor.* += 1;
    const first = cursor.*;
    try consumeNumber(value, cursor);
    if (std.mem.indexOfScalar(u8, value[first..cursor.*], '.') != null) return error.InvalidStructuredField;
}

fn consumeDisplayString(value: []const u8, cursor: *usize) Error!void {
    if (cursor.* + 1 >= value.len or value[cursor.* + 1] != '"') return error.InvalidStructuredField;
    cursor.* += 2;
    var sequence: [4]u8 = undefined;
    var present: usize = 0;
    var expected: usize = 0;
    while (cursor.* < value.len) {
        var byte = value[cursor.*];
        cursor.* += 1;
        if (byte == '"') {
            if (present != 0) return error.InvalidStructuredField;
            return;
        }
        if (byte == '%') {
            if (cursor.* + 2 > value.len) return error.InvalidStructuredField;
            for (value[cursor.*..][0..2]) |digit| if (!std.ascii.isHex(digit)) return error.InvalidStructuredField;
            byte = std.fmt.parseInt(u8, value[cursor.*..][0..2], 16) catch return error.InvalidStructuredField;
            cursor.* += 2;
        } else if (byte < 0x20 or byte > 0x7e) return error.InvalidStructuredField;
        if (present == 0) {
            expected = std.unicode.utf8ByteSequenceLength(byte) catch return error.InvalidStructuredField;
            if (expected == 1) continue;
        }
        sequence[present] = byte;
        present += 1;
        if (present == expected) {
            _ = std.unicode.utf8Decode(sequence[0..expected]) catch return error.InvalidStructuredField;
            present = 0;
        }
    }
    return error.InvalidStructuredField;
}

fn consumeToken(value: []const u8, cursor: *usize) Error!void {
    cursor.* += 1;
    while (cursor.* < value.len and isTokenChar(value[cursor.*])) {
        cursor.* += 1;
    }
}

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/' => true,
        else => false,
    };
}

fn isBase64(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '/' or byte == '=';
}

test "structured field parses boolean item values" {
    try std.testing.expect(try parseBooleanItem("?1"));
    try std.testing.expect(!(try parseBooleanItem(" ?0\t")));
    try std.testing.expect(try parseBooleanItem("?1; flag; token=abc; text=\"ok\"; data=:YWJj:"));
    try std.testing.expect(try parseBooleanItem("?1;date=@-123;label=%\"%e4%bd%a0\""));

    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("true"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?2"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1, ?1"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1 trailing"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1; Bad=1"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1;date=@1.2"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1;decimal=1234567890123.1"));
    try std.testing.expectError(error.InvalidStructuredField, parseBooleanItem("?1;label=%\"%ff\""));
}
