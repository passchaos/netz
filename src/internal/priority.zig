//! HTTP Extensible Priorities shared by HTTP/2 and HTTP/3.
//!
//! RFC 9218 deliberately gives every HTTP version the same Priority Field
//! Value representation. Keeping the recognized `u` and `i` parameters here
//! prevents the version-specific frame codecs from drifting apart.

const std = @import("std");

pub const Priority = struct {
    urgency: u3 = 3,
    incremental: bool = false,

    /// Extract the RFC 9218 parameters understood by Netz.
    ///
    /// Unknown parameters and recognized parameters with unsupported values
    /// retain the defaults, as required by RFC 9218. The wire codecs separately
    /// enforce ASCII; this parser remains useful for trusted header values too.
    pub fn parse(value: []const u8) Priority {
        var result = Priority{};
        var rest = value;
        while (rest.len != 0) {
            rest = trimLeading(rest);
            if (rest.len == 0) break;
            if (rest[0] == ',') {
                rest = rest[1..];
                continue;
            }

            const name_end = nameEnd(rest);
            const name = rest[0..name_end];
            rest = trimLeading(rest[name_end..]);
            if (rest.len != 0 and rest[0] == '=') {
                rest = trimLeading(rest[1..]);
                const value_end = valueEnd(rest);
                const parameter_value = rest[0..value_end];
                rest = rest[value_end..];
                if (std.mem.eql(u8, name, "u")) {
                    if (parameter_value.len == 1 and
                        parameter_value[0] >= '0' and
                        parameter_value[0] <= '7')
                    {
                        result.urgency =
                            @intCast(parameter_value[0] - '0');
                    }
                } else if (std.mem.eql(u8, name, "i")) {
                    if (std.mem.eql(u8, parameter_value, "?1")) {
                        result.incremental = true;
                    }
                    if (std.mem.eql(u8, parameter_value, "?0")) {
                        result.incremental = false;
                    }
                }
            } else if (std.mem.eql(u8, name, "i")) {
                result.incremental = true;
            }
        }
        return result;
    }

    /// Serialize the canonical representation of the parameters Netz knows.
    /// A default priority is represented by the valid empty Dictionary.
    pub fn serialize(self: Priority, out: []u8) []const u8 {
        var pos: usize = 0;
        if (self.urgency != 3) {
            if (out.len < 3) return out[0..0];
            out[pos] = 'u';
            pos += 1;
            out[pos] = '=';
            pos += 1;
            out[pos] = '0' + @as(u8, self.urgency);
            pos += 1;
        }
        if (self.incremental) {
            if (pos != 0) {
                if (pos + 2 > out.len) return out[0..pos];
                out[pos] = ',';
                pos += 1;
                out[pos] = ' ';
                pos += 1;
            }
            if (pos + 1 > out.len) return out[0..pos];
            out[pos] = 'i';
            pos += 1;
        }
        return out[0..pos];
    }

    /// Parse a Priority structured-field dictionary strictly enough to reject
    /// malformed wire values while still allowing extension members.
    pub fn parseStrict(value: []const u8) error{InvalidPriority}!Priority {
        var result = Priority{};
        var cursor: usize = 0;
        skipOptionalWhitespace(value, &cursor);
        if (cursor == value.len) return result;
        while (cursor < value.len) {
            const name_start = cursor;
            if (!isKeyStart(value[cursor])) return error.InvalidPriority;
            cursor += 1;
            while (cursor < value.len and isKeyChar(value[cursor])) {
                cursor += 1;
            }
            const name = value[name_start..cursor];

            var member_value: ?[]const u8 = null;
            var implicit_true = false;
            if (cursor < value.len and value[cursor] == '=') {
                cursor += 1;
                member_value = try consumeItemOrInnerList(value, &cursor);
            } else {
                implicit_true = true;
                try consumeParameters(value, &cursor);
            }

            if (std.mem.eql(u8, name, "u")) {
                result.urgency = 3;
                if (member_value) |raw| {
                    if (raw.len == 1 and raw[0] >= '0' and raw[0] <= '7') {
                        result.urgency = @intCast(raw[0] - '0');
                    }
                }
            } else if (std.mem.eql(u8, name, "i")) {
                result.incremental = false;
                if (member_value) |raw| {
                    if (std.mem.eql(u8, raw, "?1")) {
                        result.incremental = true;
                    } else if (std.mem.eql(u8, raw, "?0")) {
                        result.incremental = false;
                    }
                } else if (implicit_true) {
                    result.incremental = true;
                }
            }

            skipOptionalWhitespace(value, &cursor);
            if (cursor == value.len) break;
            if (value[cursor] != ',') return error.InvalidPriority;
            cursor += 1;
            skipOptionalWhitespace(value, &cursor);
            if (cursor == value.len) return error.InvalidPriority;
        }
        return result;
    }
};

/// PRIORITY_UPDATE specifies ASCII text. Rejecting non-ASCII bytes at the
/// version-specific wire boundary avoids ambiguous structured-field parsing.
pub fn isAsciiFieldValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte < 0x20 or byte > 0x7e) return false;
    }
    return true;
}

fn trimLeading(value: []const u8) []const u8 {
    var i: usize = 0;
    while (i < value.len and
        (value[i] == ' ' or value[i] == 0x09)) : (i += 1)
    {}
    return value[i..];
}

fn nameEnd(value: []const u8) usize {
    var i: usize = 0;
    while (i < value.len and
        value[i] != '=' and
        value[i] != ',' and
        value[i] != ' ' and
        value[i] != 0x09) : (i += 1)
    {}
    return i;
}

fn valueEnd(value: []const u8) usize {
    var i: usize = 0;
    while (i < value.len and
        value[i] != ',' and
        value[i] != ' ' and
        value[i] != 0x09) : (i += 1)
    {}
    return i;
}

fn skipOptionalWhitespace(value: []const u8, cursor: *usize) void {
    while (cursor.* < value.len and
        (value[cursor.*] == ' ' or value[cursor.*] == 0x09))
    {
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

fn consumeItemOrInnerList(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!?[]const u8 {
    if (cursor.* < value.len and value[cursor.*] == '(') {
        try consumeInnerList(value, cursor);
        return null;
    } else {
        const bare_start = cursor.*;
        try consumeBareItem(value, cursor);
        const bare_value = value[bare_start..cursor.*];
        try consumeParameters(value, cursor);
        return bare_value;
    }
}

fn consumeInnerList(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    cursor.* += 1;
    while (true) {
        while (cursor.* < value.len and value[cursor.*] == ' ') {
            cursor.* += 1;
        }
        if (cursor.* >= value.len) return error.InvalidPriority;
        if (value[cursor.*] == ')') {
            cursor.* += 1;
            try consumeParameters(value, cursor);
            return;
        }
        try consumeBareItem(value, cursor);
        try consumeParameters(value, cursor);
        if (cursor.* >= value.len or
            (value[cursor.*] != ' ' and value[cursor.*] != ')'))
        {
            return error.InvalidPriority;
        }
    }
}

fn consumeParameters(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    while (cursor.* < value.len and value[cursor.*] == ';') {
        cursor.* += 1;
        while (cursor.* < value.len and value[cursor.*] == ' ') {
            cursor.* += 1;
        }
        if (cursor.* >= value.len or !isKeyStart(value[cursor.*])) {
            return error.InvalidPriority;
        }
        cursor.* += 1;
        while (cursor.* < value.len and isKeyChar(value[cursor.*])) {
            cursor.* += 1;
        }
        if (cursor.* < value.len and value[cursor.*] == '=') {
            cursor.* += 1;
            try consumeBareItem(value, cursor);
        }
    }
}

fn consumeBareItem(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    if (cursor.* >= value.len) return error.InvalidPriority;
    return switch (value[cursor.*]) {
        '"' => consumeDelimited(value, cursor, '"', true),
        ':' => consumeByteSequence(value, cursor),
        '?' => consumeBoolean(value, cursor),
        '-', '0'...'9' => consumeNumber(value, cursor),
        'A'...'Z', 'a'...'z', '*' => consumeToken(value, cursor),
        else => error.InvalidPriority,
    };
}

fn consumeByteSequence(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    cursor.* += 1;
    const content_start = cursor.*;
    while (cursor.* < value.len and value[cursor.*] != ':') {
        if (!isBase64(value[cursor.*])) return error.InvalidPriority;
        cursor.* += 1;
    }
    if (cursor.* >= value.len) return error.InvalidPriority;
    const content = value[content_start..cursor.*];
    cursor.* += 1;

    var padding: usize = 0;
    while (padding < content.len and
        content[content.len - 1 - padding] == '=') : (padding += 1)
    {}
    if (padding > 2) return error.InvalidPriority;
    for (content[0 .. content.len - padding]) |byte| {
        if (byte == '=') return error.InvalidPriority;
    }
    const unpadded_len = content.len - padding;
    if (unpadded_len % 4 == 1) return error.InvalidPriority;
    if (padding != 0 and content.len % 4 != 0) {
        return error.InvalidPriority;
    }
}

fn consumeDelimited(
    value: []const u8,
    cursor: *usize,
    delimiter: u8,
    allow_escapes: bool,
) error{InvalidPriority}!void {
    cursor.* += 1;
    while (cursor.* < value.len) {
        const byte = value[cursor.*];
        cursor.* += 1;
        if (byte == delimiter) return;
        if (allow_escapes and byte == '\\') {
            if (cursor.* >= value.len) return error.InvalidPriority;
            const escaped = value[cursor.*];
            if (escaped != '"' and escaped != '\\') {
                return error.InvalidPriority;
            }
            cursor.* += 1;
        } else if (byte < 0x20 or byte > 0x7e) {
            return error.InvalidPriority;
        } else if (!allow_escapes and !isBase64(byte)) {
            return error.InvalidPriority;
        }
    }
    return error.InvalidPriority;
}

fn consumeBoolean(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    if (cursor.* + 1 >= value.len or
        (value[cursor.* + 1] != '0' and value[cursor.* + 1] != '1'))
    {
        return error.InvalidPriority;
    }
    cursor.* += 2;
}

fn consumeNumber(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    if (value[cursor.*] == '-') cursor.* += 1;
    const integer_start = cursor.*;
    while (cursor.* < value.len and
        std.ascii.isDigit(value[cursor.*])) : (cursor.* += 1)
    {}
    const integer_len = cursor.* - integer_start;
    if (integer_len == 0 or integer_len > 15) return error.InvalidPriority;
    if (cursor.* < value.len and value[cursor.*] == '.') {
        if (integer_len > 12) return error.InvalidPriority;
        cursor.* += 1;
        const fraction_start = cursor.*;
        while (cursor.* < value.len and
            std.ascii.isDigit(value[cursor.*])) : (cursor.* += 1)
        {}
        const fraction_len = cursor.* - fraction_start;
        if (fraction_len == 0 or fraction_len > 3) {
            return error.InvalidPriority;
        }
    }
}

fn consumeToken(
    value: []const u8,
    cursor: *usize,
) error{InvalidPriority}!void {
    cursor.* += 1;
    while (cursor.* < value.len and
        isTokenChar(value[cursor.*])) : (cursor.* += 1)
    {}
}

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~:/", byte) != null;
}

fn isBase64(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '+' or byte == '/' or byte == '=';
}

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

test "priority field values are printable ASCII" {
    try std.testing.expect(isAsciiFieldValue(""));
    try std.testing.expect(isAsciiFieldValue("u=0, i"));
    try std.testing.expect(!isAsciiFieldValue("u=0,\ti"));
    try std.testing.expect(!isAsciiFieldValue("u=0\n"));
    try std.testing.expect(!isAsciiFieldValue(&.{0xff}));
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
