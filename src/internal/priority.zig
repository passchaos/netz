//! HTTP Extensible Priorities shared by HTTP/2 and HTTP/3.
//!
//! RFC 9218 deliberately gives every HTTP version the same Priority Field
//! Value representation. Keeping the recognized `u` and `i` parameters here
//! prevents the version-specific frame codecs from drifting apart.

const std = @import("std");

pub const Priority = struct {
    urgency: u3 = 3,
    incremental: bool = false,

    /// Parse one complete structured Dictionary and extract the understood
    /// RFC 9218 parameters. Header parse failures use defaults; frame codecs
    /// can call parseStrict to apply their connection-error policy instead.
    pub fn parse(value: []const u8) Priority {
        return parseStrict(value) catch .{};
    }

    /// Parse all Priority lines in one header or trailer section in order.
    /// Each line must contain complete Dictionary members (RFC 8941 allows
    /// rejecting members split across lines). Invalid syntax discards the
    /// entire hint; repeated keys override earlier lines without allocation.
    pub fn parseFields(fields: anytype) Priority {
        var result = Priority{};
        var found = false;
        var empty = false;
        for (fields) |field| {
            if (!std.ascii.eqlIgnoreCase(field.name, "priority")) continue;
            const value = field.value;
            const line_empty = std.mem.trim(u8, value, " \t").len == 0;
            // Concatenating an empty line with another produces a leading,
            // repeated or trailing comma, which is not a valid Dictionary.
            if (found and (empty or line_empty)) return .{};
            result = parseDictionary(value, result, found) catch return .{};
            found = true;
            empty = line_empty;
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
        return parseDictionary(value, .{}, false);
    }

    fn parseDictionary(value: []const u8, initial: Priority, after_comma: bool) error{InvalidPriority}!Priority {
        var result = initial;
        var cursor: usize = 0;
        // RFC 8941's field entry algorithm strips leading SP; HTAB is
        // permitted only by Dictionary OWS after members and commas.
        if (after_comma) skipOptionalWhitespace(value, &cursor) else {
            while (cursor < value.len and value[cursor] == ' ') : (cursor += 1) {}
        }
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
                    // Structured-field integers are typed values, not their
                    // spelling. RFC 8941 allows leading zeros and -0; decimal
                    // or string members still fail integer conversion here.
                    const integer = std.fmt.parseInt(i64, raw, 10) catch 3;
                    if (integer >= 0 and integer <= 7) result.urgency = @intCast(integer);
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

/// PRIORITY_UPDATE specifies ASCII text. HTAB can be Dictionary OWS; the
/// structured parser separately rejects it inside strings, items and lists.
pub fn isAsciiFieldValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte != 0x09 and (byte < 0x20 or byte > 0x7e)) return false;
    }
    return true;
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

test {
    _ = @import("priority/tests.zig");
}
