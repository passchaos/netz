//! RFC 9112 chunk-extension grammar shared by aggregate and streaming readers.

const std = @import("std");

pub fn validate(value: []const u8) error{InvalidChunk}!void {
    if (value.len == 0) return error.InvalidChunk;

    var pos: usize = 0;
    while (true) {
        skipBws(value, &pos);
        const name_start = pos;
        while (pos < value.len and isTokenByte(value[pos])) : (pos += 1) {}
        if (pos == name_start) return error.InvalidChunk;

        const before_name_suffix_bws = pos;
        skipBws(value, &pos);
        if (pos < value.len and value[pos] == '=') {
            pos += 1;
            skipBws(value, &pos);
            if (pos == value.len) return error.InvalidChunk;
            if (value[pos] == '"') {
                try consumeQuotedString(value, &pos);
            } else {
                const value_start = pos;
                while (pos < value.len and isTokenByte(value[pos])) : (pos += 1) {}
                if (pos == value_start) return error.InvalidChunk;
            }
            const before_value_suffix_bws = pos;
            skipBws(value, &pos);
            if (pos == value.len and pos != before_value_suffix_bws) {
                return error.InvalidChunk;
            }
        } else if (pos == value.len and pos != before_name_suffix_bws) {
            return error.InvalidChunk;
        }

        if (pos == value.len) return;
        if (value[pos] != ';') return error.InvalidChunk;
        pos += 1;
        if (pos == value.len) return error.InvalidChunk;
    }
}

fn skipBws(value: []const u8, pos: *usize) void {
    while (pos.* < value.len and
        (value[pos.*] == ' ' or value[pos.*] == '\t'))
    {
        pos.* += 1;
    }
}

fn consumeQuotedString(
    value: []const u8,
    pos: *usize,
) error{InvalidChunk}!void {
    std.debug.assert(pos.* < value.len and value[pos.*] == '"');
    pos.* += 1;
    while (pos.* < value.len) {
        const byte = value[pos.*];
        pos.* += 1;
        if (byte == '"') return;
        if (byte == '\\') {
            if (pos.* == value.len or !isQuotedPairByte(value[pos.*])) {
                return error.InvalidChunk;
            }
            pos.* += 1;
            continue;
        }
        if (!isQuotedTextByte(byte)) return error.InvalidChunk;
    }
    return error.InvalidChunk;
}

fn isQuotedTextByte(byte: u8) bool {
    return byte == '\t' or byte == ' ' or byte == 0x21 or
        (byte >= 0x23 and byte <= 0x5b) or
        (byte >= 0x5d and byte <= 0x7e) or byte >= 0x80;
}

fn isQuotedPairByte(byte: u8) bool {
    return byte == '\t' or (byte >= 0x20 and byte <= 0x7e) or byte >= 0x80;
}

fn isTokenByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

test "HTTP/1 chunk extension grammar accepts tokens and quoted strings" {
    try validate("foo");
    try validate(" foo = bar ; quoted = \"one,two;three\\\"\" ; flag");

    for ([_][]const u8{
        "",
        "=value",
        "bad/name=value",
        "name=",
        "name=bad value",
        "name ",
        "name=value ",
        "name=\"unterminated",
        "name=\"bad\x01value\"",
        "name=value;",
        "name=value;;next=ok",
    }) |invalid| {
        try std.testing.expectError(error.InvalidChunk, validate(invalid));
    }
}
