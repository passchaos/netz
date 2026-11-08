//! HTTP/1, HTTP/2 and HTTP/3 field-content validation.

pub fn validate(value: []const u8) error{InvalidHeader}!void {
    if (value.len != 0 and (whitespace(value[0]) or whitespace(value[value.len - 1]))) return error.InvalidHeader;
    for (value) |byte| {
        if (invalid_bytes[byte]) return error.InvalidHeader;
    }
}

/// One table lookup for the control-byte rule shared by HTTP/1, HTTP/2 and
/// HTTP/3: bytes below 0x20 except horizontal tab, and 0x7f, are invalid.
/// Obs-text 0x80-0xff remains legal.
pub inline fn invalidByte(byte: u8) bool {
    return invalid_bytes[byte];
}

fn whitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

/// Control bytes are invalid except horizontal tab; 0x7f is invalid. Obs-text
/// 0x80-0xff remains legal. A table keeps the per-byte check to one load.
const invalid_bytes = blk: {
    var table = [_]bool{false} ** 256;
    for (0..0x20) |byte| table[byte] = true;
    table['\t'] = false;
    table[0x7f] = true;
    break :blk table;
};

test {
    _ = @import("field_value_tests.zig");
}
