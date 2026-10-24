//! HTTP/2 and HTTP/3 field-content validation (RFC 9113 8.2.1 / RFC 9114 10.3).

pub fn validate(value: []const u8) error{InvalidHeader}!void {
    if (value.len != 0 and (whitespace(value[0]) or whitespace(value[value.len - 1]))) return error.InvalidHeader;
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidHeader;
    }
}

fn whitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

test {
    _ = @import("field_value_tests.zig");
}
