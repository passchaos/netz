//! HTTP/2 and HTTP/3 field-name validation (RFC 9113 8.2.1 / RFC 9114 10.3).
//!
//! Field names are lowercase HTTP tokens: lowercase letters, digits, and the
//! token punctuation. A byte table keeps the per-byte check to one load and
//! also rejects uppercase, which RFC 9113 requires for HTTP/2 and RFC 9114
//! inherits for HTTP/3.

pub fn validate(name: []const u8) error{InvalidHeader}!void {
    if (name.len == 0) return error.InvalidHeader;
    if (name[0] == ':') {
        if (name.len == 1) return error.InvalidHeader;
        for (name[1..]) |byte| {
            if (!valid_bytes[byte]) return error.InvalidHeader;
        }
        return;
    }
    for (name) |byte| {
        if (!valid_bytes[byte]) return error.InvalidHeader;
    }
}

const valid_bytes = blk: {
    var table = [_]bool{false} ** 256;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ("!#$%&'*+-.^_`|~") |byte| table[byte] = true;
    break :blk table;
};

test {
    _ = @import("field_name_tests.zig");
}
