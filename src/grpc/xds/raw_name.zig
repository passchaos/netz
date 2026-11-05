//! Lenient extraction of a resource name from bytes that failed full decoding.
const std = @import("std");
const pb = @import("../protobuf.zig");

/// Return the first `string` field with `field_number`, or null when the
/// payload is truncated before it. This is used by `fail_on_data_errors` so a
/// resource that failed schema validation can still drop its cached entry.
pub fn first(bytes: []const u8, field_number: u32) ?[]const u8 {
    var reader: pb.Reader = .{ .bytes = bytes };
    while (reader.next() catch return null) |field| {
        if (field.number == field_number and field.wire_type == 2) {
            const value = reader.bytesValue() catch return null;
            if (value.len == 0 or !std.unicode.utf8ValidateSlice(value)) return null;
            return value;
        }
        reader.skip(field) catch return null;
    }
    return null;
}

test "xDS raw resource names are extracted from partially invalid payloads" {
    // Field 1 = "backend", followed by an invalid field-2 varint truncation.
    try std.testing.expectEqualStrings("backend", first("\x0a\x07backend\x10", 1).?);
    try std.testing.expect(first("\x10\x01", 1) == null);
    try std.testing.expect(first("\x0a\x00", 1) == null);
    try std.testing.expect(first("\x0a\x03\xff\xfe\xfd", 1) == null);
}
