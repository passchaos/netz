const std = @import("std");
const field_name = @import("field_name.zig");

test "field name accepts lowercase tokens and pseudo names" {
    const valid = [_][]const u8{
        "a",
        "host",
        "content-length",
        "x-custom_name.1",
        "!#$%&'*+-.^_`|~",
        ":method",
        ":path",
    };
    for (valid) |name| try field_name.validate(name);
}

test "field name rejects empty, uppercase, and non-token bytes" {
    const invalid = [_][]const u8{
        "",
        ":",
        "Host",
        "ACCEPT",
        "content length",
        "content\tlength",
        "content/length",
        "content:length",
        "caf\xc3\xa9",
        "x\x00y",
        "x\x7fy",
    };
    for (invalid) |name| {
        try std.testing.expectError(
            error.InvalidHeader,
            field_name.validate(name),
        );
    }
}
