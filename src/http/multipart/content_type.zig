//! `multipart/form-data` Content-Type boundary parsing.

const std = @import("std");
const boundary_rules = @import("boundary.zig");

pub const Error = error{
    InvalidContentType,
    MissingBoundary,
    DuplicateBoundary,
    InvalidBoundary,
    BufferTooSmall,
};

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
}

fn skipOws(input: []const u8, index: *usize) void {
    while (index.* < input.len and
        (input[index.*] == ' ' or input[index.*] == '\t'))
    {
        index.* += 1;
    }
}

fn skipQuoted(input: []const u8, index: *usize) Error!void {
    if (index.* == input.len or input[index.*] != '"') {
        return error.InvalidContentType;
    }
    index.* += 1;
    while (index.* < input.len) {
        if (input[index.*] == '\\') {
            index.* += 1;
            if (index.* == input.len) return error.InvalidContentType;
            index.* += 1;
            continue;
        }
        if (input[index.*] == '"') {
            index.* += 1;
            return;
        }
        index.* += 1;
    }
    return error.InvalidContentType;
}

/// Parse `multipart/form-data; boundary=...` and copy the boundary into `out`.
pub fn boundaryInto(
    out: []u8,
    content_type: []const u8,
) Error![]const u8 {
    var index: usize = 0;
    skipOws(content_type, &index);
    const type_start = index;
    while (index < content_type.len and
        content_type[index] != ';' and
        content_type[index] != ' ' and
        content_type[index] != '\t')
    {
        index += 1;
    }
    const media_type = content_type[type_start..index];
    if (!std.ascii.eqlIgnoreCase(media_type, "multipart/form-data")) {
        return error.InvalidContentType;
    }

    var boundary: ?[]const u8 = null;
    while (index < content_type.len) {
        skipOws(content_type, &index);
        if (index == content_type.len) break;
        if (content_type[index] == ';') {
            index += 1;
            skipOws(content_type, &index);
        }
        if (index == content_type.len) break;

        const name_start = index;
        while (index < content_type.len and isTokenChar(content_type[index])) {
            index += 1;
        }
        if (index == name_start) return error.InvalidContentType;
        const name = content_type[name_start..index];
        skipOws(content_type, &index);

        if (index == content_type.len or content_type[index] != '=') {
            // A parameter without a value is ignored.
            continue;
        }
        index += 1;
        skipOws(content_type, &index);
        if (index == content_type.len) return error.InvalidContentType;

        const is_boundary = std.ascii.eqlIgnoreCase(name, "boundary");
        if (content_type[index] == '"') {
            if (is_boundary) {
                if (boundary != null) return error.DuplicateBoundary;
                index += 1;
                var written: usize = 0;
                while (index < content_type.len and
                    content_type[index] != '"')
                {
                    if (content_type[index] == '\\') {
                        index += 1;
                        if (index == content_type.len) {
                            return error.InvalidContentType;
                        }
                    }
                    if (written == out.len) return error.BufferTooSmall;
                    out[written] = content_type[index];
                    written += 1;
                    index += 1;
                }
                if (index == content_type.len or
                    content_type[index] != '"')
                {
                    return error.InvalidContentType;
                }
                index += 1;
                boundary = out[0..written];
            } else {
                try skipQuoted(content_type, &index);
            }
        } else {
            const value_start = index;
            while (index < content_type.len and
                content_type[index] != ';' and
                content_type[index] != ' ' and
                content_type[index] != '\t')
            {
                index += 1;
            }
            if (is_boundary) {
                if (boundary != null) return error.DuplicateBoundary;
                boundary = content_type[value_start..index];
            }
        }
    }

    const value = boundary orelse return error.MissingBoundary;
    boundary_rules.validate(value) catch return error.InvalidBoundary;

    if (value.ptr != out.ptr) {
        if (value.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..value.len], value);
        return out[0..value.len];
    }
    return value;
}

test "content type boundary accepts quoted and unquoted forms" {
    var out: [80]u8 = undefined;
    try std.testing.expectEqualStrings(
        "----abc",
        try boundaryInto(&out, "multipart/form-data; boundary=----abc"),
    );
    try std.testing.expectEqualStrings(
        "----a b",
        try boundaryInto(
            &out,
            "Multipart/Form-Data; charset=utf-8; boundary=\"----a b\"",
        ),
    );
}

test "content type boundary rejects invalid forms" {
    var out: [80]u8 = undefined;
    try std.testing.expectError(
        error.InvalidContentType,
        boundaryInto(&out, "application/json"),
    );
    try std.testing.expectError(
        error.MissingBoundary,
        boundaryInto(&out, "multipart/form-data"),
    );
    try std.testing.expectError(
        error.DuplicateBoundary,
        boundaryInto(
            &out,
            "multipart/form-data; boundary=a; boundary=b",
        ),
    );
    try std.testing.expectError(
        error.InvalidBoundary,
        boundaryInto(&out, "multipart/form-data; boundary=\"bad\\\"x\""),
    );
}
