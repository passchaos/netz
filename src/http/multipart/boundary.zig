//! Shared multipart boundary validation.

pub const max_len = 70;

pub const Error = error{InvalidBoundary};

/// Boundaries are restricted to printable ASCII without quote or backslash.
/// Internal spaces are allowed when the Content-Type parameter is quoted;
/// leading and trailing spaces are rejected.
pub fn validate(boundary: []const u8) Error!void {
    if (boundary.len == 0 or boundary.len > max_len) {
        return error.InvalidBoundary;
    }
    if (boundary[0] == ' ' or boundary[boundary.len - 1] == ' ') {
        return error.InvalidBoundary;
    }
    for (boundary) |byte| {
        if (byte < 0x20 or byte > 0x7e or byte == '"' or byte == '\\') {
            return error.InvalidBoundary;
        }
    }
}
