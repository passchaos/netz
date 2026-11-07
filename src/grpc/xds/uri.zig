//! URI components used by xDS targets and federated resource authorities.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{ InvalidXdsTarget, XdsTargetLimitExceeded };
pub const Component = enum { authority, path };

pub const Target = struct {
    authority: []u8,
    path: []u8,

    pub fn deinit(self: *Target, allocator: std.mem.Allocator) void {
        allocator.free(self.authority);
        allocator.free(self.path);
        self.* = undefined;
    }
};

/// Match grpc-core's permissive decoding: valid triplets decode, other '%' bytes
/// remain literal. The returned allocation belongs to the caller.
pub fn percentDecode(allocator: std.mem.Allocator, encoded: []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, encoded.len);
    var offset: usize = 0;
    while (offset < encoded.len) {
        const next = decodedByte(encoded, &offset);
        out.appendAssumeCapacity(next);
    }
    return out.toOwnedSlice(allocator);
}

/// Compare a URI-encoded authority with a bootstrap key without allocating.
pub fn percentEquals(encoded: []const u8, raw: []const u8) bool {
    var offset: usize = 0;
    var index: usize = 0;
    while (offset < encoded.len) {
        if (index == raw.len or decodedByte(encoded, &offset) != raw[index]) return false;
        index += 1;
    }
    return index == raw.len;
}

pub fn percentEncode(allocator: std.mem.Allocator, raw: []const u8, comptime component: Component) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const maximum = std.math.mul(usize, raw.len, 3) catch return error.XdsTargetLimitExceeded;
    try out.ensureTotalCapacity(allocator, maximum);
    const hex = "0123456789ABCDEF";
    for (raw) |byte| {
        if (allowed(byte, component)) {
            out.appendAssumeCapacity(byte);
        } else {
            out.appendSliceAssumeCapacity(&.{ '%', hex[byte >> 4], hex[byte & 15] });
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Parse the registered xds scheme, retaining decoded authority/path only.
/// Query and fragment validation follows grpc-core; neither enters the target.
pub fn parseTarget(allocator: std.mem.Allocator, raw: []const u8) Error!Target {
    if (!std.mem.startsWith(u8, raw, "xds:")) return error.InvalidXdsTarget;
    var remaining = raw[4..];
    var authority: []const u8 = "";
    if (std.mem.startsWith(u8, remaining, "//")) {
        remaining = remaining[2..];
        const end = firstDelimiter(remaining, "/?#");
        authority = remaining[0..end];
        remaining = remaining[end..];
    }
    const path_end = firstDelimiter(remaining, "?#");
    const path = remaining[0..path_end];
    remaining = remaining[path_end..];
    if (std.mem.startsWith(u8, remaining, "?")) {
        remaining = remaining[1..];
        const query_end = firstDelimiter(remaining, "#");
        const query = remaining[0..query_end];
        if (query.len == 0 or !validQueryOrFragment(query)) return error.InvalidXdsTarget;
        remaining = remaining[query_end..];
    }
    if (std.mem.startsWith(u8, remaining, "#")) {
        if (!validQueryOrFragment(remaining[1..])) return error.InvalidXdsTarget;
    }
    const decoded_authority = try percentDecode(allocator, authority);
    errdefer allocator.free(decoded_authority);
    const decoded_path = try percentDecode(allocator, path);
    errdefer allocator.free(decoded_path);
    if (decoded_path.len == 0 or decoded_path[decoded_path.len - 1] == '/' or
        !std.unicode.utf8ValidateSlice(decoded_authority) or !std.unicode.utf8ValidateSlice(decoded_path))
    {
        return error.InvalidXdsTarget;
    }
    return .{ .authority = decoded_authority, .path = decoded_path };
}

fn firstDelimiter(bytes: []const u8, delimiters: []const u8) usize {
    for (bytes, 0..) |byte, index| {
        if (std.mem.indexOfScalar(u8, delimiters, byte) != null) return index;
    }
    return bytes.len;
}

fn decodedByte(bytes: []const u8, offset: *usize) u8 {
    const index = offset.*;
    offset.* += 1;
    if (bytes[index] == '%' and bytes.len - index >= 3) {
        if (hexDigit(bytes[index + 1])) |high| {
            if (hexDigit(bytes[index + 2])) |low| {
                offset.* += 2;
                return (high << 4) | low;
            }
        }
    }
    return bytes[index];
}

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn unreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '-', '.', '_', '~' => true,
        else => false,
    };
}

fn subDelimiter(byte: u8) bool {
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

fn allowed(byte: u8, component: Component) bool {
    if (unreserved(byte) or subDelimiter(byte) or byte == ':' or byte == '@') return true;
    return switch (component) {
        .authority => byte == '[' or byte == ']',
        .path => byte == '/',
    };
}

fn validQueryOrFragment(bytes: []const u8) bool {
    for (bytes) |byte| if (!allowed(byte, .path) and byte != '?' and byte != '%') return false;
    return true;
}
