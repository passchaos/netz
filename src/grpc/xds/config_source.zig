//! ADS/self v3 sources shared by LDS/RDS and EDS-backed CDS resources.
const pb = @import("../protobuf.zig");
pub const Error = pb.Error || error{ InvalidConfigSource, UnsupportedConfigSource };
pub const Kind = enum { ads, self };
pub fn decode(bytes: []const u8) Error!Kind {
    var reader = pb.Reader{ .bytes = bytes };
    var selected: ?Kind = null;
    while (try reader.next()) |field| {
        if ((field.number == 3 or field.number == 5) and field.wire_type == 2) {
            var nested = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try nested.next()) |entry| try nested.skip(entry);
            selected = if (field.number == 3) .ads else .self;
        } else if ((field.number == 1 or field.number == 2 or field.number == 8) and field.wire_type == 2) {
            _ = try reader.bytesValue();
            selected = null;
        } else if (field.number == 6 and field.wire_type == 0) {
            const version = try reader.varint();
            // AUTO follows the ADS session's v3 type URL; explicit V2 cannot.
            if (version != 0 and version != 2) return error.UnsupportedConfigSource;
        } else try reader.skip(field);
    }
    return selected orelse error.InvalidConfigSource;
}
test "gRPC xDS config source selects last ADS SELF and validates API version" {
    const std = @import("std");
    try std.testing.expectEqual(Kind.ads, try decode("\x1a\x00"));
    try std.testing.expectEqual(Kind.self, try decode("\x1a\x00\x2a\x00"));
    try std.testing.expectEqual(Kind.ads, try decode("\x1a\x00\x30\x00"));
    try std.testing.expectEqual(Kind.ads, try decode("\x1a\x00\x30\x02"));
    try std.testing.expectError(error.UnsupportedConfigSource, decode("\x1a\x00\x30\x01"));
    try std.testing.expectError(error.InvalidConfigSource, decode("\x1a\x00\x12\x00"));
    try std.testing.expectError(error.TruncatedMessage, decode("\x1a\x01\x08"));
}
