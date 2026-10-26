const std = @import("std");
const call = @import("../call.zig");
const http2 = @import("../../http2/mod.zig");
const compression = @import("../compression.zig");

test "gRPC compression negotiation uses the last advertised metadata field" {
    const Case = struct { first: []const u8, last: []const u8, gzip: bool, deflate: bool };
    const cases = [_]Case{
        .{ .first = "gzip", .last = "deflate", .gzip = false, .deflate = true },
        .{ .first = "deflate", .last = "gzip", .gzip = true, .deflate = false },
        .{ .first = "gzip", .last = "identity", .gzip = false, .deflate = false },
        .{ .first = "gzip,deflate", .last = "unknown", .gzip = false, .deflate = false },
        .{ .first = "gzip", .last = " unknown,\tdeflate ", .gzip = false, .deflate = true },
        .{ .first = "gzip,deflate", .last = "", .gzip = false, .deflate = false },
    };
    for (cases) |row| {
        const fields = [_]http2.Hpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "grpc-accept-encoding", .value = row.first },
            .{ .name = "x-unrelated", .value = "gzip" },
            .{ .name = "grpc-accept-encoding", .value = row.last },
        };
        const native = try call.parseRequestMetadata("POST", "/fixture.Compression/Unary", &fields);
        const web = try call.parseWebRequestMetadata("POST", "/fixture.Compression/Unary", &fields);
        for ([_]call.RequestMetadata{ native, web }) |parsed| {
            try std.testing.expectEqual(row.gzip, parsed.accepted_encodings.gzip);
            try std.testing.expectEqual(row.deflate, parsed.accepted_encodings.deflate);
            try std.testing.expect(parsed.accepted_encodings.contains(.identity));
        }
    }
}

test "gRPC compression negotiation accepts field spelling and last empty advertisement" {
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = "grpc-accept-encoding", .value = "gzip,deflate" },
        .{ .name = "Grpc-Accept-Encoding", .value = "" },
    };
    const accepted = compression.parseAcceptEncodingFields(&fields);
    try std.testing.expect(!accepted.gzip and !accepted.deflate);
    try std.testing.expect(accepted.contains(.identity));
    const absent = compression.parseAcceptEncodingFields(fields[0..0]);
    try std.testing.expect(!absent.gzip and !absent.deflate);
}
