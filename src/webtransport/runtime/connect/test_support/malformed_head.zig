const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");

pub const Kind = enum { missing_method, invalid_header };

pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, kind: Kind) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const target: []const http3.Qpack.HeaderField = &.{
        .{ .name = ":path", .value = "/malformed" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":protocol", .value = "webtransport-h3" },
    };
    var fields: [6]http3.Qpack.HeaderField = undefined;
    const selected = switch (kind) {
        .missing_method => target,
        .invalid_header => value: {
            fields[0] = .{ .name = ":method", .value = "CONNECT" };
            @memcpy(fields[1..5], target);
            fields[5] = .{ .name = ":protocol", .value = "duplicate" };
            break :value fields[0..6];
        },
    };
    try http3.Qpack.encodeLiteralBlock(&block, allocator, selected);
    try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
}
