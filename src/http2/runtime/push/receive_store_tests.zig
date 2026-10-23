const std = @import("std");
const http2 = @import("../../mod.zig");
const receive = @import("receive.zig");

fn lifecycle(allocator: std.mem.Allocator) !void {
    var store: receive.Store = .{};
    defer store.deinit(allocator);
    try store.reserve(allocator, 2, false);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "9" },
        .{ .name = "x-lifecycle", .value = "owned" },
    });
    var decoder: http2.Hpack.Decoder = .{};
    defer decoder.deinit(allocator);
    const fields = try decoder.decodeBlockOwnedWithLimit(allocator, encoded.items, 16, 4096);
    const limits = receive.Limits{ .max_bytes = 4096, .max_body_bytes = 1024, .max_informational_responses = 16 };
    try store.headers(allocator, 2, fields, false, limits);
    try store.data(allocator, 2, "first", false, limits);
    try store.data(allocator, 2, "tail", true, limits);
    const response = try store.take(allocator, 2);
    defer allocator.free(response.body);
    defer http2.Hpack.freeOwnedFields(allocator, response.headers);
    defer http2.Hpack.freeOwnedFields(allocator, response.trailers);
    try std.testing.expectEqualStrings("firsttail", response.body);
    try std.testing.expectEqual(@as(usize, 0), store.retained_bytes);
    store.remove(allocator, 2);
}

test "HTTP/2 push receive ownership survives every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, lifecycle, .{});
}
