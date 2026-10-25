//! Wire fixtures for ignored RFC 7540 priority signals.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

pub fn legacyHeaders(connection: *runtime.Connection, id: u31, fields: []const http2.Hpack.HeaderField, fragmented: bool) !void {
    var priority: [5]u8 = undefined;
    std.mem.writeInt(u32, priority[0..4], id, .big);
    priority[4] = 16;
    try runtime.testing.writeRawFrame(connection, .priority, 0, id, &priority);
    const block = try connection.hpack_encoder.encodeBlockRetained(allocator, fields);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.append(allocator, 2); // Pad Length precedes priority fields.
    try payload.appendSlice(allocator, &priority);
    try payload.appendSlice(allocator, if (fragmented) block[0..1] else block);
    try payload.appendSlice(allocator, &.{ 0, 0 });
    try runtime.testing.writeRawFrame(connection, .headers, 0x29 | @as(u8, if (fragmented) 0 else 0x4), id, payload.items);
    if (fragmented) try runtime.testing.writeRawFrame(connection, .continuation, 0x4, id, block[1..]);
    // The following stream must actually depend on this block's dynamic
    // entry, so successful reuse proves compression advanced exactly once.
    const reused = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{ .name = "x-sync", .value = "preserved" }});
    try std.testing.expectEqual(@as(usize, 1), reused.len);
    try std.testing.expect(reused[0] & 0x80 != 0);
}
