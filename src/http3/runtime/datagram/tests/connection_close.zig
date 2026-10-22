const std = @import("std");
const http3 = @import("../../../mod.zig");
const Registry = @import("../../datagram.zig").Registry;

test "HTTP/3 CONNECT datagram connection-close discard is scoped per association" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 3,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    for ([_]u62{ 0, 4, 8 }) |id| try registry.register(id);
    registry.discardOnConnectionClose(0);
    registry.discardOnConnectionClose(8);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    for (0..3) |quarter| {
        encoded.clearRetainingCapacity();
        try (http3.Datagram{ .quarter_stream_id = @intCast(quarter), .payload = "queued" }).write(&encoded, allocator);
        try registry.route(encoded.items);
    }
    registry.markTerminal(0, .peer_fin);
    registry.markTerminal(4, .peer_fin);
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(0));
    registry.markAllTerminal(.connection_closed);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(8));
    try std.testing.expect((try registry.drainedTerminal(0)).? == .connection_closed);
    var output = [_]u8{0xaa} ** 16;
    try std.testing.expect((try registry.pollInto(0, &output)) == null);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(4));
    var retained = (try registry.poll(4)).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("queued", retained.payload);
    try std.testing.expect((try registry.drainedTerminal(4)).? == .peer_fin);
    // Repeat the signal and route a late datagram without reviving any queue.
    registry.markTerminal(0, .connection_closed);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "late" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}

test "HTTP/3 CONNECT datagram discard can apply after connection-close observation" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "queued" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    registry.markTerminal(0, .connection_closed);
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(0));
    registry.discardOnConnectionClose(0);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
    try std.testing.expect((try registry.drainedTerminal(0)).? == .connection_closed);
}
