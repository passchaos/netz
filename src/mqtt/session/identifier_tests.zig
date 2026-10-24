const std = @import("std");
const session = @import("mod.zig");
const mqtt = @import("../mod.zig");

test "MQTT session identifier view survives Store moves table growth and ACK mutation" {
    const allocator = std.testing.allocator;
    var original = session.Store.init(allocator, .{ .max_sessions = 64 });
    const opened = try original.open("owner", false, 60, .zero);
    const first = try original.beginImmediatePublish(opened.handle, "ids/topic", "payload", .{ .qos = .at_least_once, .now = .zero }, 64);
    const owner = try original.packetIdentifierOwnership(opened.handle);
    var store = original;
    original = session.Store.init(allocator, .{});
    defer store.deinit();
    try std.testing.expect(owner.contains(first.packet_id));
    for (0..32) |index| {
        var id: [32]u8 = undefined;
        _ = try store.open(try std.fmt.bufPrint(&id, "sibling-{d}", .{index}), false, 60, .zero);
        const added = try store.beginImmediatePublish(opened.handle, "ids/topic", "payload", .{ .qos = .at_least_once, .now = .zero }, 64);
        try std.testing.expect(owner.contains(added.packet_id));
    }
    _ = try store.handleAck(opened.handle, .puback, first.packet_id, 0);
    try std.testing.expect(!owner.contains(first.packet_id));
}

test "MQTT session identifier exhaustion retains queued work and selected prefix" {
    var store = session.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("bounded", false, 60, .zero);
    for ([_][]const u8{ "first", "second" }) |payload| {
        _ = try store.enqueuePublish(opened.handle, "ids/topic", payload, .{ .qos = .at_least_once, .now = .zero });
    }
    const Reservations = struct {
        free: u16 = 1,
        fn contains(context: *const anyopaque, id: u16) bool {
            const self: *const @This() = @ptrCast(@alignCast(context));
            return id != self.free;
        }
    };
    var reservations: Reservations = .{};
    const owner: session.PacketIdentifierOwnership = .{ .context = &reservations, .containsFn = Reservations.contains };
    var output: [2]session.Transmission = undefined;
    const first = try store.drainIntoAvoiding(opened.handle, .zero, 2, &output, owner);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(u16, 1), first[0].publish.packet_id);
    try std.testing.expectEqualStrings("first", first[0].publish.payload);
    const retained = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 1), retained.queued_count);
    try std.testing.expectEqual(@as(usize, 1), retained.inflight_count);
    try std.testing.expectError(error.InflightFull, store.drainIntoAvoiding(opened.handle, .zero, 2, &output, owner));
    try std.testing.expectEqualDeep(retained, try store.stats(opened.handle));
    reservations.free = 2;
    const second = try store.drainIntoAvoiding(opened.handle, .zero, 2, &output, owner);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(@as(u16, 2), second[0].publish.packet_id);
    try std.testing.expectEqualStrings("second", second[0].publish.payload);
    try std.testing.expectEqual(@as(usize, 0), (try store.stats(opened.handle)).queued_count);
}
