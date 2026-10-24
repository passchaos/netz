const std = @import("std");
const mqtt = @import("../../mod.zig");
const Packet = @import("../packet_transport.zig").OwnedPacket;
const State = @import("pending.zig").State;

const first = "\x30\x04\x00\x01x1";
const second = "\x30\x05\x00\x01x22";
const third = "\x30\x06\x00\x01x333";
const fourth = "\x30\x07\x00\x01x4444";

fn matchesBytes(expected: []const u8, packet: Packet) bool {
    return std.mem.eql(u8, expected, packet.bytes);
}

test "MQTT pending correlated removal preserves prefix order and overflow quota" {
    const allocator = std.testing.allocator;
    var queue: State = .{};
    defer queue.deinit(allocator);
    for ([_][]const u8{ first, second, third }) |bytes| try queue.append(allocator, borrowed(bytes), 3, 100);
    _ = queue.pop();
    queue.retainOverflow(borrowed(fourth));
    const middle = queue.findFirstMatching(@as([]const u8, third), matchesBytes).?;
    try std.testing.expectEqualStrings(third, middle.packet.bytes);
    try std.testing.expectEqual(@as(usize, second.len + third.len), queue.queued_bytes);
    try std.testing.expectEqualStrings(third, queue.takeMatch(middle.index).bytes);
    try std.testing.expectEqual(@as(usize, second.len), queue.queued_bytes);
    const overflow = queue.findFirstMatching(@as([]const u8, fourth), matchesBytes).?;
    try std.testing.expectEqualStrings(fourth, queue.takeMatch(overflow.index).bytes);
    try std.testing.expectEqual(@as(usize, 1), queue.count());
    try std.testing.expectEqualStrings(second, queue.pop().?.bytes);
    try std.testing.expect(queue.pop() == null);
    try std.testing.expectEqual(@as(usize, 0), queue.queued_bytes);
}

fn borrowed(bytes: []const u8) Packet {
    return .{ .bytes = @constCast(bytes), .fixed = mqtt.FixedHeader.parse(bytes) catch unreachable, .owns_bytes = false };
}

fn owned(allocator: std.mem.Allocator, bytes: []const u8) !Packet {
    var packet = borrowed(bytes);
    packet.bytes = try allocator.dupe(u8, bytes);
    packet.owns_bytes = true;
    return packet;
}

test "MQTT pending packets enforce complete wire byte quota before allocation" {
    const allocator = std.testing.allocator;
    var queue: State = .{};
    defer queue.deinit(allocator);
    try queue.append(allocator, borrowed(first), 8, first.len);
    // Count remains available, but the exact byte quota is exhausted.
    try std.testing.expectError(error.TooManyPendingPackets, queue.ensureAvailable(8, first.len));
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.TooManyPendingPackets, queue.append(failing.allocator(), borrowed(second), 8, first.len));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualStrings(first, queue.pop().?.bytes);
    try queue.ensureAvailable(8, second.len);
    try queue.append(allocator, borrowed(second), 8, second.len);
    try std.testing.expectEqualStrings(second, queue.pop().?.bytes);
    try std.testing.expectEqual(@as(usize, 0), queue.queued_bytes);
}

test "MQTT pending packets preserve byte credit through compaction and overflow" {
    const allocator = std.testing.allocator;
    var queue: State = .{};
    defer queue.deinit(allocator);
    try queue.packets.ensureTotalCapacityPrecise(allocator, 3);
    for ([_][]const u8{ first, second, third }) |bytes| try queue.append(allocator, borrowed(bytes), 3, 100);
    try std.testing.expectEqualStrings(first, queue.pop().?.bytes);
    // Reuse the consumed prefix without releasing the remaining packets.
    try queue.append(allocator, borrowed(fourth), 3, second.len + third.len + fourth.len);
    try std.testing.expectEqual(@as(usize, second.len + third.len + fourth.len), queue.queued_bytes);
    try std.testing.expectError(error.TooManyPendingPackets, queue.append(allocator, borrowed(first), 3, 100));
    queue.retainOverflow(borrowed(first));
    try std.testing.expectError(error.TooManyPendingPackets, queue.ensureAvailable(8, 100));
    for ([_][]const u8{ second, third, fourth, first }) |bytes| try std.testing.expectEqualStrings(bytes, queue.pop().?.bytes);
    try std.testing.expectEqual(@as(usize, 0), queue.queued_bytes);
    try std.testing.expect(queue.pop() == null);
    try queue.ensureAvailable(8, first.len);
}

test "MQTT pending packets reject byte accounting overflow without allocation" {
    const allocator = std.testing.allocator;
    var queue = State{ .queued_bytes = std.math.maxInt(usize) - 4 };
    defer queue.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.TooManyPendingPackets, queue.append(failing.allocator(), borrowed(first), 8, std.math.maxInt(usize)));
    try std.testing.expectEqual(std.math.maxInt(usize) - 4, queue.queued_bytes);
    try std.testing.expect(!failing.has_induced_failure);
}

fn allocationLifecycle(allocator: std.mem.Allocator) !void {
    var queue: State = .{};
    defer queue.deinit(allocator);
    for ([_][]const u8{ first, second, third }) |bytes| {
        var packet = try owned(allocator, bytes);
        errdefer packet.deinit(allocator);
        try queue.append(allocator, packet, 4, 100);
    }
    var popped = queue.pop().?;
    defer popped.deinit(allocator);
    queue.retainOverflow(try owned(allocator, fourth));
    try std.testing.expectEqualStrings(first, popped.bytes);
    try std.testing.expectEqual(@as(usize, 3), queue.count());
}

test "MQTT pending packets release owned prefix and overflow under allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationLifecycle, .{});
}

test "MQTT pending packets leave bytes uncharged after append allocation failure" {
    const allocator = std.testing.allocator;
    var queue: State = .{};
    defer queue.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, queue.append(failing.allocator(), borrowed(first), 8, first.len));
    try std.testing.expectEqual(@as(usize, 0), queue.queued_bytes);
    queue.retainOverflow(borrowed(first));
    try std.testing.expectEqualStrings(first, queue.pop().?.bytes);
    try queue.ensureAvailable(8, first.len);
}
