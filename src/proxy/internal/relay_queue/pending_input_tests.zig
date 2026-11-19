const std = @import("std");
const Buffer = @import("pending_input.zig").Buffer;

test "proxy pending input small requests do not allocate" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var buffer: Buffer = .{};
    defer buffer.deinit(failing.allocator());
    try buffer.append(failing.allocator(), 256 * 1024, "request");
    try std.testing.expectEqualStrings("request", buffer.bytes());
    try std.testing.expectEqual(@as(usize, 0), buffer.heap.len);
}

test "proxy pending input retains large prefixes under an exact bound" {
    var buffer: Buffer = .{};
    defer buffer.deinit(std.testing.allocator);
    var payload: [64 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    try buffer.append(std.testing.allocator, payload.len, payload[0..31]);
    try buffer.append(std.testing.allocator, payload.len, payload[31..4096]);
    try buffer.append(std.testing.allocator, payload.len, payload[4096..]);
    try std.testing.expectEqualSlices(u8, &payload, buffer.bytes());
    try std.testing.expect(buffer.heap.len <= payload.len);
    try std.testing.expectError(error.PendingBufferFull, buffer.append(std.testing.allocator, payload.len, "x"));
    try std.testing.expectEqualSlices(u8, &payload, buffer.bytes());
}

test "proxy pending input growth failure preserves the original request" {
    var buffer: Buffer = .{};
    defer buffer.deinit(std.testing.allocator);
    try buffer.append(std.testing.allocator, 64 * 1024, "request");
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const payload = [_]u8{0x5a} ** 4096;
    try std.testing.expectError(error.OutOfMemory, buffer.append(failing.allocator(), 64 * 1024, &payload));
    try std.testing.expectEqualStrings("request", buffer.bytes());
    try buffer.append(std.testing.allocator, 64 * 1024, &payload);
    try std.testing.expectEqualStrings("request", buffer.bytes()[0..7]);
    try std.testing.expectEqualSlices(u8, &payload, buffer.bytes()[7..]);
}

test "proxy pending input teardown releases grown storage and supports reuse" {
    var buffer: Buffer = .{};
    const payload = [_]u8{0x5a} ** 4096;
    try buffer.append(std.testing.allocator, 8192, &payload);
    buffer.deinit(std.testing.allocator);
    defer buffer.deinit(std.testing.allocator);
    try buffer.append(std.testing.allocator, 8192, "next");
    try std.testing.expectEqualStrings("next", buffer.bytes());
    try std.testing.expectEqual(@as(usize, 0), buffer.heap.len);
}
