const std = @import("std");
const mod = @import("reader.zig");
const Capsule = @import("capsule.zig").Capsule;

test "WebTransport HTTP2 reader resumes every fragmented envelope and payload boundary" {
    const capsule = Capsule{ .stream = .{ .id = 16384, .data = "fragmented", .fin = true } };
    var bytes: [64]u8 = undefined;
    const wire = try capsule.writeInto(&bytes);
    for (1..wire.len) |split| {
        var reader = mod.Reader.init(std.testing.allocator, 64);
        defer reader.deinit();
        var first: []const u8 = wire[0..split];
        try std.testing.expect((try reader.next(&first)) == null);
        try std.testing.expectEqual(@as(usize, 0), first.len);
        try std.testing.expectError(error.InvalidCapsule, reader.finish());
        var rest: []const u8 = wire[split..];
        const result = (try reader.next(&rest)).?;
        try std.testing.expectEqualDeep(capsule, result);
        try std.testing.expectEqual(@as(usize, 0), rest.len);
        try reader.finish();
    }
}

test "WebTransport HTTP2 reader skips unknown capsules without allocation before a known successor" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var reader = mod.Reader.init(failing.allocator(), 0);
    defer reader.deinit();
    const unknown: []const u8 = &.{ 0x21, 6, 1, 2, 3, 4, 5, 6 };
    var first: []const u8 = unknown[0..4];
    try std.testing.expect((try reader.next(&first)) == null);
    try std.testing.expectError(error.InvalidCapsule, reader.finish());
    var remaining: []const u8 = unknown[4..];
    try std.testing.expect((try reader.next(&remaining)) == null);
    try reader.finish();
    var storage: [16]u8 = undefined;
    var drain: []const u8 = try (@as(Capsule, .drain_session)).writeInto(&storage);
    const result = (try reader.next(&drain)).?;
    try std.testing.expect(result == .drain_session);
    try std.testing.expect(!failing.has_induced_failure);
}

test "WebTransport HTTP2 reader keeps the body cursor retryable after allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var reader = mod.Reader.init(failing.allocator(), 64);
    defer reader.deinit();
    var wire: []const u8 = &.{ 0x99, 0x0b, 0x4d, 0x3b, 4, 4, 'a', 'b', 'c' };
    try std.testing.expectError(error.OutOfMemory, reader.next(&wire));
    try std.testing.expectEqualSlices(u8, &.{ 4, 'a', 'b', 'c' }, wire);
    failing.fail_index = std.math.maxInt(usize);
    const result = (try reader.next(&wire)).?;
    try std.testing.expectEqualDeep(Capsule{ .stream = .{ .id = 4, .data = "abc", .fin = true } }, result);
    try std.testing.expectEqual(@as(usize, 0), wire.len);
    try reader.finish();
}

test "WebTransport HTTP2 reader rejects excessive declared payload before body allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var reader = mod.Reader.init(failing.allocator(), 3);
    defer reader.deinit();
    var wire: []const u8 = &.{ 0x99, 0x0b, 0x4d, 0x3c, 4, 4, 'a', 'b', 'c' };
    try std.testing.expectError(error.CapsuleTooLarge, reader.next(&wire));
    try std.testing.expectEqualSlices(u8, &.{ 4, 'a', 'b', 'c' }, wire);
    try std.testing.expect(!failing.has_induced_failure);
}

test "WebTransport HTTP2 reader yields each consecutive capsule and preserves FIN boundaries" {
    var reader = mod.Reader.init(std.testing.allocator, 64);
    defer reader.deinit();
    var bytes: [64]u8 = undefined;
    const first = try (Capsule{ .stream = .{ .id = 0, .data = "one" } }).writeInto(&bytes);
    const second = try (Capsule{ .datagram = "two" }).writeInto(bytes[first.len..]);
    var all: []const u8 = bytes[0 .. first.len + second.len];
    try std.testing.expectEqualDeep(Capsule{ .stream = .{ .id = 0, .data = "one" } }, (try reader.next(&all)).?);
    try std.testing.expectEqualDeep(Capsule{ .datagram = "two" }, (try reader.next(&all)).?);
    try std.testing.expect((try reader.next(&all)) == null);
    try reader.finish();
}

test "WebTransport HTTP2 reader retains malformed payload failure across later input and FIN" {
    var reader = mod.Reader.init(std.testing.allocator, 64);
    defer reader.deinit();
    var invalid: []const u8 = &.{ 0x99, 0x0b, 0x4d, 0x3a, 1, 0 };
    try std.testing.expectError(error.InvalidCapsule, reader.next(&invalid));
    try std.testing.expectError(error.InvalidCapsule, reader.finish());
    var successor: []const u8 = &.{ 0, 0 };
    try std.testing.expectError(error.InvalidCapsule, reader.next(&successor));
    try std.testing.expectEqual(@as(usize, 2), successor.len);
}

test "WebTransport HTTP2 reader skips padding and eight-byte unknown lengths without allocating" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var reader = mod.Reader.init(failing.allocator(), 0);
    defer reader.deinit();
    var padding: []const u8 = &.{ 0x99, 0x0b, 0x4d, 0x38, 4, 0, 0, 0, 0 };
    try std.testing.expect((try reader.next(&padding)) == null);
    try reader.finish();
    var unknown: []const u8 = &.{ 0x21, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3 };
    try std.testing.expect((try reader.next(&unknown)) == null);
    try std.testing.expectEqual(@as(usize, 0), unknown.len);
    try std.testing.expectError(error.InvalidCapsule, reader.finish());
    try std.testing.expect(!failing.has_induced_failure);
}
