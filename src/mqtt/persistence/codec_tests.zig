//! Property blobs append transactionally into caller-reserved snapshot storage.
const std = @import("std");
const codec = @import("codec.zig");
const mqtt = @import("../mod.zig");
const prefix = "unchanged-prefix";

test "MQTT persistence property blob uses a reserved destination without allocating" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, 256);
    try out.appendSlice(allocator, prefix);
    const before = failing.alloc_index;
    failing.fail_index = before;
    const metadata = [_]u8{0xa7} ** 64;
    try codec.appendProperties(&out, allocator, &.{.{ .binary = .{ .id = .correlation_data, .value = &metadata } }});
    try std.testing.expectEqual(before, failing.alloc_index);
    try std.testing.expectEqualSlices(u8, prefix, out.items[0..prefix.len]);
    var cursor = codec.Cursor.init(out.items[prefix.len..]);
    const properties = try cursor.readProperties(std.testing.allocator);
    defer std.testing.allocator.free(properties);
    try cursor.finish();
    try std.testing.expectEqual(@as(usize, 1), properties.len);
    try std.testing.expectEqual(mqtt.PropertyId.correlation_data, properties[0].binary.id);
    try std.testing.expectEqualSlices(u8, &metadata, properties[0].binary.value);
}

test "MQTT persistence property blob preserves existing bytes on validation failure" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try out.appendSlice(std.testing.allocator, prefix);
    try std.testing.expectError(error.InvalidUtf8, codec.appendProperties(&out, std.testing.allocator, &.{.{ .utf8 = .{ .id = .content_type, .value = "bad\x00value" } }}));
    try std.testing.expectEqualSlices(u8, prefix, out.items);
}

test "MQTT persistence property blob rolls back partial allocation failure" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(allocator);
            try out.appendSlice(allocator, prefix);
            const metadata = [_]u8{0x31} ** 1024;
            codec.appendProperties(&out, allocator, &.{.{ .binary = .{ .id = .correlation_data, .value = &metadata } }}) catch |err| {
                try std.testing.expectEqualSlices(u8, prefix, out.items);
                return err;
            };
            var cursor = codec.Cursor.init(out.items[prefix.len..]);
            const encoded = try cursor.readBlob();
            try std.testing.expect(encoded.len > metadata.len);
            try cursor.finish();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{});
}
