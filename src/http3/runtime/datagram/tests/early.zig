const std = @import("std");
const datagram = @import("../../datagram.zig");

test "HTTP/3 early CONNECT datagrams promote in order under accepted queue limits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var registry = datagram.Registry.initWithEarly(std.testing.allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, threaded.io(), .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x01one");
    try registry.route("\x00sibling");
    try registry.route("\x01two");
    try registry.route("\x01three");
    try std.testing.expectEqual(@as(usize, 0), registry.associationCount());
    try registry.register(4);
    try std.testing.expectEqual(@as(usize, 2), try registry.queuedCount(4));
    var output: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooShort, registry.pollInto(4, output[0..1]));
    try std.testing.expectEqualStrings("two", (try registry.pollInto(4, &output)).?);
    try std.testing.expectEqualStrings("three", (try registry.pollInto(4, &output)).?);
    try registry.register(0);
    try std.testing.expectEqualStrings("sibling", (try registry.pollInto(0, &output)).?);
    registry.unregister(4);
    try registry.route("\x01late");
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.count(4));
}

test "HTTP/3 early CONNECT datagrams discard rejection expiry and connection close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var registry = datagram.Registry.initWithEarly(std.testing.allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, threaded.io(), .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x00denied");
    try registry.route("\x01sibling");
    try registry.rejectEarlyAssociation(0);
    try registry.route("\x00late");
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.count(0));
    try std.testing.expectEqual(@as(usize, 1), registry.early_datagrams.count(4));
    const now_ns = std.Io.Clock.awake.now(threaded.io()).nanoseconds;
    registry.early_datagrams.expireAt(std.testing.allocator, now_ns + registry.early_datagrams.limits.max_age.nanoseconds);
    try registry.register(4);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(4));
    try registry.route("\x02closing");
    registry.markAllTerminal(.connection_closed);
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.entries.items.len);
}

fn allocationRegistration(allocator: std.mem.Allocator, io: std.Io) !void {
    var registry = datagram.Registry.initWithEarly(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, io, .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x01one");
    try registry.route("\x01two");
    registry.register(4) catch |err| {
        try std.testing.expect(!registry.contains(4));
        try std.testing.expectEqual(@as(usize, 2), registry.early_datagrams.count(4));
        return err;
    };
    var output: [16]u8 = undefined;
    try std.testing.expectEqualStrings("one", (try registry.pollInto(4, &output)).?);
    try std.testing.expectEqualStrings("two", (try registry.pollInto(4, &output)).?);
}

test "HTTP/3 early CONNECT datagram reservation rolls back and commits without reordering" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var registry = datagram.Registry.initWithEarly(std.testing.allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, threaded.io(), .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x01one");
    try registry.route("\x01two");
    try registry.reserve(4);
    try registry.route("\x01middle");
    registry.unregister(4);
    try std.testing.expectEqual(@as(usize, 3), registry.early_datagrams.count(4));
    try std.testing.expect(!registry.early_datagrams.known.contains(1));
    try registry.route("\x01last");
    try registry.reserve(4);
    try registry.route("\x01newest");
    try registry.markStreamDetached(4);
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.count(4));
    var output: [16]u8 = undefined;
    try std.testing.expectEqualStrings("last", (try registry.pollInto(4, &output)).?);
    try std.testing.expectEqualStrings("newest", (try registry.pollInto(4, &output)).?);
    registry.unregister(4);
    try registry.route("\x01late");
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.count(4));
}

test "HTTP/3 early CONNECT datagrams expire while acceptance is pending" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var registry = datagram.Registry.initWithEarly(std.testing.allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, threaded.io(), .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x01early");
    try registry.reserve(4);
    registry.early_datagrams.entries.items[0].received_ns -= registry.early_datagrams.limits.max_age.nanoseconds;
    try registry.markStreamDetached(4);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(4));
    try std.testing.expectEqual(@as(usize, 0), registry.early_datagrams.entries.items.len);
}

fn allocationReservation(allocator: std.mem.Allocator, io: std.Io) !void {
    var registry = datagram.Registry.initWithEarly(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    }, io, .{ .max_datagrams = 8, .max_bytes = 128 });
    defer registry.deinit();
    try registry.route("\x01one");
    registry.reserve(4) catch |err| {
        try std.testing.expect(!registry.contains(4));
        try std.testing.expectEqual(@as(usize, 1), registry.early_datagrams.count(4));
        return err;
    };
    registry.unregister(4);
    try std.testing.expectEqual(@as(usize, 1), registry.early_datagrams.count(4));
    try std.testing.expect(!registry.early_datagrams.known.contains(1));
    try registry.reserve(4);
    try registry.markStreamDetached(4);
    var output: [16]u8 = undefined;
    try std.testing.expectEqualStrings("one", (try registry.pollInto(4, &output)).?);
}

test "HTTP/3 early CONNECT datagram promotion is transactional on allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRegistration, .{threaded.io()});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationReservation, .{threaded.io()});
}
