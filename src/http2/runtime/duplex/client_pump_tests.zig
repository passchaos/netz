const std = @import("std");
const Fixture = @import("testing.zig").Fixture;
const allocator = std.testing.allocator;

test "HTTP2 idle client pump applies zero and restored stream capacity" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    try fixture.frame(.settings, 0, 0, &.{ 0, 3, 0, 0, 0, 0 });
    // The existing handle-driven API still requires a registered handle.
    try std.testing.expectError(error.UnexpectedFrame, fixture.connection.pumpClientDuplexWithDeadline(until));
    try std.testing.expect((try fixture.connection.pumpClientWithDeadline(until)) == .progress);
    try std.testing.expectEqual(@as(?u32, 0), fixture.connection.availableLocalStreamCapacity());
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try fixture.frame(.settings, 0, 0, &.{ 0, 3, 0, 0, 0, 1 });
    try std.testing.expect((try fixture.connection.pumpClientWithDeadline(until)) == .progress);
    try std.testing.expectEqual(@as(?u32, 1), fixture.connection.availableLocalStreamCapacity());
    var stream = try fixture.open();
    defer stream.deinit();
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeLocalStreamCount());
}

test "HTTP2 idle client pump expires without consuming input and resumes after read timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    try std.testing.expectError(error.Timeout, fixture.connection.pumpClientWithTimeout(.fromMilliseconds(10)));
    try fixture.frame(.settings, 0, 0, &.{ 0, 3, 0, 0, 0, 1 });
    try std.testing.expectError(error.Timeout, fixture.connection.pumpClientWithTimeout(.fromNanoseconds(-1)));
    try std.testing.expectError(error.Timeout, fixture.connection.pumpClientWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectEqual(@as(?u32, null), fixture.connection.peerMaxConcurrentStreams());
    try std.testing.expect((try fixture.connection.pumpClientWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }))) == .progress);
    try std.testing.expectEqual(@as(?u32, 1), fixture.connection.peerMaxConcurrentStreams());
}
