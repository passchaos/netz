const std = @import("std");
const runtime = @import("../../runtime.zig");
const cleanup = @import("cleanup.zig");
const allocator = std.testing.allocator;

test "WebSocket fatal receive cleanup keeps expired cancellation pending without renewing budget" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var connection = runtime.Connection{ .allocator = allocator, .io = io, .stream = undefined, .role = .client };
    try connection.compression_send.payload.appendSlice(allocator, "owned output");
    cleanup.request(&connection);
    const Probe = struct {
        var calls: usize = 0;
        var before: ?std.Io.Clock.Timestamp = null;
        fn abort(_: *runtime.Connection, deadline: ?std.Io.Clock.Timestamp) bool {
            calls += 1;
            before = deadline;
            return calls == 2;
        }
    };
    Probe.calls = 0;
    cleanup.finishLocked(&connection, io, .{ .clock = .awake, .raw = .fromNanoseconds(0) }, true, Probe.abort);
    try std.testing.expectEqual(@as(usize, 0), Probe.calls);
    try std.testing.expectEqual(@as(usize, 0), connection.compression_send.payload.capacity);
    try std.testing.expect(connection.receive_abort_pending.load(.acquire));
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    cleanup.finishLocked(&connection, io, until, true, Probe.abort);
    try std.testing.expectEqual(@as(usize, 1), Probe.calls);
    try std.testing.expectEqualDeep(@as(?std.Io.Clock.Timestamp, until), Probe.before);
    try std.testing.expect(connection.receive_abort_pending.load(.acquire));
    cleanup.finishLocked(&connection, io, until, true, Probe.abort);
    try std.testing.expectEqual(@as(usize, 2), Probe.calls);
    try std.testing.expectEqualDeep(@as(?std.Io.Clock.Timestamp, until), Probe.before);
    try std.testing.expect(!connection.receive_abort_pending.load(.acquire));
}
