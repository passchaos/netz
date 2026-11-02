//! Retain a sent Watch across local read interruption against Node HTTP/2.
const std = @import("std");
const netz = @import("netz");
const Probe = struct {
    base: std.Io,
    fault: ?enum { canceled, executor } = null,
    hits: usize = 0,
    var active: ?*Probe = null;
    fn read(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self = active.?;
        if (self.fault) |fault| {
            self.fault = null;
            self.hits += 1;
            return if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
        }
        return self.base.vtable.batchAwaitConcurrent(userdata, batch, timeout);
    }
};

pub fn run(allocator: std.mem.Allocator, base: std.Io, port: u16) !void {
    var probe = Probe{ .base = base };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.batchAwaitConcurrent = Probe.read;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var watch = try netz.grpc.health.ReconnectingWatch.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) } } }, .{ .watch = .{ .service = "demo.Echo", .metadata = &.{.{ .name = "x-health-read-probe", .value = "yes" }} } });
    defer watch.deinit();
    try std.testing.expectEqual(netz.grpc.health.ServingStatus.serving, (try watch.nextWithTimeout(.fromSeconds(5))).status.status);
    for (0..2) |index| {
        probe.fault = if (index == 0) .canceled else .executor;
        const result = watch.nextWithTimeout(.fromSeconds(3));
        if (index == 0) try std.testing.expectError(error.Canceled, result) else try std.testing.expectError(error.ConcurrencyUnavailable, result);
        try std.testing.expect(watch.watch != null);
        try std.testing.expect(watch.isServing());
        try std.testing.expectEqual(@as(u31, 1), watch.watch.?.stream.transport.streamId());
        try std.testing.expectEqual(@as(u31, 3), watch.owner.slots[0].connection.?.next_client_stream_id);
        try std.testing.expect(watch.retry_at == null);
    }
    try std.testing.expectEqual(@as(usize, 2), probe.hits);
    std.debug.print("netz grpc health read retained: canceled+executor same-watch=true\n", .{});
    try std.testing.expectEqual(netz.grpc.health.ServingStatus.not_serving, (try watch.nextWithTimeout(.fromSeconds(5))).status.status);
    try std.testing.expect(!watch.isServing());
    try std.testing.expectEqual(netz.grpc.health.ReconnectingWatchEvent.disabled, try watch.nextWithTimeout(.fromSeconds(5)));
    try std.testing.expect(watch.isServing());
    std.debug.print("netz grpc health read complete: watch=1 resets=0 statuses=serving+not-serving disabled=true\n", .{});
}
