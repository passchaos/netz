//! Raw-controller CSDS uses the current Envoy TIMEOUT status as well.
const std = @import("std");
const grpc = @import("../mod.zig");
const runtime = @import("runtime.zig");
const ads = @import("ads.zig");
const delta = @import("ads/delta.zig");
const lds = @import("lds.zig");
const csds = @import("csds.zig");
const decode = @import("runtime/managed/status/testing.zig").decode;
const gpa = std.testing.allocator;

fn transient(comptime is_delta: bool) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = if (is_delta) try delta.Client.init(gpa, sender, .{ .node = .{ .id = "timer" } }) else try ads.Client.init(gpa, sender, .{ .node = .{ .id = "timer" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" }, .resource_timer_is_transient_error = true });
    defer controller.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    if (is_delta) _ = try controller.startDeltaWithDeadline(&client, channel, deadline) else _ = try controller.startWithDeadline(&client, channel, deadline);
    try controller.pollResourceTimers(&client);
    try std.testing.expectEqual(@as(usize, 1), controller.resource_timers.items.len);
    controller.resource_timers.items[0].deadline.raw = .fromNanoseconds(std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds - 1);
    try controller.pollResourceTimers(&client);
    const bytes = try controller.encodeClientStatus(&client, gpa, .{});
    defer gpa.free(bytes);
    const dump = try decode(bytes);
    defer dump.deinit();
    const resource = dump.find(lds.type_url, "frontend") orelse return error.MissingResource;
    try std.testing.expectEqual(csds.ClientStatus.timeout, resource.status);
    try std.testing.expect(resource.wire.len == 0 and resource.version.len == 0);
    try std.testing.expectEqualStrings("initial resource fetch timed out", resource.error_state.?.details);
}
test "gRPC CSDS SotW reports current-schema TIMEOUT for transient initial fetch" {
    try transient(false);
}
test "gRPC CSDS delta reports current-schema TIMEOUT for transient initial fetch" {
    try transient(true);
}
