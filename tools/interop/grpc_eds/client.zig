//! Validate and publish EDS resources received from an independent ADS service.
const std = @import("std");
const netz = @import("netz");
const eds = netz.grpc.xds.eds;
const ads = netz.grpc.xds.ads;
const allocator = std.heap.c_allocator;
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn call(sender: netz.grpc.SharedChannelSender) !netz.grpc.UnaryResponse {
    return sender.unary(.{ .path = "/fixture.Eds/Unary", .authority = "backend.test", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
fn count(sender: netz.grpc.SharedChannelSender, amount: usize) ![4]usize {
    var counts = [_]usize{ 0, 0, 0, 0 };
    for (0..amount) |_| {
        var response = try call(sender);
        defer response.deinit();
        const payload = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, payload, "a1")) 0 else if (std.mem.eql(u8, payload, "a2")) 1 else if (std.mem.eql(u8, payload, "b")) 2 else if (std.mem.eql(u8, payload, "fallback")) 3 else return error.UnexpectedBackend;
        counts[index] += 1;
    }
    return counts;
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var control = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var discovery = try ads.Client.init(allocator, control_sender, .{ .node = .{ .id = "netz-eds-node" } });
    defer discovery.deinit();
    try discovery.setSubscription(eds.type_url, &.{"backend"});
    try discovery.connectWithDeadline(until(io));
    var destination = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    const options: eds.TargetOptions = .{ .authority = "backend.test" };
    var first = try discovery.nextWithDeadline(until(io));
    defer first.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, first.update, "backend", destination, options, .{}, until(io));
    // Ensure all primary backends have connected before measuring ratios.
    destination.connect();
    for (0..3) |index| {
        var watch = destination.watchEndpointConnectivity(index).?;
        defer watch.deinit();
        while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
    }
    const before = try count(sender, 400);
    try std.testing.expect(before[2] > 240 and before[2] < 360 and before[3] == 0);
    const diff = if (before[0] > before[1]) before[0] - before[1] else before[1] - before[0];
    try std.testing.expect(diff <= 1);
    try discovery.setSubscription(eds.type_url, &.{ "backend", "phase-bad" });
    _ = try discovery.flushWithDeadline(until(io));
    var invalid = try discovery.nextWithDeadline(until(io));
    defer invalid.deinit();
    const revision = destination.configurationRevision();
    try std.testing.expectError(error.InvalidEdsResource, eds.publishUpdateWithDeadline(&discovery, invalid.update, "backend", destination, options, .{}, until(io)));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings("v1", discovery.acceptedVersion(eds.type_url).?);
    try discovery.rejectWithDeadline(invalid.update, .{ .message = "duplicate locality" }, until(io));
    var fallback = try discovery.nextWithDeadline(until(io));
    defer fallback.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, fallback.update, "backend", destination, options, .{}, until(io));
    const failed_over = try count(sender, 20);
    try std.testing.expectEqual(@as(usize, 20), failed_over[3]);
    try discovery.setSubscription(eds.type_url, &.{ "backend", "phase-restore" });
    _ = try discovery.flushWithDeadline(until(io));
    var restored = try discovery.nextWithDeadline(until(io));
    defer restored.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, restored.update, "backend", destination, options, .{}, until(io));
    const after = try count(sender, 400);
    try std.testing.expect(after[0] + after[1] > 240 and after[0] + after[1] < 360 and after[3] == 0);
    try discovery.setSubscription(eds.type_url, &.{ "backend", "phase-delete" });
    _ = try discovery.flushWithDeadline(until(io));
    var deleted = try discovery.nextWithDeadline(until(io));
    defer deleted.deinit();
    _ = try eds.publishUpdateWithDeadline(&discovery, deleted.update, "backend", destination, options, .{}, until(io));
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/fixture.Eds/Unary", .message = "request", .wait_for_ready = false }));
    try std.testing.expectEqualStrings("v4", discovery.acceptedVersion(eds.type_url).?);
    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(netz.grpc.Status.ok, terminal.terminal.status);
    std.debug.print("EDS_RESULT {{\"status\":\"passed\",\"before\":[{d},{d},{d},{d}],\"fallback\":[{d},{d},{d},{d}],\"after\":[{d},{d},{d},{d}],\"nack_preserved\":true,\"deleted\":true}}\n", .{ before[0], before[1], before[2], before[3], failed_over[0], failed_over[1], failed_over[2], failed_over[3], after[0], after[1], after[2], after[3] });
}
