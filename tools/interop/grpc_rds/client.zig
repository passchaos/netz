//! RDS through ADS into automatic shared unary/duplex dispatch.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const ads = grpc.xds.ads;
const rds = grpc.xds.rds;
const allocator = std.heap.c_allocator;
const config = "{\"retryThrottling\":{\"maxTokens\":4,\"tokenRatio\":0.1},\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]},\"cluster:b\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn apply(client: *ads.Client, destination: grpc.SharedChannel, io: std.Io) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    _ = try rds.publishUpdateWithDeadline(client, event.update, "routes", destination, .{ .authority = "backend.test" }, .{}, until(io));
}
fn call(sender: grpc.SharedChannelSender, path: []const u8, metadata: []const netz.http2.Hpack.HeaderField) !grpc.UnaryResponse {
    return sender.unary(.{ .path = path, .authority = "backend.test", .message = "request", .metadata = metadata, .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
fn held(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return call(sender, "/fixture.Rds/Hold", &.{});
}
fn reject(client: *ads.Client, destination: grpc.SharedChannel, io: std.Io, expected: rds.Error) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    const revision = destination.configurationRevision();
    try std.testing.expectError(expected, rds.publishUpdateWithDeadline(client, event.update, "routes", destination, .{ .authority = "backend.test" }, .{}, until(io)));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(rds.type_url).?);
    try client.rejectWithDeadline(event.update, .{ .message = @errorName(expected) }, until(io));
}
fn noRoute(sender: grpc.SharedChannelSender) !void {
    var response = try call(sender, "/missing.Service/Unary", &.{});
    defer response.deinit();
    try std.testing.expect(response.status == .unavailable and response.transport == null and response.message == null and !response.was_dropped);
    try std.testing.expectError(error.NoMatchingRoute, sender.startDuplex(.{ .path = "/missing.Service/Stream", .authority = "backend.test", .timeout = .{ .value = 1, .unit = .second } }));
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var control = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var discovery = try ads.Client.init(allocator, control_sender, .{ .node = .{ .id = "netz-rds-node" } });
    defer discovery.deinit();
    try discovery.setSubscription(rds.type_url, &.{"routes"});
    try discovery.connectWithDeadline(until(io));
    var endpoints: [2]grpc.ChannelEndpoint = undefined;
    for (&endpoints, args[2..], 0..) |*endpoint, port, index| endpoint.* = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, port, 10)) }, .hierarchical_path = if (index == 0) &.{"cluster:a"} else &.{"cluster:b"} } };
    var destination = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = config });
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    try apply(&discovery, destination, io);
    const storage = destination.state.config.load(.acquire).?.storage;
    destination.connect();
    for (0..2) |index| {
        var watch = destination.watchEndpointConnectivity(index).?;
        defer watch.deinit();
        while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
    }
    for (0..20) |_| {
        var response = try call(sender, "/fixture.Rds/Unary", &.{ .{ .name = "x-route", .value = "b" }, .{ .name = "x-key", .value = "client" } });
        defer response.deinit();
        try std.testing.expectEqualStrings("b", response.message.?.payload);
    }
    var weights = [_]usize{ 0, 0 };
    for (0..400) |_| {
        var response = try call(sender, "/fixture.Rds/Weighted", &.{});
        defer response.deinit();
        const label = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, label, "a")) 0 else if (std.mem.eql(u8, label, "b")) 1 else return error.InvalidBackend;
        weights[index] += 1;
    }
    try std.testing.expect(weights[1] > 240 and weights[1] < 360);
    {
        var duplex = try sender.startDuplex(.{ .path = "/fixture.Rds/Stream", .authority = "backend.test", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
        defer duplex.deinit();
        var writer = duplex.writer();
        defer writer.deinit();
        var reader = duplex.reader();
        defer reader.deinit();
        try writer.writeFinalMessage("request");
        var seen: usize = 0;
        while (true) {
            var event = try reader.nextWithTimeout(.fromSeconds(3));
            defer event.deinit(allocator);
            switch (event) {
                .message => |message| {
                    try std.testing.expectEqualStrings("b", message.payload);
                    seen += 1;
                },
                .terminal => |terminal| {
                    try std.testing.expectEqual(grpc.Status.ok, terminal.status);
                    try std.testing.expectEqual(@as(usize, 1), seen);
                    break;
                },
                else => {},
            }
        }
    }
    var retry = try call(sender, "/fixture.Rds/Retry", &.{});
    defer retry.deinit();
    try std.testing.expectEqualStrings("b", retry.message.?.payload);
    const throttle_tokens = destination.state.config.load(.acquire).?.config.retry_throttler.?.milli_tokens.load(.acquire);
    try std.testing.expectEqual(@as(u64, 3100), throttle_tokens);
    const started = std.Io.Clock.awake.now(io);
    var timed_out = false;
    var slow: ?grpc.UnaryResponse = call(sender, "/fixture.Rds/Slow", &.{}) catch |err| blk: {
        try std.testing.expect(err == error.Timeout);
        timed_out = true;
        break :blk null;
    };
    if (slow) |*response| {
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.deadline_exceeded, response.status);
    }
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 150 * std.time.ns_per_ms);
    try noRoute(sender);
    try discovery.setSubscription(rds.type_url, &.{ "routes", "phase-bad" });
    _ = try discovery.flushWithDeadline(until(io));
    try reject(&discovery, destination, io, error.InvalidRdsResource);
    try reject(&discovery, destination, io, error.DuplicateRdsResource);
    try reject(&discovery, destination, io, error.UnsupportedRdsFeature);
    var old = try io.concurrent(held, .{sender});
    defer _ = old.cancel(io) catch {};
    try apply(&discovery, destination, io);
    try std.testing.expect(destination.state.config.load(.acquire).?.storage == storage);
    for (0..20) |_| {
        var response = try call(sender, "/fixture.Rds/After", &.{});
        defer response.deinit();
        try std.testing.expectEqualStrings("b", response.message.?.payload);
    }
    var release = try call(sender, "/fixture.Rds/Release", &.{});
    defer release.deinit();
    var previous = try old.await(io);
    defer previous.deinit();
    try std.testing.expectEqualStrings("a", previous.message.?.payload);
    try discovery.setSubscription(rds.type_url, &.{ "routes", "phase-delete" });
    _ = try discovery.flushWithDeadline(until(io));
    try apply(&discovery, destination, io);
    try std.testing.expectEqualStrings("v3", discovery.acceptedVersion(rds.type_url).?);
    try noRoute(sender);
    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("RDS_RESULT {{\"status\":\"passed\",\"weighted\":[{d},{d}],\"nacks\":3,\"timeout\":true,\"local_timeout\":{},\"throttle_tokens\":{d},\"stream\":true,\"storage_reused\":true,\"old_route_completed\":true,\"deleted\":true}}\n", .{ weights[0], weights[1], timed_out, throttle_tokens });
}
