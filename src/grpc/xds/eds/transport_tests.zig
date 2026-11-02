const std = @import("std");
const grpc = @import("../../mod.zig");
const target = @import("target.zig");
const fixture = @import("testing.zig");
const allocator = std.testing.allocator;
const Peer = @import("../../channel/shared/weighted_target/test_support.zig").Peer;
fn call(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Eds/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}

test "gRPC EDS publication owns target strings after caller release and reuses backend connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(Peer.run, .{ &server, &stop, "reply", null });
    defer _ = peer.cancel(io) catch {};
    var client = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const bytes = try fixture.encode(allocator, "backend", &.{.{ .region = "a", .weight = 1, .endpoints = &.{.{ .port = server.address().getPort() }} }}, null);
    defer allocator.free(bytes);
    const first = try target.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost" });
    _ = try first.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    first.release(); // Channel/source references must now own all paths/keys.
    var warm = try call(sender);
    defer warm.deinit();
    try std.testing.expectEqualStrings("reply", warm.message.?.payload);
    const source = client.state.sources[0];
    const worker = source.current[0];
    const second = try target.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost" });
    _ = try second.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    second.release();
    try std.testing.expect(client.state.sources[0] == source and source.current[0] == worker);
    var again = try call(sender);
    defer again.deinit();
    try std.testing.expectEqualStrings("reply", again.message.?.payload);
    // Keeping the target on a config-only update must retain its snapshot too.
    _ = try client.updateWithTimeout(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"round_robin\":{}}]}" } }, .fromSeconds(3));
    var ordinary = try call(sender);
    defer ordinary.deinit();
    try std.testing.expectEqualStrings("reply", ordinary.message.?.payload);
    client.deinit();
    live = false;
    stop.set(io);
    try peer.await(io);
}

test "gRPC EDS multi-address endpoint races to a healthy alternate under one deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(Peer.run, .{ &server, &stop, "alternate", null });
    defer _ = peer.cancel(io) catch {};
    const bytes = try fixture.encode(allocator, "backend", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1, .extra_port = server.address().getPort() }} }}, null);
    defer allocator.free(bytes);
    const snapshot = try target.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost" });
    var snapshot_live = true;
    defer if (snapshot_live) snapshot.release();
    try std.testing.expect(snapshot.endpoints[0] == .custom);
    var client = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var live = true;
    defer if (live) client.deinit();
    _ = try snapshot.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    snapshot.release();
    snapshot_live = false;
    var sender = client.sender();
    defer sender.deinit();
    var response = try call(sender);
    defer response.deinit();
    try std.testing.expectEqualStrings("alternate", response.message.?.payload);
    client.deinit();
    live = false;
    stop.set(io);
    try peer.await(io);
}

test "gRPC EDS publication failure retains old target and releases provisional resource references" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var client = try grpc.SharedChannel.init(failing.allocator(), io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    const bytes = try fixture.encode(allocator, "backend", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer allocator.free(bytes);
    const snapshot = try target.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost" });
    defer snapshot.release();
    const revision = client.configurationRevision();
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, snapshot.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(revision, client.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), snapshot.refs.load(.acquire));
    try std.testing.expect(client.state.target_lifetime == null);
}
