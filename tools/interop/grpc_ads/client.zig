//! ADS lifecycle against an independent official protobuf/gRPC server.
const std = @import("std");
const netz = @import("netz");
const ads = netz.grpc.xds.ads;
const allocator = std.heap.c_allocator;
const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const eds = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}
fn update(client: *ads.Client, io: std.Io, type_url: []const u8, version: []const u8) !ads.Event {
    var event = try client.nextWithDeadline(until(io));
    errdefer event.deinit();
    try std.testing.expect(event == .update);
    try std.testing.expectEqualStrings(type_url, event.update.response.value.type_url);
    try std.testing.expectEqualStrings(version, event.update.response.value.version);
    return event;
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var channel = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(allocator, sender, .{ .node = .{ .id = "netz-ads-node", .cluster = "interop-client", .metadata = "\x0a\x0a\x0a\x04role\x12\x02\x20\x01", .locality = .{ .region = "region", .zone = "zone", .sub_zone = "sub" }, .client_features = &.{"envoy.lb.does_not_support_overprovisioning"} } });
    defer client.deinit();
    try client.setSubscription(cds, &.{"a"});
    try client.setSubscription(eds, &.{"a"});
    try client.connectWithDeadline(until(io));
    var c1 = try update(&client, io, cds, "c1");
    defer c1.deinit();
    try std.testing.expect(c1.update.resourcesMatchType());
    try std.testing.expectEqualSlices(u8, "\x0a\x01a", c1.update.response.value.resources[0].value);
    try client.setSubscription(cds, &.{ "b", "a" });
    try std.testing.expectEqual(@as(usize, 0), try client.flushWithDeadline(until(io)));
    try client.acknowledgeWithDeadline(c1.update, until(io));
    var e1 = try update(&client, io, eds, "e1");
    defer e1.deinit();
    try client.acknowledgeWithDeadline(e1.update, until(io));
    var bad = try update(&client, io, cds, "bad");
    defer bad.deinit();
    try std.testing.expect(!bad.update.resourcesMatchType());
    try std.testing.expectError(error.InvalidDiscoveryMessage, client.acknowledgeWithDeadline(bad.update, until(io)));
    try client.rejectWithDeadline(bad.update, .{ .message = "resource type mismatch" }, until(io));
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds).?);
    var c2 = try update(&client, io, cds, "c2");
    defer c2.deinit();
    var c3 = try update(&client, io, cds, "c3");
    defer c3.deinit();
    try std.testing.expectError(error.StaleDiscoveryResponse, client.acknowledgeWithDeadline(c2.update, until(io)));
    try client.acknowledgeWithDeadline(c3.update, until(io));
    var terminal = try client.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(netz.grpc.Status.unavailable, terminal.terminal.status);
    try client.connectWithTimeout(.fromMilliseconds(50));
    try std.testing.expectError(error.StaleDiscoveryResponse, client.acknowledgeWithDeadline(c3.update, until(io)));
    // Timeout is local to this poll and leaves the live long-lived stream intact.
    try std.testing.expectError(error.Timeout, client.nextWithTimeout(.fromMilliseconds(10)));
    var e2 = try update(&client, io, eds, "e2");
    defer e2.deinit();
    try client.acknowledgeWithDeadline(e2.update, until(io));
    var done = try client.nextWithDeadline(until(io));
    defer done.deinit();
    try std.testing.expectEqual(netz.grpc.Status.ok, done.terminal.status);
    try std.testing.expectEqualStrings("c3", client.acceptedVersion(cds).?);
    try std.testing.expectEqualStrings("e2", client.acceptedVersion(eds).?);
    std.debug.print("ADS_RESULT {{\"status\":\"passed\",\"ack\":true,\"nack\":true,\"latest_nonce\":true,\"multi_type\":true,\"replay\":true,\"bounded_open_lifetime\":true,\"local_read_timeout\":true}}\n", .{});
}
