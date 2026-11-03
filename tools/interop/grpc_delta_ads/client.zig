//! Delta ADS transport against an independent official-schema peer.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const xds = grpc.xds;
const delta = xds.ads.delta;
const gpa = std.heap.c_allocator;

const cds = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const eds = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";

fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "netz-delta-xds" } });
    defer client.deinit();

    try client.setSubscription(cds, &.{ "b", "a" });
    try client.connectWithDeadline(until(io));
    var first = try client.nextWithDeadline(until(io));
    defer first.deinit();
    try std.testing.expect(first == .update and first.update.resourcesMatchType());
    try std.testing.expectEqual(@as(usize, 2), first.update.response.value.resources.len);
    try std.testing.expectEqualStrings("v1", first.update.response.value.resources[0].version);
    try std.testing.expectEqualStrings("v2", first.update.response.value.resources[1].version);
    try client.acknowledgeWithDeadline(first.update, until(io));
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(cds, "a").?);
    try std.testing.expectEqualStrings("v2", client.acceptedVersion(cds, "b").?);

    try client.setSubscription(cds, &.{ "a", "c" });
    try std.testing.expectEqual(@as(usize, 1), try client.flushWithDeadline(until(io)));
    var changed = try client.nextWithDeadline(until(io));
    defer changed.deinit();
    try std.testing.expectEqualStrings("v3", changed.update.response.value.resources[0].version);
    try std.testing.expectEqualStrings("b", changed.update.response.value.removed[0]);
    try client.acceptAppliedUpdate(changed.update);
    try std.testing.expectEqual(@as(usize, 1), try client.flushWithDeadline(until(io)));
    try std.testing.expect(client.acceptedVersion(cds, "b") == null);
    try std.testing.expectEqualStrings("v3", client.acceptedVersion(cds, "c").?);

    var invalid = try client.nextWithDeadline(until(io));
    defer invalid.deinit();
    try std.testing.expect(!invalid.update.resourcesMatchType());
    try client.rejectWithDeadline(invalid.update, .{ .message = "wrong type" }, until(io));

    var terminal = try client.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    try client.connectWithTimeout(.fromMilliseconds(50));

    var heartbeat = try client.nextWithDeadline(until(io));
    defer heartbeat.deinit();
    try std.testing.expect(heartbeat == .update and heartbeat.update.resourcesMatchType());
    try std.testing.expectEqual(@as(usize, 1), heartbeat.update.response.value.resources.len);
    try std.testing.expect(heartbeat.update.response.value.resources[0].resource == null);
    try std.testing.expectEqual(@as(u64, std.time.ns_per_s), try heartbeat.update.response.value.resources[0].ttl.?.nanoseconds());
    try client.acknowledgeWithDeadline(heartbeat.update, until(io));
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(cds, "a").?);

    var ended = try client.nextWithDeadline(until(io));
    defer ended.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ended.terminal.status);
    std.debug.print("DELTA_RESULT {{\"status\":\"passed\",\"subscribe_diff\":true,\"unsubscribe_diff\":true,\"version_apply\":true,\"explicit_removal\":true,\"nack_retained\":true,\"reconnect_versions\":true,\"ttl_heartbeat\":true}}\n", .{});
}
