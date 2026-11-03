//! Typed delta resources publish through the same transactional runtime plan.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const rds = @import("../rds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const gpa = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn update(client: *delta.Client, url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource, removed: []const []const u8) !delta.Update {
    const encoded = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = nonce, .resources = resources, .removed = removed }, .{});
    defer gpa.free(encoded);
    var response = try delta.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn accept(controller: *runtime.Controller, client: *delta.Client, channel: grpc.SharedChannel, io: std.Io, value: delta.Update) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(client, value, channel, deadline(io)));
}

fn payload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

fn heartbeat(name: []const u8, version: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version };
}

test "gRPC delta runtime applies partial EDS, removals and heartbeats" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Beta", .cluster = "b" }, .{ .prefix = "/", .cluster = "a" } }, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var value = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer value.deinit();
    try accept(controller, &client, channel, io, value);
    try std.testing.expectEqual(@as(usize, 2), controller.entries.items.len);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("b", client.subscriptions.find(cds.type_url).?.names[1]);

    const a = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(a);
    const b = try cds_fixture.cluster(gpa, "b", "eds-b", "");
    defer gpa.free(b);
    var cds_update = try update(&client, cds.type_url, "c1", &.{ payload(cds.type_url, "a", "ca1", a), payload(cds.type_url, "b", "cb1", b) }, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    try std.testing.expect(controller.entries.items[0].pending() and controller.entries.items[1].pending());
    try std.testing.expectEqualStrings("eds-a", client.subscriptions.find(eds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("eds-b", client.subscriptions.find(eds.type_url).?.names[1]);

    // The Resource envelope name must agree with the decoded payload name.
    var mismatch = try update(&client, cds.type_url, "c-bad", &.{payload(cds.type_url, "a", "bad", b)}, &.{});
    defer mismatch.deinit();
    try std.testing.expectError(error.InvalidDiscoveryMessage, controller.applyDeltaWithDeadline(&client, mismatch, channel, deadline(io)));
    try std.testing.expectEqualStrings("cb1", client.acceptedVersion(cds.type_url, "b").?);

    const ea = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(ea);
    const eb = try eds_fixture.encode(gpa, "eds-b", &.{.{ .region = "b", .endpoints = &.{.{ .port = 1002 }} }}, null);
    defer gpa.free(eb);
    var endpoints = try update(&client, eds.type_url, "e1", &.{ payload(eds.type_url, "eds-a", "ea1", ea), payload(eds.type_url, "eds-b", "eb1", eb) }, &.{});
    defer endpoints.deinit();
    try accept(controller, &client, channel, io, endpoints);
    try std.testing.expectEqual(@as(usize, 2), channel.configuredEndpointCount());
    try std.testing.expect(!controller.entries.items[0].pending() and !controller.entries.items[1].pending());
    const sibling = controller.entries.items[0].snapshot.?;

    var partial = try update(&client, eds.type_url, "e2", &.{payload(eds.type_url, "eds-b", "eb2", eb)}, &.{});
    defer partial.deinit();
    try accept(controller, &client, channel, io, partial);
    try std.testing.expectEqual(@as(usize, 2), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].snapshot.? == sibling);
    try std.testing.expectEqualStrings("eb2", client.acceptedVersion(eds.type_url, "eds-b").?);

    const unchanged = channel.configurationRevision();
    var beat = try update(&client, eds.type_url, "e3", &.{heartbeat("eds-a", "ea-heartbeat")}, &.{});
    defer beat.deinit();
    try accept(controller, &client, channel, io, beat);
    try std.testing.expectEqual(unchanged, channel.configurationRevision());
    try std.testing.expectEqualStrings("ea-heartbeat", client.acceptedVersion(eds.type_url, "eds-a").?);

    const empty_b = try eds_fixture.encode(gpa, "eds-b", &.{}, null);
    defer gpa.free(empty_b);
    var removed_b = try update(&client, eds.type_url, "e4", &.{}, &.{"eds-b"});
    defer removed_b.deinit();
    try accept(controller, &client, channel, io, removed_b);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expectEqualSlices(u8, empty_b, controller.entries.items[1].snapshot.?.resource.wire);
    try std.testing.expect(controller.entries.items[1].eds_seen);

    var removed_cluster = try update(&client, cds.type_url, "c2", &.{}, &.{"b"});
    defer removed_cluster.deinit();
    try accept(controller, &client, channel, io, removed_cluster);
    try std.testing.expect(controller.entries.items[1].cluster == null and controller.entries.items[1].cds_seen);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var cds_beat = try update(&client, cds.type_url, "c3", &.{heartbeat("a", "ca-heartbeat")}, &.{});
    defer cds_beat.deinit();
    const before = channel.configurationRevision();
    try accept(controller, &client, channel, io, cds_beat);
    try std.testing.expectEqual(before, channel.configurationRevision());

    var removed_listener = try update(&client, lds.type_url, "l2", &.{}, &.{"frontend"});
    defer removed_listener.deinit();
    try accept(controller, &client, channel, io, removed_listener);
    try std.testing.expect(controller.listener.?.listener == null);
    try std.testing.expect(controller.listener.?.routes == null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expect(client.acceptedVersion(lds.type_url, "frontend") == null);
}

test "gRPC delta runtime publishes STATIC clusters without an EDS subscription" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var lds_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer lds_update.deinit();
    try accept(controller, &client, channel, io, lds_update);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds.type_url).?.names[0]);

    const a = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(a);
    var cds_update = try update(&client, cds.type_url, "c1", &.{payload(cds.type_url, "a", "ca1", a)}, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    try std.testing.expect(!controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(client.subscriptions.find(eds.type_url) == null);

    const moved = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1002);
    defer gpa.free(moved);
    var moved_update = try update(&client, cds.type_url, "c2", &.{payload(cds.type_url, "a", "ca2", moved)}, &.{});
    defer moved_update.deinit();
    try accept(controller, &client, channel, io, moved_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta runtime applies dynamic RDS removal and resubscription" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const listener = try lds_fixture.encode(gpa, .{ .route_name = "routes-a" });
    defer gpa.free(listener);
    var lds_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer lds_update.deinit();
    try accept(controller, &client, channel, io, lds_update);
    try std.testing.expectEqualStrings("routes-a", client.subscriptions.find(rds.type_url).?.names[0]);

    const routes = try rds_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    var rds_update = try update(&client, rds.type_url, "r1", &.{payload(rds.type_url, "routes-a", "ra1", routes)}, &.{});
    defer rds_update.deinit();
    try accept(controller, &client, channel, io, rds_update);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds.type_url).?.names[0]);

    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cds_update = try update(&client, cds.type_url, "c1", &.{payload(cds.type_url, "a", "ca1", cluster)}, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var eds_update = try update(&client, eds.type_url, "e1", &.{payload(eds.type_url, "eds-a", "ea1", assignment)}, &.{});
    defer eds_update.deinit();
    try accept(controller, &client, channel, io, eds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var beat = try update(&client, rds.type_url, "r2", &.{heartbeat("routes-a", "ra-heartbeat")}, &.{});
    defer beat.deinit();
    const before = channel.configurationRevision();
    try accept(controller, &client, channel, io, beat);
    try std.testing.expectEqual(before, channel.configurationRevision());

    var removed = try update(&client, rds.type_url, "r3", &.{}, &.{"routes-a"});
    defer removed.deinit();
    try accept(controller, &client, channel, io, removed);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expect(!controller.listener.?.routes_accepted);

    var restored = try update(&client, rds.type_url, "r4", &.{payload(rds.type_url, "routes-a", "ra2", routes)}, &.{});
    defer restored.deinit();
    try accept(controller, &client, channel, io, restored);
    try std.testing.expectEqual(@as(usize, 1), controller.latest.?.source.required_clusters.len);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    // The old projection can still be referenced by an in-flight selector,
    // so its cluster cache remains usable for the restored route.
    try std.testing.expect(!controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds.type_url).?.names[0]);
    var cds_again = try update(&client, cds.type_url, "c2", &.{payload(cds.type_url, "a", "ca2", cluster)}, &.{});
    defer cds_again.deinit();
    try accept(controller, &client, channel, io, cds_again);
    var eds_again = try update(&client, eds.type_url, "e2", &.{payload(eds.type_url, "eds-a", "ea2", assignment)}, &.{});
    defer eds_again.deinit();
    try accept(controller, &client, channel, io, eds_again);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}
