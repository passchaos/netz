//! Delta Resource TTL expiry, heartbeat refresh and version forgetting.
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

fn expire(controller: *runtime.Controller, client: *delta.Client, channel: grpc.SharedChannel, io: std.Io) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.expireDeltaWithDeadline(client, channel, deadline(io)));
}

fn payload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8, ttl: ?delta.codec.Duration) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes }, .ttl = ttl };
}

fn heartbeat(name: []const u8, version: []const u8, ttl: ?delta.codec.Duration) delta.codec.Resource {
    return .{ .name = name, .version = version, .ttl = ttl };
}

const short: delta.codec.Duration = .{ .nanos = 50_000_000 };
const long: delta.codec.Duration = .{ .nanos = 200_000_000 };

test "gRPC delta EDS TTL expires, forgets its version and restores without a timer" {
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
    var listener_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener, null)}, &.{});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);

    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cds_update = try update(&client, cds.type_url, "c1", &.{payload(cds.type_url, "a", "ca1", cluster, null)}, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);

    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var eds_update = try update(&client, eds.type_url, "e1", &.{payload(eds.type_url, "eds-a", "ea1", assignment, short)}, &.{});
    defer eds_update.deinit();
    try accept(controller, &client, channel, io, eds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].eds_deadline != null);
    try std.testing.expect(controller.nextDeltaExpiry() != null);

    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try expire(controller, &client, channel, io);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].eds_deadline == null);
    try std.testing.expect(client.acceptedVersion(eds.type_url, "eds-a") == null);
    try std.testing.expect(controller.nextDeltaExpiry() == null);

    var restored = try update(&client, eds.type_url, "e2", &.{payload(eds.type_url, "eds-a", "ea2", assignment, null)}, &.{});
    defer restored.deinit();
    try accept(controller, &client, channel, io, restored);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].eds_deadline == null);
    try std.testing.expect(controller.nextDeltaExpiry() == null);
}

test "gRPC delta TTL heartbeat refreshes and then clears the timer" {
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
    var listener_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener, null)}, &.{});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);
    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cds_update = try update(&client, cds.type_url, "c1", &.{payload(cds.type_url, "a", "ca1", cluster, null)}, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var eds_update = try update(&client, eds.type_url, "e1", &.{payload(eds.type_url, "eds-a", "ea1", assignment, short)}, &.{});
    defer eds_update.deinit();
    try accept(controller, &client, channel, io, eds_update);

    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    var refreshed = try update(&client, eds.type_url, "e2", &.{heartbeat("eds-a", "ea1", long)}, &.{});
    defer refreshed.deinit();
    try accept(controller, &client, channel, io, refreshed);
    try std.Io.sleep(io, .fromMilliseconds(60), .awake);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.nextDeltaExpiry() != null);

    var cleared = try update(&client, eds.type_url, "e3", &.{heartbeat("eds-a", "ea1", null)}, &.{});
    defer cleared.deinit();
    try accept(controller, &client, channel, io, cleared);
    try std.testing.expect(controller.entries.items[0].eds_deadline == null);
    try std.testing.expect(controller.nextDeltaExpiry() == null);
    try std.Io.sleep(io, .fromMilliseconds(200), .awake);
    try expire(controller, &client, channel, io);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta CDS TTL removes the cluster and restores it" {
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
    var listener_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener, null)}, &.{});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);
    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cds_update = try update(&client, cds.type_url, "c1", &.{payload(cds.type_url, "a", "ca1", cluster, short)}, &.{});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var eds_update = try update(&client, eds.type_url, "e1", &.{payload(eds.type_url, "eds-a", "ea1", assignment, null)}, &.{});
    defer eds_update.deinit();
    try accept(controller, &client, channel, io, eds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try expire(controller, &client, channel, io);
    try std.testing.expect(controller.entries.items[0].cluster == null);
    try std.testing.expect(controller.entries.items[0].cds_deadline == null);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(client.acceptedVersion(cds.type_url, "a") == null);

    var restored = try update(&client, cds.type_url, "c2", &.{payload(cds.type_url, "a", "ca2", cluster, null)}, &.{});
    defer restored.deinit();
    try accept(controller, &client, channel, io, restored);
    try std.testing.expect(controller.entries.items[0].cluster != null);
    try std.testing.expect(controller.entries.items[0].cds_deadline == null);
    // The cluster image was released with the expired CDS resource, so its
    // endpoints require a fresh EDS answer before admission resumes.
    try std.testing.expect(controller.entries.items[0].pending());
    var restored_eds = try update(&client, eds.type_url, "e2", &.{payload(eds.type_url, "eds-a", "ea2", assignment, null)}, &.{});
    defer restored_eds.deinit();
    try accept(controller, &client, channel, io, restored_eds);
    try std.testing.expect(!controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta RDS and LDS TTL expiry" {
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
    var lds_update = try update(&client, lds.type_url, "l1", &.{payload(lds.type_url, "frontend", "v1", listener, null)}, &.{});
    defer lds_update.deinit();
    try accept(controller, &client, channel, io, lds_update);
    const routes = try rds_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    var rds_update = try update(&client, rds.type_url, "r1", &.{payload(rds.type_url, "routes-a", "ra1", routes, short)}, &.{});
    defer rds_update.deinit();
    try accept(controller, &client, channel, io, rds_update);
    try std.testing.expect(controller.listener.?.routes_deadline != null);

    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try expire(controller, &client, channel, io);
    try std.testing.expect(controller.listener.?.listener != null);
    try std.testing.expect(!controller.listener.?.routes_accepted);
    try std.testing.expect(controller.listener.?.routes_deadline == null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expect(client.acceptedVersion(rds.type_url, "routes-a") == null);

    var restored_rds = try update(&client, rds.type_url, "r2", &.{payload(rds.type_url, "routes-a", "ra2", routes, null)}, &.{});
    defer restored_rds.deinit();
    try accept(controller, &client, channel, io, restored_rds);
    try std.testing.expect(controller.listener.?.routes_accepted);
    try std.testing.expect(controller.listener.?.routes_deadline == null);

    // A listener TTL removes the whole listener even while routes are accepted.
    const listener_ttl = try lds_fixture.encode(gpa, .{ .route_name = "routes-a" });
    defer gpa.free(listener_ttl);
    var lds_ttl_update = try update(&client, lds.type_url, "l2", &.{payload(lds.type_url, "frontend", "v2", listener_ttl, short)}, &.{});
    defer lds_ttl_update.deinit();
    try accept(controller, &client, channel, io, lds_ttl_update);
    try std.testing.expect(controller.listener.?.listener_deadline != null);
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try expire(controller, &client, channel, io);
    try std.testing.expect(controller.listener.?.listener == null);
    try std.testing.expect(controller.listener.?.routes == null);
    try std.testing.expect(controller.listener.?.listener_deadline == null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expect(client.acceptedVersion(lds.type_url, "frontend") == null);
    try std.testing.expect(client.acceptedVersion(rds.type_url, "routes-a") == null);
}
