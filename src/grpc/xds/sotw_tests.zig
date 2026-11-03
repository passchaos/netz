//! Partial RDS/EDS responses validate and ACK without replacing omitted state.
const std = @import("std");
const grpc = @import("../mod.zig");
const ads = @import("ads.zig");
const eds = @import("eds.zig");
const rds = @import("rds.zig");
const eds_fixture = @import("eds/testing.zig");
const rds_fixture = @import("rds/testing.zig");
const gpa = std.testing.allocator;
const Kind = enum { endpoints, routes };
const manager = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";

fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}
fn url(kind: Kind) []const u8 {
    return if (kind == .endpoints) eds.type_url else rds.type_url;
}
fn bytes(kind: Kind, name: []const u8, empty: bool) ![]u8 {
    if (empty) {
        var builder = rds_fixture.Builder{ .allocator = gpa };
        defer builder.deinit();
        try builder.bytes(1, name);
        return gpa.dupe(u8, builder.data.items);
    }
    return if (kind == .endpoints)
        eds_fixture.encode(gpa, name, &.{.{ .region = "r", .endpoints = &.{.{ .port = 1001 }} }}, null)
    else
        rds_fixture.encode(gpa, name, &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
}
fn update(client: *ads.Client, kind: Kind, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const wire = try ads.codec.encodeResponse(gpa, .{ .type_url = url(kind), .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(wire);
    var response = try ads.codec.decodeResponse(gpa, wire, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}
fn publish(kind: Kind, client: *ads.Client, value: ads.Update, channel: grpc.SharedChannel, deadline: std.Io.Clock.Timestamp) !u64 {
    return if (kind == .endpoints)
        eds.publishUpdateWithDeadline(client, value, "selected", channel, .{ .authority = "backend.test" }, .{}, deadline)
    else
        rds.publishUpdateWithDeadline(client, value, "selected", channel, .{ .authority = "backend.test" }, .{}, deadline);
}
fn accept(kind: Kind, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, version: []const u8, resources: []const ads.codec.Any) !void {
    var value = try update(client, kind, version, resources);
    defer value.deinit();
    // Acceptance must survive ACK output failure, including no-op responses.
    try std.testing.expectError(error.AdsNotConnected, publish(kind, client, value, channel, until(io)));
    try std.testing.expectEqualStrings(version, client.acceptedVersion(url(kind)).?);
    try std.testing.expectError(error.StaleDiscoveryResponse, client.validateUpdate(value));
}
fn standalone(kind: Kind) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = if (kind == .routes) manager else null });
    var live = true;
    defer if (live) channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    try client.setSubscription(url(kind), &.{ "selected", "other" });
    const initial_revision = channel.configurationRevision();
    try accept(kind, &client, channel, io, "initial-omission", &.{});
    try std.testing.expectEqual(initial_revision, channel.configurationRevision());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    if (kind == .routes) try std.testing.expect(channel.state.config.load(.acquire).?.call_selector == null);

    const selected = try bytes(kind, "selected", false);
    defer gpa.free(selected);
    try accept(kind, &client, channel, io, "accepted", &.{.{ .type_url = url(kind), .value = selected }});
    const revision = channel.configurationRevision();
    const generation = channel.state.retainConfig();
    defer if (generation) |value| value.release();
    const target = channel.state.target_lifetime;
    const source = channel.state.sources[0];
    const other = try bytes(kind, "other", false);
    defer gpa.free(other);
    for (0..2) |index| {
        try accept(kind, &client, channel, io, if (index == 0) "empty-response" else "unrelated", if (index == 0) &.{} else &.{.{ .type_url = url(kind), .value = other }});
        try std.testing.expectEqual(revision, channel.configurationRevision());
        try std.testing.expect(channel.state.config.load(.acquire) == generation);
        try std.testing.expectEqualDeep(target, channel.state.target_lifetime);
        try std.testing.expect(channel.state.sources[0] == source);
    }

    // Even unrelated resources must validate before an omission can be ACKed.
    var duplicate = try update(&client, kind, "duplicate", &.{ .{ .type_url = url(kind), .value = other }, .{ .type_url = url(kind), .value = other } });
    defer duplicate.deinit();
    try std.testing.expectError(if (kind == .endpoints) error.DuplicateEdsResource else error.DuplicateRdsResource, publish(kind, &client, duplicate, channel, until(io)));
    var invalid = try update(&client, kind, "invalid", &.{.{ .type_url = url(kind), .value = "\x0a\xff" }});
    defer invalid.deinit();
    try std.testing.expectError(error.TruncatedMessage, publish(kind, &client, invalid, channel, until(io)));
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expectEqualStrings("unrelated", client.acceptedVersion(url(kind)).?);
    var expired = try update(&client, kind, "expired", &.{});
    defer expired.deinit();
    try std.testing.expectError(error.Timeout, publish(kind, &client, expired, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectEqualStrings("unrelated", client.acceptedVersion(url(kind)).?);

    var contended = try update(&client, kind, "contended", &.{});
    defer contended.deinit();
    channel.state.mutex.lockUncancelable(io);
    const blocked_result = publish(kind, &client, contended, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) }));
    channel.state.mutex.unlock(io);
    try std.testing.expectError(error.Timeout, blocked_result);
    try client.validateUpdate(contended);
    try std.testing.expectEqualStrings("unrelated", client.acceptedVersion(url(kind)).?);

    const empty = try bytes(kind, "selected", true);
    defer gpa.free(empty);
    try accept(kind, &client, channel, io, "explicit-empty", &.{.{ .type_url = url(kind), .value = empty }});
    try std.testing.expect(channel.configurationRevision() > revision);
    if (kind == .endpoints) {
        try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    } else {
        var response = try sender.unary(.{ .path = "/demo.Service/Get", .message = "request" });
        defer response.deinit();
        try std.testing.expect(response.status == .unavailable and response.transport == null);
    }
    var closed = try update(&client, kind, "closed", &.{});
    defer closed.deinit();
    channel.deinit();
    live = false;
    try std.testing.expectError(error.SharedChannelClosed, publish(kind, &client, closed, .{ .state = sender.state }, until(io)));
    try client.validateUpdate(closed);
    try std.testing.expectEqualStrings("explicit-empty", client.acceptedVersion(url(kind)).?);
}
test "gRPC xDS SotW standalone EDS retains omitted targets and accepts explicit empty assignments" {
    try standalone(.endpoints);
}
test "gRPC xDS SotW standalone RDS retains omitted selectors and accepts explicit empty routes" {
    try standalone(.routes);
}
