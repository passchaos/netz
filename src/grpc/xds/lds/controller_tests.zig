const std = @import("std");
const grpc = @import("../../mod.zig");
const ads = @import("../ads.zig");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const fixture = @import("testing.zig");
const route_fixture = @import("../rds/testing.zig");
const gpa = std.testing.allocator;
const manager = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]},\"cluster:b\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
fn update(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 4096);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}
fn apply(controller: *lds.Controller, client: *ads.Client, destination: grpc.SharedChannel, io: std.Io, url: []const u8, version: []const u8, bytes: ?[]const u8) !void {
    var event = try update(client, url, version, if (bytes) |value| &.{.{ .type_url = url, .value = value }} else &.{});
    defer event.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(client, event, destination, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqualStrings(version, client.acceptedVersion(url).?);
}
fn resolve(channel: grpc.SharedChannel, io: std.Io) !@import("../../service_config.zig").ResolvedUnary {
    const generation = channel.state.retainConfig().?;
    defer generation.release();
    const selected = generation.call_selector.?;
    return selected.unary_fn(selected.context, .{ .allocator = gpa, .io = io, .deadline = null, .channel_id = 42 }, .{ .options = .{ .path = "/demo.Service/Get", .message = "request" }, .retry_policy = null, .hedging_policy = null, .wait_for_ready = false });
}
test "gRPC LDS controller reprojections cached RDS and prevents restoration after name inline and deletion changes" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{ .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) }, .hierarchical_path = &.{"cluster:b"} } } } } }, .{ .service_config_json = manager });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    var controller = try lds.Controller.init(gpa, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    const initial_revision = channel.configurationRevision();
    try apply(&controller, &client, channel, io, lds.type_url, "initial-omission", null);
    try std.testing.expectEqual(initial_revision, channel.configurationRevision());
    try std.testing.expect(controller.listener == null);
    const first = try fixture.encode(gpa, .{ .maximum_ms = 100 });
    defer gpa.free(first);
    try apply(&controller, &client, channel, io, lds.type_url, "l1", first);
    try std.testing.expectEqualStrings("routes-a", client.subscriptions.find(rds.type_url).?.names[0]);
    try std.testing.expectError(error.NoMatchingRoute, resolve(channel, io));
    const routes = try route_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(routes);
    try apply(&controller, &client, channel, io, rds.type_url, "r1", routes);
    const source = controller.routes.?;
    const resolved = try resolve(channel, io);
    try std.testing.expectEqualStrings("cluster:a", resolved.options.xds_cluster.?);
    try std.testing.expectEqual(@as(i96, 100 * std.time.ns_per_ms), resolved.options.timeout.?.duration().nanoseconds);
    const accepted_revision = channel.configurationRevision();
    try apply(&controller, &client, channel, io, rds.type_url, "omitted", null);
    const other = try route_fixture.encode(gpa, "other", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "b" }}, null);
    defer gpa.free(other);
    try apply(&controller, &client, channel, io, rds.type_url, "unrelated", other);
    try std.testing.expectEqual(accepted_revision, channel.configurationRevision());
    try std.testing.expect(controller.routes.? == source);
    try std.testing.expectEqualStrings("cluster:a", (try resolve(channel, io)).options.xds_cluster.?);
    var empty_routes = route_fixture.Builder{ .allocator = gpa };
    defer empty_routes.deinit();
    try empty_routes.bytes(1, "routes-a");
    try apply(&controller, &client, channel, io, rds.type_url, "explicit-empty", empty_routes.data.items);
    try std.testing.expectError(error.NoMatchingRoute, resolve(channel, io));
    try apply(&controller, &client, channel, io, rds.type_url, "restored", routes);
    const restored_source = controller.routes.?;
    const capped = try fixture.encode(gpa, .{ .maximum_ms = 10 });
    defer gpa.free(capped);
    try apply(&controller, &client, channel, io, lds.type_url, "l2", capped);
    try std.testing.expect(controller.routes.? == restored_source);
    try std.testing.expectEqual(@as(i96, 10 * std.time.ns_per_ms), (try resolve(channel, io)).options.timeout.?.duration().nanoseconds);
    const renamed = try fixture.encode(gpa, .{ .route_name = "routes-b" });
    defer gpa.free(renamed);
    try apply(&controller, &client, channel, io, lds.type_url, "l3", renamed);
    try std.testing.expectEqualStrings("routes-b", client.subscriptions.find(rds.type_url).?.names[0]);
    try std.testing.expectError(error.NoMatchingRoute, resolve(channel, io));
    try apply(&controller, &client, channel, io, rds.type_url, "r2", routes);
    try std.testing.expectError(error.NoMatchingRoute, resolve(channel, io));
    const inline_routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "b" }}, null);
    defer gpa.free(inline_routes);
    const inlined = try fixture.encode(gpa, .{ .inline_rds = inline_routes });
    defer gpa.free(inlined);
    try apply(&controller, &client, channel, io, lds.type_url, "l4", inlined);
    const revision = channel.configurationRevision();
    try apply(&controller, &client, channel, io, rds.type_url, "r3", routes);
    try std.testing.expectEqual(revision, channel.configurationRevision());
    try std.testing.expectEqualStrings("cluster:b", (try resolve(channel, io)).options.xds_cluster.?);
    try apply(&controller, &client, channel, io, lds.type_url, "l5", null);
    try std.testing.expect(controller.listener == null and controller.routes == null);
    const removed = channel.configurationRevision();
    try apply(&controller, &client, channel, io, rds.type_url, "r4", routes);
    try std.testing.expectEqual(removed, channel.configurationRevision());
    try std.testing.expectError(error.NoMatchingRoute, resolve(channel, io));
}

test "gRPC LDS controller applies auto host rewrite only for a trusted server" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ false, true }) |trusted| {
        var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{ .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) }, .hierarchical_path = &.{"cluster:b"} } } } } }, .{ .service_config_json = manager });
        defer channel.deinit();
        var sender = channel.sender();
        defer sender.deinit();
        var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
        defer client.deinit();
        var controller = try lds.Controller.init(gpa, .{
            .listener_name = "frontend",
            .authority = "backend.test",
            .trusted_xds_server = trusted,
        });
        defer controller.deinit();
        try controller.subscribe(&client);
        var action = route_fixture.Builder{ .allocator = gpa };
        defer action.deinit();
        try action.wrapper(7, 1);
        const routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
        defer gpa.free(routes);
        const listener = try fixture.encode(gpa, .{ .inline_rds = routes });
        defer gpa.free(listener);
        try apply(&controller, &client, channel, io, lds.type_url, "l1", listener);
        const resolved = try resolve(channel, io);
        try std.testing.expectEqual(trusted, resolved.options.xds_auto_host_rewrite);
        try std.testing.expectEqualStrings("cluster:a", resolved.options.xds_cluster.?);
    }
}

fn resolveWith(
    channel: grpc.SharedChannel,
    io: std.Io,
    metadata: []const @import("../../../http2/mod.zig").Hpack.HeaderField,
) !@import("../../service_config.zig").ResolvedUnary {
    const generation = channel.state.retainConfig().?;
    defer generation.release();
    const selected = generation.call_selector.?;
    return selected.unary_fn(selected.context, .{ .allocator = gpa, .io = io, .deadline = null, .channel_id = 42 }, .{ .options = .{ .path = "/demo.Service/Get", .message = "request", .metadata = metadata }, .retry_policy = null, .hedging_policy = null, .wait_for_ready = false });
}

test "gRPC LDS RBAC denies a matching request and allows others" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{ .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) }, .hierarchical_path = &.{"cluster:b"} } } } } }, .{ .service_config_json = manager });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    var controller = try lds.Controller.init(gpa, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    const routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    // DENY when the x-deny header is present; every other request is allowed.
    // HTTP RBAC filter config: DENY (action 1) inside the `rules` field.
    const rbac_value = "\x0a\x1b\x08\x01\x12\x17\x0a\x01p\x12\x12\x0a\x0c\x22\x0a\x0a\x06x-deny\x38\x01\x12\x02\x18\x01";
    const listener = try fixture.encode(gpa, .{ .inline_rds = routes, .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "l1", listener);
    const allowed = try resolve(channel, io);
    try std.testing.expectEqualStrings("cluster:a", allowed.options.xds_cluster.?);
    try std.testing.expectError(
        error.PermissionDenied,
        resolveWith(channel, io, &.{.{ .name = "x-deny", .value = "1" }}),
    );
}
