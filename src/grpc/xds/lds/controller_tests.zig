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

fn fixedAbort(allocator: std.mem.Allocator, status: u32) ![]u8 {
    var abort = fixture.Builder{ .allocator = allocator };
    defer abort.deinit();
    try abort.number(5, status);
    var percentage = fixture.Builder{ .allocator = gpa };
    defer percentage.deinit();
    try percentage.number(1, 100);
    try percentage.number(2, 0);
    try abort.bytes(3, percentage.data.items);
    var fault = fixture.Builder{ .allocator = gpa };
    errdefer fault.deinit();
    try fault.bytes(2, abort.data.items);
    return fault.data.toOwnedSlice(allocator);
}

test "gRPC LDS fault injection aborts unary and streaming before any backend" {
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
    const fault_value = try fixedAbort(gpa, 14);
    defer gpa.free(fault_value);
    const listener = try fixture.encode(gpa, .{ .inline_rds = routes, .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault_value },
        .{},
    } });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "l1", listener);
    const resolved = try resolve(channel, io);
    try std.testing.expect(resolved.options.fault_policy != null);

    var response = try sender.unary(.{ .path = "/demo.Service/Get", .authority = "backend.test", .message = "request", .timeout = .{ .value = 3, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);
    try std.testing.expectEqualStrings("Fault injected", response.status_message);

    var duplex = try sender.startDuplex(.{ .path = "/demo.Service/Stream", .authority = "backend.test", .timeout = .{ .value = 3, .unit = .second } });
    defer duplex.deinit();
    var reader = duplex.reader();
    defer reader.deinit();
    var event = try reader.nextWithTimeout(.fromSeconds(1));
    defer event.deinit(gpa);
    switch (event) {
        .terminal => |terminal| {
            try std.testing.expectEqual(grpc.Status.unavailable, terminal.status);
            try std.testing.expectEqualStrings("Fault injected", terminal.status_message);
        },
        else => return error.UnexpectedStreamEvent,
    }
}

fn resolvePathWith(
    channel: grpc.SharedChannel,
    io: std.Io,
    path: []const u8,
    metadata: []const @import("../../../http2/mod.zig").Hpack.HeaderField,
) !@import("../../service_config.zig").ResolvedUnary {
    const generation = channel.state.retainConfig().?;
    defer generation.release();
    const selected = generation.call_selector.?;
    return selected.unary_fn(selected.context, .{ .allocator = gpa, .io = io, .deadline = null, .channel_id = 42 }, .{ .options = .{ .path = path, .message = "request", .metadata = metadata }, .retry_policy = null, .hedging_policy = null, .wait_for_ready = false });
}

fn rbacRouteOverride(allocator: std.mem.Allocator, filter: ?[]const u8) ![]u8 {
    var per_route = fixture.Builder{ .allocator = allocator };
    defer per_route.deinit();
    if (filter) |bytes| try per_route.bytes(2, bytes);
    var any = fixture.Builder{ .allocator = allocator };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute");
    try any.bytes(2, per_route.data.items);
    var entry = fixture.Builder{ .allocator = allocator };
    defer entry.deinit();
    try entry.bytes(1, "rbac");
    try entry.bytes(2, any.data.items);
    var route_extra = fixture.Builder{ .allocator = allocator };
    defer route_extra.deinit();
    try route_extra.bytes(13, entry.data.items);
    return route_extra.data.toOwnedSlice(allocator);
}

test "gRPC LDS RBAC route overrides use HTTP rules and preserve empty config semantics" {
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

    // RBACPerRoute.rbac is HTTP RBAC; its rules omit default action ALLOW.
    const allow = try rbacRouteOverride(gpa, "\x0a\x0f\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01");
    defer gpa.free(allow);
    const deny = try rbacRouteOverride(gpa, "\x0a\x11\x08\x01\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01");
    defer gpa.free(deny);
    const disabled = try rbacRouteOverride(gpa, null);
    defer gpa.free(disabled);
    const empty_filter = try rbacRouteOverride(gpa, "");
    defer gpa.free(empty_filter);
    const empty_rules = try rbacRouteOverride(gpa, "\x0a\x00");
    defer gpa.free(empty_rules);

    const routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{
        .{ .exact = "/demo.Service/Get", .route_extra = allow },
        .{ .exact = "/demo.Service/Deny", .route_extra = deny },
        .{ .exact = "/demo.Service/Disabled", .route_extra = disabled },
        .{ .exact = "/demo.Service/EmptyFilter", .route_extra = empty_filter },
        .{ .exact = "/demo.Service/EmptyRules", .route_extra = empty_rules },
        .{ .prefix = "/" },
    }, null);
    defer gpa.free(routes);
    const rbac_value = "\x0a\x1b\x08\x01\x12\x17\x0a\x01p\x12\x12\x0a\x0c\x22\x0a\x0a\x06x-deny\x38\x01\x12\x02\x18\x01";
    const listener = try fixture.encode(gpa, .{ .inline_rds = routes, .filters = &.{
        .{ .name = "rbac", .type_name = lds.resource.rbac_type, .value = rbac_value },
        .{},
    } });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "l1", listener);

    const denied = [_]@import("../../../http2/mod.zig").Hpack.HeaderField{.{ .name = "x-deny", .value = "1" }};
    const overridden = try resolvePathWith(channel, io, "/demo.Service/Get", &denied);
    try std.testing.expectEqualStrings("cluster:a", overridden.options.xds_cluster.?);
    for ([_][]const u8{ "/demo.Service/Disabled", "/demo.Service/EmptyFilter" }) |path| {
        const unrestricted = try resolvePathWith(channel, io, path, &denied);
        try std.testing.expectEqualStrings("cluster:a", unrestricted.options.xds_cluster.?);
    }
    for ([_][]const u8{ "/demo.Service/Deny", "/demo.Service/EmptyRules" }) |path| {
        try std.testing.expectError(error.PermissionDenied, resolvePathWith(channel, io, path, &.{}));
    }
    const inherited = try resolvePathWith(channel, io, "/demo.Service/Other", &.{});
    try std.testing.expectEqualStrings("cluster:a", inherited.options.xds_cluster.?);
    try std.testing.expectError(
        error.PermissionDenied,
        resolvePathWith(channel, io, "/demo.Service/Other", &denied),
    );
}

test "gRPC LDS fault route override disables injection for the matched route" {
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

    const fault_value = try fixedAbort(gpa, 14);
    defer gpa.free(fault_value);
    // FilterConfig { disabled: true } for the "fault" filter on Get.
    var filter_config = fixture.Builder{ .allocator = gpa };
    defer filter_config.deinit();
    try filter_config.number(3, 1);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.config.route.v3.FilterConfig");
    try any.bytes(2, filter_config.data.items);
    var entry = fixture.Builder{ .allocator = gpa };
    defer entry.deinit();
    try entry.bytes(1, "fault");
    try entry.bytes(2, any.data.items);
    var route_extra = fixture.Builder{ .allocator = gpa };
    defer route_extra.deinit();
    try route_extra.bytes(13, entry.data.items);

    const routes = try route_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{
        .{ .exact = "/demo.Service/Get", .route_extra = route_extra.data.items },
        .{ .prefix = "/" },
    }, null);
    defer gpa.free(routes);
    const listener = try fixture.encode(gpa, .{ .inline_rds = routes, .filters = &.{
        .{ .name = "fault", .type_name = lds.resource.fault_type, .value = fault_value },
        .{},
    } });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "l1", listener);

    const overridden = try resolvePathWith(channel, io, "/demo.Service/Get", &.{});
    try std.testing.expect(overridden.options.fault_policy == null);
    const inherited = try resolvePathWith(channel, io, "/demo.Service/Other", &.{});
    try std.testing.expect(inherited.options.fault_policy != null);
}

test "gRPC LDS applies header mutations to resolved calls" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = manager });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    var controller = try lds.Controller.init(gpa, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    const routes = try route_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/" }}, null);
    defer gpa.free(routes);
    const mutation = try fixture.headerMutation(gpa);
    defer gpa.free(mutation);
    const listener = try fixture.encode(gpa, .{
        .inline_rds = routes,
        .filters = &.{
            .{ .name = "hm", .type_name = lds.resource.header_mutation_type, .value = mutation },
            .{},
        },
    });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "hm", listener);
    const resolved = try resolve(channel, io);
    try std.testing.expectEqual(@as(usize, 1), resolved.options.xds_request_header_mutations.len);
    try std.testing.expectEqualStrings("x-req", resolved.options.xds_request_header_mutations[0].name);
    try std.testing.expectEqualStrings("one", resolved.options.xds_request_header_mutations[0].value);
    try std.testing.expectEqual(@as(usize, 1), resolved.options.xds_request_header_removals.len);
    try std.testing.expectEqualStrings("x-remove", resolved.options.xds_request_header_removals[0]);
    try std.testing.expectEqual(@as(usize, 1), resolved.options.xds_response_header_mutations.len);
    try std.testing.expectEqualStrings("x-resp", resolved.options.xds_response_header_mutations[0].name);
    try std.testing.expectEqualStrings("two", resolved.options.xds_response_header_mutations[0].value);
    try std.testing.expectEqual(@as(usize, 1), resolved.options.xds_response_header_removals.len);
    try std.testing.expectEqualStrings("x-resp-remove", resolved.options.xds_response_header_removals[0]);
}

test "gRPC LDS header-mutation per-route override replaces the listener policy" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = manager });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    var controller = try lds.Controller.init(gpa, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    const mutation = try fixture.headerMutation(gpa);
    defer gpa.free(mutation);
    const override = try fixture.headerMutationPerRoute(gpa, "hm", "x-route", "override");
    defer gpa.free(override);
    const routes = try route_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = override }}, null);
    defer gpa.free(routes);
    const listener = try fixture.encode(gpa, .{
        .inline_rds = routes,
        .filters = &.{
            .{ .name = "hm", .type_name = lds.resource.header_mutation_type, .value = mutation },
            .{},
        },
    });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "hm-override", listener);
    const resolved = try resolve(channel, io);
    try std.testing.expectEqual(@as(usize, 1), resolved.options.xds_request_header_mutations.len);
    try std.testing.expectEqualStrings("x-route", resolved.options.xds_request_header_mutations[0].name);
    try std.testing.expectEqualStrings("override", resolved.options.xds_request_header_mutations[0].value);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_request_header_removals.len);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_response_header_mutations.len);
}

test "gRPC LDS header-mutation per-route disable removes listener mutations" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &.{.{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &.{"cluster:a"} } }} } }, .{ .service_config_json = manager });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    var controller = try lds.Controller.init(gpa, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    const mutation = try fixture.headerMutation(gpa);
    defer gpa.free(mutation);
    const disabled = try fixture.headerMutationDisabled(gpa, "hm");
    defer gpa.free(disabled);
    const routes = try route_fixture.encode(gpa, "routes-a", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = disabled }}, null);
    defer gpa.free(routes);
    const listener = try fixture.encode(gpa, .{
        .inline_rds = routes,
        .filters = &.{
            .{ .name = "hm", .type_name = lds.resource.header_mutation_type, .value = mutation },
            .{},
        },
    });
    defer gpa.free(listener);
    try apply(&controller, &client, channel, io, lds.type_url, "hm-disabled", listener);
    const resolved = try resolve(channel, io);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_request_header_mutations.len);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_request_header_removals.len);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_response_header_mutations.len);
    try std.testing.expectEqual(@as(usize, 0), resolved.options.xds_response_header_removals.len);
}
