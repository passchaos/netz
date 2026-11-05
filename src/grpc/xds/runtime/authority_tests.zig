//! Single-authority `xdstp://` resource names.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const gpa = std.testing.allocator;

const cds_cluster = "xdstp://auth-1/envoy.config.cluster.v3.Cluster/a";
const eds_service = "xdstp://auth-1/envoy.config.endpoint.v3.ClusterLoadAssignment/eds-a";
const listener_name = "xdstp://auth-1/envoy.config.listener.v3.Listener/frontend";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn update(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn accept(controller: *runtime.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, value: ads.Update) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(client, value, channel, deadline(io)));
}

test "gRPC xDS runtime accepts matching xdstp cluster and EDS names" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cds_cluster }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);
    try std.testing.expectEqualStrings(cds_cluster, controller.entries.items[0].identity.name);

    const cluster = try cds_fixture.cluster(gpa, cds_cluster, eds_service, "");
    defer gpa.free(cluster);
    var cluster_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    defer cluster_update.deinit();
    try accept(controller, &client, channel, io, cluster_update);
    try std.testing.expectEqualStrings(eds_service, client.subscriptions.find(eds.type_url).?.names[0]);

    const assignment = try eds_fixture.encode(gpa, eds_service, &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var eds_update = try update(&client, eds.type_url, "e1", &.{.{ .type_url = eds.type_url, .value = assignment }});
    defer eds_update.deinit();
    try accept(controller, &client, channel, io, eds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC xDS runtime validates xdstp listener names" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    try std.testing.expectError(error.InvalidXdsResourceName, runtime.Controller.create(gpa, .{
        .listener_name = listener_name,
        .target = .{ .authority = "backend.test" },
        .authority = "other",
    }));
    try std.testing.expectError(error.InvalidXdsResourceName, runtime.Controller.create(gpa, .{
        .listener_name = listener_name,
        .target = .{ .authority = "backend.test" },
    }));
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = listener_name,
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .name = listener_name, .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);
    try std.testing.expect(controller.listener != null);
}

test "gRPC xDS runtime rejects mismatched xdstp authority and type" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    for ([_][]const u8{
        "xdstp://other/envoy.config.cluster.v3.Cluster/a",
        "xdstp://auth-1/envoy.config.listener.v3.Listener/a",
    }) |cluster_name| {
        const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cluster_name }}, null);
        defer gpa.free(routes);
        const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
        defer gpa.free(listener);
        var listener_update = try update(&client, lds.type_url, cluster_name, &.{.{ .type_url = lds.type_url, .value = listener }});
        defer listener_update.deinit();
        try std.testing.expectError(error.InvalidXdsResourceName, controller.applyWithDeadline(&client, listener_update, channel, deadline(io)));
    }
}

test "gRPC xDS runtime accepts additional authorities on one control plane" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
        .additional_authorities = &.{"auth-2"},
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    const second_cluster = "xdstp://auth-2/envoy.config.cluster.v3.Cluster/b";
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = second_cluster }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);
    try std.testing.expectEqualStrings(second_cluster, controller.entries.items[0].identity.name);

    try std.testing.expectError(error.InvalidXdsOptions, runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
        .additional_authorities = &.{""},
    }));
    try std.testing.expectError(error.InvalidXdsResourceName, runtime.Controller.create(gpa, .{
        .listener_name = "xdstp://auth-9/envoy.config.listener.v3.Listener/frontend",
        .target = .{ .authority = "backend.test" },
        .authority = "auth-1",
        .additional_authorities = &.{"auth-2"},
    }));
}
