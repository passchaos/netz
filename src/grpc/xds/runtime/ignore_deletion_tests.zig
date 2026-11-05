//! gRPC xDS `ignore_resource_deletion` retains omitted and removed resources.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const rds = @import("../rds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const gpa = std.testing.allocator;

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

fn deltaUpdate(client: *delta.Client, url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource, removed: []const []const u8) !delta.Update {
    const encoded = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = nonce, .resources = resources, .removed = removed }, .{});
    defer gpa.free(encoded);
    var response = try delta.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn acceptDelta(controller: *runtime.Controller, client: *delta.Client, channel: grpc.SharedChannel, io: std.Io, value: delta.Update) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(client, value, channel, deadline(io)));
}

fn deltaPayload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

const Fixture = struct {
    routes: []u8,
    listener: []u8,
    cluster: []u8,
    fn deinit(self: Fixture) void {
        gpa.free(self.routes);
        gpa.free(self.listener);
        gpa.free(self.cluster);
    }
};

fn fixture() !Fixture {
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    errdefer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    errdefer gpa.free(listener);
    const cluster = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    return .{ .routes = routes, .listener = listener, .cluster = cluster };
}

test "gRPC xDS runtime ignore_resource_deletion retains SotW resources" {
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
        .ignore_resource_deletion = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    const data = try fixture();
    defer data.deinit();

    var lds_update = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = data.listener }});
    defer lds_update.deinit();
    try accept(controller, &client, channel, io, lds_update);
    var cds_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = data.cluster }});
    defer cds_update.deinit();
    try accept(controller, &client, channel, io, cds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // Omitting the cluster from a complete CDS response must retain it.
    var omitted_cds = try update(&client, cds.type_url, "c2", &.{});
    defer omitted_cds.deinit();
    try accept(controller, &client, channel, io, omitted_cds);
    try std.testing.expect(controller.entries.items[0].cluster != null);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // Omitting the listener must retain the listener and its route tree.
    var omitted_lds = try update(&client, lds.type_url, "l2", &.{});
    defer omitted_lds.deinit();
    try accept(controller, &client, channel, io, omitted_lds);
    try std.testing.expect(controller.listener != null);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta xDS runtime ignore_resource_deletion retains removed resources" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .ignore_resource_deletion = true,
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
    const data = try fixture();
    defer data.deinit();

    var lds_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", data.listener)}, &.{});
    defer lds_update.deinit();
    try acceptDelta(controller, &client, channel, io, lds_update);
    var cds_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", data.cluster)}, &.{});
    defer cds_update.deinit();
    try acceptDelta(controller, &client, channel, io, cds_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var removed_cluster = try deltaUpdate(&client, cds.type_url, "c2", &.{}, &.{"a"});
    defer removed_cluster.deinit();
    try acceptDelta(controller, &client, channel, io, removed_cluster);
    try std.testing.expect(controller.entries.items[0].cluster != null);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var removed_routes = try deltaUpdate(&client, rds.type_url, "r1", &.{}, &.{"inline"});
    defer removed_routes.deinit();
    try acceptDelta(controller, &client, channel, io, removed_routes);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var removed_listener = try deltaUpdate(&client, lds.type_url, "l2", &.{}, &.{"frontend"});
    defer removed_listener.deinit();
    try acceptDelta(controller, &client, channel, io, removed_listener);
    try std.testing.expect(controller.listener != null);
    try std.testing.expectEqual(@as(usize, 1), controller.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}
