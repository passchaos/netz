//! gRPC xDS `fail_on_data_errors`: drop cached resources and NACK.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const rds = @import("../rds.zig");
const sds = @import("../sds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const sds_fixture = @import("../sds/testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
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

fn deltaPayload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

fn listenRoute(controller: *runtime.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, cluster: []const u8) !void {
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cluster }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var value = try update(client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer value.deinit();
    try accept(controller, client, channel, io, value);
}

test "gRPC xDS runtime fail_on_data_errors drops a cached SotW cluster" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    try listenRoute(controller, &client, channel, io, "a");

    const valid = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(valid);
    var valid_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = valid }});
    defer valid_update.deinit();
    try accept(controller, &client, channel, io, valid_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // The invalid resource keeps its name but fails validation.
    const invalid = try cds_fixture.cluster(gpa, "a", "", "\x30\x01");
    defer gpa.free(invalid);
    var invalid_update = try update(&client, cds.type_url, "c2", &.{.{ .type_url = cds.type_url, .value = invalid }});
    defer invalid_update.deinit();
    try std.testing.expectError(error.UnsupportedCdsPolicy, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.entries.items[0].cluster == null);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    // The NACKed version is not accepted.
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds.type_url).?);
}

test "gRPC delta xDS runtime fail_on_data_errors drops a cached cluster" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer listener_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, listener_update, channel, deadline(io)));

    const valid = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(valid);
    var valid_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", valid)}, &.{});
    defer valid_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, valid_update, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    const invalid = try cds_fixture.cluster(gpa, "a", "", "\x30\x01");
    defer gpa.free(invalid);
    var invalid_update = try deltaUpdate(&client, cds.type_url, "c2", &.{deltaPayload(cds.type_url, "a", "v2", invalid)}, &.{});
    defer invalid_update.deinit();
    try std.testing.expectError(error.UnsupportedCdsPolicy, controller.applyDeltaWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.entries.items[0].cluster == null);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
}

test "gRPC xDS runtime fail_on_data_errors drops a cached SotW assignment" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    try listenRoute(controller, &client, channel, io, "a");

    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", "");
    defer gpa.free(cluster);
    var cluster_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    defer cluster_update.deinit();
    try accept(controller, &client, channel, io, cluster_update);

    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    var assignment_update = try update(&client, eds.type_url, "e1", &.{.{ .type_url = eds.type_url, .value = assignment }});
    defer assignment_update.deinit();
    try accept(controller, &client, channel, io, assignment_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // Name field intact, followed by a truncated field.
    const invalid = "\x0a\x05eds-a\x18";
    var invalid_update = try update(&client, eds.type_url, "e2", &.{.{ .type_url = eds.type_url, .value = invalid }});
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].eds_seen);
}

test "gRPC xDS runtime fail_on_data_errors drops a cached secret" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    try listenRoute(controller, &client, channel, io, "a");

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    const cluster = try cds_fixture.staticClusterTls(gpa, "a", "127.0.0.1", 1001, tls);
    defer gpa.free(cluster);
    var cluster_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    defer cluster_update.deinit();
    try accept(controller, &client, channel, io, cluster_update);

    const roots = try sds_fixture.validationSecret(gpa, "roots", tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    var secret_update = try update(&client, sds.type_url, "s1", &.{
        .{ .type_url = sds.type_url, .value = certificate },
        .{ .type_url = sds.type_url, .value = roots },
    });
    defer secret_update.deinit();
    try accept(controller, &client, channel, io, secret_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // The certificate secret keeps its name but is truncated.
    const invalid = "\x0a\x06cert-1\x12";
    var invalid_update = try update(&client, sds.type_url, "s2", &.{
        .{ .type_url = sds.type_url, .value = invalid },
        .{ .type_url = sds.type_url, .value = roots },
    });
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.entries.items[0].cluster.?.sdsPending());
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
}

test "gRPC xDS runtime fail_on_data_errors drops a cached SotW listener" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    try listenRoute(controller, &client, channel, io, "a");

    const cluster = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(cluster);
    var cluster_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    defer cluster_update.deinit();
    try accept(controller, &client, channel, io, cluster_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.listener.?.listener != null);

    // Name field intact, followed by a truncated field.
    const invalid = "\x0a\x08frontend\x1a";
    var invalid_update = try update(&client, lds.type_url, "l2", &.{.{ .type_url = lds.type_url, .value = invalid }});
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.listener.?.listener == null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    // Old projection epochs keep their endpoints while config references
    // remain; the next synchronization prunes them.
    try std.testing.expectError(error.AdsNotConnected, controller.synchronizeWithDeadline(&client, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
}

test "gRPC xDS runtime fail_on_data_errors drops cached dynamic routes" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));

    const listener = try lds_fixture.encode(gpa, .{ .route_name = "routes" });
    defer gpa.free(listener);
    var listener_update = try update(&client, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
    defer listener_update.deinit();
    try accept(controller, &client, channel, io, listener_update);

    const routes = try rds_fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    var routes_update = try update(&client, rds.type_url, "r1", &.{.{ .type_url = rds.type_url, .value = routes }});
    defer routes_update.deinit();
    try accept(controller, &client, channel, io, routes_update);

    const cluster = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(cluster);
    var cluster_update = try update(&client, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    defer cluster_update.deinit();
    try accept(controller, &client, channel, io, cluster_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.listener.?.listener != null);

    const invalid = "\x0a\x06routes\x12";
    var invalid_update = try update(&client, rds.type_url, "r2", &.{.{ .type_url = rds.type_url, .value = invalid }});
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(!controller.listener.?.routes_accepted);
    try std.testing.expect(controller.listener.?.listener != null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expectError(error.AdsNotConnected, controller.synchronizeWithDeadline(&client, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
}

test "gRPC delta xDS runtime fail_on_data_errors drops a cached listener" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer listener_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, listener_update, channel, deadline(io)));
    const cluster = try cds_fixture.staticCluster(gpa, "a", "127.0.0.1", 1001);
    defer gpa.free(cluster);
    var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)}, &.{});
    defer cluster_update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&client, cluster_update, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    const invalid = "\x0a\x08frontend\x1a";
    var invalid_update = try deltaUpdate(&client, lds.type_url, "l2", &.{deltaPayload(lds.type_url, "frontend", "v2", invalid)}, &.{});
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyDeltaWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.listener.?.listener == null);
    try std.testing.expectEqual(@as(usize, 0), controller.latest.?.source.required_clusters.len);
    try std.testing.expectError(error.AdsNotConnected, controller.synchronizeDeltaWithDeadline(&client, channel, deadline(io)));
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
}

test "gRPC xDS runtime fail_on_data_errors still rejects invalid RDS for an inline listener" {
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
        .fail_on_data_errors = true,
    });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, deadline(io));
    try listenRoute(controller, &client, channel, io, "a");
    try std.testing.expect(controller.listener.?.routes != null);

    // A control plane may send RDS even though the listener uses inline routes.
    // Malformed resources must still be NACKed instead of silently acknowledged.
    var subscription = try client.subscriptions.prepare(rds.type_url, &.{"routes"});
    defer subscription.deinit();
    subscription.commit();
    const invalid = "\x0a\x06routes\x12";
    var invalid_update = try update(&client, rds.type_url, "r2", &.{.{ .type_url = rds.type_url, .value = invalid }});
    defer invalid_update.deinit();
    try std.testing.expectError(error.TruncatedMessage, controller.applyWithDeadline(&client, invalid_update, channel, deadline(io)));
    try std.testing.expect(controller.listener.?.listener != null);
    try std.testing.expect(controller.listener.?.routes != null);
}
