//! SDS references gate endpoint publication and follow secret rotation.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const sds = @import("../sds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const sds_fixture = @import("../sds/testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
const gpa = std.testing.allocator;

fn update(client: *ads.Client, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !ads.Update {
    const encoded = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
    defer gpa.free(encoded);
    var response = try ads.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn accept(controller: *runtime.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, url: []const u8, version: []const u8, resources: []const ads.codec.Any) !void {
    var value = try update(client, url, version, resources);
    defer value.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyWithDeadline(client, value, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
    try std.testing.expectEqualStrings(version, client.acceptedVersion(url).?);
}

fn listenRoute(controller: *runtime.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io, cluster: []const u8) !void {
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cluster }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    try accept(controller, client, channel, io, lds.type_url, "l1", &.{.{ .type_url = lds.type_url, .value = listener }});
}

fn secretResources(certificate: []const u8, validation: []const u8) [2]ads.codec.Any {
    return .{
        .{ .type_url = sds.type_url, .value = certificate },
        .{ .type_url = sds.type_url, .value = validation },
    };
}

fn deltaUpdate(client: *delta.Client, url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource, removed: []const []const u8) !delta.Update {
    const encoded = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = nonce, .resources = resources, .removed = removed }, .{});
    defer gpa.free(encoded);
    var response = try delta.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn acceptDelta(controller: *runtime.Controller, client: *delta.Client, channel: grpc.SharedChannel, io: std.Io, value: delta.Update) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(client, value, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
}

fn deltaPayload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

fn deltaPayloadTtl(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8, ttl: ?delta.codec.Duration) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes }, .ttl = ttl };
}

fn heartbeat(name: []const u8, version: []const u8, ttl: ?delta.codec.Duration) delta.codec.Resource {
    return .{ .name = name, .version = version, .ttl = ttl };
}

fn expireDelta(controller: *runtime.Controller, client: *delta.Client, channel: grpc.SharedChannel, io: std.Io) !void {
    try std.testing.expectError(error.AdsNotConnected, controller.expireDeltaWithDeadline(client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
}

test "gRPC xDS runtime gates STATIC endpoints on SDS and reopens after removal" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    try listenRoute(controller, &client, channel, io, "a");

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    const cluster = try cds_fixture.staticClusterTls(gpa, "a", "127.0.0.1", 1001, tls);
    defer gpa.free(cluster);
    try accept(controller, &client, channel, io, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});
    try std.testing.expect(controller.entries.items[0].cluster.?.sdsPending());
    try std.testing.expect(controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expectEqualStrings("cert-1", client.subscriptions.find(sds.type_url).?.names[0]);
    try std.testing.expectEqualStrings("roots", client.subscriptions.find(sds.type_url).?.names[1]);

    const pin = [_]u8{0x11} ** 32;
    const spki_pin = [_]u8{0x22} ** 32;
    const roots = try sds_fixture.validationSecretPins(gpa, "roots", tls_testing.certificate_pem, &.{}, &.{pin}, &.{spki_pin});
    defer gpa.free(roots);
    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);

    // Only the validation secret is available: endpoints stay unpublished.
    try accept(controller, &client, channel, io, sds.type_url, "s1", &.{.{ .type_url = sds.type_url, .value = roots }});
    try std.testing.expect(controller.entries.items[0].cluster.?.sdsPending());
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());

    // Both secrets resolve: the cluster publishes one endpoint with TLS.
    try accept(controller, &client, channel, io, sds.type_url, "s2", &secretResources(certificate, roots));
    try std.testing.expect(!controller.entries.items[0].cluster.?.sdsPending());
    try std.testing.expect(!controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    const config = controller.entries.items[0].cluster.?.resolvedTls().?;
    try std.testing.expect(std.mem.indexOf(u8, config.certificate_chain, "BEGIN CERTIFICATE") != null);
    try std.testing.expect(std.mem.indexOf(u8, config.trusted_ca, "BEGIN CERTIFICATE") != null);
    try std.testing.expectEqual(@as(usize, 1), config.verify_certificate_hashes.?.len);
    try std.testing.expectEqualSlices(u8, &pin, &config.verify_certificate_hashes.?[0]);
    try std.testing.expectEqual(@as(usize, 1), config.verify_certificate_spkis.?.len);
    try std.testing.expectEqualSlices(u8, &spki_pin, &config.verify_certificate_spkis.?[0]);

    // SotW omission of the certificate secret makes the cluster pending again
    // and removes its endpoint instead of falling back to cleartext.
    try accept(controller, &client, channel, io, sds.type_url, "s3", &.{.{ .type_url = sds.type_url, .value = roots }});
    try std.testing.expect(controller.entries.items[0].cluster.?.sdsPending());
    try std.testing.expect(controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());

    try accept(controller, &client, channel, io, sds.type_url, "s4", &secretResources(certificate, roots));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC xDS runtime holds EDS endpoints until SDS resolves" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    try listenRoute(controller, &client, channel, io, "a");

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    var transport = cds_fixture.Builder{ .allocator = gpa };
    defer transport.deinit();
    try transport.bytes(24, tls);
    const cluster = try cds_fixture.cluster(gpa, "a", "eds-a", transport.data.items);
    defer gpa.free(cluster);
    try accept(controller, &client, channel, io, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});

    const assignment = try eds_fixture.encode(gpa, "eds-a", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }}, null);
    defer gpa.free(assignment);
    try accept(controller, &client, channel, io, eds.type_url, "e1", &.{.{ .type_url = eds.type_url, .value = assignment }});
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].pending());

    const roots = try sds_fixture.validationSecret(gpa, "roots", tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    try accept(controller, &client, channel, io, sds.type_url, "s1", &secretResources(certificate, roots));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(!controller.entries.items[0].pending());
}

test "gRPC xDS runtime rejects wrong-kind SDS references on every retry" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try ads.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer client.deinit();
    const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    try listenRoute(controller, &client, channel, io, "a");

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    const cluster = try cds_fixture.staticClusterTls(gpa, "a", "127.0.0.1", 1001, tls);
    defer gpa.free(cluster);
    try accept(controller, &client, channel, io, cds.type_url, "c1", &.{.{ .type_url = cds.type_url, .value = cluster }});

    const wrong = try sds_fixture.validationSecret(gpa, "cert-1", tls_testing.certificate_pem, &.{});
    defer gpa.free(wrong);
    const roots = try sds_fixture.validationSecret(gpa, "roots", tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    for ([_][]const u8{ "s1", "s2" }) |version| {
        var value = try update(&client, sds.type_url, version, &secretResources(wrong, roots));
        defer value.deinit();
        try std.testing.expectError(error.InvalidSdsResource, controller.applyWithDeadline(&client, value, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) })));
        try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
        try std.testing.expect(controller.entries.items[0].pending());
    }

    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    try accept(controller, &client, channel, io, sds.type_url, "s3", &secretResources(certificate, roots));
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta xDS runtime resolves and removes SDS secrets incrementally" {
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
    _ = try controller.startDeltaWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer listener_update.deinit();
    try acceptDelta(controller, &client, channel, io, listener_update);

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    const cluster = try cds_fixture.staticClusterTls(gpa, "a", "127.0.0.1", 1001, tls);
    defer gpa.free(cluster);
    var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)}, &.{});
    defer cluster_update.deinit();
    try acceptDelta(controller, &client, channel, io, cluster_update);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].pending());

    const roots = try sds_fixture.validationSecret(gpa, "roots", tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    var secret_update = try deltaUpdate(&client, sds.type_url, "s1", &.{
        deltaPayload(sds.type_url, "cert-1", "v1", certificate),
        deltaPayload(sds.type_url, "roots", "v1", roots),
    }, &.{});
    defer secret_update.deinit();
    try acceptDelta(controller, &client, channel, io, secret_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    var removal = try deltaUpdate(&client, sds.type_url, "s2", &.{}, &.{"cert-1"});
    defer removal.deinit();
    try acceptDelta(controller, &client, channel, io, removal);
    try std.testing.expect(controller.entries.items[0].pending());
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());

    var restore = try deltaUpdate(&client, sds.type_url, "s3", &.{deltaPayload(sds.type_url, "cert-1", "v2", certificate)}, &.{});
    defer restore.deinit();
    try acceptDelta(controller, &client, channel, io, restore);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}

test "gRPC delta xDS runtime expires SDS secrets and refreshes their TTL" {
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
    _ = try controller.startDeltaWithDeadline(&client, channel, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var listener_update = try deltaUpdate(&client, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)}, &.{});
    defer listener_update.deinit();
    try acceptDelta(controller, &client, channel, io, listener_update);

    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", "cert-1", "roots");
    defer gpa.free(tls);
    const cluster = try cds_fixture.staticClusterTls(gpa, "a", "127.0.0.1", 1001, tls);
    defer gpa.free(cluster);
    var cluster_update = try deltaUpdate(&client, cds.type_url, "c1", &.{deltaPayload(cds.type_url, "a", "v1", cluster)}, &.{});
    defer cluster_update.deinit();
    try acceptDelta(controller, &client, channel, io, cluster_update);

    const roots = try sds_fixture.validationSecret(gpa, "roots", tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    const certificate = try sds_fixture.tlsSecret(gpa, "cert-1", tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    const short: delta.codec.Duration = .{ .nanos = 50_000_000 };
    const long: delta.codec.Duration = .{ .nanos = 200_000_000 };
    var secret_update = try deltaUpdate(&client, sds.type_url, "s1", &.{
        deltaPayloadTtl(sds.type_url, "cert-1", "v1", certificate, short),
        deltaPayloadTtl(sds.type_url, "roots", "v1", roots, short),
    }, &.{});
    defer secret_update.deinit();
    try acceptDelta(controller, &client, channel, io, secret_update);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
    try std.testing.expect(controller.nextDeltaExpiry() != null);

    // A heartbeat moves both timers before the short TTL elapses.
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    var refreshed = try deltaUpdate(&client, sds.type_url, "s2", &.{
        heartbeat("cert-1", "v1", long),
        heartbeat("roots", "v1", long),
    }, &.{});
    defer refreshed.deinit();
    try acceptDelta(controller, &client, channel, io, refreshed);
    try std.Io.sleep(io, .fromMilliseconds(60), .awake);
    try expireDelta(controller, &client, channel, io);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());

    // Clearing the TTL stops expiry entirely.
    var cleared = try deltaUpdate(&client, sds.type_url, "s3", &.{
        heartbeat("cert-1", "v1", null),
        heartbeat("roots", "v1", null),
    }, &.{});
    defer cleared.deinit();
    try acceptDelta(controller, &client, channel, io, cleared);
    try std.testing.expect(controller.nextDeltaExpiry() == null);

    // Re-arm, let both expire, and observe the cluster return to pending.
    var rearmed = try deltaUpdate(&client, sds.type_url, "s4", &.{
        heartbeat("cert-1", "v1", short),
        heartbeat("roots", "v1", short),
    }, &.{});
    defer rearmed.deinit();
    try acceptDelta(controller, &client, channel, io, rearmed);
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try expireDelta(controller, &client, channel, io);
    try std.testing.expectEqual(@as(usize, 0), channel.configuredEndpointCount());
    try std.testing.expect(controller.entries.items[0].pending());
    try std.testing.expect(client.acceptedVersion(sds.type_url, "cert-1") == null);
    try std.testing.expect(controller.nextDeltaExpiry() == null);

    var restored = try deltaUpdate(&client, sds.type_url, "s5", &.{
        deltaPayload(sds.type_url, "cert-1", "v2", certificate),
        deltaPayload(sds.type_url, "roots", "v2", roots),
    }, &.{});
    defer restored.deinit();
    try acceptDelta(controller, &client, channel, io, restored);
    try std.testing.expectEqual(@as(usize, 1), channel.configuredEndpointCount());
}
