//! Supplying authorities own their resource updates, omissions and removals.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const entry = @import("entry.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const sds = @import("../sds.zig");
const rds = @import("../rds.zig");
const lds_fixture = @import("../lds/testing.zig");
const rds_fixture = @import("../rds/testing.zig");
const cds_fixture = @import("../cds/testing.zig");
const eds_fixture = @import("../eds/testing.zig");
const sds_fixture = @import("../sds/testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
const gpa = std.testing.allocator;
const cluster_a = "xdstp://A/envoy.config.cluster.v3.Cluster/a";
const cluster_b = "xdstp://B/envoy.config.cluster.v3.Cluster/b";
const endpoint_a = "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/a";
const endpoint_b = "xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/b";
const secret_a = "xdstp://A/envoy.extensions.transport_sockets.tls.v3.Secret/a";
const secret_b = "xdstp://B/envoy.extensions.transport_sockets.tls.v3.Secret/b";
const certificate_a = "xdstp://A/envoy.extensions.transport_sockets.tls.v3.Secret/certificate-a";
const pending_routes_b = "xdstp://B/envoy.config.route.v3.RouteConfiguration/pending";
const Payload = struct { name: []const u8, bytes: ?[]const u8 = null, ttl: ?delta.codec.Duration = null };

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn Harness(comptime is_delta: bool) type {
    return struct {
        const Self = @This();
        io: std.Io,
        controller: *runtime.Controller,
        channel: grpc.SharedChannel,
        client: if (is_delta) delta.Client else ads.Client,

        fn init(io: std.Io, channel_allocator: std.mem.Allocator) !Self {
            var channel = try grpc.SharedChannel.init(channel_allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
            errdefer channel.deinit();
            var sender = channel.sender();
            defer sender.deinit();
            var client = try (if (is_delta) delta.Client else ads.Client).init(gpa, sender, .{ .node = .{ .id = "federated" } });
            errdefer client.deinit();
            const controller = try runtime.Controller.create(gpa, .{
                .listener_name = "frontend",
                .target = .{ .authority = "backend.test" },
                .authority = "A",
                .additional_authorities = &.{"B"},
            });
            errdefer controller.deinit();
            if (is_delta) {
                _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
            } else {
                _ = try controller.startWithDeadline(&client, channel, deadline(io));
            }
            return .{ .io = io, .controller = controller, .channel = channel, .client = client };
        }

        fn deinit(self: *Self) void {
            self.controller.deinit();
            self.client.deinit();
            self.channel.deinit();
        }

        fn apply(self: *Self, url: []const u8, version: []const u8, payloads: []const Payload, removed: []const []const u8) !void {
            if (is_delta) {
                const resources = try gpa.alloc(delta.codec.Resource, payloads.len);
                defer gpa.free(resources);
                for (payloads, resources) |payload, *resource| resource.* = .{
                    .name = payload.name,
                    .version = version,
                    .resource = if (payload.bytes) |bytes| .{ .type_url = url, .value = bytes } else null,
                    .ttl = payload.ttl,
                };
                const wire = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = version, .resources = resources, .removed = removed }, .{});
                defer gpa.free(wire);
                var response = try delta.codec.decodeResponse(gpa, wire, .{});
                defer response.deinit();
                const value = delta.Update{ .response = response, .token = try self.client.subscriptions.received(response.value) };
                _ = try self.controller.applyDeltaWithDeadline(&self.client, value, self.channel, deadline(self.io));
            } else {
                const resources = try gpa.alloc(ads.codec.Any, payloads.len);
                defer gpa.free(resources);
                for (payloads, resources) |payload, *resource| resource.* = .{ .type_url = url, .value = payload.bytes.? };
                const wire = try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = resources }, 65536);
                defer gpa.free(wire);
                var response = try ads.codec.decodeResponse(gpa, wire, .{});
                defer response.deinit();
                const value = ads.Update{ .response = response, .token = try self.client.subscriptions.received(response.value) };
                _ = try self.controller.applyWithDeadline(&self.client, value, self.channel, deadline(self.io));
            }
        }

        fn accept(self: *Self, url: []const u8, version: []const u8, payloads: []const Payload, removed: []const []const u8) !void {
            try std.testing.expectError(error.AdsNotConnected, self.apply(url, version, payloads, removed));
        }

        fn find(self: *Self, name: []const u8) *entry.Entry {
            for (self.controller.entries.items) |*item| {
                if (std.mem.eql(u8, name, item.identity.name)) return item;
            }
            unreachable;
        }

        fn seed(self: *Self) !void {
            const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{
                .{ .exact = "/demo.Service/Beta", .cluster = cluster_b },
                .{ .prefix = "/", .cluster = cluster_a },
            }, null);
            defer gpa.free(routes);
            const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
            defer gpa.free(listener);
            try self.accept(lds.type_url, "l1", &.{.{ .name = "frontend", .bytes = listener }}, &.{});
            const a = try clusterWire(cluster_a, endpoint_a, secret_a);
            defer gpa.free(a);
            const b = try clusterWire(cluster_b, endpoint_b, secret_b);
            defer gpa.free(b);
            try self.accept(cds.type_url, "c1", &.{ .{ .name = cluster_a, .bytes = a }, .{ .name = cluster_b, .bytes = b } }, &.{});
            const ea = try endpointWire(endpoint_a, 1001);
            defer gpa.free(ea);
            const eb = try endpointWire(endpoint_b, 1002);
            defer gpa.free(eb);
            try self.accept(eds.type_url, "e1", &.{ .{ .name = endpoint_a, .bytes = ea }, .{ .name = endpoint_b, .bytes = eb } }, &.{});
            const sa = try sds_fixture.validationSecret(gpa, secret_a, tls_testing.certificate_pem, &.{});
            defer gpa.free(sa);
            const sb = try sds_fixture.validationSecret(gpa, secret_b, tls_testing.certificate_pem, &.{});
            defer gpa.free(sb);
            try self.accept(sds.type_url, "s1", &.{ .{ .name = secret_a, .bytes = sa }, .{ .name = secret_b, .bytes = sb } }, &.{});
            try std.testing.expectEqual(@as(usize, 2), self.channel.configuredEndpointCount());
        }
    };
}

fn clusterWire(name: []const u8, endpoint: []const u8, secret: []const u8) ![]u8 {
    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", null, secret);
    defer gpa.free(tls);
    var extra = cds_fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(24, tls);
    return cds_fixture.cluster(gpa, name, endpoint, extra.data.items);
}

fn endpointWire(name: []const u8, port: u16) ![]u8 {
    return eds_fixture.encode(gpa, name, &.{.{ .region = "region", .endpoints = &.{.{ .port = port }} }}, null);
}

fn scopeIsolation(comptime is_delta: bool, io: std.Io) !void {
    var h = try Harness(is_delta).init(io, gpa);
    defer h.deinit();
    try h.seed();
    const b_cluster = h.find(cluster_b).cluster.?;
    const b_snapshot = h.find(cluster_b).snapshot.?;
    const b_secret = h.controller.sds_secrets.get(secret_b).?;
    h.controller.response_authority = "A";
    try h.accept(eds.type_url, "e-empty", &.{}, &.{});
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);

    const eb = try endpointWire(endpoint_b, 2002);
    defer gpa.free(eb);
    try h.accept(eds.type_url, "e-foreign", &.{.{ .name = endpoint_b, .bytes = eb }}, &.{});
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);
    const ea = try endpointWire(endpoint_a, 2001);
    defer gpa.free(ea);
    try h.accept(eds.type_url, "e-partial", &.{ .{ .name = endpoint_a, .bytes = ea }, .{ .name = endpoint_b, .bytes = eb } }, &.{});
    try std.testing.expectEqualSlices(u8, ea, h.find(cluster_a).snapshot.?.resource.wire);
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);

    const a = try clusterWire(cluster_a, endpoint_a, secret_a);
    defer gpa.free(a);
    const foreign_b = try cds_fixture.staticCluster(gpa, cluster_b, "127.0.0.1", 3002);
    defer gpa.free(foreign_b);
    try h.accept(cds.type_url, "c-partial", &.{ .{ .name = cluster_a, .bytes = a }, .{ .name = cluster_b, .bytes = foreign_b } }, &.{});
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);

    if (is_delta) {
        try h.accept(eds.type_url, "e-foreign-beat", &.{.{ .name = endpoint_b, .ttl = .{ .seconds = 100 } }}, &.{});
        try h.accept(cds.type_url, "c-foreign-beat", &.{.{ .name = cluster_b, .ttl = .{ .seconds = 100 } }}, &.{});
        try h.accept(sds.type_url, "s-foreign-beat", &.{.{ .name = secret_b, .ttl = .{ .seconds = 100 } }}, &.{});
        try h.accept(eds.type_url, "e-foreign-remove", &.{}, &.{endpoint_b});
        try h.accept(cds.type_url, "c-foreign-remove", &.{}, &.{cluster_b});
        try h.accept(sds.type_url, "s-foreign-remove", &.{}, &.{secret_b});
        try std.testing.expect(h.find(cluster_b).eds_deadline == null);
        try std.testing.expect(h.find(cluster_b).cds_deadline == null);
        try std.testing.expect(b_secret.deadline == null);
        try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);
    }
    h.controller.response_authority = "B";
    try h.accept(eds.type_url, "e-b", &.{.{ .name = endpoint_b, .bytes = eb }}, &.{});
    try std.testing.expectEqualSlices(u8, eb, h.find(cluster_b).snapshot.?.resource.wire);
    const accepted_b = h.find(cluster_b).snapshot.?;
    h.controller.response_authority = "A";
    if (is_delta) {
        try h.accept(eds.type_url, "e-remove", &.{}, &.{ endpoint_a, endpoint_b });
        try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
        try std.testing.expect(h.find(cluster_b).snapshot.? == accepted_b);
        try h.accept(eds.type_url, "e-restore", &.{.{ .name = endpoint_a, .bytes = ea }}, &.{});
    }
    try h.accept(sds.type_url, "s-remove", &.{}, &.{ secret_a, secret_b });
    try std.testing.expect(h.find(cluster_a).cluster.?.sdsPending());
    try std.testing.expect(h.controller.sds_secrets.get(secret_a) == null);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.find(cluster_b).snapshot.? == accepted_b);
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
    try h.accept(cds.type_url, "c-remove", &.{}, &.{ cluster_a, cluster_b });
    try std.testing.expect(h.find(cluster_a).cluster == null);
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());

    // A default-authority session does not own either xdstp authority.
    h.controller.response_authority = "";
    try h.accept(cds.type_url, "c-default", &.{}, &.{cluster_b});
    try h.accept(sds.type_url, "s-default", &.{}, &.{secret_b});
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    // The unscoped API retains its existing whole-type/removal behavior.
    h.controller.response_authority = null;
    try h.accept(cds.type_url, "c-raw", &.{}, &.{cluster_b});
    try h.accept(sds.type_url, "s-raw", &.{}, &.{secret_b});
    try std.testing.expect(h.find(cluster_b).cluster == null);
    try std.testing.expectEqual(@as(usize, 0), h.controller.sds_secrets.count());
    try std.testing.expectEqual(@as(usize, 0), h.channel.configuredEndpointCount());
}

fn rollback(comptime is_delta: bool, io: std.Io) !void {
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var h = try Harness(is_delta).init(io, failing.allocator());
    defer h.deinit();
    try h.seed();
    h.controller.response_authority = "A";
    const a_cluster = h.find(cluster_a).cluster.?;
    const a_snapshot = h.find(cluster_a).snapshot.?;
    const b_cluster = h.find(cluster_b).cluster.?;
    const b_snapshot = h.find(cluster_b).snapshot.?;
    const a_secret = h.controller.sds_secrets.get(secret_a).?;
    const b_secret = h.controller.sds_secrets.get(secret_b).?;
    const revision = h.channel.configurationRevision();
    failing.fail_index = failing.alloc_index;
    const result = h.apply(sds.type_url, "s-failed", &.{}, &.{secret_a});
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expect(h.find(cluster_a).cluster.? == a_cluster);
    try std.testing.expect(h.find(cluster_a).snapshot.? == a_snapshot);
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);
    try std.testing.expect(h.controller.sds_secrets.get(secret_a).? == a_secret);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    try std.testing.expect(!a_cluster.sdsPending());
    const replacement = try sds_fixture.tlsSecret(gpa, secret_a, tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(replacement);
    try std.testing.expectError(error.InvalidSdsResource, h.apply(sds.type_url, "s-invalid", &.{.{ .name = secret_a, .bytes = replacement }}, &.{}));
    try std.testing.expect(h.controller.sds_secrets.get(secret_a).? == a_secret);
    try std.testing.expect(h.find(cluster_a).cluster.? == a_cluster);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
}

fn foreignDataErrors(comptime is_delta: bool, io: std.Io) !void {
    var h = try Harness(is_delta).init(io, gpa);
    defer h.deinit();
    try h.seed();
    h.controller.response_authority = "A";
    h.controller.options.fail_on_data_errors = true;
    const b_cluster = h.find(cluster_b).cluster.?;
    const b_snapshot = h.find(cluster_b).snapshot.?;
    const b_secret = h.controller.sds_secrets.get(secret_b).?;
    const a = try clusterWire(cluster_a, endpoint_a, secret_a);
    defer gpa.free(a);
    const invalid_b = try cds_fixture.cluster(gpa, cluster_b, endpoint_b, "\x30\x01");
    defer gpa.free(invalid_b);
    try h.accept(cds.type_url, "c-invalid-foreign", &.{ .{ .name = cluster_a, .bytes = a }, .{ .name = cluster_b, .bytes = invalid_b } }, &.{});
    var bad_endpoint = cds_fixture.Builder{ .allocator = gpa };
    defer bad_endpoint.deinit();
    try bad_endpoint.bytes(1, endpoint_b);
    try bad_endpoint.data.append(gpa, 0x18);
    try h.accept(eds.type_url, "e-invalid-foreign", &.{.{ .name = endpoint_b, .bytes = bad_endpoint.data.items }}, &.{});
    var bad_secret = cds_fixture.Builder{ .allocator = gpa };
    defer bad_secret.deinit();
    try bad_secret.bytes(1, secret_b);
    try bad_secret.data.append(gpa, 0x12);
    const sa = try sds_fixture.validationSecret(gpa, secret_a, tls_testing.certificate_pem, &.{});
    defer gpa.free(sa);
    try h.accept(sds.type_url, "s-invalid-foreign", &.{ .{ .name = secret_a, .bytes = sa }, .{ .name = secret_b, .bytes = bad_secret.data.items } }, &.{});
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
}

fn retainedSdsWithdrawal(comptime is_delta: bool, comptime expires: bool, io: std.Io) !void {
    var h = try Harness(is_delta).init(io, gpa);
    defer h.deinit();
    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cluster_a }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    try h.accept(lds.type_url, "retained-l1", &.{.{ .name = "frontend", .bytes = listener }}, &.{});
    h.controller.response_authority = "A";
    const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", certificate_a, secret_a);
    defer gpa.free(tls);
    var extra = cds_fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(24, tls);
    const cluster = try cds_fixture.cluster(gpa, cluster_a, endpoint_a, extra.data.items);
    defer gpa.free(cluster);
    try h.accept(cds.type_url, "retained-c1", &.{.{ .name = cluster_a, .bytes = cluster }}, &.{});
    const certificate = try sds_fixture.tlsSecret(gpa, certificate_a, tls_testing.certificate_pem, tls_testing.private_key_pem);
    defer gpa.free(certificate);
    const roots = try sds_fixture.validationSecret(gpa, secret_a, tls_testing.certificate_pem, &.{});
    defer gpa.free(roots);
    try h.accept(sds.type_url, "retained-s1", &.{ .{ .name = certificate_a, .bytes = certificate }, .{ .name = secret_a, .bytes = roots } }, &.{});
    const assignment = try endpointWire(endpoint_a, 1001);
    defer gpa.free(assignment);
    try h.accept(eds.type_url, "retained-e1", &.{.{ .name = endpoint_a, .bytes = assignment }}, &.{});
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
    try std.testing.expect(!h.find(cluster_a).pending());
    try std.testing.expect(h.find(cluster_a).cluster.?.resolvedTls().?.certificate_chain.len != 0);
    h.controller.retain_valid_routes = true;
    // Establish A as the retained serving selector after enabling retention.
    try h.accept(cds.type_url, "retained-c2", &.{.{ .name = cluster_a, .bytes = cluster }}, &.{});
    const served = h.controller.served_projection.?;
    try std.testing.expect(served == h.controller.latest.?);
    const replacement = try lds_fixture.encode(gpa, .{ .route_name = pending_routes_b });
    defer gpa.free(replacement);
    try h.accept(lds.type_url, "retained-l2", &.{.{ .name = "frontend", .bytes = replacement }}, &.{});
    try std.testing.expect(h.controller.latest.? != served);
    try std.testing.expect(h.controller.latest.?.pending);
    try std.testing.expect(h.controller.served_projection.? == served);
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
    const accepted_certificate = h.controller.sds_secrets.get(certificate_a).?;
    const accepted_snapshot = h.find(cluster_a).snapshot.?;
    const wrong_kind = try sds_fixture.validationSecret(gpa, certificate_a, tls_testing.certificate_pem, &.{});
    defer gpa.free(wrong_kind);
    try std.testing.expectError(error.InvalidSdsResource, h.apply(sds.type_url, "retained-nack", &.{ .{ .name = certificate_a, .bytes = wrong_kind }, .{ .name = secret_a, .bytes = roots } }, &.{}));
    try std.testing.expect(h.controller.sds_secrets.get(certificate_a).? == accepted_certificate);
    try std.testing.expect(h.find(cluster_a).snapshot.? == accepted_snapshot);
    try std.testing.expect(!h.find(cluster_a).cluster.?.sdsPending());
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
    const before_withdrawal = h.channel.configurationRevision();
    if (expires) {
        try h.accept(sds.type_url, "retained-ttl", &.{.{ .name = certificate_a, .ttl = .{} }}, &.{});
        try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
        try std.testing.expect(h.client.acceptedVersion(sds.type_url, certificate_a) == null);
    } else if (is_delta) {
        try h.accept(sds.type_url, "retained-remove", &.{}, &.{certificate_a});
    } else {
        try h.accept(sds.type_url, "retained-omit", &.{.{ .name = secret_a, .bytes = roots }}, &.{});
    }
    try std.testing.expect(h.controller.latest.?.pending);
    try std.testing.expect(h.controller.served_projection.? == served);
    try std.testing.expect(h.controller.sds_secrets.get(certificate_a) == null);
    try std.testing.expect(h.controller.sds_secrets.get(secret_a) != null);
    try std.testing.expect(h.find(cluster_a).cluster.?.sdsPending());
    const pending_cluster = h.find(cluster_a).cluster.?;
    try std.testing.expect(pending_cluster.tls_override == null);
    const raw_tls = pending_cluster.resolvedTls().?;
    try std.testing.expectEqualStrings("localhost", raw_tls.server_name);
    try std.testing.expectEqual(@as(usize, 0), raw_tls.certificate_chain.len);
    try std.testing.expectEqual(@as(usize, 0), raw_tls.private_key.len);
    try std.testing.expect(!h.find(cluster_a).eds_seen);
    try std.testing.expectEqual(@as(usize, 0), h.channel.configuredEndpointCount());
    try std.testing.expect(h.channel.configurationRevision() > before_withdrawal);
    const published = h.channel.state.retainConfig().?;
    defer published.release();
    try std.testing.expect(published.call_selector.?.context == @as(*anyopaque, @ptrCast(served)));
    var sender = h.channel.sender();
    defer sender.deinit();
    // A new RPC uses the retained A route, but has no TLS endpoint to admit it.
    try std.testing.expectError(error.Timeout, sender.unary(.{ .path = "/demo.Service/Alpha", .authority = "backend.test", .message = "", .wait_for_ready = false, .timeout = .{ .value = 25, .unit = .millisecond } }));
}

fn expiryScope(io: std.Io) !void {
    var h = try Harness(true).init(io, gpa);
    defer h.deinit();
    try h.seed();
    const b_cluster = h.find(cluster_b).cluster.?;
    const b_snapshot = h.find(cluster_b).snapshot.?;
    const b_secret = h.controller.sds_secrets.get(secret_b).?;
    try h.accept(cds.type_url, "due-cds", &.{ .{ .name = cluster_a, .ttl = .{} }, .{ .name = cluster_b, .ttl = .{} } }, &.{});
    try h.accept(eds.type_url, "due-eds", &.{ .{ .name = endpoint_a, .ttl = .{} }, .{ .name = endpoint_b, .ttl = .{} } }, &.{});
    try h.accept(sds.type_url, "due-sds", &.{ .{ .name = secret_a, .ttl = .{} }, .{ .name = secret_b, .ttl = .{} } }, &.{});
    h.controller.response_authority = "A";
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.find(cluster_a).cluster == null);
    try std.testing.expect(h.controller.sds_secrets.get(secret_a) == null);
    try std.testing.expect(h.find(cluster_b).cluster.? == b_cluster);
    try std.testing.expect(h.find(cluster_b).snapshot.? == b_snapshot);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    try std.testing.expect(h.find(cluster_b).cds_deadline != null);
    try std.testing.expect(h.find(cluster_b).eds_deadline != null);
    try std.testing.expect(b_secret.deadline != null);
    try std.testing.expect(h.client.acceptedVersion(cds.type_url, cluster_a) == null);
    try std.testing.expect(h.client.acceptedVersion(eds.type_url, endpoint_a) == null);
    try std.testing.expect(h.client.acceptedVersion(sds.type_url, secret_a) == null);
    try std.testing.expectEqualStrings("due-cds", h.client.acceptedVersion(cds.type_url, cluster_b).?);
    try std.testing.expectEqualStrings("due-eds", h.client.acceptedVersion(eds.type_url, endpoint_b).?);
    try std.testing.expectEqualStrings("due-sds", h.client.acceptedVersion(sds.type_url, secret_b).?);
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
    h.controller.response_authority = "B";
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.find(cluster_b).cluster == null);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b) == null);
    try std.testing.expect(h.client.acceptedVersion(cds.type_url, cluster_b) == null);
    try std.testing.expect(h.client.acceptedVersion(eds.type_url, endpoint_b) == null);
    try std.testing.expect(h.client.acceptedVersion(sds.type_url, secret_b) == null);
    try std.testing.expectEqual(@as(usize, 0), h.channel.configuredEndpointCount());
}

fn expiryRollback(io: std.Io) !void {
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var h = try Harness(true).init(io, failing.allocator());
    defer h.deinit();
    try h.seed();
    try h.accept(sds.type_url, "due-secret", &.{ .{ .name = secret_a, .ttl = .{} }, .{ .name = secret_b, .ttl = .{} } }, &.{});
    h.controller.response_authority = "A";
    const a_cluster = h.find(cluster_a).cluster.?;
    const a_snapshot = h.find(cluster_a).snapshot.?;
    const a_secret = h.controller.sds_secrets.get(secret_a).?;
    const b_secret = h.controller.sds_secrets.get(secret_b).?;
    const revision = h.channel.configurationRevision();
    failing.fail_index = failing.alloc_index;
    const result = h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expectEqual(revision, h.channel.configurationRevision());
    try std.testing.expect(h.find(cluster_a).cluster.? == a_cluster);
    try std.testing.expect(h.find(cluster_a).snapshot.? == a_snapshot);
    try std.testing.expect(!a_cluster.sdsPending());
    try std.testing.expect(h.controller.sds_secrets.get(secret_a).? == a_secret);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    try std.testing.expect(a_secret.deadline != null and b_secret.deadline != null);
    try std.testing.expectEqualStrings("due-secret", h.client.acceptedVersion(sds.type_url, secret_a).?);
    try std.testing.expectEqualStrings("due-secret", h.client.acceptedVersion(sds.type_url, secret_b).?);
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.controller.sds_secrets.get(secret_a) == null);
    try std.testing.expect(h.controller.sds_secrets.get(secret_b).? == b_secret);
    try std.testing.expect(h.client.acceptedVersion(sds.type_url, secret_a) == null);
    try std.testing.expectEqualStrings("due-secret", h.client.acceptedVersion(sds.type_url, secret_b).?);
    try std.testing.expectEqual(@as(usize, 1), h.channel.configuredEndpointCount());
}

fn expiryRouteScope(io: std.Io) !void {
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    var h = try Harness(true).init(io, failing.allocator());
    defer h.deinit();
    try h.seed();
    const listener = try lds_fixture.encode(gpa, .{ .route_name = pending_routes_b });
    defer gpa.free(listener);
    try h.accept(lds.type_url, "dynamic-listener", &.{.{ .name = "frontend", .bytes = listener }}, &.{});
    const routes = try rds_fixture.encode(gpa, pending_routes_b, &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = cluster_a }}, null);
    defer gpa.free(routes);
    try h.accept(rds.type_url, "dynamic-routes", &.{.{ .name = pending_routes_b, .bytes = routes }}, &.{});
    try h.accept(lds.type_url, "due-listener", &.{.{ .name = "frontend", .ttl = .{} }}, &.{});
    try h.accept(rds.type_url, "due-routes", &.{.{ .name = pending_routes_b, .ttl = .{} }}, &.{});
    const accepted_routes = h.controller.listener.?.routes.?;
    const accepted_projection = h.controller.latest.?;
    h.controller.response_authority = "A";
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.controller.listener.?.routes.? == accepted_routes);
    try std.testing.expect(h.controller.listener.?.listener_deadline != null);
    try std.testing.expect(h.controller.listener.?.routes_deadline != null);
    h.controller.response_authority = "B";
    failing.fail_index = failing.alloc_index;
    const result = h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(h.controller.listener.?.routes.? == accepted_routes);
    try std.testing.expect(h.controller.latest.? == accepted_projection);
    try std.testing.expectEqualStrings("due-routes", h.client.acceptedVersion(rds.type_url, pending_routes_b).?);
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.controller.listener.?.listener != null);
    try std.testing.expect(!h.controller.listener.?.routes_accepted);
    try std.testing.expect(h.controller.listener.?.routes_deadline == null);
    try std.testing.expect(h.controller.listener.?.listener_deadline != null);
    try std.testing.expect(h.client.acceptedVersion(rds.type_url, pending_routes_b) == null);
    try std.testing.expectEqualStrings("due-listener", h.client.acceptedVersion(lds.type_url, "frontend").?);
    h.controller.response_authority = "";
    try std.testing.expectError(error.AdsNotConnected, h.controller.expireDeltaWithDeadline(&h.client, h.channel, deadline(io)));
    try std.testing.expect(h.controller.listener.?.listener == null);
    try std.testing.expect(h.client.acceptedVersion(lds.type_url, "frontend") == null);
}

test "gRPC xDS federated SotW scope preserves foreign caches and raw behavior" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try scopeIsolation(false, threaded.io());
}

test "gRPC xDS federated delta scope isolates candidates removals and heartbeats" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try scopeIsolation(true, threaded.io());
}

test "gRPC xDS federated SDS rejects and publication failures preserve accepted caches" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try rollback(false, threaded.io());
    try rollback(true, threaded.io());
}

test "gRPC xDS federated lenient data errors do not drop foreign resources" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try foreignDataErrors(false, threaded.io());
    try foreignDataErrors(true, threaded.io());
}

test "gRPC xDS federated pending route handoff cannot retain omitted SDS certificate" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try retainedSdsWithdrawal(false, false, threaded.io());
}

test "gRPC xDS federated pending route handoff cannot retain removed SDS certificate" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try retainedSdsWithdrawal(true, false, threaded.io());
}

test "gRPC xDS federated pending route handoff cannot retain expired SDS certificate" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try retainedSdsWithdrawal(true, true, threaded.io());
}

test "gRPC xDS federated delta expiry preserves foreign cache timers and versions" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try expiryScope(threaded.io());
}

test "gRPC xDS federated delta expiry publication failure preserves secrets TLS and versions" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try expiryRollback(threaded.io());
}

test "gRPC xDS federated delta expiry scopes LDS and RDS and retains versions on rejection" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try expiryRouteScope(threaded.io());
}
