//! Typed resource fixtures for partial delta acceptance and real reconnects.
const std = @import("std");
pub const grpc = @import("../../mod.zig");
pub const runtime = @import("../runtime.zig");
pub const delta = @import("../ads/delta.zig");
pub const cds = @import("../cds.zig");
pub const eds = @import("../eds.zig");
pub const sds = @import("../sds.zig");
pub const lds = @import("../lds.zig");
const cds_fixture = @import("../cds/testing.zig");
const sds_fixture = @import("../sds/testing.zig");
const tls_testing = @import("../../../tls/testing.zig");
pub const gpa = std.testing.allocator;
pub const Kind = enum { cds, eds, sds };
pub const clusters = [_][]const u8{
    "xdstp://A/envoy.config.cluster.v3.Cluster/a",
    "xdstp://A/envoy.config.cluster.v3.Cluster/b",
    "xdstp://B/envoy.config.cluster.v3.Cluster/c",
};
const endpoints = [_][]const u8{
    "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/a",
    "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/b",
    "xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/c",
};
const secrets = [_][]const u8{
    "xdstp://A/envoy.extensions.transport_sockets.tls.v3.Secret/a",
    "xdstp://A/envoy.extensions.transport_sockets.tls.v3.Secret/b",
    "xdstp://B/envoy.extensions.transport_sockets.tls.v3.Secret/c",
};
pub fn url(kind: Kind) []const u8 {
    return switch (kind) {
        .cds => cds.type_url,
        .eds => eds.type_url,
        .sds => sds.type_url,
    };
}
pub fn name(kind: Kind, index: usize) []const u8 {
    return switch (kind) {
        .cds => clusters[index],
        .eds => endpoints[index],
        .sds => secrets[index],
    };
}
pub fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
pub fn listener() ![]u8 {
    const routes = try @import("../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, &.{
        .{ .exact = "/demo.Service/Beta", .cluster = clusters[1] },
        .{ .exact = "/demo.Service/Gamma", .cluster = clusters[2] },
        .{ .prefix = "/", .cluster = clusters[0] },
    }, null);
    defer gpa.free(routes);
    return @import("../lds/testing.zig").encode(gpa, .{ .inline_rds = routes });
}
fn payload(kind: Kind, index: usize, changed: bool) ![]u8 {
    const port: u16 = @intCast((if (changed) @as(usize, 2001) else 1001) + index);
    return switch (kind) {
        .cds => cds_fixture.staticCluster(gpa, clusters[index], "127.0.0.1", port),
        .eds => cds_fixture.assignment(gpa, endpoints[index], "127.0.0.1", port),
        .sds => sds_fixture.validationSecret(gpa, secrets[index], tls_testing.certificate_pem, &.{}),
    };
}
fn invalid(kind: Kind) ![]u8 {
    // Field 6 value 1 is the known legacy LEAST_REQUEST policy. A federated
    // EDS cluster also needs its explicit service name to reach policy parsing.
    if (kind == .cds) return cds_fixture.cluster(gpa, clusters[1], endpoints[1], "\x30\x01");
    var builder = cds_fixture.Builder{ .allocator = gpa };
    defer builder.deinit();
    try builder.bytes(1, name(kind, 1));
    try builder.data.append(gpa, 0x12);
    return gpa.dupe(u8, builder.data.items);
}

pub const Payloads = struct {
    resources: [3]delta.codec.Resource,
    bytes: [3][]u8,
    pub fn init(kind: Kind, mixed: bool) !Payloads {
        var result: Payloads = undefined;
        var count: usize = 0;
        errdefer for (result.bytes[0..count]) |bytes| gpa.free(bytes);
        for (0..3) |index| {
            result.bytes[index] = if (mixed and index == 1) try invalid(kind) else try payload(kind, index, mixed);
            count += 1;
            result.resources[index] = .{ .name = name(kind, index), .version = if (mixed) "v2" else "v1", .resource = .{ .type_url = url(kind), .value = result.bytes[index] } };
        }
        return result;
    }
    pub fn cdsFor(kind: Kind) !Payloads {
        if (kind == .cds) return init(.cds, false);
        var result: Payloads = undefined;
        var count: usize = 0;
        errdefer for (result.bytes[0..count]) |bytes| gpa.free(bytes);
        for (0..3) |index| {
            if (kind == .eds) {
                result.bytes[index] = try cds_fixture.cluster(gpa, clusters[index], endpoints[index], "");
            } else {
                const tls = try cds_fixture.upstreamTlsSds(gpa, "localhost", null, secrets[index]);
                defer gpa.free(tls);
                result.bytes[index] = try cds_fixture.staticClusterTls(gpa, clusters[index], "127.0.0.1", @intCast(1001 + index), tls);
            }
            count += 1;
            result.resources[index] = .{ .name = clusters[index], .version = "v1", .resource = .{ .type_url = cds.type_url, .value = result.bytes[index] } };
        }
        return result;
    }
    pub fn deinit(self: Payloads) void {
        for (self.bytes) |bytes| gpa.free(bytes);
    }
};

pub const Fixture = struct {
    io: std.Io,
    channel: grpc.SharedChannel,
    client: delta.Client,
    controller: *runtime.Controller,
    pub fn init(io: std.Io, control_sender: ?grpc.SharedChannelSender) !Fixture {
        var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
        errdefer channel.deinit();
        var sender = if (control_sender) |value| value.clone() else channel.sender();
        defer sender.deinit();
        var client = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "partial" } });
        errdefer client.deinit();
        const controller = try runtime.Controller.create(gpa, .{ .listener_name = "frontend", .authority = "A", .additional_authorities = &.{"B"}, .target = .{ .authority = "backend.test" }, .ignore_resource_deletion = true, .fail_on_data_errors = true, .disable_automatic_lrs = true });
        errdefer controller.deinit();
        _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
        return .{ .io = io, .channel = channel, .client = client, .controller = controller };
    }
    pub fn deinit(self: *Fixture) void {
        self.controller.deinit();
        self.client.deinit();
        self.channel.deinit();
    }
    pub fn update(self: *Fixture, type_url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource, removed: []const []const u8) !delta.Update {
        const wire = try delta.codec.encodeResponse(gpa, .{ .type_url = type_url, .nonce = nonce, .resources = resources, .removed = removed }, .{});
        defer gpa.free(wire);
        var response = try delta.codec.decodeResponse(gpa, wire, .{});
        errdefer response.deinit();
        return .{ .response = response, .token = try self.client.subscriptions.received(response.value) };
    }
    pub fn apply(self: *Fixture, value: delta.Update) !u64 {
        return self.controller.applyDeltaWithDeadline(&self.client, value, self.channel, deadline(self.io));
    }
    pub fn accept(self: *Fixture, type_url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource) !void {
        var value = try self.update(type_url, nonce, resources, &.{});
        defer value.deinit();
        try std.testing.expectError(error.AdsNotConnected, self.apply(value));
    }
    pub fn seed(self: *Fixture, kind: Kind) !void {
        const bytes = try listener();
        defer gpa.free(bytes);
        try self.accept(lds.type_url, "listener", &.{.{ .name = "frontend", .version = "l1", .resource = .{ .type_url = lds.type_url, .value = bytes } }});
        try std.testing.expectEqual(@as(usize, 3), self.controller.latest.?.source.required_clusters.len);
        var clusters_payload = try Payloads.cdsFor(kind);
        defer clusters_payload.deinit();
        try self.accept(cds.type_url, "clusters", &clusters_payload.resources);
        if (kind != .cds) {
            var values = try Payloads.init(kind, false);
            defer values.deinit();
            try self.accept(url(kind), "initial", &values.resources);
        }
        try std.testing.expectEqual(@as(usize, 3), self.channel.configuredEndpointCount());
    }
    pub fn find(self: *Fixture, index: usize) *@import("entry.zig").Entry {
        for (self.controller.entries.items) |*entry| if (std.mem.eql(u8, entry.identity.name, clusters[index])) return entry;
        unreachable;
    }
    pub fn acceptedTime(self: *Fixture, kind: Kind, index: usize) i128 {
        const entry = self.client.subscriptions.find(url(kind)).?;
        for (entry.versions) |version| if (std.mem.eql(u8, version.name, name(kind, index))) return version.accepted_ns;
        return 0;
    }
};
