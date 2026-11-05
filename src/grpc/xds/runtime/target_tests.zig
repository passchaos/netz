const std = @import("std");
const cds = @import("../cds.zig");
const entry = @import("entry.zig");
const target = @import("target.zig");
const runtime = @import("../runtime.zig");
const fixture = @import("../cds/testing.zig");

const gpa = std.testing.allocator;

fn aggregateCluster(leaves: []const []const u8) ![]u8 {
    var config = fixture.Builder{ .allocator = gpa };
    defer config.deinit();
    for (leaves) |leaf| try config.bytes(1, leaf);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig");
    try any.bytes(2, config.data.items);
    var custom = fixture.Builder{ .allocator = gpa };
    defer custom.deinit();
    try custom.bytes(1, "envoy.clusters.aggregate");
    try custom.bytes(2, any.data.items);
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(38, custom.data.items);
    return fixture.cluster(gpa, "aggregate", "", extra.data.items);
}

test "gRPC xDS target expands aggregate clusters into ordered priorities" {
    const leaf_a = try fixture.dnsCluster(gpa, "leaf-a", "a.test", 1001, 1);
    defer gpa.free(leaf_a);
    const leaf_b = try fixture.dnsCluster(gpa, "leaf-b", "b.test", 1002, 1);
    defer gpa.free(leaf_b);
    const aggregate = try aggregateCluster(&.{ "leaf-a", "leaf-b" });
    defer gpa.free(aggregate);

    const decoded_a = try cds.decode(gpa, leaf_a, .{});
    const decoded_b = try cds.decode(gpa, leaf_b, .{});
    const decoded_aggregate = try cds.decode(gpa, aggregate, .{});
    try std.testing.expect(decoded_aggregate.value.isAggregate());

    // Ownership transfers into entry.Cluster; do not deinit the originals.
    const cluster_a = try entry.Cluster.create(gpa, decoded_a);
    defer cluster_a.release();
    const cluster_b = try entry.Cluster.create(gpa, decoded_b);
    defer cluster_b.release();
    const cluster_aggregate = try entry.Cluster.create(gpa, decoded_aggregate);
    defer cluster_aggregate.release();

    const identity_a = try entry.Identity.create(gpa, "leaf-a");
    defer identity_a.release();
    const identity_b = try entry.Identity.create(gpa, "leaf-b");
    defer identity_b.release();
    const identity_aggregate = try entry.Identity.create(gpa, "aggregate");
    defer identity_aggregate.release();

    const entries = [_]entry.Entry{
        .{ .identity = identity_a, .cluster = cluster_a, .cds_seen = true, .eds_seen = true },
        .{ .identity = identity_b, .cluster = cluster_b, .cds_seen = true, .eds_seen = true },
        .{ .identity = identity_aggregate, .cluster = cluster_aggregate, .cds_seen = true, .eds_seen = true },
    };
    const built = try target.Target.create(gpa, std.testing.io, &entries, null);
    defer built.release();

    try std.testing.expect(std.mem.indexOf(u8, built.json, "\"priority_experimental\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, built.json, "\"leaf-a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, built.json, "\"leaf-b\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, built.json, "\"cluster:aggregate\"") != null);
}

test "gRPC xDS target resolves a LOGICAL_DNS cluster without re-resolution" {
    // kind 2 is CDS Discovery.logical_dns.
    const logical = try fixture.dnsCluster(gpa, "logical", "logical.test", 1003, 2);
    defer gpa.free(logical);
    const decoded = try cds.decode(gpa, logical, .{});
    try std.testing.expect(decoded.value.isDns());

    const cluster = try entry.Cluster.create(gpa, decoded);
    defer cluster.release();
    const identity = try entry.Identity.create(gpa, "logical");
    defer identity.release();

    const entries = [_]entry.Entry{
        .{ .identity = identity, .cluster = cluster, .cds_seen = true, .eds_seen = true },
    };
    const built = try target.Target.create(gpa, std.testing.io, &entries, null);
    defer built.release();

    // LOGICAL_DNS resolves once when the cluster is applied and asks the child
    // policy not to re-resolve on connection failure.
    try std.testing.expectEqual(@as(usize, 1), built.endpoints.len);
    const endpoint = built.endpoints[0].cleartext_host;
    try std.testing.expectEqualStrings("logical.test", endpoint.host);
    try std.testing.expectEqual(@as(u16, 1003), endpoint.port);
    try std.testing.expect(std.mem.indexOf(u8, built.json, "\"ignoreReresolutionRequests\":true") != null);

    // STRICT_DNS keeps re-resolution enabled so a connection failure can
    // refresh the address list.
    const strict = try fixture.dnsCluster(gpa, "strict", "strict.test", 1004, 1);
    defer gpa.free(strict);
    const strict_decoded = try cds.decode(gpa, strict, .{});
    const strict_cluster = try entry.Cluster.create(gpa, strict_decoded);
    defer strict_cluster.release();
    const strict_identity = try entry.Identity.create(gpa, "strict");
    defer strict_identity.release();
    const strict_entries = [_]entry.Entry{
        .{ .identity = strict_identity, .cluster = strict_cluster, .cds_seen = true, .eds_seen = true },
    };
    const strict_built = try target.Target.create(gpa, std.testing.io, &strict_entries, null);
    defer strict_built.release();
    try std.testing.expectEqualStrings("strict.test", strict_built.endpoints[0].cleartext_host.host);
    try std.testing.expect(std.mem.indexOf(u8, strict_built.json, "\"ignoreReresolutionRequests\":false") != null);
}
test "gRPC xDS controller projects CDS HTTP/2 upstream limits" {
    var h2 = fixture.Builder{ .allocator = gpa };
    defer h2.deinit();
    try h2.wrapper(1, 4096);
    try h2.wrapper(2, 100);
    try h2.wrapper(3, 1048576);
    try h2.wrapper(4, 2097152);
    var http = fixture.Builder{ .allocator = gpa };
    defer http.deinit();
    try http.bytes(2, h2.data.items);
    var any = fixture.Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions");
    try any.bytes(2, http.data.items);
    var typed = fixture.Builder{ .allocator = gpa };
    defer typed.deinit();
    try typed.bytes(2, any.data.items);
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(48, typed.data.items);
    const cluster_bytes = try fixture.cluster(
        gpa,
        "backend",
        "backend-eds",
        extra.data.items,
    );
    defer gpa.free(cluster_bytes);
    const decoded = try cds.decode(gpa, cluster_bytes, .{});
    const cluster = try entry.Cluster.create(gpa, decoded);
    defer cluster.release();
    const controller = try runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
    });
    defer controller.deinit();
    const assignment = try fixture.assignment(
        gpa,
        "backend-eds",
        "127.0.0.1",
        8080,
    );
    defer gpa.free(assignment);
    const snapshot = try controller.project(
        std.testing.io,
        cluster,
        assignment,
    );
    defer snapshot.release();
    const limits = switch (snapshot.endpoints[0]) {
        .cleartext_ip => |value| value.limits,
        else => return error.UnexpectedEndpoint,
    };
    try std.testing.expectEqual(@as(?u32, 100), limits.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 1048576), limits.initial_window_size);
    try std.testing.expectEqual(
        @as(u32, 2097152),
        limits.initial_connection_window_size,
    );
    try std.testing.expectEqual(@as(usize, 4096), limits.header_table_size);
}
