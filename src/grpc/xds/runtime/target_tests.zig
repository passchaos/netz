const std = @import("std");
const cds = @import("../cds.zig");
const entry = @import("entry.zig");
const target = @import("target.zig");
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
