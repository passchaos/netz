const std = @import("std");
const resource = @import("decode.zig");
const target = @import("target.zig");
const fixture = @import("testing.zig");
const allocator = std.testing.allocator;

test "gRPC EDS decodes priority locality endpoint weights health and additional addresses" {
    const encoded = try fixture.encode(allocator, "backend", &.{
        .{ .region = "a", .weight = 2, .endpoints = &.{ .{ .port = 1001, .weight = 3, .extra_port = 1002 }, .{ .port = 1003, .health = 3 }, .{ .port = 1004, .health = 2 } } },
        .{ .region = "ignored", .weight = null, .endpoints = &.{.{ .port = 0 }} },
        .{ .region = "b", .priority = 1, .weight = 4, .endpoints = &.{.{ .port = 1005 }} },
    }, .{ .category = "throttle", .requests_per_million = 1234 });
    defer allocator.free(encoded);
    var owned = try resource.decode(allocator, encoded, .{});
    defer owned.deinit();
    try std.testing.expectEqualStrings("backend", owned.value.cluster_name);
    try std.testing.expectEqual(@as(usize, 2), owned.value.localities.len);
    try std.testing.expectEqual(@as(usize, 2), owned.value.priority_count);
    const a = owned.value.localities[0];
    try std.testing.expectEqual(@as(u32, 2), a.weight);
    try std.testing.expectEqual(@as(usize, 2), a.endpoints.len);
    try std.testing.expectEqual(@as(u32, 3), a.endpoints[0].weight);
    try std.testing.expectEqual(@as(usize, 2), a.endpoints[0].addresses.len);
    try std.testing.expectEqual(resource.Health.draining, a.endpoints[1].health);
    try std.testing.expectEqual(@as(u32, 1234), owned.value.drops[0].requests_per_million);
    const snapshot = try target.Snapshot.create(allocator, encoded, .{}, .{ .authority = "localhost" });
    defer snapshot.release();
    try std.testing.expectEqual(@as(u32, 1234), snapshot.resource.value.drops[0].requests_per_million);
}

test "gRPC EDS rejects duplicate locality addresses priority gaps and invalid endpoint weights" {
    const invalid = [_][]const fixture.Locality{
        &.{ .{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }, .{ .region = "a", .endpoints = &.{.{ .port = 1002 }} } },
        &.{ .{ .region = "a", .endpoints = &.{.{ .port = 1001 }} }, .{ .region = "b", .endpoints = &.{.{ .port = 1001 }} } },
        &.{.{ .region = "a", .priority = 1, .endpoints = &.{.{ .port = 1001 }} }},
        &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001, .weight = 0 }} }},
        &.{.{ .region = "a", .endpoints = &.{.{ .port = 0 }} }},
        &.{ .{ .region = "a", .weight = std.math.maxInt(u32), .endpoints = &.{} }, .{ .region = "b", .weight = 1, .endpoints = &.{} } },
    };
    for (invalid) |localities| {
        const bytes = try fixture.encode(allocator, "cluster", localities, null);
        defer allocator.free(bytes);
        try std.testing.expectError(error.InvalidEdsResource, resource.decode(allocator, bytes, .{}));
    }
    try std.testing.expectError(error.InvalidEdsResource, resource.decode(allocator, "", .{}));
    try std.testing.expectError(error.TruncatedMessage, resource.decode(allocator, "\x0a\x02a", .{}));
    const udp = try fixture.encode(allocator, "cluster", &.{.{ .region = "a", .endpoints = &.{.{ .port = 1001, .protocol = 1 }} }}, null);
    defer allocator.free(udp);
    try std.testing.expectError(error.UnsupportedEdsAddress, resource.decode(allocator, udp, .{}));
}

test "gRPC EDS owned projection preserves priority locality identity and rollback on allocation failure" {
    const bytes = try fixture.encode(allocator, "cluster", &.{
        .{ .region = "r:1", .zone = "z", .endpoints = &.{.{ .port = 1001 }} },
        .{ .region = "r", .zone = "1:z", .endpoints = &.{.{ .port = 1002 }} },
        .{ .region = "b", .priority = 1, .endpoints = &.{.{ .port = 1003 }} },
    }, null);
    defer allocator.free(bytes);
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, image: []const u8) !void {
            const snapshot = try target.Snapshot.create(gpa, image, .{}, .{ .authority = "backend.test" });
            defer snapshot.release();
            try std.testing.expectEqual(@as(usize, 3), snapshot.endpoints.len);
            try std.testing.expect(!std.mem.eql(u8, snapshot.endpoints[0].hierarchicalPath()[1], snapshot.endpoints[1].hierarchicalPath()[1]));
            try std.testing.expectEqualStrings("priority-1", snapshot.endpoints[2].hierarchicalPath()[0]);
            const retained = snapshot.lifetime().retain();
            retained.release();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{bytes});
    try std.testing.expectError(error.EdsLimitExceeded, resource.decode(allocator, bytes, .{ .max_localities = 2 }));
    try std.testing.expectError(error.EdsLimitExceeded, resource.decode(allocator, bytes, .{ .max_endpoints = 2 }));
    try std.testing.expectError(error.EdsLimitExceeded, resource.decode(allocator, bytes, .{ .max_bytes = bytes.len - 1 }));
}

test "gRPC EDS direct CDS policy flattens localities and multiplies ring weights with overflow rejection" {
    const bytes = try fixture.encode(allocator, "cluster", &.{
        .{ .region = "a", .weight = 3, .endpoints = &.{.{ .port = 1001, .weight = 2 }} },
        .{ .region = "b", .weight = 1, .endpoints = &.{.{ .port = 1002 }} },
    }, null);
    defer allocator.free(bytes);
    const direct = try target.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost", .locality_weighted = false, .child_policy_json = "[{\"ring_hash_experimental\":{\"minRingSize\":32,\"maxRingSize\":64}}]" });
    defer direct.release();
    try std.testing.expectEqual(@as(usize, 2), direct.endpoints[0].hierarchicalPath().len);
    try std.testing.expectEqual(@as(u32, 6), @import("../../channel/ring_hash.zig").endpointWeight(direct.endpoints[0]));
    try std.testing.expect(std.mem.indexOf(u8, direct.service_config_json, "xds_wrr_locality") == null);
    const overflow = try fixture.encode(allocator, "cluster", &.{.{ .region = "a", .weight = std.math.maxInt(u32), .endpoints = &.{.{ .port = 1001, .weight = 2 }} }}, null);
    defer allocator.free(overflow);
    try std.testing.expectError(error.InvalidEdsTarget, target.Snapshot.create(allocator, overflow, .{}, .{ .authority = "localhost", .locality_weighted = false }));
}
