const std = @import("std");
const rds = @import("../rds.zig");
const fixture = @import("testing.zig");
const gpa = std.testing.allocator;
fn random() std.Random.DefaultPrng {
    return .init(1234);
}
test "gRPC RDS owns regex header cluster identities and selects ordered routes" {
    var headers = fixture.Builder{ .allocator = gpa };
    defer headers.deinit();
    var header = fixture.Builder{ .allocator = gpa };
    defer header.deinit();
    try header.bytes(1, "x-tenant");
    try header.bytes(4, "beta");
    try headers.bytes(6, header.data.items);
    const bytes = try fixture.encode(gpa, "routes", &.{"*.test"}, &.{ .{ .regex = "/demo\\.[A-Za-z]+/(Get|List)", .cluster = "b", .match_extra = headers.data.items }, .{ .prefix = "/", .cluster = "a" } }, null);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    gpa.free(bytes);
    defer snapshot.release();
    try std.testing.expectEqualStrings("routes", snapshot.resource.value.name);
    try std.testing.expectEqualStrings("cluster:a", snapshot.required_clusters[0]);
    try std.testing.expectEqualStrings("cluster:b", snapshot.required_clusters[1]);
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test", .metadata = &.{.{ .name = "x-tenant", .value = "beta" }} }, 42, prng.random());
    try std.testing.expectEqualStrings("cluster:b", selected.cluster);
    const fallback = try snapshot.selectWith(gpa, .{ .path = "/demo.Service/Put", .authority = "backend.test" }, 42, prng.random());
    try std.testing.expectEqualStrings("cluster:a", fallback.cluster);
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, image: []const u8) !void {
            const value = try rds.Snapshot.create(allocator, image, .{}, .{ .authority = "backend.test" });
            defer value.release();
            var rng = random();
            _ = try value.selectWith(allocator, .{ .path = "/demo.Service/Get", .authority = "backend.test", .metadata = &.{.{ .name = "x-tenant", .value = "beta" }} }, 1, rng.random());
        }
    };
    const image = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .regex = "/demo\\..+/Get" }}, null);
    defer gpa.free(image);
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{image});
}
test "gRPC RDS skips non-gRPC route matches and enforces regex resource bounds" {
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{ .{ .prefix = "not-a-path", .cluster = "wrong" }, .{ .exact = "/service", .cluster = "wrong" }, .{ .prefix = "/", .cluster = "right" } }, null);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 1), owned.value.virtual_hosts[0].routes.len);
    const invalid = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .regex = "(?=a)" }}, null);
    defer gpa.free(invalid);
    try std.testing.expectError(error.InvalidRdsResource, rds.decode(gpa, invalid, .{}));
    try std.testing.expectError(error.RdsLimitExceeded, rds.decode(gpa, bytes, .{ .max_routes = 2 }));
    try std.testing.expectError(error.RdsLimitExceeded, rds.decode(gpa, bytes, .{ .max_storage_bytes = 1 }));
    try std.testing.expectError(error.RdsLimitExceeded, rds.decode(gpa, bytes, .{ .max_cluster_entries = 0 }));
}
test "gRPC RDS preserves explicit retry disable and grpc-core default backoff" {
    var retry = fixture.Builder{ .allocator = gpa };
    defer retry.deinit();
    try retry.bytes(1, "unavailable,internal");
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{ .{ .exact = "/demo.Service/Disabled", .retry = "" }, .{ .prefix = "/" } }, retry.data.items);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const routes = owned.value.virtual_hosts[0].routes;
    try std.testing.expect(routes[0].action.forward.retry_policy == null);
    const inherited = routes[1].action.forward.retry_policy.?;
    try std.testing.expectEqual(@as(u8, 2), inherited.max_attempts);
    try std.testing.expectEqual(@as(i96, 25 * std.time.ns_per_ms), inherited.initial_backoff.nanoseconds);
    try std.testing.expectEqual(@as(usize, 2), inherited.retryable_status_codes.len);
}
