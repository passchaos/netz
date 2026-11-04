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
test "gRPC RDS rewrites matched prefixes and literal or header authorities" {
    var prefix_action = fixture.Builder{ .allocator = gpa };
    defer prefix_action.deinit();
    try prefix_action.bytes(5, "/api");
    try prefix_action.bytes(6, "rewritten.example");
    const prefix_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/demo", .action_extra = prefix_action.data.items }}, null);
    defer gpa.free(prefix_bytes);
    const prefix_snapshot = try rds.Snapshot.create(gpa, prefix_bytes, .{}, .{ .authority = "backend.test" });
    defer prefix_snapshot.release();
    var prng = random();
    const prefixed = try prefix_snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expectEqual(@as(usize, "/demo".len), prefixed.path_rewrite.?.prefix.matched);
    try std.testing.expectEqualStrings("/api", prefixed.path_rewrite.?.prefix.replacement);
    try std.testing.expectEqualStrings("rewritten.example", prefixed.authority.?);
    var rewritten: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/api.Service/Get", prefixed.path_rewrite.?.write("/demo.Service/Get", &rewritten));

    var header_action = fixture.Builder{ .allocator = gpa };
    defer header_action.deinit();
    try header_action.bytes(5, "/v2");
    try header_action.bytes(29, "x-host");
    const header_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = header_action.data.items }}, null);
    defer gpa.free(header_bytes);
    const header_snapshot = try rds.Snapshot.create(gpa, header_bytes, .{}, .{ .authority = "backend.test" });
    defer header_snapshot.release();
    const header = try header_snapshot.selectWith(gpa, .{
        .path = "/demo.Service/Get",
        .authority = "backend.test",
        .metadata = &.{.{ .name = "x-host", .value = "header.example" }},
    }, 1, prng.random());
    try std.testing.expectEqualStrings("header.example", header.authority.?);
    try std.testing.expectEqual(@as(usize, 1), header.path_rewrite.?.prefix.matched);

    var whole_action = fixture.Builder{ .allocator = gpa };
    defer whole_action.deinit();
    try whole_action.bytes(5, "/only");
    const whole_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .exact = "/demo.Service/Get", .action_extra = whole_action.data.items }}, null);
    defer gpa.free(whole_bytes);
    const whole_snapshot = try rds.Snapshot.create(gpa, whole_bytes, .{}, .{ .authority = "backend.test" });
    defer whole_snapshot.release();
    const whole = try whole_snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expectEqualStrings("/only", whole.path_rewrite.?.whole);
}
test "gRPC RDS rejects unsupported regex and format rewrites" {
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.bytes(32, "");
    const regex_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
    defer gpa.free(regex_bytes);
    try std.testing.expectError(error.UnsupportedRdsFeature, rds.decode(gpa, regex_bytes, .{}));
    var path_action = fixture.Builder{ .allocator = gpa };
    defer path_action.deinit();
    try path_action.bytes(45, "/formatted%REQ(x)%");
    const path_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = path_action.data.items }}, null);
    defer gpa.free(path_bytes);
    try std.testing.expectError(error.UnsupportedRdsFeature, rds.decode(gpa, path_bytes, .{}));
    var auto_action = fixture.Builder{ .allocator = gpa };
    defer auto_action.deinit();
    try auto_action.bytes(7, &.{1});
    const auto_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = auto_action.data.items }}, null);
    defer gpa.free(auto_bytes);
    try std.testing.expectError(error.UnsupportedRdsFeature, rds.decode(gpa, auto_bytes, .{}));
}
