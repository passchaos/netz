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
    try std.testing.expectEqualStrings("/api.Service/Get", try prefixed.path_rewrite.?.write(gpa, "/demo.Service/Get", &rewritten));

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

    var literal_action = fixture.Builder{ .allocator = gpa };
    defer literal_action.deinit();
    try literal_action.bytes(44, "literal.example");
    try literal_action.bytes(45, "/literal.Service/Get");
    const literal_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = literal_action.data.items }}, null);
    defer gpa.free(literal_bytes);
    const literal_snapshot = try rds.Snapshot.create(gpa, literal_bytes, .{}, .{ .authority = "backend.test" });
    defer literal_snapshot.release();
    const literal = try literal_snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expectEqualStrings("literal.example", literal.authority.?);
    try std.testing.expectEqualStrings("/literal.Service/Get", literal.path_rewrite.?.whole);
}
test "gRPC RDS honors auto host rewrite only for a trusted server" {
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.wrapper(7, 1);
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
    defer gpa.free(bytes);
    var prng = random();

    // An untrusted control plane may not redirect the request authority.
    const untrusted = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer untrusted.release();
    const ignored = try untrusted.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expect(!ignored.auto_host_rewrite);
    try std.testing.expect(ignored.authority == null);

    // The bootstrap `trusted_xds_server` feature enables the grpc-core behavior.
    const trusted = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test", .trusted_xds_server = true });
    defer trusted.release();
    const selected = try trusted.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expect(selected.auto_host_rewrite);
    try std.testing.expect(selected.authority == null);
}
test "gRPC RDS owns literal request header mutations and removals" {
    var header = fixture.Builder{ .allocator = gpa };
    defer header.deinit();
    try header.bytes(1, "x-add");
    try header.bytes(2, "added");
    var option = fixture.Builder{ .allocator = gpa };
    defer option.deinit();
    try option.bytes(1, header.data.items);
    try option.number(3, 2); // OVERWRITE_IF_EXISTS_OR_ADD
    var route_extra = fixture.Builder{ .allocator = gpa };
    defer route_extra.deinit();
    try route_extra.bytes(9, option.data.items);
    try route_extra.bytes(12, "x-remove");
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = route_extra.data.items }}, null);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const route = owned.value.virtual_hosts[0].routes[0];
    try std.testing.expectEqual(@as(usize, 1), route.request_headers_to_add.len);
    try std.testing.expectEqualStrings("x-add", route.request_headers_to_add[0].name);
    try std.testing.expectEqualStrings("added", route.request_headers_to_add[0].value);
    try std.testing.expectEqual(@import("../../call.zig").HeaderMutationAction.overwrite, route.request_headers_to_add[0].action);
    try std.testing.expectEqual(@as(usize, 1), route.request_headers_to_remove.len);
    try std.testing.expectEqualStrings("x-remove", route.request_headers_to_remove[0]);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expectEqual(@as(usize, 1), selected.request_header_mutations.len);
    try std.testing.expectEqual(@as(usize, 1), selected.request_header_removals.len);
}
test "gRPC RDS owns literal response header mutations and removals" {
    var header = fixture.Builder{ .allocator = gpa };
    defer header.deinit();
    try header.bytes(1, "x-response");
    try header.bytes(2, "mutated");
    var option = fixture.Builder{ .allocator = gpa };
    defer option.deinit();
    try option.bytes(1, header.data.items);
    try option.number(3, 2); // OVERWRITE_IF_EXISTS_OR_ADD
    var route_extra = fixture.Builder{ .allocator = gpa };
    defer route_extra.deinit();
    try route_extra.bytes(10, option.data.items);
    try route_extra.bytes(11, "x-response-remove");
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = route_extra.data.items }}, null);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const route = owned.value.virtual_hosts[0].routes[0];
    try std.testing.expectEqual(@as(usize, 1), route.response_headers_to_add.len);
    try std.testing.expectEqualStrings("x-response", route.response_headers_to_add[0].name);
    try std.testing.expectEqualStrings("mutated", route.response_headers_to_add[0].value);
    try std.testing.expectEqual(@import("../../call.zig").HeaderMutationAction.overwrite, route.response_headers_to_add[0].action);
    try std.testing.expectEqual(@as(usize, 1), route.response_headers_to_remove.len);
    try std.testing.expectEqualStrings("x-response-remove", route.response_headers_to_remove[0]);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{ .path = "/demo.Service/Get", .authority = "backend.test" }, 1, prng.random());
    try std.testing.expectEqual(@as(usize, 1), selected.response_header_mutations.len);
    try std.testing.expectEqual(@as(usize, 1), selected.response_header_removals.len);
}
test "gRPC RDS rejects reserved, binary and format request header mutations" {
    const Case = struct { key: []const u8, value: []const u8 = "v" };
    const cases = [_]Case{
        .{ .key = "content-type" },
        .{ .key = "x-data-bin" },
        .{ .key = ":authority" },
        .{ .key = "x-format", .value = "prefix-%REQ(x)%" },
    };
    for (cases) |case| {
        var header = fixture.Builder{ .allocator = gpa };
        defer header.deinit();
        try header.bytes(1, case.key);
        try header.bytes(2, case.value);
        var option = fixture.Builder{ .allocator = gpa };
        defer option.deinit();
        try option.bytes(1, header.data.items);
        var route_extra = fixture.Builder{ .allocator = gpa };
        defer route_extra.deinit();
        try route_extra.bytes(9, option.data.items);
        const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = route_extra.data.items }}, null);
        defer gpa.free(bytes);
        if (std.mem.eql(u8, case.value, "v")) {
            try std.testing.expectError(error.InvalidRdsResource, rds.decode(gpa, bytes, .{}));
        } else {
            try std.testing.expectError(error.UnsupportedRdsFeature, rds.decode(gpa, bytes, .{}));
        }
    }
    var remove_extra = fixture.Builder{ .allocator = gpa };
    defer remove_extra.deinit();
    try remove_extra.bytes(12, ":authority");
    const remove_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .route_extra = remove_extra.data.items }}, null);
    defer gpa.free(remove_bytes);
    try std.testing.expectError(error.InvalidRdsResource, rds.decode(gpa, remove_bytes, .{}));
}
test "gRPC RDS applies regex rewrites and rejects format rewrites" {
    var matcher = fixture.Builder{ .allocator = gpa };
    defer matcher.deinit();
    try matcher.bytes(2, "^/service/([^/]+)(/.*)$");
    var rewrite = fixture.Builder{ .allocator = gpa };
    defer rewrite.deinit();
    try rewrite.bytes(1, matcher.data.items);
    try rewrite.bytes(2, "\\2/instance/\\1");
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.bytes(32, rewrite.data.items);
    const regex_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
    defer gpa.free(regex_bytes);
    var decoded = try rds.decode(gpa, regex_bytes, .{});
    defer decoded.deinit();
    const snapshot = try rds.Snapshot.create(gpa, regex_bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{
        .path = "/service/foo/v1/api",
        .authority = "backend.test",
    }, 1, prng.random());
    try std.testing.expect(selected.path_rewrite != null);
    try std.testing.expectEqual(@as(usize, "/v1/api/instance/foo".len), selected.path_rewrite.?.outputLen("/service/foo/v1/api".len));
    var rewritten: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/v1/api/instance/foo",
        try selected.path_rewrite.?.write(gpa, "/service/foo/v1/api", &rewritten),
    );

    var empty = fixture.Builder{ .allocator = gpa };
    defer empty.deinit();
    try empty.bytes(32, "");
    const empty_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = empty.data.items }}, null);
    defer gpa.free(empty_bytes);
    try std.testing.expectError(error.InvalidRdsResource, rds.decode(gpa, empty_bytes, .{}));

    var bad_matcher = fixture.Builder{ .allocator = gpa };
    defer bad_matcher.deinit();
    try bad_matcher.bytes(2, "(a)");
    var bad_rewrite = fixture.Builder{ .allocator = gpa };
    defer bad_rewrite.deinit();
    try bad_rewrite.bytes(1, bad_matcher.data.items);
    try bad_rewrite.bytes(2, "\\2");
    var bad_action = fixture.Builder{ .allocator = gpa };
    defer bad_action.deinit();
    try bad_action.bytes(32, bad_rewrite.data.items);
    const bad_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = bad_action.data.items }}, null);
    defer gpa.free(bad_bytes);
    try std.testing.expectError(error.InvalidRdsResource, rds.decode(gpa, bad_bytes, .{}));

    var malformed_matcher = fixture.Builder{ .allocator = gpa };
    defer malformed_matcher.deinit();
    try malformed_matcher.bytes(2, "(");
    var malformed_rewrite = fixture.Builder{ .allocator = gpa };
    defer malformed_rewrite.deinit();
    try malformed_rewrite.bytes(1, malformed_matcher.data.items);
    try malformed_rewrite.bytes(2, "x");
    var malformed_action = fixture.Builder{ .allocator = gpa };
    defer malformed_action.deinit();
    try malformed_action.bytes(32, malformed_rewrite.data.items);
    const malformed_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = malformed_action.data.items }}, null);
    defer gpa.free(malformed_bytes);
    try std.testing.expectError(error.InvalidRegex, rds.decode(gpa, malformed_bytes, .{}));

    var path_action = fixture.Builder{ .allocator = gpa };
    defer path_action.deinit();
    try path_action.bytes(45, "/formatted%REQ(x)%");
    const path_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = path_action.data.items }}, null);
    defer gpa.free(path_bytes);
    try std.testing.expectError(error.UnsupportedRdsFeature, rds.decode(gpa, path_bytes, .{}));
}
test "gRPC RDS applies header hash regex rewrites" {
    var matcher = fixture.Builder{ .allocator = gpa };
    defer matcher.deinit();
    try matcher.bytes(2, "^tenant-(\\d+)$");
    var rewrite = fixture.Builder{ .allocator = gpa };
    defer rewrite.deinit();
    try rewrite.bytes(1, matcher.data.items);
    try rewrite.bytes(2, "\\1");
    var header = fixture.Builder{ .allocator = gpa };
    defer header.deinit();
    try header.bytes(1, "x-tenant");
    try header.bytes(2, rewrite.data.items);
    var policy = fixture.Builder{ .allocator = gpa };
    defer policy.deinit();
    try policy.bytes(1, header.data.items);
    try policy.number(4, 1);
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.bytes(15, policy.data.items);
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
    defer gpa.free(bytes);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{
        .path = "/demo.Service/Get",
        .authority = "backend.test",
        .metadata = &.{.{ .name = "x-tenant", .value = "tenant-42" }},
    }, 1, prng.random());
    try std.testing.expectEqual(
        std.hash.XxHash64.hash(0, "42"),
        selected.hash,
    );
    const unmatched = try snapshot.selectWith(gpa, .{
        .path = "/demo.Service/Get",
        .authority = "backend.test",
        .metadata = &.{.{ .name = "x-tenant", .value = "other" }},
    }, 1, prng.random());
    try std.testing.expectEqual(
        std.hash.XxHash64.hash(0, "other"),
        unmatched.hash,
    );
}
test "gRPC RDS applies host rewrite path regex" {
    var matcher = fixture.Builder{ .allocator = gpa };
    defer matcher.deinit();
    try matcher.bytes(2, "^/([^/]+)/.*$");
    var rewrite = fixture.Builder{ .allocator = gpa };
    defer rewrite.deinit();
    try rewrite.bytes(1, matcher.data.items);
    try rewrite.bytes(2, "\\1");
    var action = fixture.Builder{ .allocator = gpa };
    defer action.deinit();
    try action.bytes(35, rewrite.data.items);
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .prefix = "/", .action_extra = action.data.items }}, null);
    defer gpa.free(bytes);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const path = "/envoyproxy.io/some/path?x=1#frag";
    const selected = try snapshot.selectWith(gpa, .{
        .path = path,
        .authority = "backend.test",
    }, 1, prng.random());
    try std.testing.expect(selected.authority == null);
    try std.testing.expect(selected.host_rewrite != null);
    try std.testing.expectEqual(
        @as(usize, "envoyproxy.io".len),
        selected.host_rewrite.?.outputLen(),
    );
    var rewritten: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "envoyproxy.io",
        try selected.host_rewrite.?.write(gpa, path, &rewritten),
    );
}
test "gRPC RDS matches path-separated prefixes" {
    var extra = fixture.Builder{ .allocator = gpa };
    defer extra.deinit();
    try extra.bytes(14, "/demo.Service");
    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .match_extra = extra.data.items }}, null);
    defer gpa.free(bytes);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    for ([_][]const u8{
        "/demo.Service",
        "/demo.Service/Get",
        "/demo.Service/Get?x=1",
    }) |path| {
        const selected = try snapshot.selectWith(gpa, .{
            .path = path,
            .authority = "backend.test",
        }, 1, prng.random());
        try std.testing.expectEqualStrings("cluster:a", selected.cluster);
    }
    try std.testing.expectError(
        error.NoMatchingRoute,
        snapshot.selectWith(gpa, .{
            .path = "/demo.ServiceX/Get",
            .authority = "backend.test",
        }, 1, prng.random()),
    );

    var invalid = fixture.Builder{ .allocator = gpa };
    defer invalid.deinit();
    try invalid.bytes(14, "/demo.Service/");
    const invalid_bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{ .match_extra = invalid.data.items }}, null);
    defer gpa.free(invalid_bytes);
    var invalid_owned = try rds.decode(gpa, invalid_bytes, .{});
    defer invalid_owned.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_owned.value.virtual_hosts[0].routes.len,
    );
}
test "gRPC RDS applies URI template path rewrites" {
    var match_config = fixture.Builder{ .allocator = gpa };
    defer match_config.deinit();
    try match_config.bytes(1, "/{one}/{two}");
    var match_any = fixture.Builder{ .allocator = gpa };
    defer match_any.deinit();
    try match_any.bytes(1, "type.googleapis.com/envoy.extensions.path.match.uri_template.v3.UriTemplateMatchConfig");
    try match_any.bytes(2, match_config.data.items);
    var match_policy = fixture.Builder{ .allocator = gpa };
    defer match_policy.deinit();
    try match_policy.bytes(1, "envoy.path.match.uri_template.uri_template_matcher");
    try match_policy.bytes(2, match_any.data.items);

    var rewrite_config = fixture.Builder{ .allocator = gpa };
    defer rewrite_config.deinit();
    try rewrite_config.bytes(1, "/{two}/{one}");
    var rewrite_any = fixture.Builder{ .allocator = gpa };
    defer rewrite_any.deinit();
    try rewrite_any.bytes(1, "type.googleapis.com/envoy.extensions.path.rewrite.uri_template.v3.UriTemplateRewriteConfig");
    try rewrite_any.bytes(2, rewrite_config.data.items);
    var rewrite_policy = fixture.Builder{ .allocator = gpa };
    defer rewrite_policy.deinit();
    try rewrite_policy.bytes(1, "envoy.path.rewrite.uri_template.uri_template_rewriter");
    try rewrite_policy.bytes(2, rewrite_any.data.items);

    var match_extra = fixture.Builder{ .allocator = gpa };
    defer match_extra.deinit();
    try match_extra.bytes(15, match_policy.data.items);
    var action_extra = fixture.Builder{ .allocator = gpa };
    defer action_extra.deinit();
    try action_extra.bytes(41, rewrite_policy.data.items);

    const bytes = try fixture.encode(gpa, "routes", &.{"backend.test"}, &.{.{
        .match_extra = match_extra.data.items,
        .action_extra = action_extra.data.items,
    }}, null);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const route = owned.value.virtual_hosts[0].routes[0];
    try std.testing.expect(route.path == .path_template);
    try std.testing.expectEqual(@as(usize, 2), route.path.templateVariables().len);
    const snapshot = try rds.Snapshot.create(gpa, bytes, .{}, .{ .authority = "backend.test" });
    defer snapshot.release();
    var prng = random();
    const selected = try snapshot.selectWith(gpa, .{
        .path = "/cat/dog",
        .authority = "backend.test",
    }, 1, prng.random());
    try std.testing.expect(selected.path_rewrite != null);
    try std.testing.expectEqual(
        @as(usize, "/dog/cat".len),
        selected.path_rewrite.?.outputLen("/cat/dog".len),
    );
    var rewritten: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/dog/cat",
        try selected.path_rewrite.?.write(gpa, "/cat/dog", &rewritten),
    );
}

fn anyBytes(allocator: std.mem.Allocator, type_url: []const u8, value: []const u8) ![]u8 {
    var any = fixture.Builder{ .allocator = allocator };
    defer any.deinit();
    try any.bytes(1, type_url);
    try any.bytes(2, value);
    return any.data.toOwnedSlice(allocator);
}
fn overrideEntry(allocator: std.mem.Allocator, name: []const u8, any_bytes: []const u8) ![]u8 {
    var entry = fixture.Builder{ .allocator = allocator };
    defer entry.deinit();
    try entry.bytes(1, name);
    try entry.bytes(2, any_bytes);
    return entry.data.toOwnedSlice(allocator);
}
test "gRPC RDS decodes route and virtual-host per-filter overrides" {
    const rbac_policy = "\x08\x00\x12\x0d\x0a\x01p\x12\x08\x0a\x02\x18\x01\x12\x02\x18\x01";
    var per_route = fixture.Builder{ .allocator = gpa };
    defer per_route.deinit();
    try per_route.bytes(2, rbac_policy);
    const rbac_any = try anyBytes(gpa, "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute", per_route.data.items);
    defer gpa.free(rbac_any);
    const route_entry = try overrideEntry(gpa, "rbac", rbac_any);
    defer gpa.free(route_entry);
    var route_extra = fixture.Builder{ .allocator = gpa };
    defer route_extra.deinit();
    try route_extra.bytes(13, route_entry);

    var abort = fixture.Builder{ .allocator = gpa };
    defer abort.deinit();
    try abort.number(5, 14);
    var percentage = fixture.Builder{ .allocator = gpa };
    defer percentage.deinit();
    try percentage.number(1, 100);
    try percentage.number(2, 0);
    try abort.bytes(3, percentage.data.items);
    var fault = fixture.Builder{ .allocator = gpa };
    defer fault.deinit();
    try fault.bytes(2, abort.data.items);
    const fault_any = try anyBytes(gpa, "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault", fault.data.items);
    defer gpa.free(fault_any);
    const host_entry = try overrideEntry(gpa, "fault", fault_any);
    defer gpa.free(host_entry);
    var host_extra = fixture.Builder{ .allocator = gpa };
    defer host_extra.deinit();
    try host_extra.bytes(15, host_entry);

    const bytes = try fixture.encodeWithHostExtra(gpa, "routes", &.{"backend.test"}, &.{.{
        .exact = "/svc/Get",
        .route_extra = route_extra.data.items,
    }}, null, host_extra.data.items);
    defer gpa.free(bytes);
    var owned = try rds.decode(gpa, bytes, .{});
    defer owned.deinit();
    const host = owned.value.virtual_hosts[0];
    try std.testing.expectEqual(@as(usize, 1), host.overrides.len);
    try std.testing.expectEqual(rds.resource.OverrideKind.fault, host.overrides[0].kind.?);
    try std.testing.expectEqualStrings("fault", host.overrides[0].name);
    const route = host.routes[0];
    try std.testing.expectEqual(@as(usize, 1), route.overrides.len);
    try std.testing.expectEqual(rds.resource.OverrideKind.rbac, route.overrides[0].kind.?);
    try std.testing.expectEqualStrings("rbac", route.overrides[0].name);
    try std.testing.expectEqualStrings(rbac_policy, route.overrides[0].config);
}
