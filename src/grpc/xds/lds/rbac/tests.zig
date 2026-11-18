const std = @import("std");
const rbac_root = @import("../rbac.zig");

const routing = @import("../../routing/mod.zig");

const Action = rbac_root.Action;
const TestBuilder = rbac_root.TestBuilder;
const buildPolicy = rbac_root.buildPolicy;
const buildRbac = rbac_root.buildRbac;
const decode = rbac_root.decode;
const decodePolicyBytes = rbac_root.decodePolicyBytes;
const evaluate = rbac_root.evaluate;
const evaluateBytes = rbac_root.evaluateBytes;

test "RBAC omitted proto3 action allows only matching policies" {
    // Canonical RBAC policy bytes omit action = ALLOW (0). The permission
    // requires x-deny to be present and the principal is any.
    const policy_bytes = "\x12\x17\x0a\x01p\x12\x12\x0a\x0c\x22\x0a\x0a\x06x-deny\x38\x01\x12\x02\x18\x01";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const policy = try decodePolicyBytes(arena.allocator(), policy_bytes, .{});
    try std.testing.expectEqual(Action.allow, policy.action);
    try std.testing.expectEqual(@as(usize, 1), policy.rules.len);
    const matching = routing.header.Request{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-deny", .value = "1" }},
    };
    const nonmatching = routing.header.Request{ .path = "/x", .authority = "a" };
    try std.testing.expect(try evaluate(&policy, std.testing.allocator, matching));
    try std.testing.expect(!try evaluate(&policy, std.testing.allocator, nonmatching));
    // The HTTP filter adds its own rules wrapper around the same policy.
    try std.testing.expect(try evaluateBytes("\x0a\x19" ++ policy_bytes, matching));
    try std.testing.expect(!try evaluateBytes("\x0a\x19" ++ policy_bytes, nonmatching));
}

test "RBAC absent HTTP rules disable enforcement and present empty rules deny all" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const policy = try decodePolicyBytes(arena.allocator(), "", .{});
    try std.testing.expectEqual(Action.allow, policy.action);
    try std.testing.expectEqual(@as(usize, 0), policy.rules.len);
    const request = routing.header.Request{ .path = "/x", .authority = "a" };
    try std.testing.expect(!try evaluate(&policy, std.testing.allocator, request));
    try std.testing.expect(!try evaluateBytes("\x0a\x00", request));
    try std.testing.expect(try evaluateBytes("", request));
    // Shadow rules do not introduce enforcing rules.
    try std.testing.expect(try evaluateBytes("\x12\x00", request));
}

test "RBAC explicit DENY reverses matching and rejects unsupported or invalid actions" {
    const policy_bytes = "\x08\x01\x12\x17\x0a\x01p\x12\x12\x0a\x0c\x22\x0a\x0a\x06x-deny\x38\x01\x12\x02\x18\x01";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const policy = try decodePolicyBytes(arena.allocator(), policy_bytes, .{});
    try std.testing.expectEqual(Action.deny, policy.action);
    const matching = routing.header.Request{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-deny", .value = "1" }},
    };
    const nonmatching = routing.header.Request{ .path = "/x", .authority = "a" };
    try std.testing.expect(!try evaluate(&policy, std.testing.allocator, matching));
    try std.testing.expect(try evaluate(&policy, std.testing.allocator, nonmatching));
    try std.testing.expect(!try evaluateBytes("\x0a\x1b" ++ policy_bytes, matching));
    try std.testing.expect(try evaluateBytes("\x0a\x1b" ++ policy_bytes, nonmatching));
    try std.testing.expect(try evaluateBytes("\x0a\x02\x08\x01", matching));
    try std.testing.expectError(error.UnsupportedRbacFeature, decodePolicyBytes(arena.allocator(), "\x08\x02", .{}));
    try std.testing.expectError(error.InvalidRbacResource, decodePolicyBytes(arena.allocator(), "\x08\x03", .{}));
    try std.testing.expectError(error.UnsupportedRbacFeature, decode(arena.allocator(), "\x0a\x02\x08\x02", .{}));
    try std.testing.expectError(error.InvalidRbacResource, decode(arena.allocator(), "\x0a\x02\x08\x03", .{}));
}

test "RBAC allows and denies any-any policies" {
    var any = TestBuilder{};
    defer any.deinit();
    try any.number(3, 1);
    const policy = try buildPolicy(any.data.items, any.data.items);
    defer std.testing.allocator.free(policy);
    const allow = try buildRbac(0, policy);
    defer std.testing.allocator.free(allow);
    const deny = try buildRbac(1, policy);
    defer std.testing.allocator.free(deny);
    const request = routing.header.Request{ .path = "/x", .authority = "a" };
    try std.testing.expect(try evaluateBytes(allow, request));
    try std.testing.expect(!try evaluateBytes(deny, request));
}

test "RBAC matches header principals and permissions" {
    var header = TestBuilder{};
    defer header.deinit();
    try header.bytes(1, "x-allow");
    try header.bytes(4, "yes");
    var permission = TestBuilder{};
    defer permission.deinit();
    try permission.bytes(4, header.data.items);
    var principal = TestBuilder{};
    defer principal.deinit();
    try principal.bytes(6, header.data.items);
    const policy = try buildPolicy(permission.data.items, principal.data.items);
    defer std.testing.allocator.free(policy);
    const rbac_bytes = try buildRbac(0, policy);
    defer std.testing.allocator.free(rbac_bytes);
    const matching = routing.header.Request{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-allow", .value = "yes" }},
    };
    try std.testing.expect(try evaluateBytes(rbac_bytes, matching));
    try std.testing.expect(!try evaluateBytes(rbac_bytes, .{ .path = "/x", .authority = "a" }));
}

test "RBAC DENY treats missing headers as empty only when configured" {
    const cases = [_]struct { header_bytes: []const u8, deny_missing: bool }{
        .{ .header_bytes = "\x0a\x01x\x22\x00", .deny_missing = false },
        .{ .header_bytes = "\x0a\x01x\x22\x00\x70\x00", .deny_missing = false },
        .{ .header_bytes = "\x0a\x01x\x22\x00\x70\x01", .deny_missing = true },
    };
    for (cases) |case| {
        var permission = TestBuilder{};
        defer permission.deinit();
        try permission.bytes(4, case.header_bytes);
        const policy = try buildPolicy(permission.data.items, "\x18\x01");
        defer std.testing.allocator.free(policy);
        const rbac_bytes = try buildRbac(1, policy);
        defer std.testing.allocator.free(rbac_bytes);
        try std.testing.expectEqual(!case.deny_missing, try evaluateBytes(rbac_bytes, .{ .path = "/x", .authority = "a" }));
        try std.testing.expect(!try evaluateBytes(rbac_bytes, .{ .path = "/x", .authority = "a", .metadata = &.{.{ .name = "x", .value = "" }} }));
        try std.testing.expect(try evaluateBytes(rbac_bytes, .{ .path = "/x", .authority = "a", .metadata = &.{.{ .name = "x", .value = "value" }} }));
    }
}

test "RBAC matches URL path permissions" {
    var string = TestBuilder{};
    defer string.deinit();
    try string.bytes(2, "/api");
    var path = TestBuilder{};
    defer path.deinit();
    try path.bytes(1, string.data.items);
    var permission = TestBuilder{};
    defer permission.deinit();
    try permission.bytes(10, path.data.items);
    var principal = TestBuilder{};
    defer principal.deinit();
    try principal.number(3, 1);
    const policy = try buildPolicy(permission.data.items, principal.data.items);
    defer std.testing.allocator.free(policy);
    const rbac_bytes = try buildRbac(0, policy);
    defer std.testing.allocator.free(rbac_bytes);
    try std.testing.expect(try evaluateBytes(rbac_bytes, .{ .path = "/api/v1", .authority = "a" }));
    try std.testing.expect(!try evaluateBytes(rbac_bytes, .{ .path = "/other", .authority = "a" }));
}

test "RBAC rejects unsupported principals, permissions and conditions" {
    var any = TestBuilder{};
    defer any.deinit();
    try any.number(3, 1);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var authenticated = TestBuilder{};
    defer authenticated.deinit();
    try authenticated.bytes(4, "");
    const principal_policy = try buildPolicy(any.data.items, authenticated.data.items);
    defer std.testing.allocator.free(principal_policy);
    const principal_rbac = try buildRbac(1, principal_policy);
    defer std.testing.allocator.free(principal_rbac);
    try std.testing.expectError(error.UnsupportedRbacFeature, decode(arena.allocator(), principal_rbac, .{}));

    var destination_ip = TestBuilder{};
    defer destination_ip.deinit();
    try destination_ip.bytes(5, "");
    const permission_policy = try buildPolicy(destination_ip.data.items, any.data.items);
    defer std.testing.allocator.free(permission_policy);
    const permission_rbac = try buildRbac(1, permission_policy);
    defer std.testing.allocator.free(permission_rbac);
    try std.testing.expectError(error.UnsupportedRbacFeature, decode(arena.allocator(), permission_rbac, .{}));

    var condition_policy = TestBuilder{};
    defer condition_policy.deinit();
    try condition_policy.bytes(1, any.data.items);
    try condition_policy.bytes(2, any.data.items);
    try condition_policy.bytes(3, "");
    const condition_rbac = try buildRbac(1, condition_policy.data.items);
    defer std.testing.allocator.free(condition_rbac);
    try std.testing.expectError(error.UnsupportedRbacFeature, decode(arena.allocator(), condition_rbac, .{}));
}

test "RBAC honors not_id and not_rule with Envoy field numbers" {
    var permission_inner = TestBuilder{};
    defer permission_inner.deinit();
    try permission_inner.number(3, 1); // any
    var permission = TestBuilder{};
    defer permission.deinit();
    try permission.bytes(8, permission_inner.data.items); // not_rule

    var principal_inner = TestBuilder{};
    defer principal_inner.deinit();
    try principal_inner.number(3, 1); // any
    var principal = TestBuilder{};
    defer principal.deinit();
    try principal.bytes(8, principal_inner.data.items); // not_id

    const policy = try buildPolicy(permission.data.items, principal.data.items);
    defer std.testing.allocator.free(policy);
    const allow = try buildRbac(0, policy);
    defer std.testing.allocator.free(allow);
    const deny = try buildRbac(1, policy);
    defer std.testing.allocator.free(deny);
    const request = routing.header.Request{ .path = "/x", .authority = "a" };
    // A rule whose permission and principal both negate `any` never matches.
    try std.testing.expect(!try evaluateBytes(allow, request));
    try std.testing.expect(try evaluateBytes(deny, request));
}

test "RBAC matches header safe-regex and string-match fields" {
    var regex = TestBuilder{};
    defer regex.deinit();
    try regex.bytes(2, "yes$"); // RegexMatcher.regex
    var regex_header = TestBuilder{};
    defer regex_header.deinit();
    try regex_header.bytes(1, "x-allow");
    try regex_header.bytes(11, regex.data.items); // safe_regex_match
    var permission = TestBuilder{};
    defer permission.deinit();
    try permission.bytes(4, regex_header.data.items); // header permission
    var principal = TestBuilder{};
    defer principal.deinit();
    try principal.number(3, 1); // any
    const policy = try buildPolicy(permission.data.items, principal.data.items);
    defer std.testing.allocator.free(policy);
    const rbac_bytes = try buildRbac(0, policy);
    defer std.testing.allocator.free(rbac_bytes);
    try std.testing.expect(try evaluateBytes(rbac_bytes, .{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-allow", .value = "yes" }},
    }));
    try std.testing.expect(!try evaluateBytes(rbac_bytes, .{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-allow", .value = "no" }},
    }));
}

test "RBAC matches header string-match field" {
    var matcher = TestBuilder{};
    defer matcher.deinit();
    try matcher.bytes(2, "/api"); // StringMatcher.prefix
    var string_header = TestBuilder{};
    defer string_header.deinit();
    try string_header.bytes(1, "x-path");
    try string_header.bytes(13, matcher.data.items); // string_match
    var permission = TestBuilder{};
    defer permission.deinit();
    try permission.bytes(4, string_header.data.items);
    var principal = TestBuilder{};
    defer principal.deinit();
    try principal.number(3, 1);
    const policy = try buildPolicy(permission.data.items, principal.data.items);
    defer std.testing.allocator.free(policy);
    const rbac_bytes = try buildRbac(0, policy);
    defer std.testing.allocator.free(rbac_bytes);
    try std.testing.expect(try evaluateBytes(rbac_bytes, .{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-path", .value = "/api/v1" }},
    }));
    try std.testing.expect(!try evaluateBytes(rbac_bytes, .{
        .path = "/x",
        .authority = "a",
        .metadata = &.{.{ .name = "x-path", .value = "/other" }},
    }));
}
