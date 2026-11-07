//! Core URI vectors and owned bootstrap-derived client targets.
const std = @import("std");
const target = @import("../client_target.zig");
const bootstrap = @import("../bootstrap.zig");
const uri = @import("../uri.zig");
const gpa = std.testing.allocator;
const prefix = "xdstp://tenant/envoy.config.listener.v3.Listener/";
const base =
    \\{"xds_servers":[{"server_uri":"http://127.0.0.1:1","channel_creds":[{"type":"insecure"}]}],"node":{"id":"test"},"authorities":{"tenant":{},"tenant space":{}}}
;

test "gRPC xDS client target follows decoded URI and bootstrap defaults" {
    const configuration = try bootstrap.parse(gpa, base, .{});
    defer configuration.deinit();
    const Case = struct {
        input: []const u8,
        listener: []const u8,
        authority: []const u8,
        discovery: ?[]const u8 = null,
        resource_authority: ?[]const u8 = null,
    };
    const cases = [_]Case{
        .{ .input = "xds:///svc", .listener = "svc", .authority = "svc" },
        .{ .input = "xds:/svc", .listener = "svc", .authority = "svc" },
        .{ .input = "xds:svc", .listener = "svc", .authority = "svc" },
        .{ .input = "xds:///a/b", .listener = "a/b", .authority = "a%2Fb" },
        .{ .input = "xds:///a%2Fb", .listener = "a/b", .authority = "a%2Fb" },
        .{ .input = "xds:////svc", .listener = "/svc", .authority = "%2Fsvc" },
        .{ .input = "xds:///svc?x=y#f", .listener = "svc", .authority = "svc" },
        .{ .input = "xds:///svc#", .listener = "svc", .authority = "svc" },
        .{ .input = "xds:///svc%zz", .listener = "svc%zz", .authority = "svc%25zz" },
        .{ .input = "xds://tenant/svc", .listener = prefix ++ "svc", .authority = "svc", .discovery = "tenant", .resource_authority = "tenant" },
        .{ .input = "xds://tenant/svc:443", .listener = prefix ++ "svc:443", .authority = "svc:443", .discovery = "tenant", .resource_authority = "tenant" },
        .{ .input = "xds://tenant/a/b", .listener = prefix ++ "a/b", .authority = "a%2Fb", .discovery = "tenant", .resource_authority = "tenant" },
        .{ .input = "xds://tenant/svc%20name", .listener = prefix ++ "svc%20name", .authority = "svc%20name", .discovery = "tenant", .resource_authority = "tenant" },
        .{ .input = "xds://tenant/svc%2520name", .listener = prefix ++ "svc%2520name", .authority = "svc%2520name", .discovery = "tenant", .resource_authority = "tenant" },
        .{ .input = "xds://tenant%20space/svc", .listener = "xdstp://tenant%20space/envoy.config.listener.v3.Listener/svc", .authority = "svc", .discovery = "tenant space", .resource_authority = "tenant space" },
    };
    for (cases) |case| {
        const value = try target.resolve(gpa, configuration, case.input, .{});
        defer value.deinit();
        try std.testing.expectEqualStrings(case.listener, value.listener_name);
        try std.testing.expectEqualStrings(case.authority, value.data_authority);
        try expectOptional(case.discovery, value.discovery_authority);
        try expectOptional(case.resource_authority, value.listener_resource_authority);
    }
}

fn expectOptional(expected: ?[]const u8, actual: ?[]const u8) !void {
    if (expected) |bytes| try std.testing.expectEqualStrings(bytes, actual orelse return error.TestUnexpectedResult) else try std.testing.expect(actual == null);
}

fn configured(allocator: std.mem.Allocator, top: []const u8, authority_template: []const u8) !*bootstrap.Bootstrap {
    const json = try std.json.Stringify.valueAlloc(allocator, .{
        .xds_servers = .{.{ .server_uri = "http://127.0.0.1:1", .channel_creds = .{.{ .type = "insecure" }} }},
        .node = .{ .id = "test" },
        .client_default_listener_resource_name_template = top,
        .authorities = .{ .tenant = .{ .client_listener_resource_name_template = authority_template } },
    }, .{});
    defer allocator.free(json);
    return bootstrap.parse(allocator, json, .{});
}

test "gRPC xDS client target substitutes every placeholder and permits constant templates" {
    const configuration = try configured(gpa, "old/%s/again/%s", prefix ++ "prefix/%s/%s");
    defer configuration.deinit();
    const old = try target.resolve(gpa, configuration, "xds:///a%20b", .{});
    defer old.deinit();
    try std.testing.expectEqualStrings("old/a b/again/a b", old.listener_name);
    const qualified = try target.resolve(gpa, configuration, "xds://tenant/a%2Fb", .{});
    defer qualified.deinit();
    try std.testing.expectEqualStrings(prefix ++ "prefix/a/b/a/b", qualified.listener_name);
    try std.testing.expectEqualStrings("a%2Fb", qualified.data_authority);
    const constant = try configured(gpa, "fixed-listener", prefix ++ "fixed");
    defer constant.deinit();
    const value = try target.resolve(gpa, constant, "xds:///svc", .{});
    defer value.deinit();
    try std.testing.expectEqualStrings("fixed-listener", value.listener_name);
    try std.testing.expectEqualStrings("svc", value.data_authority);
    const defaults = try configured(gpa, "", "");
    defer defaults.deinit();
    const empty = try target.resolve(gpa, defaults, "xds://tenant/svc", .{});
    defer empty.deinit();
    try std.testing.expectEqualStrings(prefix ++ "svc", empty.listener_name);
}

test "gRPC xDS client target routes custom default templates by listener authority" {
    const configuration = try configured(gpa, prefix ++ "%s", "");
    defer configuration.deinit();
    const value = try target.resolveWithOptions(gpa, configuration, "xds:///svc%20name?x=y#f", .{ .default_authority = "backend.test/a b" });
    defer value.deinit();
    try std.testing.expectEqualStrings(prefix ++ "svc%20name", value.listener_name);
    try std.testing.expectEqualStrings("backend.test%2Fa%20b", value.data_authority);
    try std.testing.expect(value.discovery_authority == null);
    try std.testing.expectEqualStrings("tenant", value.listener_resource_authority.?);
}

test "gRPC xDS client target rejects absent authorities invalid paths and bounded expansion" {
    const configuration = try bootstrap.parse(gpa, base, .{});
    defer configuration.deinit();
    try std.testing.expectError(error.UnknownXdsAuthority, target.resolve(gpa, configuration, "xds://unknown/svc", .{}));
    for ([_][]const u8{ "", "https://tenant/svc", "xds:", "xds://", "xds:///", "xds://tenant", "xds://tenant/", "xds:///svc/", "xds:///svc%2F", "xds:///svc?", "xds:///svc?#fragment", "xds:///svc?bad space", "xds:///svc#bad#fragment", "xds://tenant/%ff" }) |invalid| {
        try std.testing.expectError(error.InvalidXdsTarget, target.resolve(gpa, configuration, invalid, .{}));
    }
    try std.testing.expectError(error.XdsTargetLimitExceeded, target.resolve(gpa, configuration, "xds:///svc", .{ .max_uri_bytes = 5 }));
    try std.testing.expectError(error.XdsTargetLimitExceeded, target.resolve(gpa, configuration, "xds://tenant/svc", .{ .max_listener_name_bytes = 8 }));
    const wrong_type = try configured(gpa, "xdstp://tenant/envoy.config.cluster.v3.Cluster/%s", "");
    defer wrong_type.deinit();
    try std.testing.expectError(error.InvalidXdsListenerTemplate, target.resolve(gpa, wrong_type, "xds:///svc", .{}));
    try std.testing.expectError(error.InvalidBootstrap, configured(gpa, "", "xdstp://other/envoy.config.listener.v3.Listener/%s"));
}

fn ownedTarget(allocator: std.mem.Allocator) !void {
    const value = block: {
        const configuration = try configured(allocator, prefix ++ "%s", "");
        defer configuration.deinit();
        const input = try allocator.dupe(u8, "xds:///owned%20service");
        defer allocator.free(input);
        break :block try target.resolve(allocator, configuration, input, .{});
    };
    defer value.deinit();
    try std.testing.expectEqualStrings(prefix ++ "owned%20service", value.listener_name);
    try std.testing.expectEqualStrings("owned%20service", value.data_authority);
    try std.testing.expectEqualStrings("tenant", value.listener_resource_authority.?);
}

test "gRPC xDS client target owns inputs and cleans up every allocation failure" {
    try ownedTarget(gpa);
    try std.testing.checkAllAllocationFailures(gpa, ownedTarget, .{});
}

test "gRPC xDS URI compares encoded authority without allocating or decoding twice" {
    try std.testing.expect(uri.percentEquals("tenant%20space", "tenant space"));
    try std.testing.expect(uri.percentEquals("tenant%2520space", "tenant%20space"));
    try std.testing.expect(!uri.percentEquals("tenant%2520space", "tenant space"));
    try std.testing.expect(uri.percentEquals("tenant%zz", "tenant%zz"));
    try std.testing.expect(!uri.percentEquals("tenant%2f", "tenant%2f"));
}
