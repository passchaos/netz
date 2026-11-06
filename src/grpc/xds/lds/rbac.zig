//! Envoy HTTP RBAC policy decoding and evaluation.
//!
//! Supports the grpc-core request-side subset: `any`, header, URL-path,
//! `and`/`or`/`not` principals and permissions with ALLOW/DENY policies.
//! Authenticated/IP/metadata principals, destination IP/port/metadata
//! permissions, requested server names and CEL conditions are rejected so an
//! unsupported policy never silently allows traffic.

const std = @import("std");
const pb = @import("protobuf.zig");
const routing = @import("../routing/mod.zig");

pub const Error = pb.Error || routing.regex.Error || error{
    UnsupportedRbacFeature,
    InvalidRbacResource,
    RbacLimitExceeded,
};

pub const Limits = struct {
    max_rules: usize = 256,
    max_nodes: usize = 256,
    max_depth: u8 = 16,
    max_text_bytes: usize = 4096,
    regex: routing.regex.Limits = .{},
};

pub const Action = enum { deny, allow };

pub const Rule = struct {
    /// A policy matches when any permission matches and any principal matches.
    permissions: []const Node,
    principals: []const Node,
};

pub const Policy = struct {
    action: Action,
    rules: []const Rule,
};

pub const Node = union(enum) {
    any,
    never,
    header: routing.header.Match,
    url_path: routing.string.Match,
    all: []const Node,
    any_of: []const Node,
    negate: *const Node,
};

fn literal(kind: u32, text: []const u8, ignore_case: bool) routing.string.Match {
    const value = routing.string.Match.Literal{ .text = text, .ignore_case = ignore_case };
    return switch (kind) {
        1 => .{ .exact = value },
        2 => .{ .prefix = value },
        3 => .{ .suffix = value },
        14 => .{ .path_separated_prefix = value },
        else => .{ .contains = value },
    };
}

fn regexMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.string.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var pattern: ?[]const u8 = null;
    while (try reader.next()) |field| {
        // Envoy RegexMatcher: google_re2 engine = 1, regex pattern = 2.
        if (field.number == 2 and field.wire_type == 2) {
            pattern = try pb.text(&reader, limits.max_text_bytes);
        } else try reader.skip(field);
    }
    return routing.string.Match.compileRegex(arena, pattern orelse return error.InvalidRbacResource, limits.regex);
}

fn stringMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.string.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var kind: ?u32 = null;
    var text: []const u8 = "";
    var ignore_case = false;
    var regex_bytes: ?[]const u8 = null;
    while (try reader.next()) |field| {
        // Envoy StringMatcher: exact = 1, prefix = 2, suffix = 3,
        // safe_regex = 5, contains = 7; ignore_case = 6.
        if ((field.number == 1 or field.number == 2 or field.number == 3 or
            field.number == 7) and field.wire_type == 2)
        {
            kind = field.number;
            text = try pb.text(&reader, limits.max_text_bytes);
            regex_bytes = null;
        } else if (field.number == 5 and field.wire_type == 2) {
            kind = 5;
            regex_bytes = try reader.bytesValue();
        } else if (field.number == 6 and field.wire_type == 0) {
            ignore_case = (try reader.varint()) != 0;
        } else try reader.skip(field);
    }
    const value = kind orelse return error.InvalidRbacResource;
    if (value == 5) return regexMatcher(arena, regex_bytes.?, limits);
    if (text.len == 0 and value != 1) return error.InvalidRbacResource;
    return literal(value, text, ignore_case);
}

fn rangeMatcher(bytes: []const u8) Error!routing.header.Range {
    var reader = pb.Reader{ .bytes = bytes };
    var start: i64 = 0;
    var end: i64 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            start = @bitCast(try reader.varint());
        } else if (field.number == 2 and field.wire_type == 0) {
            end = @bitCast(try reader.varint());
        } else try reader.skip(field);
    }
    if (end < start) return error.InvalidRbacResource;
    return .{ .start = start, .end = end };
}

fn headerMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.header.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var name: []const u8 = "";
    var condition: ?routing.header.Condition = null;
    var invert = false;
    while (try reader.next()) |field| {
        switch (field.number) {
            1 => if (field.wire_type == 2) {
                name = try pb.text(&reader, limits.max_text_bytes);
            } else try reader.skip(field),
            4 => if (field.wire_type == 2) {
                condition = .{ .string = literal(1, try pb.text(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            11 => if (field.wire_type == 2) {
                condition = .{ .string = try regexMatcher(arena, try reader.bytesValue(), limits) };
            } else try reader.skip(field),
            6 => if (field.wire_type == 2) {
                condition = .{ .range = try rangeMatcher(try reader.bytesValue()) };
            } else try reader.skip(field),
            7 => if (field.wire_type == 0) {
                condition = .{ .present = (try reader.varint()) != 0 };
            } else try reader.skip(field),
            8 => if (field.wire_type == 0) {
                invert = (try reader.varint()) != 0;
            } else try reader.skip(field),
            9 => if (field.wire_type == 2) {
                condition = .{ .string = literal(2, try pb.text(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            10 => if (field.wire_type == 2) {
                condition = .{ .string = literal(3, try pb.text(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            12 => if (field.wire_type == 2) {
                condition = .{ .string = literal(7, try pb.text(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            13 => if (field.wire_type == 2) {
                condition = .{ .string = try stringMatcher(arena, try reader.bytesValue(), limits) };
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    if (name.len == 0) return error.InvalidRbacResource;
    return .{ .name = name, .condition = condition orelse return error.InvalidRbacResource, .invert = invert };
}

fn pathMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.string.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var matcher: ?routing.string.Match = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            matcher = try stringMatcher(arena, try reader.bytesValue(), limits);
        } else try reader.skip(field);
    }
    return matcher orelse error.InvalidRbacResource;
}

const Context = struct {
    arena: std.mem.Allocator,
    limits: Limits,
    nodes: *usize,
};

fn decodeSet(
    context: *Context,
    bytes: []const u8,
    is_principal: bool,
    depth: u8,
) Error![]const Node {
    var list: std.ArrayList(Node) = .empty;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            try list.append(context.arena, try decodeNode(context, try reader.bytesValue(), is_principal, depth + 1));
        } else try reader.skip(field);
    }
    return list.toOwnedSlice(context.arena);
}

fn decodeNode(
    context: *Context,
    bytes: []const u8,
    is_principal: bool,
    depth: u8,
) Error!Node {
    if (depth > context.limits.max_depth) return error.RbacLimitExceeded;
    if (context.nodes.* >= context.limits.max_nodes) return error.RbacLimitExceeded;
    context.nodes.* += 1;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (is_principal) {
            // Envoy Principal: and_ids = 1, or_ids = 2, any = 3,
            // authenticated = 4, source_ip = 5, header = 6, metadata = 7,
            // not_id = 8, url_path = 9, direct_remote_ip = 10, remote_ip = 11,
            // filter_state = 12, sourced_metadata = 13, custom = 14.
            switch (field.number) {
                1 => if (field.wire_type == 2) return .{ .all = try decodeSet(context, try reader.bytesValue(), true, depth) } else try reader.skip(field),
                2 => if (field.wire_type == 2) return .{ .any_of = try decodeSet(context, try reader.bytesValue(), true, depth) } else try reader.skip(field),
                3 => if (field.wire_type == 0) {
                    return if ((try reader.varint()) != 0) .any else .never;
                } else try reader.skip(field),
                6 => if (field.wire_type == 2) {
                    return .{ .header = try headerMatcher(context.arena, try reader.bytesValue(), context.limits) };
                } else try reader.skip(field),
                8 => if (field.wire_type == 2) {
                    const nested = try context.arena.create(Node);
                    nested.* = try decodeNode(context, try reader.bytesValue(), true, depth + 1);
                    return .{ .negate = nested };
                } else try reader.skip(field),
                9 => if (field.wire_type == 2) {
                    return .{ .url_path = try pathMatcher(context.arena, try reader.bytesValue(), context.limits) };
                } else try reader.skip(field),
                else => return error.UnsupportedRbacFeature,
            }
        } else {
            // Envoy Permission: and_rules = 1, or_rules = 2, any = 3,
            // header = 4, destination_ip = 5, destination_port = 6,
            // metadata = 7, not_rule = 8, requested_server_name = 9,
            // url_path = 10, destination_port_range = 11, matcher = 12,
            // uri_template = 13, sourced_metadata = 14.
            switch (field.number) {
                1 => if (field.wire_type == 2) return .{ .all = try decodeSet(context, try reader.bytesValue(), false, depth) } else try reader.skip(field),
                2 => if (field.wire_type == 2) return .{ .any_of = try decodeSet(context, try reader.bytesValue(), false, depth) } else try reader.skip(field),
                3 => if (field.wire_type == 0) {
                    return if ((try reader.varint()) != 0) .any else .never;
                } else try reader.skip(field),
                4 => if (field.wire_type == 2) {
                    return .{ .header = try headerMatcher(context.arena, try reader.bytesValue(), context.limits) };
                } else try reader.skip(field),
                8 => if (field.wire_type == 2) {
                    const nested = try context.arena.create(Node);
                    nested.* = try decodeNode(context, try reader.bytesValue(), false, depth + 1);
                    return .{ .negate = nested };
                } else try reader.skip(field),
                10 => if (field.wire_type == 2) {
                    return .{ .url_path = try pathMatcher(context.arena, try reader.bytesValue(), context.limits) };
                } else try reader.skip(field),
                else => return error.UnsupportedRbacFeature,
            }
        }
    }
    return error.InvalidRbacResource;
}

fn decodeRule(context: *Context, bytes: []const u8) Error!Rule {
    var reader = pb.Reader{ .bytes = bytes };
    var permissions: std.ArrayList(Node) = .empty;
    var principals: std.ArrayList(Node) = .empty;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            try permissions.append(context.arena, try decodeNode(context, try reader.bytesValue(), false, 0));
        } else if (field.number == 2 and field.wire_type == 2) {
            try principals.append(context.arena, try decodeNode(context, try reader.bytesValue(), true, 0));
        } else if (field.number == 3 or field.number == 4) {
            return error.UnsupportedRbacFeature;
        } else try reader.skip(field);
    }
    return .{
        .permissions = try permissions.toOwnedSlice(context.arena),
        .principals = try principals.toOwnedSlice(context.arena),
    };
}

/// Decode an `envoy.config.rbac.v3.RBAC` policy into arena-owned nodes.
fn decodePolicy(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Policy {
    var reader = pb.Reader{ .bytes = bytes };
    var action: ?Action = null;
    var rules: std.ArrayList(Rule) = .empty;
    var node_count: usize = 0;
    var context = Context{ .arena = arena, .limits = limits, .nodes = &node_count };
    while (try reader.next()) |field| {
        switch (field.number) {
            1 => if (field.wire_type == 0) {
                // Envoy Action: ALLOW = 0, DENY = 1, LOG = 2.
                action = switch (try reader.varint()) {
                    0 => .allow,
                    1 => .deny,
                    2 => return error.UnsupportedRbacFeature,
                    else => return error.InvalidRbacResource,
                };
            } else try reader.skip(field),
            2 => if (field.wire_type == 2) {
                var entry = pb.Reader{ .bytes = try reader.bytesValue() };
                var value: ?[]const u8 = null;
                while (try entry.next()) |entry_field| {
                    if (entry_field.number == 2 and entry_field.wire_type == 2) {
                        value = try entry.bytesValue();
                    } else try entry.skip(entry_field);
                }
                if (value) |rule_bytes| {
                    if (rules.items.len >= limits.max_rules) return error.RbacLimitExceeded;
                    try rules.append(arena, try decodeRule(&context, rule_bytes));
                } else return error.InvalidRbacResource;
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    return .{ .action = action orelse return error.InvalidRbacResource, .rules = try rules.toOwnedSlice(arena) };
}

/// Decode an `envoy.extensions.filters.http.rbac.v3.RBAC` filter config.
/// The enforcing policy is the nested `rules` message (field 1).
pub fn decode(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Policy {
    var reader = pb.Reader{ .bytes = bytes };
    var policy: ?[]const u8 = null;
    while (try reader.next()) |field| {
        switch (field.number) {
            1 => if (field.wire_type == 2) {
                policy = try reader.bytesValue();
            } else try reader.skip(field),
            2 => if (field.wire_type == 2) {
                // shadow_rules only affect audit logging, never enforcement.
                _ = try reader.bytesValue();
            } else try reader.skip(field),
            4, 5 => return error.UnsupportedRbacFeature, // action-based matcher forms
            else => try reader.skip(field),
        }
    }
    return decodePolicy(arena, policy orelse return error.InvalidRbacResource, limits);
}

fn anyNode(nodes: []const Node, gpa: std.mem.Allocator, request: routing.header.Request) (std.mem.Allocator.Error || routing.header.Error)!bool {
    for (nodes) |*node| if (try evaluateNode(node, gpa, request)) return true;
    return false;
}

fn evaluateNode(node: *const Node, gpa: std.mem.Allocator, request: routing.header.Request) (std.mem.Allocator.Error || routing.header.Error)!bool {
    return switch (node.*) {
        .any => true,
        .never => false,
        .header => |matcher| matcher.matches(gpa, request),
        .url_path => |matcher| matcher.matches(gpa, request.path),
        .all => |nodes| blk: {
            for (nodes) |*nested| if (!try evaluateNode(nested, gpa, request)) break :blk false;
            break :blk true;
        },
        .any_of => |nodes| anyNode(nodes, gpa, request),
        .negate => |nested| !try evaluateNode(nested, gpa, request),
    };
}

/// Envoy RBAC semantics: ALLOW admits only when a rule matches; DENY admits
/// only when no rule matches.
pub fn evaluate(policy: *const Policy, gpa: std.mem.Allocator, request: routing.header.Request) (std.mem.Allocator.Error || routing.header.Error)!bool {
    var matched = false;
    for (policy.rules) |rule| {
        if (try anyNode(rule.permissions, gpa, request) and
            try anyNode(rule.principals, gpa, request))
        {
            matched = true;
            break;
        }
    }
    return if (policy.action == .allow) matched else !matched;
}

const TestBuilder = struct {
    data: std.ArrayList(u8) = .empty,
    fn deinit(self: *TestBuilder) void {
        self.data.deinit(std.testing.allocator);
    }
    fn varint(self: *TestBuilder, value: u64) !void {
        var remaining = value;
        while (remaining >= 0x80) {
            try self.data.append(std.testing.allocator, @as(u8, @truncate(remaining)) | 0x80);
            remaining >>= 7;
        }
        try self.data.append(std.testing.allocator, @intCast(remaining));
    }
    fn bytes(self: *TestBuilder, field: u32, value: []const u8) !void {
        try self.varint((@as(u64, field) << 3) | 2);
        try self.varint(value.len);
        try self.data.appendSlice(std.testing.allocator, value);
    }
    fn number(self: *TestBuilder, field: u32, value: u64) !void {
        try self.varint(@as(u64, field) << 3);
        try self.varint(value);
    }
};

fn buildPolicy(permission: []const u8, principal: []const u8) ![]u8 {
    var policy = TestBuilder{};
    try policy.bytes(1, permission);
    try policy.bytes(2, principal);
    return policy.data.toOwnedSlice(std.testing.allocator);
}

fn buildRbac(action: u64, policy_bytes: []const u8) ![]u8 {
    var entry = TestBuilder{};
    defer entry.deinit();
    try entry.bytes(1, "p");
    try entry.bytes(2, policy_bytes);
    var policy = TestBuilder{};
    defer policy.deinit();
    try policy.number(1, action);
    try policy.bytes(2, entry.data.items);
    // Wrap the policy in the HTTP RBAC filter's `rules` field.
    var filter = TestBuilder{};
    try filter.bytes(1, policy.data.items);
    return filter.data.toOwnedSlice(std.testing.allocator);
}

fn evaluateBytes(rbac_bytes: []const u8, request: routing.header.Request) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const policy = try decode(arena.allocator(), rbac_bytes, .{});
    return evaluate(&policy, std.testing.allocator, request);
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
