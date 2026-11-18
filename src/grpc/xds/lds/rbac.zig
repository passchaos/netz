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

fn headerMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.header.Match {
    return routing.header.decode(arena, bytes, .{
        .max_text_bytes = limits.max_text_bytes,
        .regex = limits.regex,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HeaderMatcherLimitExceeded => return error.RbacLimitExceeded,
        error.InvalidHeaderMatcher => return error.InvalidRbacResource,
        else => return @errorCast(err),
    };
}

fn pathMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!routing.string.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var matcher: ?routing.string.Match = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            matcher = routing.header.decodeStringMatcher(arena, try reader.bytesValue(), .{
                .max_text_bytes = limits.max_text_bytes,
                .regex = limits.regex,
            }) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.HeaderMatcherLimitExceeded => return error.RbacLimitExceeded,
                error.InvalidHeaderMatcher => return error.InvalidRbacResource,
                else => return @errorCast(err),
            };
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
    // Action is a proto3 scalar: omitted ALLOW (0) is the default.
    var action: Action = .allow;
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
    return .{ .action = action, .rules = try rules.toOwnedSlice(arena) };
}

/// Decode a bare `envoy.config.rbac.v3.RBAC` policy.
pub fn decodePolicyBytes(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Policy {
    return decodePolicy(arena, bytes, limits);
}

/// Decode an `envoy.extensions.filters.http.rbac.v3.RBAC` filter config.
/// Absent `rules` (field 1) disables enforcement; present empty rules deny all.
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
    const bytes_value = policy orelse return .{ .action = .deny, .rules = &.{} };
    return decodePolicy(arena, bytes_value, limits);
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

pub const TestBuilder = struct {
    data: std.ArrayList(u8) = .empty,
    pub fn deinit(self: *TestBuilder) void {
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
    pub fn bytes(self: *TestBuilder, field: u32, value: []const u8) !void {
        try self.varint((@as(u64, field) << 3) | 2);
        try self.varint(value.len);
        try self.data.appendSlice(std.testing.allocator, value);
    }
    pub fn number(self: *TestBuilder, field: u32, value: u64) !void {
        try self.varint(@as(u64, field) << 3);
        try self.varint(value);
    }
};

pub fn buildPolicy(permission: []const u8, principal: []const u8) ![]u8 {
    var policy = TestBuilder{};
    try policy.bytes(1, permission);
    try policy.bytes(2, principal);
    return policy.data.toOwnedSlice(std.testing.allocator);
}

pub fn buildRbac(action: u64, policy_bytes: []const u8) ![]u8 {
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

pub fn evaluateBytes(rbac_bytes: []const u8, request: routing.header.Request) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const policy = try decode(arena.allocator(), rbac_bytes, .{});
    return evaluate(&policy, std.testing.allocator, request);
}

test {
    _ = @import("rbac/tests.zig");
}
