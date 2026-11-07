//! Resolve an xds target through bootstrap listener-name templates.
const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const resource_name = @import("resource_name.zig");
const uri = @import("uri.zig");

pub const Error = uri.Error || resource_name.Error || error{ UnknownXdsAuthority, InvalidXdsListenerTemplate };
pub const Limits = struct {
    max_uri_bytes: usize = 4096,
    max_listener_name_bytes: usize = 4096,
};
pub const Options = struct {
    limits: Limits = .{},
    /// Raw channel default-authority override; encoded independently of LDS.
    default_authority: ?[]const u8 = null,
};

pub const Resolved = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    listener_name: []const u8,
    /// Decoded authority in the xds target URI, null for unqualified targets.
    discovery_authority: ?[]const u8,
    /// Decoded authority of the generated xdstp listener name, if any.
    listener_resource_authority: ?[]const u8,
    /// Core-style data authority, independent of discovery routing. Request
    /// writers still apply HTTP authority syntax validation.
    data_authority: []const u8,

    pub fn deinit(self: *Resolved) void {
        self.arena.deinit();
        self.allocator.destroy(self);
    }
};

pub fn resolve(gpa: std.mem.Allocator, configuration: *const bootstrap.Bootstrap, target: []const u8, limits: Limits) Error!*Resolved {
    return resolveWithOptions(gpa, configuration, target, .{ .limits = limits });
}

pub fn resolveWithOptions(gpa: std.mem.Allocator, configuration: *const bootstrap.Bootstrap, target: []const u8, options: Options) Error!*Resolved {
    const limits = options.limits;
    if (limits.max_uri_bytes == 0 or limits.max_listener_name_bytes == 0) return error.InvalidXdsTarget;
    if (target.len > limits.max_uri_bytes) return error.XdsTargetLimitExceeded;
    const self = try gpa.create(Resolved);
    self.* = .{ .allocator = gpa, .arena = .init(gpa), .listener_name = "", .discovery_authority = null, .listener_resource_authority = null, .data_authority = "" };
    errdefer self.deinit();
    const arena = self.arena.allocator();
    const parsed = try uri.parseTarget(arena, target);
    const service = if (parsed.path[0] == '/') parsed.path[1..] else parsed.path;
    var template = configuration.client_default_listener_resource_name_template;
    const qualified = parsed.authority.len != 0;
    if (qualified) {
        const authority = configuration.authority(parsed.authority) orelse return error.UnknownXdsAuthority;
        self.discovery_authority = parsed.authority;
        template = authority.client_listener_resource_name_template;
        if (template.len == 0) {
            const escaped = try uri.percentEncode(arena, parsed.authority, .authority);
            template = try std.fmt.allocPrint(arena, "xdstp://{s}/envoy.config.listener.v3.Listener/%s", .{escaped});
        }
    } else if (template.len == 0) template = "%s";
    const fragment = if (qualified or std.mem.startsWith(u8, template, "xdstp:"))
        try uri.percentEncode(arena, service, .path)
    else
        service;
    self.listener_name = try expand(arena, template, fragment, limits.max_listener_name_bytes);
    if (self.listener_name.len == 0 or !std.unicode.utf8ValidateSlice(self.listener_name)) return error.InvalidXdsListenerTemplate;
    const name = try resource_name.parse(self.listener_name);
    if (name.authority) |encoded| {
        const raw_authority = try uri.percentDecode(arena, encoded);
        const raw_type = try uri.percentDecode(arena, name.type_url.?);
        if (!std.mem.eql(u8, raw_type, "envoy.config.listener.v3.Listener")) return error.InvalidXdsListenerTemplate;
        if (configuration.authority(raw_authority) == null) return error.UnknownXdsAuthority;
        self.listener_resource_authority = raw_authority;
    }
    const data_authority = options.default_authority orelse service;
    if (data_authority.len == 0 or !std.unicode.utf8ValidateSlice(data_authority)) return error.InvalidXdsTarget;
    if (data_authority.len > limits.max_uri_bytes) return error.XdsTargetLimitExceeded;
    self.data_authority = try uri.percentEncode(arena, data_authority, .authority);
    return self;
}

fn expand(allocator: std.mem.Allocator, template: []const u8, replacement: []const u8, limit: usize) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, template, offset, "%s")) |position| {
        try appendBounded(&out, allocator, template[offset..position], limit);
        try appendBounded(&out, allocator, replacement, limit);
        offset = position + 2;
    }
    try appendBounded(&out, allocator, template[offset..], limit);
    return out.toOwnedSlice(allocator);
}

fn appendBounded(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8, limit: usize) Error!void {
    if (bytes.len > limit - out.items.len) return error.XdsTargetLimitExceeded;
    try out.appendSlice(allocator, bytes);
}

test {
    _ = @import("client_target/tests.zig");
}
