//! Owned typed route configuration; all strings/sets borrow the resource arena.
const std = @import("std");
const routing = @import("../routing/mod.zig");
pub const type_url = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub const Error = @import("../../protobuf.zig").Error || std.mem.Allocator.Error || routing.regex.Error || routing.template.Error || error{ InvalidRdsResource, RdsLimitExceeded, UnsupportedRdsFeature };
pub const Limits = struct {
    max_bytes: usize = 8 * 1024 * 1024,
    max_text_bytes: usize = 4096,
    max_virtual_hosts: usize = 1024,
    max_domains: usize = 4096,
    max_routes: usize = 4096,
    max_headers_per_route: usize = 128,
    max_clusters_per_route: usize = 256,
    max_cluster_entries: usize = 16384,
    max_referenced_clusters: usize = 4096,
    max_hash_policies: usize = 64,
    max_overrides: usize = 64,
    max_total_regex_instructions: usize = 65536,
    max_storage_bytes: usize = 64 * 1024 * 1024,
    regex: routing.regex.Limits = .{},
    template: routing.template.Limits = .{},
};
pub const Weighted = struct { name: []const u8, key: []const u8, weight: u32 };
pub const RegexRewrite = @import("../../path_rewrite.zig").RegexRewrite;
pub const TemplateRewrite = @import("../../path_rewrite.zig").TemplateRewrite;
pub const HashPolicy = struct {
    kind: union(enum) {
        header: struct {
            name: []const u8,
            regex: ?*const RegexRewrite = null,
        },
        channel_id,
    },
    terminal: bool,
};
pub const PathRewrite = union(enum) {
    /// Replace the complete request path.
    whole: []const u8,
    /// Replace the matched route prefix.
    prefix: []const u8,
    /// Apply an RE2-style capture-aware replacement.
    regex: *const RegexRewrite,
    /// Apply a URI-template replacement using the route match variables.
    template: *const TemplateRewrite,
};
pub const HostRewrite = union(enum) {
    /// Replace `:authority` with this literal.
    literal: []const u8,
    /// Replace `:authority` with the first value of this request header.
    header: []const u8,
    /// Use the selected endpoint's authority.
    auto,
    /// Apply an RE2-style replacement to the path (query/fragment removed).
    path_regex: *const RegexRewrite,
};
pub const Forward = struct {
    clusters: []const Weighted,
    total_weight: u32,
    hash_policies: []const HashPolicy,
    max_stream_duration: ?std.Io.Duration,
    retry_policy: ?@import("../../call.zig").RetryPolicy,
    retry_present: bool,
    path_rewrite: ?PathRewrite = null,
    host_rewrite: ?HostRewrite = null,
};
pub const OverrideKind = enum { rbac, fault };
/// One `typed_per_filter_config` entry. `kind` is null when a disabled
/// `FilterConfig` omitted its inner config; the projection resolves it by
/// matching the HCM filter name.
pub const Override = struct {
    name: []const u8 = "",
    kind: ?OverrideKind = null,
    disabled: bool = false,
    /// `envoy.config.rbac.v3.RBAC` for RBAC or HTTPFault for fault.
    config: []const u8 = "",
};
pub const Route = struct {
    path: routing.string.Match,
    headers: []const routing.header.Match,
    fraction_per_million: ?u32,
    action: union(enum) { forward: Forward, inappropriate },
    request_headers_to_add: []const @import("../../call.zig").HeaderMutation = &.{},
    request_headers_to_remove: []const []const u8 = &.{},
    response_headers_to_add: []const @import("../../call.zig").HeaderMutation = &.{},
    response_headers_to_remove: []const []const u8 = &.{},
    overrides: []const Override = &.{},
};
pub const VirtualHost = struct {
    domains: []const []const u8,
    routes: []const Route,
    overrides: []const Override = &.{},
};
pub const Config = struct { name: []const u8, virtual_hosts: []const VirtualHost };
pub const Owned = struct {
    wire: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    value: Config,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
