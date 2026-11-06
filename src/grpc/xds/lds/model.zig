//! Client API Listener and its route source; inline RDS owns parsed storage.
const std = @import("std");
const rds = @import("../rds.zig");
pub const type_url = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub const hcm_type = "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
pub const router_type = "envoy.extensions.filters.http.router.v3.Router";
pub const rbac_type = "envoy.extensions.filters.http.rbac.v3.RBAC";
pub const fault_type = "envoy.extensions.filters.http.fault.v3.HTTPFault";
pub const Error = rds.resource.Error || error{
    InvalidLdsResource,
    LdsLimitExceeded,
    UnsupportedLdsFeature,
    InvalidRbacResource,
    RbacLimitExceeded,
    UnsupportedRbacFeature,
    InvalidFaultResource,
    FaultLimitExceeded,
    UnsupportedFaultFeature,
};
pub const Limits = struct {
    max_bytes: usize = 8 * 1024 * 1024,
    max_text_bytes: usize = 4096,
    max_http_filters: usize = 128,
    max_storage_bytes: usize = 64 * 1024 * 1024,
    rds: rds.resource.Limits = .{},
};
pub const Filter = struct {
    name: []const u8,
    type_name: []const u8,
    optional: bool,
    /// A supported filter disabled by the control plane is ignored.
    disabled: bool = false,
    /// Raw typed config bytes for supported non-router filters.
    config: []const u8 = "",
};
pub const Hcm = struct {
    route_source: union(enum) { rds: []const u8, inline_rds: []const u8 },
    max_stream_duration: ?std.Io.Duration,
    filters: []const Filter,
    /// Raw `envoy.filters.http.rbac.v3.RBAC` config, when present.
    rbac_config: ?[]const u8 = null,
    /// HCM filter instance name that owns RBAC overrides.
    rbac_name: ?[]const u8 = null,
    /// Raw `envoy.filters.http.fault.v3.HTTPFault` config, when present.
    fault_config: ?[]const u8 = null,
    /// HCM filter instance name that owns fault overrides.
    fault_name: ?[]const u8 = null,
};
pub const Listener = struct { name: []const u8, hcm: Hcm };
pub const Owned = struct {
    wire: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    value: Listener,
    inline_rds: ?rds.resource.Owned = null,
    pub fn storageBytes(self: *const Owned) usize {
        return self.arena.queryCapacity() + if (self.inline_rds) |*resource| resource.arena.queryCapacity() else @as(usize, 0);
    }
    pub fn deinit(self: *Owned) void {
        if (self.inline_rds) |*resource| resource.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
