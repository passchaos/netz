//! Control-plane limits and data-plane connection settings.
const eds = @import("../eds.zig");
pub const Limits = struct {
    lds: @import("../lds.zig").resource.Limits = .{},
    cds: @import("../cds.zig").resource.Limits = .{},
    eds: eds.resource.Limits = .{},
    max_clusters: usize = 4096,
    max_projections: usize = 4096,
    max_storage_bytes: usize = 64 * 1024 * 1024,
};
pub const Options = struct {
    listener_name: []const u8,
    target: eds.TargetOptions,
    max_header_bytes: usize = 65536,
    /// Preserve local method/health/retry settings; discovery replaces only LB.
    /// Null captures the destination's initial service-config JSON at start.
    local_service_config_json: ?[]const u8 = null,
    limits: Limits = .{},
};
