//! Control-plane limits and data-plane connection settings.
const std = @import("std");
const eds = @import("../eds.zig");
const lrs = @import("../lrs.zig");
const shared = @import("../../channel/shared.zig");
const control_plane = @import("../control_plane.zig");
pub const Limits = struct {
    lds: @import("../lds.zig").resource.Limits = .{},
    cds: @import("../cds.zig").resource.Limits = .{},
    eds: eds.resource.Limits = .{},
    sds: @import("../sds.zig").Limits = .{},
    max_clusters: usize = 4096,
    max_projections: usize = 4096,
    max_storage_bytes: usize = 64 * 1024 * 1024,
};
pub const LrsOptions = struct {
    /// Borrowed by the controller-owned runner; keep it alive until deinit.
    sender: shared.Sender,
    /// Dedicated to LRS: the runner mutates it from a background task.
    control_plane: *control_plane.ControlPlane,
    client: lrs.Options,
    reporter: lrs.ReporterOptions = .{},
    poll_interval: std.Io.Duration = .fromSeconds(1),
    connect_timeout: std.Io.Duration = .fromSeconds(5),
};
pub const Options = struct {
    listener_name: []const u8,
    target: eds.TargetOptions,
    max_header_bytes: usize = 65536,
    /// Preserve local method/health/retry settings; discovery replaces only LB.
    /// Null captures the destination's initial service-config JSON at start.
    local_service_config_json: ?[]const u8 = null,
    /// xDS authority for `xdstp://` resource names. Old-style names are always
    /// accepted; xdstp names must match this authority and their resource type.
    authority: ?[]const u8 = null,
    limits: Limits = .{},
    /// gRPC xDS `ignore_resource_deletion` server feature: retain resources
    /// omitted from SotW responses or listed in delta removals.
    ignore_resource_deletion: bool = false,
    /// Optional controller-owned LRS reporting. The destination channel must
    /// have LRS statistics enabled.
    lrs: ?LrsOptions = null,
};
