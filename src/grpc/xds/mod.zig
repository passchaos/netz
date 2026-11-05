//! xDS control-plane protocol support.
pub const eds = @import("eds.zig");
pub const cds = @import("cds.zig");
pub const routing = @import("routing/mod.zig");
pub const rds = @import("rds.zig");
pub const lds = @import("lds.zig");
pub const config_source = @import("config_source.zig");
pub const resource_name = @import("resource_name.zig");
pub const bootstrap = @import("bootstrap.zig");
pub const control_plane = @import("control_plane.zig");
pub const lrs = @import("lrs.zig");
pub const sds = @import("sds.zig");
pub const runtime = @import("runtime.zig");
pub const ads = @import("ads.zig");
test {
    _ = ads;
    _ = @import("tls_material.zig");
    _ = eds;
    _ = cds;
    _ = routing;
    _ = rds;
    _ = lds;
    _ = config_source;
    _ = resource_name;
    _ = bootstrap;
    _ = control_plane;
    _ = lrs;
    _ = sds;
    _ = runtime;
    _ = @import("sotw_tests.zig");
    _ = @import("bootstrap_tests.zig");
    _ = @import("control_plane_tests.zig");
}
