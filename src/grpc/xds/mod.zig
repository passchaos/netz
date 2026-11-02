//! xDS control-plane protocol support.
pub const eds = @import("eds.zig");
pub const cds = @import("cds.zig");
pub const routing = @import("routing/mod.zig");
pub const rds = @import("rds.zig");
pub const ads = @import("ads.zig");
test {
    _ = ads;
    _ = eds;
    _ = cds;
    _ = routing;
    _ = rds;
}
