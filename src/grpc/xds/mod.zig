//! xDS control-plane protocol support.
pub const eds = @import("eds.zig");
pub const ads = @import("ads.zig");
test {
    _ = ads;
    _ = eds;
}
