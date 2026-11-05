//! Automatic typed LDS/RDS/CDS/EDS dependencies and immutable target publication.
pub const Controller = @import("runtime/controller.zig").Controller;
pub const Options = @import("runtime/options.zig").Options;
pub const Limits = @import("runtime/options.zig").Limits;
pub const Error = @import("runtime/controller.zig").Error;
test {
    _ = @import("runtime/tests.zig");
    _ = @import("runtime/target_tests.zig");
    _ = @import("runtime/rollback_tests.zig");
    _ = @import("runtime/constructor_tests.zig");
    _ = @import("runtime/delta_tests.zig");
    _ = @import("runtime/delta_ttl_tests.zig");
    _ = @import("runtime/lrs_tests.zig");
    _ = @import("runtime/sds_tests.zig");
}
