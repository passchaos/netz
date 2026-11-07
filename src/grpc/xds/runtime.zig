//! Automatic typed LDS/RDS/CDS/EDS dependencies and immutable target publication.
pub const Controller = @import("runtime/controller.zig").Controller;
pub const Options = @import("runtime/options.zig").Options;
pub const Limits = @import("runtime/options.zig").Limits;
pub const Error = @import("runtime/controller.zig").Error;
pub const ResourceStatus = @import("runtime/controller.zig").ResourceStatus;
pub const managed = @import("runtime/managed.zig");
test {
    _ = @import("runtime/tests.zig");
    _ = @import("runtime/target_tests.zig");
    _ = @import("runtime/rollback_tests.zig");
    _ = @import("runtime/constructor_tests.zig");
    _ = @import("runtime/delta_tests.zig");
    _ = @import("runtime/delta_ttl_tests.zig");
    _ = @import("runtime/lrs_tests.zig");
    _ = @import("runtime/lrs_selection_tests.zig");
    _ = @import("runtime/lrs_automatic_tests.zig");
    _ = @import("runtime/lrs_automatic/routing_tests.zig");
    _ = @import("runtime/lrs_named_metric_tests.zig");
    _ = @import("runtime/sds_tests.zig");
    _ = @import("runtime/ignore_deletion_tests.zig");
    _ = @import("runtime/authority_tests.zig");
    _ = @import("runtime/fail_on_data_errors_tests.zig");
    _ = @import("runtime/federated_scope_tests.zig");
    _ = @import("runtime/managed/tests.zig");
    _ = @import("runtime/managed/registry_tests.zig");
    _ = @import("runtime/resource_timer_tests.zig");
}
