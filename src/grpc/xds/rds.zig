//! Typed RDS resources and retained per-RPC selection over cluster managers.
pub const resource = @import("rds/model.zig");
pub const type_url = resource.type_url;
pub const decode = @import("rds/decode.zig").decode;
pub const Snapshot = @import("rds/snapshot.zig").Snapshot;
pub const Options = @import("rds/snapshot.zig").Options;
pub const Error = @import("rds/apply.zig").Error;
pub const publishUpdateWithDeadline = @import("rds/apply.zig").publishWithDeadline;
test {
    _ = @import("rds/tests.zig");
    _ = @import("rds/transport_tests.zig");
    _ = @import("rds/lifecycle_tests.zig");
}
