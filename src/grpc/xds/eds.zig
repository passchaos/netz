//! Typed EDS resource decoding and reference-owned channel publication.
pub const resource = @import("eds/decode.zig");
pub const type_url = resource.type_url;
pub const decode = resource.decode;
pub const Snapshot = @import("eds/target.zig").Snapshot;
pub const TargetOptions = @import("eds/target.zig").Options;
pub const Error = @import("eds/apply.zig").Error;
pub const publishUpdateWithDeadline = @import("eds/apply.zig").publishWithDeadline;
test {
    _ = @import("eds/tests.zig");
    _ = @import("eds/transport_tests.zig");
}
