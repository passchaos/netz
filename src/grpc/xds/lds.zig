//! Client LDS/HCM decoding and listener-driven inline/dynamic RDS publication.
pub const resource = @import("lds/model.zig");
pub const type_url = resource.type_url;
pub const decode = @import("lds/decode.zig").decode;
pub const Controller = @import("lds/controller.zig").Controller;
pub const Options = @import("lds/controller.zig").Options;
pub const Error = @import("lds/controller.zig").Error;
pub const rbac = @import("lds/rbac.zig");
test {
    _ = rbac;
    _ = @import("lds/tests.zig");
    _ = @import("lds/controller_tests.zig");
    _ = @import("lds/rollback_tests.zig");
}
