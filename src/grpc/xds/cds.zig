//! Typed EDS-backed CDS resources and serialized CDS/EDS application state.
pub const resource = @import("cds/decode.zig");
pub const type_url = resource.type_url;
pub const decode = resource.decode;
pub const Controller = @import("cds/controller.zig").Controller;
pub const Options = @import("cds/controller.zig").Options;
pub const Error = @import("cds/controller.zig").Error;
test {
    _ = @import("cds/tests.zig");
    _ = @import("cds/controller_tests.zig");
}
