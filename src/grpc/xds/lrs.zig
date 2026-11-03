//! xDS Load Reporting Service.
pub const codec = @import("lrs/codec.zig");
pub const path = @import("lrs/client.zig").path;
pub const Client = @import("lrs/client.zig").Client;
pub const Options = @import("lrs/client.zig").Options;
pub const Error = @import("lrs/client.zig").Error;
pub const Event = @import("lrs/client.zig").Event;
test {
    _ = @import("lrs/tests.zig");
    _ = @import("lrs/transport_tests.zig");
}
