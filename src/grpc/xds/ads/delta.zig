//! xDS v3 delta Aggregated Discovery Service.
pub const codec = @import("delta_codec.zig");
pub const subscriptions = @import("delta_subscriptions.zig");
pub const path = @import("delta_client.zig").path;
pub const Client = @import("delta_client.zig").Client;
pub const Options = @import("delta_client.zig").Options;
pub const Error = @import("delta_client.zig").Error;
pub const Update = @import("delta_client.zig").Update;
pub const Event = @import("delta_client.zig").Event;
test {
    _ = @import("delta_tests.zig");
    _ = @import("delta_transport_tests.zig");
}
