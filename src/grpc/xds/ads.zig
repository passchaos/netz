//! xDS v3 state-of-the-world Aggregated Discovery Service.
pub const codec = @import("ads/codec.zig");
pub const subscriptions = @import("ads/subscriptions.zig");
pub const path = @import("ads/client.zig").path;
pub const Client = @import("ads/client.zig").Client;
pub const Options = @import("ads/client.zig").Options;
pub const Error = @import("ads/client.zig").Error;
pub const Update = @import("ads/client.zig").Update;
pub const Event = @import("ads/client.zig").Event;
test {
    _ = @import("ads/tests.zig");
    _ = @import("ads/transport_tests.zig");
}
