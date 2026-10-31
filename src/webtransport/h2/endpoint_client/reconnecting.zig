//! Automatic transport reconnection for future HTTP/2 WebTransport Sessions.
const runtime = @import("reconnecting/runtime.zig");

pub const Error = runtime.Error;
pub const Target = runtime.Target;
pub const CustomConnector = runtime.CustomConnector;
pub const Backoff = runtime.Backoff;
pub const Options = runtime.Options;
pub const Handle = runtime.Handle;
pub const Accepted = runtime.Accepted;
pub const ConnectAttempt = runtime.ConnectAttempt;
pub const Event = runtime.Event;
pub const KeyingMaterial = runtime.KeyingMaterial;
pub const ReconnectingEndpointClient = runtime.ReconnectingEndpointClient;

test {
    _ = runtime;
    _ = @import("reconnecting/proxy_tests.zig");
    _ = @import("reconnecting/tests.zig");
}
