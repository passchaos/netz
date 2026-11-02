//! Listener-owning multi-connection HTTP/2 WebTransport server.
const runtime = @import("endpoint_listener/runtime.zig");

pub const Error = runtime.Error;
pub const Options = runtime.Options;
pub const ConnectionHandle = runtime.ConnectionHandle;
pub const Handle = runtime.Handle;
pub const Event = runtime.Event;
pub const KeyingMaterial = runtime.KeyingMaterial;
pub const Accepted = runtime.Accepted;
pub const PendingRequest = runtime.PendingRequest;
pub const EndpointListener = runtime.EndpointListener;

test {
    _ = runtime;
    _ = @import("endpoint_listener/admission_tests.zig");
}
