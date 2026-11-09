//! DERP relay protocol.
//!
//! Bounded frame codec, relay/client state machines, and the WebSocket
//! transport adapter. Relay authorization policy and control-plane DERP maps
//! remain in `meshz`.

pub const frame = @import("frame.zig");
pub const relay = @import("relay.zig");
pub const client = @import("client.zig");
pub const websocket = @import("websocket.zig");

pub const Frame = frame.Frame;
pub const FrameType = frame.FrameType;
pub const Relay = relay.Relay;
pub const Client = client.Client;
pub const ClientState = client.State;

test {
    _ = frame;
    _ = relay;
    _ = client;
    _ = websocket;
}
