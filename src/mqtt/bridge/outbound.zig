//! Outbound and single-remote-Session bidirectional broker bridges.
const engine = @import("outbound_engine.zig");
pub const Endpoint = engine.Endpoint;
pub const Error = engine.Error;
pub const Rule = engine.Rule;
pub const InboundRule = engine.InboundRule;
pub const Options = engine.Options;
pub const MultiOptions = engine.MultiOptions;
pub const NotificationOptions = engine.NotificationOptions;
pub const ProtocolFallback = engine.ProtocolFallback;
pub const CoordinatorMode = engine.CoordinatorMode;
pub const CoordinatorOptions = engine.CoordinatorOptions;
pub const ConnectEvent = engine.ConnectEvent;
pub const Bridge = engine.Bridge;
pub const testing = engine.testing;
pub const LocalBridge = engine.LocalBridge;

test {
    _ = engine;
    _ = @import("local_outbound_tests.zig");
}
