//! WireGuard protocol core.
//!
//! This module owns the Noise IKpsk2 handshake, message codecs, cookie
//! replies, replay protection, transport sessions, timers, and metrics. Device
//! orchestration, TUN/routing integration, configuration parsing, and platform
//! runtimes remain in `vpnz`.

pub const keys = @import("keys.zig");
pub const message = @import("message.zig");
pub const noise = @import("noise.zig");
pub const cookie = @import("cookie.zig");
pub const replay = @import("replay.zig");
pub const session = @import("session.zig");
pub const timers = @import("timers.zig");
pub const metrics = @import("metrics.zig");

test {
    _ = keys;
    _ = message;
    _ = noise;
    _ = cookie;
    _ = replay;
    _ = session;
    _ = timers;
    _ = metrics;
}
