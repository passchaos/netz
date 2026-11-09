//! IP-layer VPN protocol cores.
//!
//! Reusable wire codecs and state machines live here. Product policy (TUN,
//! routing, DNS, kill-switch, configuration, credentials, and platform
//! runtimes) stays in `vpnz`.

pub const wireguard = @import("wireguard/mod.zig");

test {
    _ = wireguard;
}
