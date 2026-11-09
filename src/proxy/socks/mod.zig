//! SOCKS5 server protocol.

pub const codec = @import("codec.zig");
pub const auth = @import("auth.zig");
pub const relay = @import("relay.zig");
pub const udp_relay = @import("udp_relay.zig");
pub const server = @import("server.zig");

test {
    _ = codec;
    _ = auth;
    _ = relay;
    _ = udp_relay;
    _ = server;
}
