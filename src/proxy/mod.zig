//! Reusable application-proxy protocols.

pub const socks5 = @import("socks5.zig");

test {
    _ = socks5;
}
