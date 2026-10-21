//! Reusable application-proxy protocols.

pub const socks5 = @import("socks5.zig");

test {
    _ = socks5;
    _ = @import("socks5/udp_association_tests.zig");
}
