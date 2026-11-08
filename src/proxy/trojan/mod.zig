//! Trojan TLS + password proxy protocol.

pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");

test {
    _ = protocol;
    _ = server;
}
