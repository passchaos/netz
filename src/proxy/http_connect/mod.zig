//! HTTP/1 CONNECT server protocol.

pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");

test {
    _ = protocol;
    _ = server;
}
