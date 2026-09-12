//! Shared blocking stream transport primitives.
//!
//! Protocol packages can import this narrow facade when they need bounded
//! TCP/DNS connection establishment, deadline-safe stream I/O, or verified
//! TLS without pulling in Netz's application protocol root.

pub const connect = @import("internal/tcp_connect.zig");
pub const io = @import("internal/stream_io.zig");
pub const socket_options = @import("internal/socket_options.zig");
pub const tls = @import("tls/stream/mod.zig");

test {
    _ = connect;
    _ = io;
    _ = socket_options;
    _ = tls;
}
