//! TLS stream adapters backed by Vail.

pub const server = @import("server.zig");
pub const client = @import("client.zig");

test {
    _ = server;
    _ = client;
}
