//! VMess AEAD and legacy wire codecs.

pub const crypto = @import("crypto.zig");
pub const aead = @import("aead.zig");
pub const body = @import("body.zig");
pub const legacy_body = @import("legacy_body.zig");
pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");
pub const quic_server = @import("quic_server.zig");
pub const h2_server = @import("h2_server.zig");
pub const grpc_server = @import("grpc_server.zig");

test {
    _ = crypto;
    _ = aead;
    _ = body;
    _ = legacy_body;
    _ = protocol;
    _ = server;
    _ = quic_server;
    _ = h2_server;
    _ = grpc_server;
}
