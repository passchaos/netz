//! TLS 1.3 session-ticket lifecycle for QUIC resumption.

pub const codec = @import("codec.zig");
pub const store = @import("store.zig");
pub const handshake = @import("handshake.zig");
pub const keyring = @import("keyring.zig");

pub const ServerStore = store.Store;
pub const Issued = store.Issued;
pub const Keyring = keyring.Keyring;

test {
    _ = @import("tests.zig");
}
