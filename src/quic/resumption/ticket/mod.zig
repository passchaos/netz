//! TLS 1.3 session-ticket lifecycle for QUIC resumption.

pub const codec = @import("vail").tls.ticket;
pub const store = @import("store.zig");
pub const handshake = @import("handshake.zig");
pub const keyring = @import("vail").tls.ticket_keyring;

pub const ServerStore = store.Store;
pub const Issued = store.Issued;
pub const Keyring = keyring.Keyring;

test {
    _ = @import("tests.zig");
}
