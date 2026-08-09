//! QUIC transport adapters for the Vail TLS protocol library.

const vail = @import("vail");

pub const auth = vail.tls.auth;
pub const client_auth = vail.tls.client_auth;
pub const key_schedule = vail.tls.key_schedule;
pub const trust = vail.x509.trust;

test {
    _ = @import("handshake_tests.zig");
}
