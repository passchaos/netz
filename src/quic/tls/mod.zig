//! QUIC transport adapters for the Vail TLS protocol library.

const vail = @import("vail");

pub const auth = vail.tls.auth;
pub const certificate_compression = vail.tls.certificate_compression;
pub const cipher_suite = vail.tls.cipher_suite;
pub const client_auth = vail.tls.client_auth;
pub const key_exchange = vail.tls.key_exchange;
pub const key_schedule = vail.tls.key_schedule;
pub const secret = vail.tls.secret;
pub const transcript = vail.tls.transcript;
pub const trust = vail.x509.trust;
pub const platform = vail.x509.platform;

test {
    _ = @import("handshake_tests.zig");
}
