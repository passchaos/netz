//! TLS stream transports shared by application protocols.

pub const stream = @import("stream/mod.zig");
pub const alpn_server = @import("alpn_server.zig");
pub const server_identity_file = @import("server_identity_file.zig");
pub const client_ca_file = @import("client_ca_file.zig");
pub const client_ca_dir = @import("client_ca_dir.zig");
pub const client_crl_file = @import("client_crl_file.zig");
pub const cipher_suites = @import("cipher_suites.zig");
pub const encrypted_private_key = @import("encrypted_private_key.zig");
pub const testing = @import("testing.zig");
pub const trust = @import("vail").x509.trust;
pub const RootSource = @import("../trust.zig").RootSource;
pub const bundled = @import("../trust.zig");
pub const ClientCertificateTrustContext = @import("vail").tls.auth.TrustContext;
pub const trust_cache = @import("trust_cache.zig");

test {
    _ = @import("trust_completion_admission_tests.zig");
    _ = @import("trust_loading_tests.zig");
    _ = stream;
    _ = server_identity_file;
    _ = client_ca_file;
    _ = client_ca_dir;
    _ = client_crl_file;
    _ = cipher_suites;
    _ = encrypted_private_key;
    _ = testing;
    _ = trust;
    _ = RootSource;
    _ = bundled;
    _ = trust_cache;
}
