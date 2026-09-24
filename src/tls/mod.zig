//! TLS stream transports shared by application protocols.

pub const stream = @import("stream/mod.zig");
pub const server_identity_file = @import("server_identity_file.zig");
pub const client_ca_file = @import("client_ca_file.zig");
pub const client_crl_file = @import("client_crl_file.zig");
pub const testing = @import("testing.zig");
pub const trust = @import("vail").x509.trust;
pub const trust_cache = @import("trust_cache.zig");

test {
    _ = stream;
    _ = server_identity_file;
    _ = client_ca_file;
    _ = client_crl_file;
    _ = testing;
    _ = trust;
    _ = trust_cache;
}
