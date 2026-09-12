//! TLS stream transports shared by application protocols.

pub const stream = @import("stream/mod.zig");
pub const testing = @import("testing.zig");
pub const trust = @import("vail").x509.trust;

test {
    _ = stream;
    _ = testing;
    _ = trust;
}
