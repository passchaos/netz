//! Mesh/overlay wire protocols.
//!
//! Shared identity/endpoint types, bounded byte helpers, discovery messages,
//! and DERP relay frames/state machines. Control plane, MagicDNS, ACL,
//! routing, and NAT/path selection policy remain in `meshz`.

pub const wire = @import("wire.zig");
pub const types = @import("types.zig");
pub const disco = @import("disco/mod.zig");
pub const derp = @import("derp/mod.zig");

test {
    _ = wire;
    _ = types;
    _ = disco;
    _ = derp;
}
