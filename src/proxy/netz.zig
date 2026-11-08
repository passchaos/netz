//! Internal bridge to the public Netz protocol modules.
//!
//! Proxy implementations live inside the Netz package, so they cannot import
//! themselves by package name. This shim exposes only the protocol families
//! they use and avoids importing the package root (which would create an
//! import cycle through `root.zig`).

pub const quic = @import("../quic/mod.zig");
pub const grpc = @import("../grpc/mod.zig");
pub const http2 = @import("../http2/mod.zig");
