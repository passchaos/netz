//! HTTP authority syntax and scheme-based comparison shared by wire versions.
pub const Error = @import("parse.zig").Error;
pub const Parsed = @import("parse.zig").Parsed;
pub const parse = @import("parse.zig").parse;
pub const validateConnect = @import("parse.zig").validateConnect;
pub const equivalent = @import("equivalence.zig").equivalent;
pub const defaultPort = @import("equivalence.zig").defaultPort;
pub const hostEquivalent = @import("host.zig").equivalent;
pub const canonicalHostAlloc = @import("host.zig").canonicalAlloc;
pub const canonicalHostInto = @import("host.zig").canonicalInto;
pub const hostHash = @import("host.zig").hash;

test {
    _ = @import("tests.zig");
    _ = @import("ipv6.zig");
    _ = @import("protocol_tests.zig");
    _ = @import("host.zig");
}
