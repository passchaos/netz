//! HTTP authority syntax and scheme-based comparison shared by wire versions.
pub const Error = @import("parse.zig").Error;
pub const Parsed = @import("parse.zig").Parsed;
pub const parse = @import("parse.zig").parse;
pub const validateConnect = @import("parse.zig").validateConnect;
pub const equivalent = @import("equivalence.zig").equivalent;
pub const defaultPort = @import("equivalence.zig").defaultPort;

test {
    _ = @import("tests.zig");
    _ = @import("ipv6.zig");
    _ = @import("protocol_tests.zig");
}
