//! gRPC-Web CORS policy. Origins are permission checks, not authentication.
pub const Policy = @import("policy.zig").Policy;
pub const Decision = @import("policy.zig").Decision;
pub const Error = @import("policy.zig").Error;
pub const evaluate = @import("policy.zig").evaluate;
pub const Headers = @import("headers.zig").Headers;

test {
    _ = @import("tests.zig");
}
