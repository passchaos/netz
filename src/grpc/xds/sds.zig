//! Secret Discovery Service resources for xDS transport security.
pub const secret = @import("sds/secret.zig");
pub const Secret = secret.Secret;
pub const Owned = secret.Owned;
pub const Limits = secret.Limits;
pub const Error = secret.Error;
pub const type_url = secret.type_url;
pub const decode = secret.decode;
test {
    _ = @import("sds/secret_tests.zig");
}
