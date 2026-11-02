//! Request matching shared by typed xDS route configuration and selectors.
pub const regex = @import("regex.zig");
pub const string = @import("string.zig");
pub const header = @import("header.zig");
pub const domain = @import("domain.zig");
test {
    _ = regex;
    _ = @import("tests.zig");
}
