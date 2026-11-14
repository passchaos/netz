//! Request matching shared by typed xDS route configuration and selectors.
pub const regex = @import("regexz");
pub const string = @import("string.zig");
pub const header = @import("header.zig");
pub const domain = @import("domain.zig");
pub const template = @import("template.zig");
test {
    _ = regex;
    _ = template;
    _ = @import("tests.zig");
}
