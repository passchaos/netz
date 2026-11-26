//! Shared handler-stack command lifetime and owner publication.
const borrowed = @import("../../../internal/borrowed_command.zig");
pub const submit = borrowed.submit;
pub const drain = borrowed.drain;
