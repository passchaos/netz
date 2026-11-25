//! Commit an owned trust result only after checking the caller's budget.
const owned = @import("../internal/owned_result_deadline.zig");
pub const checkpoint = owned.checkpoint;
pub const complete = owned.complete;
