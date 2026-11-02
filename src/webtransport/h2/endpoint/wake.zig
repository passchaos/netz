//! Clear a sole endpoint owner's event while acquiring prior publications.
const std = @import("std");

/// As with Event.reset, the owner's preceding wait must have returned. The
/// acquire reads the prior Event.set release so a subsequent cancellation or
/// cleanup predicate check cannot miss the publication whose wake it clears.
pub fn clear(event: *std.Io.Event) void {
    _ = @atomicRmw(std.Io.Event, event, .Xchg, .unset, .acq_rel);
}
