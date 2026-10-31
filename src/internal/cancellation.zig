//! Preserve a one-shot cancellation when committed progress must be returned.
const std = @import("std");

pub fn preserveIgnored(io: std.Io, err: anyerror) void {
    if (err == error.Canceled) io.recancel();
}
