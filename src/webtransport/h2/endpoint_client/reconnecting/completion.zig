//! One pending failure for the one admitted connection attempt.
//! Its timestamp is written before release publication. State's mutex keeps
//! another attempt from starting until the pending completion is consumed.
const std = @import("std");

pub const Failure = struct {
    ready: std.atomic.Value(bool) = .init(false),
    at_ns: i96 = 0,

    pub fn publish(self: *Failure, io: std.Io) void {
        self.at_ns = std.Io.Clock.awake.now(io).nanoseconds;
        self.ready.store(true, .release);
    }

    /// The owning State mutex must be held; the next attempt cannot start
    /// until its caller applies this completion and releases that mutex.
    pub fn take(self: *Failure) ?i96 {
        if (!self.ready.load(.acquire)) return null;
        const at = self.at_ns;
        self.ready.store(false, .release);
        return at;
    }
};
