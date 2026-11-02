//! Heap-owned health publication wake state for a movable ordinary Channel.
//! The single waiting owner snapshots before scanning endpoint states, then
//! waits only if no publisher changed the revision since that snapshot.
const std = @import("std");
const Sync = @This();

generation: std.atomic.Value(u64) = .init(0),
changed: std.Io.Event = .unset,

pub fn snapshot(self: *const Sync) u64 {
    return self.generation.load(.acquire);
}

/// Endpoint state must be published before this call.
pub fn notify(self: *Sync, io: std.Io) void {
    _ = self.generation.fetchAdd(1, .acq_rel);
    self.changed.set(io);
}

/// The caller owns state scans and absolute-deadline checks. Timeout returns
/// to that scan so a racing status publication is observed before expiring.
pub fn wait(self: *Sync, io: std.Io, observed: u64, deadline: ?std.Io.Clock.Timestamp) std.Io.Event.WaitTimeoutError!void {
    if (self.snapshot() != observed) return;
    self.changed.reset();
    if (self.snapshot() != observed) return;
    if (deadline) |until| {
        self.changed.waitTimeout(io, .{ .deadline = until }) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
    } else {
        try self.changed.wait(io);
    }
}

test {
    _ = @import("sync_tests.zig");
}
