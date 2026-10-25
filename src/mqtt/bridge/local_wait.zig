//! Lazy activation waits apply only to work that has not begun delivery.
const std = @import("std");
const source = @import("local_source.zig");
const broker_mod = @import("../broker.zig");

/// Finish pending local completion, then wait without selecting publications
/// until queued work reaches `threshold` or in-flight protocol work can resume.
/// Queue and shutdown Events share the same race-safe wait.
pub fn waitForPending(self: *source.Client, threshold: usize) source.Error!void {
    if (threshold == 0) return error.InvalidProperty;
    while (true) {
        if (self.shutdown.isSet()) return error.Canceled;
        _ = try self.finishPendingCompletion();
        const observed = self.wake.observe();
        const consumer = if (self.consumer) |*value| value else return error.SourceSessionLost;
        const value = try self.broker.localConsumerStats(consumer);
        if (value.inflight_count != 0 or value.queued_count >= threshold) return;
        const WakeResult = union(enum) {
            ready: std.Io.Cancelable!void,
            shutdown: std.Io.Cancelable!void,
        };
        var buffer: [2]WakeResult = undefined;
        var select: std.Io.Select(WakeResult) = .init(self.io, &buffer);
        defer select.cancelDiscard();
        try select.concurrent(.ready, broker_mod.LocalConsumerWake.waitForChange, .{ self.wake, self.io, observed });
        try select.concurrent(.shutdown, std.Io.Event.wait, .{ self.shutdown, self.io });
        switch (try select.await()) {
            .ready => |result| try result,
            .shutdown => |result| {
                try result;
                return error.Canceled;
            },
        }
    }
}
