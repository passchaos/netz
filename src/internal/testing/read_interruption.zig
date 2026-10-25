//! Inject local bounded-read faults before the next operation is scheduled.
const std = @import("std");
pub const Fault = enum { executor, cancellation };

pub const InterruptedIo = struct {
    pub threadlocal var next: ?Fault = null;
    pub threadlocal var delegate: std.Io = undefined;

    pub fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        if (next) |fault| {
            next = null;
            return if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
        }
        return delegate.vtable.batchAwaitConcurrent(userdata, batch, timeout);
    }
};
