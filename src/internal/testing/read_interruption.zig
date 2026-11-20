//! Inject local bounded-read faults before the next operation is scheduled.
const std = @import("std");
pub const Fault = enum { executor, cancellation };

pub const InterruptedIo = struct {
    pub threadlocal var next: ?Fault = null;
    // Worker threads also forward futex waits through this wrapper. The
    // fixture installs one delegate and joins its tasks before replacing it.
    pub var delegate: std.Io = undefined;

    pub fn groupConcurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        if (next == .executor) {
            next = null;
            return error.ConcurrencyUnavailable;
        }
        return delegate.vtable.groupConcurrent(userdata, group, context, alignment, start);
    }

    pub fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        if (next == .cancellation) {
            next = null;
            return error.Canceled;
        }
        return delegate.vtable.futexWait(userdata, ptr, expected, timeout);
    }

    pub fn awaitConcurrent(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        if (next) |fault| {
            next = null;
            return if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
        }
        return delegate.vtable.batchAwaitConcurrent(userdata, batch, timeout);
    }
};
