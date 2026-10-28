//! Physical resource retirement can finish before accounting ownership is free.
const std = @import("std");
const Queue = @import("owned_fifo_admission.zig").Queue;

pub const Retirements = struct {
    pending: std.atomic.Value(usize) = .init(0),

    pub fn retire(self: *Retirements, count: usize) void {
        if (count == 0) return;
        const previous = self.pending.fetchAdd(count, .release);
        std.debug.assert(previous <= std.math.maxInt(usize) - count);
    }

    /// The caller owns the resource accounting mutex, or exclusive teardown.
    pub fn drain(self: *Retirements, connections: *usize) usize {
        if (self.pending.load(.acquire) == 0) return 0;
        const count = self.pending.swap(0, .acq_rel);
        std.debug.assert(connections.* >= count);
        connections.* -= count;
        return count;
    }

    pub fn apply(self: *Retirements, connections: *usize, waiters: *Queue, io: std.Io) void {
        if (self.drain(connections) != 0) waiters.notifyHead(io);
    }

    /// Call only after the physical resource has been released. No caller
    /// storage is retained and an occupied accounting mutex never delays exit.
    pub fn release(self: *Retirements, connections: *usize, waiters: *Queue, mutex: *std.Io.Mutex, io: std.Io, count: usize) void {
        if (count == 0) return;
        self.retire(count);
        if (mutex.tryLock()) {
            self.apply(connections, waiters, io);
            mutex.unlock(io);
        } else {
            waiters.notifyRetry(io);
        }
    }

    /// An idle resource may be reusable/reclaimable while its reservation
    /// stays live. This feedback also cannot wait on the accounting mutex.
    pub fn notify(self: *Retirements, connections: *usize, waiters: *Queue, mutex: *std.Io.Mutex, io: std.Io) void {
        if (mutex.tryLock()) {
            self.apply(connections, waiters, io);
            waiters.notifyHead(io);
            mutex.unlock(io);
        } else {
            waiters.notifyRetry(io);
        }
    }
};

test {
    _ = @import("retired_capacity/tests.zig");
}
