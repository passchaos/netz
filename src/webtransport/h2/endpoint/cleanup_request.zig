//! Generation-scoped cleanup marker shared by HTTP/2 endpoint owners.
const std = @import("std");

pub const Request = struct {
    generation: std.atomic.Value(u64) = .init(0),
    pending: std.atomic.Value(u64) = .init(0),

    /// The owner calls publish before returning an accepted result.
    pub fn publish(self: *Request, generation: u64) void {
        std.debug.assert(generation != 0);
        self.generation.store(generation, .release);
    }

    /// Called by the owner before releasing the slot's Session resources.
    pub fn retire(self: *Request) void {
        self.generation.store(0, .release);
    }

    pub fn request(self: *Request, generation: u64) bool {
        if (generation == 0) return false;
        while (true) {
            const observed = self.pending.load(.acquire);
            // Read the live generation after pending. Acquiring a newer
            // request must prevent an old caller from replacing that request.
            if (self.generation.load(.acquire) != generation) return false;
            if (observed == generation) return true;
            if (self.pending.cmpxchgWeak(observed, generation, .acq_rel, .acquire) == null) return true;
        }
    }

    pub fn take(self: *Request) u64 {
        return self.pending.swap(0, .acq_rel);
    }
};
