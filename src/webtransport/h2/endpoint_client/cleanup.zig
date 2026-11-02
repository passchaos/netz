//! One allocation-free removal request per fixed Session slot.
//! Published Session generations prevent a late dropped result from removing
//! another Session that reused the same slot.
const std = @import("std");
const Handle = @import("job.zig").Handle;

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

pub fn request(state: anytype, handle: Handle) void {
    if (handle.index >= state.slots.len) return;
    if (state.slots[handle.index].cleanup.request(handle.generation)) {
        state.cleanup_pending.store(true, .release);
        state.wake.set(state.io);
    }
}

pub fn pending(state: anytype) bool {
    return state.cleanup_pending.load(.acquire);
}

pub fn drain(state: anytype, comptime remove: anytype) void {
    if (!state.cleanup_pending.swap(false, .acq_rel)) return;
    for (state.slots, 0..) |*slot, index| {
        const generation = slot.cleanup.take();
        if (generation != 0) _ = remove(state, Handle{ .index = @intCast(index), .generation = generation });
    }
}
