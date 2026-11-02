//! Fixed pending-request cleanup, independent of caller command allocation.
const PendingHandle = @import("job.zig").PendingHandle;

pub fn request(state: anytype, handle: PendingHandle) void {
    if (handle.index >= state.pending.len) return;
    if (state.pending[handle.index].cleanup.request(handle.generation)) {
        state.cleanup_pending.store(true, .release);
        state.wake.set(state.io);
    }
}

pub fn drain(state: anytype, comptime remove: anytype) void {
    if (!state.cleanup_pending.swap(false, .acq_rel)) return;
    for (state.pending, 0..) |*slot, index| {
        const generation = slot.cleanup.take();
        if (generation != 0) _ = remove(state, PendingHandle{ .index = @intCast(index), .generation = generation }, true);
    }
}
