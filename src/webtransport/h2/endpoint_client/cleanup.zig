//! One allocation-free removal request per fixed Session slot.
//! Published Session generations prevent a late dropped result from removing
//! another Session that reused the same slot.
const Handle = @import("job.zig").Handle;

pub const Request = @import("../endpoint/cleanup_request.zig").Request;

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
