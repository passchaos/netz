//! Evaluate each queued physical RPC once per changed drop-policy revision.
const call = @import("../../call.zig");
pub fn evaluate(state: anytype, job: anytype) @TypeOf(state.*).Failure!?call.UnaryResponse {
    if (job.canceled()) return error.Canceled;
    if (job.drop_revision == state.drop_revision) return null;
    job.drop_revision = state.drop_revision;
    const category = state.drop.choose(state.io, &state.drop_counters) orelse return null;
    if (job.stream != null) return error.CallDropped;
    return try call.policyDropResponse(state.allocator, category);
}
