//! Circuit rejection remains a policy drop, before wire output or retry.
const call = @import("../../call.zig");
pub fn rejectIfSaturated(state: anytype, job: anytype) @TypeOf(state.*).Failure!?call.UnaryResponse {
    const policy = state.circuit orelse return null;
    if (!policy.saturated()) return null;
    if (job.canceled()) return error.Canceled;
    policy.recordRejection();
    if (job.stream != null) return error.CallDropped;
    return try call.circuitBreakerResponse(state.allocator);
}
