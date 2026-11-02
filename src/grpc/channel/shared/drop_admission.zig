//! Evaluate each queued physical RPC once per changed drop-policy revision.
const call = @import("../../call.zig");
pub fn evaluate(state: anytype, job: anytype) @TypeOf(state.*).Failure!?call.UnaryResponse {
    if (job.canceled()) return error.Canceled;
    if (job.drop_revision != state.drop_revision) {
        job.drop_revision = state.drop_revision;
        if (state.drop.choose(state.io, &state.drop_counters)) |category| {
            if (job.stream != null) return error.CallDropped;
            return try call.policyDropResponse(state.allocator, category);
        }
    }
    if (comptime @hasField(@TypeOf(state.*), "weighted_target")) {
        const runtime = if (state.weighted_target) |*value| value else return null;
        const policy = (@import("../cluster_impl.zig").forCluster(runtime.root, @import("../cluster_route.zig").jobCluster(job)) catch return null) orelse return null;
        if (job.cluster_drop_revision == policy.revision) return null;
        job.cluster_drop_revision = policy.revision;
        const category = policy.drops.choose(state.io, &policy.counters) orelse return null;
        if (job.stream != null) return error.CallDropped;
        return try call.policyDropResponse(state.allocator, category);
    }
    return null;
}
