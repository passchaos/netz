//! Circuit rejection remains a policy drop, before wire output or retry.
const call = @import("../../call.zig");
const lrs_stats = @import("lrs_stats.zig");
pub fn rejectIfSaturated(state: anytype, job: anytype) @TypeOf(state.*).Failure!?call.UnaryResponse {
    var saturated = if (state.circuit) |policy| if (policy.saturated()) policy else null else null;
    if (saturated == null) if (state.weighted_target) |*runtime| {
        if (try @import("../cluster_impl.zig").forCluster(runtime.root, @import("../cluster_route.zig").jobCluster(job))) |policy| if (policy.circuit.saturated()) {
            saturated = policy.circuit;
        };
    };
    const policy = saturated orelse return null;
    if (job.canceled()) return error.Canceled;
    policy.recordRejection();
    if (comptime @hasField(@TypeOf(state.*), "lrs_stats")) if (@import("../cluster_route.zig").jobCluster(job)) |key| state.lrs_stats.recordDropped(state.io, lrs_stats.stripCluster(key), "circuit_breaking");
    if (job.stream != null) return error.CallDropped;
    return try call.circuitBreakerResponse(state.allocator);
}
pub fn acquire(state: anytype, job: anytype) @TypeOf(state.*).Failure!bool {
    const child = if (state.weighted_target) |*runtime| (try @import("../cluster_impl.zig").forCluster(runtime.root, @import("../cluster_route.zig").jobCluster(job))) else null;
    const cluster = if (child) |policy| policy.circuit else null;
    if (state.circuit == null and cluster == null) return true;
    job.circuit_permit = @import("../circuit_breaker.zig").acquirePair(state.circuit, cluster) orelse return false;
    return true;
}
