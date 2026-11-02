//! Per-cluster queue admission without allowing one failed cluster to block peers.
const route = @import("../cluster_route.zig");

pub fn choose(state: anytype, runtime: anytype, claimant: anytype, comptime remove: anytype, comptime finish: anytype) ?@TypeOf(state.head.?) {
    var cursor = state.head;
    while (cursor) |job| {
        cursor = job.next;
        if (job.canceled()) {
            remove(state, job);
            finish(state, job, null, error.Canceled);
            continue;
        }
        if (job.deadline) |deadline| if (deadline.durationFromNow(state.io).raw.nanoseconds <= 0) {
            remove(state, job);
            finish(state, job, null, error.Timeout);
            continue;
        };
        const cluster = route.jobCluster(job);
        route.validate(runtime.root, cluster) catch |err| {
            remove(state, job);
            finish(state, job, null, err);
            continue;
        };
        if (!job.wait_for_ready and runtime.clusterState(state, cluster) == .transient_failure) {
            remove(state, job);
            finish(state, job, null, error.ConnectionUnavailable);
            continue;
        }
        const picked = if (job.selected_worker) |worker|
            if (runtime.available(state, worker)) worker else null
        else
            null;
        job.selected_worker = picked orelse (runtime.pick(state, job) catch |err| {
            remove(state, job);
            finish(state, job, null, err);
            continue;
        });
        if (job.selected_worker) |worker| if (worker == claimant) return job;
    }
    return null;
}
