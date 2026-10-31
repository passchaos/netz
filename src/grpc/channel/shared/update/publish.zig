//! Stage all fallible allocation/task admission, then publish under one State lock.
const std = @import("std");
const State = @import("../state.zig").State;
const Prepared = @import("prepare.zig").Prepared;
const Settings = @import("../worker_settings.zig").Settings;
const Outlier = @import("../../outlier_detection.zig").Endpoint;

const Change = struct {
    worker: *State.Worker,
    settings: *Settings,
    outliers: []Outlier,
};

fn contains(sources: []const *State.Source, source: *State.Source) bool {
    for (sources) |candidate| if (candidate == source) return true;
    return false;
}

pub fn publish(state: *State, prepared: *Prepared, deadline: ?std.Io.Clock.Timestamp) State.Failure!void {
    const allocator = state.allocator;
    const weights = try allocator.alloc(u32, prepared.sources.len);
    defer allocator.free(weights);
    const added = try allocator.alloc(bool, prepared.sources.len);
    defer allocator.free(added);
    for (prepared.sources, weights, added, 0..) |*candidate, *weight, *is_added, index| {
        weight.* = candidate.*.ring_hash_weight;
        const existing = for (state.sources) |old| {
            if (!contains(prepared.sources[0..index], old) and
                @import("../../ring_hash.zig").sameEndpointIdentity(old.endpoint, candidate.*.endpoint)) break old;
        } else null;
        is_added.* = existing == null;
        if (existing) |source| {
            source.retain();
            candidate.*.release();
            candidate.* = source;
        }
    }
    const outlier_count = if (prepared.weighted) |*runtime| runtime.outlierCount() else 0;
    var changes: std.ArrayList(Change) = .empty;
    defer changes.deinit(allocator);
    var changes_transferred = false;
    defer if (!changes_transferred) {
        for (changes.items) |change| {
            change.settings.destroy();
            allocator.free(change.outliers);
        }
    };
    const same_config = prepared.config == state.config.load(.acquire);
    const same_policy = prepared.policy == state.policy;
    var same_layout = prepared.sources.len == state.sources.len;
    if (same_layout) for (prepared.sources, state.sources) |candidate, current| {
        if (candidate != current) same_layout = false;
    };
    var weights_changed = false;
    for (prepared.sources, weights) |source, weight| weights_changed = weights_changed or source.ring_hash_weight != weight;
    for (state.workers.items) |worker| {
        if (worker.retired or !contains(prepared.sources, worker.source)) continue;
        try changes.ensureUnusedCapacity(allocator, 1);
        const settings = try Settings.create(allocator, prepared.health_service, prepared.orcaFor(worker.source));
        errdefer settings.destroy();
        const outliers = try allocator.alloc(Outlier, outlier_count);
        for (outliers) |*outlier| outlier.* = .{};
        if (same_config and outliers.len == worker.weighted_outliers.len) @memcpy(outliers, worker.weighted_outliers);
        changes.appendAssumeCapacity(.{ .worker = worker, .settings = settings, .outliers = outliers });
    }
    var workers: std.ArrayList(*State.Worker) = .empty;
    defer workers.deinit(allocator);
    var started: usize = 0;
    var committed = false;
    defer if (!committed) {
        for (workers.items, 0..) |worker, index| {
            if (index < started) {
                worker.retired = true;
                worker.activation.set(state.io);
            } else State.Membership.destroyUnstarted(worker);
        }
        for (prepared.sources, added) |source, is_added| if (is_added) {
            source.retired = true;
            source.activation.set(state.io);
            source.wake.set(state.io);
        };
    };
    for (prepared.sources, added, 0..) |source, is_added, index| {
        if (!is_added or source.resolver != null) continue;
        try workers.ensureUnusedCapacity(allocator, 1);
        source.current = try allocator.alloc(*State.Worker, 1);
        const worker = try State.Membership.prepare(state, source, index, null, prepared.config, outlier_count, prepared.health_service, prepared.orcaFor(source));
        source.current[0] = worker;
        workers.appendAssumeCapacity(worker);
    }
    try state.workers.ensureUnusedCapacity(allocator, workers.items.len);
    try state.io.checkCancel();
    if (deadline) |until| _ = try @import("../../../../internal/deadline.zig").usableAwake(state.io, until);
    for (workers.items) |worker| {
        try state.group.concurrent(state.io, State.Worker.run, .{worker});
        started += 1;
    }
    for (prepared.sources, added) |source, is_added| {
        if (!is_added) continue;
        if (source.resolver) |resolver| {
            resolver.notifyPublication(&source.wake);
            source.retain();
            state.group.concurrent(state.io, State.Resolution.run, .{ state, source }) catch |err| {
                source.release();
                return err;
            };
        }
    }
    try state.io.checkCancel();
    if (deadline) |until| _ = try @import("../../../../internal/deadline.zig").usableAwake(state.io, until);
    // No fallible operation follows this boundary. Task owners cannot proceed
    // until activation is signaled after the complete snapshot is installed.
    const previous_sources = state.sources;
    for (previous_sources) |source| if (!contains(prepared.sources, source)) {
        source.retired = true;
        source.wake.set(state.io);
    };
    for (state.workers.items) |worker| {
        if (!worker.retired and !contains(prepared.sources, worker.source)) State.Membership.retireLocked(state, worker);
    }
    state.sources = prepared.sources;
    prepared.sources = previous_sources;
    const previous_endpoints = state.canonical_endpoints;
    state.canonical_endpoints = prepared.endpoints;
    prepared.endpoints = previous_endpoints;
    for (changes.items) |change| {
        if (change.worker.pending_settings) |settings| settings.destroy();
        change.worker.pending_settings = null;
        if (change.worker.settings.equivalent(change.settings)) change.settings.destroy() else {
            change.worker.pending_settings = change.settings;
            if (change.settings.health_service != null) {
                change.worker.published = .connecting;
                change.worker.capacity = 0;
                change.worker.tracker.setState(.connecting);
            }
        }
        allocator.free(change.worker.weighted_outliers);
        change.worker.weighted_outliers = change.outliers;
        if (!same_config) {
            change.worker.outlier = .{};
            change.worker.wrr_weight.disconnected();
        }
    }
    changes_transferred = true;
    const previous_health = state.health_service;
    state.health_service = prepared.health_service;
    prepared.health_service = previous_health;
    state.options.health_service = state.health_service;
    state.options.health_metadata.service = state.health_service orelse "";
    const previous_orca = state.orca_oob;
    state.orca_oob = prepared.orca_oob;
    prepared.orca_oob = previous_orca;
    if (same_config and same_policy and state.weighted_target != null and prepared.weighted != null) {
        prepared.weighted.?.deinit();
        prepared.weighted = null;
        if (!same_layout or weights_changed) state.weighted_target.?.invalidatePickers();
    } else {
        const previous_weighted = state.weighted_target;
        state.weighted_target = prepared.weighted;
        prepared.weighted = previous_weighted;
    }
    state.policy = prepared.policy;
    state.resolver_policy = prepared.resolver_policy;
    state.shuffle_addresses = prepared.shuffle;
    state.wrr_config = if (state.policy == .weighted_round_robin) prepared.balancing.weighted_round_robin else null;
    state.least_request_config = prepared.balancing.least_request;
    state.ring_hash_config = prepared.balancing.ring_hash;
    state.outlier_config = if (state.weighted_target == null) prepared.balancing.outlier_detection else null;
    if (!same_config or !same_policy) state.outlier_next_evaluation_ns = if (state.outlier_config) |config| if (config.countingEnabled()) std.Io.Clock.awake.now(state.io).nanoseconds +| config.interval.nanoseconds else null else null;
    state.wrr_scheduler.deinit(allocator);
    state.wrr_scheduler = .{};
    state.ring_hash_ring.deinit(allocator);
    state.ring_hash_dirty = true;
    var queued = state.head;
    if (!same_config or !same_policy) while (queued) |job| : (queued = job.next) {
        job.routing_hash = null;
    };
    if (!same_policy or state.policy != .pick_first or
        (state.selected != null and state.selected.?.retired)) state.selected = null;
    state.weighted_target_selected = null;
    state.least_request_selected = null;
    if (!same_config or !same_policy or !same_layout) {
        state.next_pick = 0;
        state.wrr_sequence = 0;
    }
    for (state.sources, weights, 0..) |source, weight, index| {
        source.ring_hash_weight = weight;
        for (source.current) |worker| worker.source_index = index;
        if (source.pending) |pending| {
            for (pending) |worker| worker.source_index = index;
        }
    }
    for (workers.items) |worker| {
        worker.eligible = true;
        state.workers.appendAssumeCapacity(worker);
        worker.activation.set(state.io);
    }
    for (state.sources) |source| source.activation.set(state.io);
    state.demand = state.demand or state.orca_oob != null or
        (if (state.weighted_target) |*runtime| runtime.hasOob() else false);
    state.publishConfigLocked(prepared.config);
    prepared.config = null;
    state.config_revision +%= 1;
    state.resolution_changed.set(state.io);
    state.recomputeLocked();
    state.wakeAllLocked();
    committed = true;
}
