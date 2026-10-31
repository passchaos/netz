const std = @import("std");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const channel = @import("../../channel.zig");
const call = @import("../../call.zig");
const health = @import("../../health.zig");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const retry = @import("../../call/retry.zig");
const keepalive = @import("keepalive.zig");
const hedging_stats = @import("hedging/stats.zig");
const weighted_round_robin = @import("../weighted_round_robin.zig");
const least_request = @import("../least_request.zig");
const ring_hash = @import("../ring_hash.zig");
const outlier_detection = @import("../outlier_detection.zig");
const orca = @import("../../orca.zig");
const orca_oob = @import("../../orca/oob.zig");
const orca_config = @import("orca/config.zig");
pub const orca_tracker = @import("orca/tracker.zig");
const Job = @import("job.zig").Job;
pub const Options = @import("options.zig").Options;
pub const Error = health.WatchError || orca_oob.Error || channel.Error || service_config.Error || error{ SharedChannelClosed, SharedQueueFull, InvalidSharedOptions, StreamReceiveBufferExceeded };

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    refs: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    group: std.Io.Group = .init,
    workers: std.ArrayList(*Worker) = .empty,
    sources: []Source = &.{},
    shuffle_addresses: bool = false,
    resolution_changed: std.Io.Event = .unset,
    config: ?service_config.ServiceConfig = null,
    health_service: ?[]u8 = null,
    orca_oob: ?orca_config.Config = null,
    tracker: *connectivity.Tracker,
    policy: channel.SelectionPolicy,
    head: ?*Job = null,
    tail: ?*Job = null,
    queued: usize = 0,
    abandoned_pending: std.atomic.Value(bool) = .init(false),
    demand: bool = false,
    closed: bool = false,
    selected: ?*Worker = null,
    next_pick: usize = 0,
    keepalive_counters: keepalive.Counters = .{},
    hedging_counters: hedging_stats.Counters = .{},
    /// Zero means disabled. Config validation keeps enabled intervals within
    /// i64 nanoseconds so endpoint workers can observe throttling lock-free.
    keepalive_interval_ns: std.atomic.Value(i64) = .init(0),
    wrr_config: ?service_config.WeightedRoundRobinConfig = null,
    wrr_sequence: u32 = 0,
    wrr_scheduler: weighted_round_robin.Scheduler = .{},
    least_request_config: least_request.Config = .{},
    least_request_selected: ?*Worker = null,
    ring_hash_config: ring_hash.Config = .{},
    ring_hash_ring: ring_hash.Ring = .{},
    ring_hash_dirty: bool = true,
    outlier_config: ?service_config.OutlierDetectionConfig = null,
    outlier_next_evaluation_ns: ?i96 = null,

    pub const Worker = @import("worker.zig").Worker(State);
    pub const Source = @import("source.zig").Source(Worker);
    pub const Membership = @import("membership.zig").Membership(State);
    pub const Resolution = @import("resolution.zig").Resolution(State);
    pub const Failure = @import("state.zig").Error;
    pub const HedgingStats = hedging_stats.Snapshot;
    pub const StreamCall = @import("stream/call.zig").Call(State);
    pub const OrcaTracker = orca_tracker.Tracker;

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn keepAliveOptions(self: *const State) ?keepalive.Options {
        var options = self.options.keepalive orelse return null;
        const interval = self.keepalive_interval_ns.load(.acquire);
        if (interval == 0) return null;
        options.interval = .fromNanoseconds(interval);
        return options;
    }

    pub fn keepAliveInterval(self: *const State) ?std.Io.Duration {
        const interval = self.keepalive_interval_ns.load(.acquire);
        return if (interval == 0) null else .fromNanoseconds(interval);
    }

    pub fn applyKeepAliveThrottle(
        self: *State,
        transport_interval: std.Io.Duration,
    ) bool {
        if (self.options.keepalive == null) return false;
        const proposed: i64 = @intCast(keepalive.throttledInterval(
            transport_interval,
        ).nanoseconds);
        var current = self.keepalive_interval_ns.load(.acquire);
        while (current != 0) {
            if (proposed <= current) return false;
            if (self.keepalive_interval_ns.cmpxchgWeak(
                current,
                proposed,
                .acq_rel,
                .acquire,
            )) |observed| {
                current = observed;
                continue;
            }
            _ = self.keepalive_counters.throttles.fetchAdd(1, .release);
            self.lock();
            self.wakeAllLocked();
            self.unlock();
            return true;
        }
        return false;
    }

    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.head == null);
        std.debug.assert(self.workers.items.len == 0);
        self.workers.deinit(self.allocator);
        self.wrr_scheduler.deinit(self.allocator);
        self.ring_hash_ring.deinit(self.allocator);
        for (self.sources) |*source| source.deinit(self.allocator);
        self.allocator.free(self.sources);
        if (self.config) |*config| config.deinit();
        if (self.health_service) |name| self.allocator.free(name);
        if (self.orca_oob) |*config| config.deinit();
        self.tracker.release();
        self.allocator.destroy(self);
    }

    pub fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
        self.pruneAbandonedLocked();
    }
    pub fn unlock(self: *State) void {
        // A departure can race the owner's last notification. Check once
        // under ownership and again after unlock; a new owner inherits work.
        while (true) {
            self.pruneAbandonedLocked();
            self.mutex.unlock(self.io);
            if (!self.abandoned_pending.load(.acquire) or !self.mutex.tryLock()) return;
        }
    }
    fn pruneAbandonedLocked(self: *State) void {
        if (!self.abandoned_pending.swap(false, .acq_rel)) return;
        var current = self.head;
        while (current) |job| {
            current = job.next;
            if (job.canceled()) {
                self.removeQueuedLocked(job);
                self.finishLocked(job, null, error.Canceled);
            }
        }
        self.wakeAllLocked();
    }
    pub fn lockBefore(self: *State, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline != null) {
            try timed_mutex.lock(&self.mutex, self.io, deadline);
        } else {
            try self.mutex.lock(self.io);
        }
        self.pruneAbandonedLocked();
    }

    pub fn endpointCountLocked(self: *State) usize {
        if (self.closed) return 0;
        var count: usize = 0;
        for (self.sources) |*source| count += source.latest().len;
        return count;
    }
    pub fn selectionPolicy(self: *const State) channel.SelectionPolicy {
        return self.policy;
    }
    pub fn endpointCount(self: *State) usize {
        self.lock();
        defer self.unlock();
        return self.endpointCountLocked();
    }
    pub fn endpointCountWithDeadline(self: *State, deadline: std.Io.Clock.Timestamp) Error!usize {
        try self.lockBefore(deadline);
        defer self.unlock();
        return self.endpointCountLocked();
    }
    pub fn watchEndpoint(self: *State, index: usize) ?connectivity.Watch {
        self.lock();
        defer self.unlock();
        const tracker = self.endpointTrackerLocked(index) orelse return null;
        return .init(tracker);
    }
    pub fn watchEndpointWithDeadline(self: *State, index: usize, deadline: std.Io.Clock.Timestamp) Error!?connectivity.Watch {
        try self.lockBefore(deadline);
        defer self.unlock();
        const tracker = self.endpointTrackerLocked(index) orelse return null;
        return try .initWithDeadline(tracker, deadline);
    }
    pub fn watchEndpointOrca(self: *State, index: usize) ?orca_tracker.Watch {
        self.lock();
        defer self.unlock();
        if (self.closed or self.orca_oob == null) return null;
        const tracker = self.endpointOrcaTrackerLocked(index) orelse return null;
        return .init(tracker);
    }
    pub fn watchEndpointOrcaWithDeadline(
        self: *State,
        index: usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?orca_tracker.Watch {
        try self.lockBefore(deadline);
        defer self.unlock();
        if (self.closed or self.orca_oob == null) return null;
        const tracker = self.endpointOrcaTrackerLocked(index) orelse return null;
        tracker.retain();
        return .{ .tracker = tracker };
    }
    fn endpointTrackerLocked(self: *State, index: usize) ?*connectivity.Tracker {
        if (self.closed) return null;
        var ordinal = index;
        for (self.sources) |*source| {
            const members = source.latest();
            if (ordinal < members.len) return members[ordinal].tracker;
            ordinal -= members.len;
        }
        return null;
    }
    fn endpointOrcaTrackerLocked(
        self: *State,
        index: usize,
    ) ?*orca_tracker.Tracker {
        var ordinal = index;
        for (self.sources) |*source| {
            const members = source.latest();
            if (ordinal < members.len) return members[ordinal].orca_tracker;
            ordinal -= members.len;
        }
        return null;
    }
    pub fn requestNameResolution(self: *State) Error!void {
        return Resolution.request(self);
    }
    pub fn refreshNameResolution(self: *State, deadline: std.Io.Clock.Timestamp) Error!usize {
        return Resolution.refresh(self, deadline);
    }
    pub fn wakeAllLocked(self: *State) void {
        for (self.workers.items) |worker| worker.wake.set(self.io);
        for (self.sources) |*source| source.wake.set(self.io);
    }
    pub fn isClosed(self: *State) bool {
        self.lock();
        defer self.unlock();
        return self.closed;
    }
    pub fn close(self: *State) void {
        self.lock();
        defer self.unlock();
        self.closed = true;
        while (self.head) |job| {
            self.removeQueuedLocked(job);
            self.finishLocked(job, null, error.SharedChannelClosed);
        }
        self.tracker.setState(.shutdown);
        for (self.workers.items) |worker| worker.tracker.setState(.shutdown);
        self.resolution_changed.set(self.io);
        self.wakeAllLocked();
    }
    /// Resolver callbacks borrow target/custom context only until the owning
    /// channel is destroyed, even when Sender references retain this state.
    /// Call after the endpoint/manager group has been joined.
    pub fn stopResolution(self: *State) void {
        for (self.sources) |*source| {
            self.lock();
            const resolver = source.resolver;
            source.resolver = null;
            self.unlock();
            if (resolver) |value| value.deinit();
        }
    }
    fn finishLocked(self: *State, job: *Job, result: ?call.UnaryResponse, err: ?anyerror) void {
        job.result = result;
        job.err = if (self.closed and err != null) error.SharedChannelClosed else err;
        if (job.stream) |stream| if (job.err) |failure| stream.retireLocked(failure);
        if (job.completion.cmpxchgStrong(.waiting, .completed, .release, .acquire) == null) {
            // Retain list/worker ownership through notification even when
            // the caller immediately takes its result and drops its ref.
            job.done.set(self.io);
        } else {
            if (job.result) |*owned| owned.deinit();
            job.result = null;
        }
        job.release();
    }
    pub fn finish(self: *State, job: *Job, result: ?call.UnaryResponse, err: ?anyerror) void {
        self.lock();
        defer self.unlock();
        self.finishLocked(job, result, err);
        self.wakeAllLocked();
    }
    pub fn finishAttempt(
        self: *State,
        worker: *Worker,
        job: *Job,
        result: ?call.UnaryResponse,
        err: ?anyerror,
    ) void {
        self.lock();
        defer self.unlock();
        self.finishOutstandingLocked(worker);
        self.observeOutlierLocked(worker, if (result) |response|
            response.status == .ok
        else
            err == null);
        self.finishLocked(job, result, err);
        self.wakeAllLocked();
    }
    pub fn finishOutstandingLocked(self: *State, worker: anytype) void {
        if (self.policy != .least_request) return;
        std.debug.assert(worker.outstanding_requests != 0);
        worker.outstanding_requests -= 1;
        self.wakeAllLocked();
    }
    pub fn observeOutlierLocked(
        self: *State,
        worker: anytype,
        success: bool,
    ) void {
        if (self.outlier_config == null) return;
        if (comptime @hasField(@TypeOf(worker.*), "outlier")) {
            worker.outlier.record(success);
        }
    }
    fn removeQueuedLocked(self: *State, job: *Job) void {
        var previous: ?*Job = null;
        var cursor = self.head;
        while (cursor) |item| : (cursor = item.next) {
            if (item == job) {
                if (previous) |before| before.next = item.next else self.head = item.next;
                if (self.tail == item) self.tail = previous;
                self.queued -= 1;
                return;
            }
            previous = item;
        }
        unreachable;
    }
    pub fn aggregateLocked(self: *State) connectivity.State {
        self.evaluateOutliersLocked();
        if (self.closed) return .shutdown;
        if (!self.demand) return .idle;
        var connecting = false;
        for (self.workers.items) |worker| {
            if (worker.retired) continue;
            if (worker.eligible and worker.published == .ready) return .ready;
            if (worker.published == .connecting or worker.published == .idle) connecting = true;
        }
        for (self.sources) |source| if (source.resolver != null and source.generation == 0) {
            connecting = true;
        };
        return if (connecting) .connecting else .transient_failure;
    }
    pub fn publish(self: *State, worker: *Worker, state: connectivity.State, capacity: usize) void {
        self.lock();
        defer self.unlock();
        self.evaluateOutliersLocked();
        const effective_state: connectivity.State = if (worker.outlier.isEjected())
            .transient_failure
        else
            state;
        const effective_capacity = if (worker.outlier.isEjected()) 0 else capacity;
        const changed = worker.published != effective_state or
            worker.capacity != effective_capacity;
        worker.published = effective_state;
        worker.capacity = effective_capacity;
        worker.tracker.setState(if (self.closed or worker.retired) .shutdown else effective_state);
        Membership.promoteLocked(self, worker.source_index);
        self.recomputeLocked();
        if (changed) self.wakeAllLocked();
    }
    pub fn updateWrr(
        self: *State,
        worker: *Worker,
        report: orca.LoadReport,
        oob: bool,
    ) void {
        self.lock();
        defer self.unlock();
        const config = self.wrr_config orelse return;
        if (config.enable_oob_load_report != oob) return;
        worker.wrr_weight.update(
            report,
            std.Io.Clock.awake.now(self.io).nanoseconds,
            config,
        );
    }
    pub fn disconnectWrr(self: *State, worker: *Worker) void {
        self.lock();
        defer self.unlock();
        worker.wrr_weight.disconnected();
        self.wrr_scheduler.next_update_ns = 0;
    }
    pub fn recomputeLocked(self: *State) void {
        const aggregate = self.aggregateLocked();
        self.tracker.setState(aggregate);
        if (aggregate == .transient_failure) {
            var cursor = self.head;
            while (cursor) |job| {
                const next = job.next;
                if (!job.wait_for_ready) {
                    self.removeQueuedLocked(job);
                    self.finishLocked(job, null, error.ConnectionUnavailable);
                }
                cursor = next;
            }
        }
    }
    pub fn needsConnection(self: *State, worker: *Worker) bool {
        self.lock();
        defer self.unlock();
        self.evaluateOutliersLocked();
        worker.wake.reset();
        return self.demand and !worker.retired;
    }
    pub fn shouldStop(self: *State, worker: *Worker, drained: bool) bool {
        self.lock();
        defer self.unlock();
        return self.closed or (worker.retired and drained);
    }
    pub fn isRetired(self: *State, worker: *Worker) bool {
        self.lock();
        defer self.unlock();
        return worker.retired;
    }
    pub fn connectionFailed(self: *State, worker: *Worker) void {
        self.lock();
        defer self.unlock();
        if (self.closed or worker.retired) return;
        const source = &self.sources[worker.source_index];
        if (source.resolver != null) {
            source.refresh_requested = true;
            source.wake.set(self.io);
        }
    }
    pub fn workerStopped(self: *State, worker: *Worker) void {
        self.lock();
        defer self.unlock();
        for (self.workers.items, 0..) |member, index| if (member == worker) {
            _ = self.workers.swapRemove(index);
            break;
        };
        worker.tracker.setState(.shutdown);
        self.wrr_scheduler.remove(worker);
        self.ring_hash_dirty = true;
        if (self.selected == worker) self.selected = null;
        if (self.least_request_selected == worker) {
            self.least_request_selected = null;
        }
        self.recomputeLocked();
    }
    pub fn canceled(self: *State, job: *Job) bool {
        self.lock();
        defer self.unlock();
        return job.canceled() or self.closed;
    }
    pub fn nextQueuedDeadline(self: *State) ?std.Io.Clock.Timestamp {
        self.lock();
        defer self.unlock();
        var result: ?std.Io.Clock.Timestamp = null;
        var cursor = self.head;
        while (cursor) |job| : (cursor = job.next) {
            if (job.deadline) |deadline| if (result == null or std.Io.Clock.Timestamp.compare(deadline, .lt, result.?)) {
                result = deadline;
            };
        }
        return result;
    }
    pub fn nextOutlierDeadline(self: *State) ?std.Io.Clock.Timestamp {
        self.lock();
        defer self.unlock();
        const raw = self.outlier_next_evaluation_ns orelse return null;
        return .{ .raw = .{ .nanoseconds = raw }, .clock = .awake };
    }
    pub fn expireQueued(self: *State) void {
        self.lock();
        defer self.unlock();
        var cursor = self.head;
        while (cursor) |job| {
            const next = job.next;
            if (job.deadline) |deadline| if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                self.removeQueuedLocked(job);
                self.finishLocked(job, null, error.Timeout);
            };
            cursor = next;
        }
    }
    fn pickLocked(self: *State, claimant: *Worker) Error!?*Worker {
        self.evaluateOutliersLocked();
        if (self.policy == .pick_first) {
            if (self.selected) |worker| if (worker.eligible and worker.published == .ready) {
                return if (worker.capacity != 0) worker else null;
            };
        }
        if (self.policy == .weighted_round_robin) {
            if (self.wrr_config) |config| {
                const now = std.Io.Clock.awake.now(self.io).nanoseconds;
                if (now >= self.wrr_scheduler.next_update_ns) {
                    self.wrr_scheduler.rebuild(
                        self.allocator,
                        self.workers.items,
                        now,
                        config,
                        wrrReady,
                    ) catch {};
                }
                // Endpoint tasks race to claim the shared queue. Only consume
                // a stride choice when its selected endpoint owns this claim;
                // otherwise a non-selected task could discard every pick.
                var sequence = self.wrr_sequence;
                if (self.wrr_scheduler.pick(
                    Worker,
                    &sequence,
                    wrrAvailable,
                )) |worker| {
                    if (worker == claimant) self.wrr_sequence = sequence;
                    return worker;
                }
            }
        }
        if (self.policy == .least_request) {
            if (self.least_request_selected) |selected| {
                if (leastRequestWorkerAvailable(self, selected)) {
                    return selected;
                }
                self.least_request_selected = null;
            }
            var seed: u64 = undefined;
            self.io.random(std.mem.asBytes(&seed));
            const count = self.currentWorkerCount();
            const ordinal = least_request.pickIndex(
                self,
                count,
                self.least_request_config,
                seed,
                leastRequestOrdinalAvailable,
                leastRequestOrdinalOutstanding,
            ) orelse return null;
            const selected = self.currentWorkerAt(ordinal);
            self.least_request_selected = selected;
            return selected;
        }
        if (self.policy == .ring_hash) {
            try self.ensureRingLocked();
            const job = self.head orelse return null;
            const request_hash = job.routing_hash.?;
            const start = self.ring_hash_ring.start(request_hash.value) orelse
                return null;
            for (0..self.sources.len) |ordinal| {
                const source_index = self.ring_hash_ring.uniqueEndpointAt(
                    start,
                    ordinal,
                ) orelse return null;
                switch (self.pickRingSourceLocked(source_index)) {
                    .worker => |worker| return worker,
                    .pending => if (!request_hash.random) return null,
                    .failed => {},
                }
            }
            return null;
        }
        var count: usize = 0;
        for (self.sources) |source| count += source.current.len;
        for (0..count) |offset| {
            const rotates = self.policy == .round_robin or self.policy == .weighted_round_robin;
            var ordinal = if (rotates) (self.next_pick + offset) % count else offset;
            for (self.sources) |source| {
                if (ordinal >= source.current.len) {
                    ordinal -= source.current.len;
                    continue;
                }
                const worker = source.current[ordinal];
                if (worker.published == .ready and worker.capacity != 0) {
                    return worker;
                }
                break;
            }
        }
        return null;
    }
    fn wrrReady(worker: *Worker) bool {
        return worker.eligible and worker.published == .ready;
    }
    fn wrrAvailable(worker: *Worker) bool {
        return wrrReady(worker) and worker.capacity != 0;
    }
    fn currentWorkerCount(self: *const State) usize {
        var count: usize = 0;
        for (self.sources) |source| count += source.current.len;
        return count;
    }
    fn currentWorkerAt(self: *const State, target: usize) *Worker {
        var ordinal = target;
        for (self.sources) |source| {
            if (ordinal < source.current.len) return source.current[ordinal];
            ordinal -= source.current.len;
        }
        unreachable;
    }
    fn leastRequestWorkerAvailable(_: *const State, worker: *Worker) bool {
        return worker.eligible and worker.published == .ready and
            worker.capacity != 0;
    }
    fn leastRequestOrdinalAvailable(self: *State, ordinal: usize) bool {
        return leastRequestWorkerAvailable(self, self.currentWorkerAt(ordinal));
    }
    fn leastRequestOrdinalOutstanding(self: *State, ordinal: usize) usize {
        return self.currentWorkerAt(ordinal).outstanding_requests;
    }
    fn ensureRingLocked(self: *State) Error!void {
        if (!self.ring_hash_dirty) return;
        for (self.sources) |source| {
            if (source.resolver != null and source.generation == 0 and
                source.current.len == 0)
            {
                return;
            }
        }
        self.ring_hash_ring.rebuild(
            self.allocator,
            self,
            self.sources.len,
            self.ring_hash_config,
            ring_hash.default_ring_size_cap,
            ringSourceKey,
            ringSourceWeight,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidSharedOptions,
        };
        self.ring_hash_dirty = false;
    }
    const RingSourcePick = union(enum) {
        worker: *Worker,
        pending,
        failed,
    };
    fn pickRingSourceLocked(
        self: *State,
        source_index: usize,
    ) RingSourcePick {
        const source = &self.sources[source_index];
        var pending = source.resolver != null and source.current.len == 0;
        for (source.current) |worker| {
            if (!worker.eligible or worker.retired or
                worker.outlier.isEjected())
            {
                continue;
            }
            switch (worker.published) {
                .ready => if (worker.capacity != 0) {
                    return .{ .worker = worker };
                } else {
                    pending = true;
                },
                .idle, .connecting => pending = true,
                .transient_failure, .shutdown => {},
            }
        }
        return if (pending) .pending else .failed;
    }
    fn ringSourceKey(
        self: *State,
        source_index: usize,
        buffer: *[256]u8,
    ) ![]const u8 {
        const source = &self.sources[source_index];
        return source.ringHashKey(
            if (source.current.len == 0)
                null
            else
                source.current[0].address,
            buffer,
        );
    }
    fn ringSourceWeight(self: *State, source_index: usize) u32 {
        return self.sources[source_index].ring_hash_weight;
    }
    fn outlierEndpoint(
        workers: []const *Worker,
        index: usize,
    ) *outlier_detection.Endpoint {
        return &workers[index].outlier;
    }
    fn outlierEligible(workers: []const *Worker, index: usize) bool {
        return !workers[index].retired;
    }
    fn evaluateOutliersLocked(self: *State) void {
        const config = self.outlier_config orelse return;
        const next = self.outlier_next_evaluation_ns orelse return;
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (now < next) return;
        const changed = outlier_detection.evaluate(
            self.io,
            config,
            self.workers.items,
            self.workers.items.len,
            now,
            outlierEndpoint,
            outlierEligible,
        );
        self.outlier_next_evaluation_ns = now +| @max(
            config.interval.nanoseconds,
            1,
        );
        if (!changed) return;
        for (self.workers.items) |worker| {
            if (worker.retired) continue;
            const state: connectivity.State = if (worker.outlier.isEjected())
                .transient_failure
            else
                worker.local_state;
            const capacity = if (state == .ready)
                self.workerCapacityLocked(worker)
            else
                0;
            worker.published = state;
            worker.capacity = capacity;
            worker.tracker.setState(state);
            Membership.promoteLocked(self, worker.source_index);
        }
        self.wrr_scheduler.next_update_ns = 0;
        self.wakeAllLocked();
    }
    fn workerCapacityLocked(self: *State, worker: *Worker) usize {
        const connection = worker.connection orelse return 0;
        const used = worker.active.items.len + worker.streams.items.len;
        const room = self.options.max_active_calls_per_endpoint -| used;
        return @min(
            room,
            connection.availableLocalStreamCapacity() orelse room,
        );
    }
    pub fn claim(self: *State, worker: *Worker) ?*Job {
        self.lock();
        defer self.unlock();
        if (self.closed or self.head == null) return null;
        const picked = self.pickLocked(worker) catch |err| {
            const job = self.head.?;
            self.removeQueuedLocked(job);
            self.finishLocked(job, null, err);
            return null;
        } orelse return null;
        if (picked != worker) return null;
        const job = self.head.?;
        self.removeQueuedLocked(job);
        job.setOwnerWake(worker.wake);
        worker.capacity -= 1;
        if (self.policy == .least_request) {
            worker.outstanding_requests += 1;
            self.least_request_selected = null;
        }
        self.selected = picked;
        var count: usize = 0;
        var next: usize = 0;
        for (self.sources) |source| {
            for (source.current, count..) |member, ordinal| if (member == picked) {
                next = ordinal + 1;
            };
            count += source.current.len;
        }
        self.next_pick = next % count;
        self.wakeAllLocked();
        return job;
    }
    pub fn enqueue(self: *State, job: *Job) Error!void {
        try self.lockBefore(job.deadline);
        if (self.closed) {
            self.unlock();
            return error.SharedChannelClosed;
        }
        if (self.queued >= self.options.max_queued_calls) {
            self.unlock();
            return error.SharedQueueFull;
        }
        if (!job.wait_for_ready and self.aggregateLocked() == .transient_failure) {
            self.unlock();
            return error.ConnectionUnavailable;
        }
        std.debug.assert(job.parent != null);
        job.retain();
        if (self.tail) |tail| tail.next = job else self.head = job;
        self.tail = job;
        self.queued += 1;
        self.demand = true;
        self.tracker.setState(self.aggregateLocked());
        self.wakeAllLocked();
        self.unlock();
    }
    pub fn awaitJob(self: *State, job: *Job) Error!void {
        std.debug.assert(job.parent != null);
        self.waitForJob(job, job.deadline) catch |err| {
            if (!job.abandon()) {
                if (job.err) |failure| return @errorCast(failure);
                return;
            }
            if (job.stream) |stream| stream.cancel_requested.store(true, .release);
            self.abandoned_pending.store(true, .release);
            if (job.owner_wake.load(.acquire)) |wake| wake.set(self.io);
            if (self.mutex.tryLock()) self.unlock();
            return err;
        };
        if (job.err) |err| return @errorCast(err);
    }
    pub fn attempt(self: *State, _: std.mem.Allocator, options: call.UnaryCallOptions, deadline: ?std.Io.Clock.Timestamp, rpc_deadline: ?std.Io.Clock.Timestamp, timeout_header: ?@import("../../wire.zig").Timeout, previous: ?u8) Error!call.UnaryResponse {
        var attempt_options = options;
        attempt_options.timeout = timeout_header;
        const job = try Job.create(
            self,
            attempt_options,
            deadline,
            rpc_deadline,
            previous,
        );
        defer job.release();
        try self.enqueue(job);
        try self.awaitJob(job);
        return job.takeResult();
    }
    fn waitForJob(self: *State, job: *Job, deadline: ?std.Io.Clock.Timestamp) std.Io.Event.WaitTimeoutError!void {
        const until = deadline orelse return job.done.wait(self.io);
        while (true) {
            job.done.waitTimeout(self.io, .{ .deadline = until }) catch |err| {
                // Event's timed wait also reports a spurious futex wake as
                // Timeout. Only the original absolute deadline expires an RPC.
                if (err == error.Timeout and until.durationFromNow(self.io).raw.nanoseconds > 0) continue;
                return err;
            };
            return;
        }
    }
    pub fn unary(self: *State, options: call.UnaryCallOptions, explicit_retry: ?call.RetryPolicy, explicit_hedging: ?call.HedgingPolicy, entered: std.Io.Timestamp) Error!call.UnaryResponse {
        var resolved: service_config.ResolvedUnary = .{ .options = options, .retry_policy = null, .hedging_policy = null, .wait_for_ready = options.wait_for_ready orelse false };
        if (self.config) |*config| resolved = try config.resolveUnary(options);
        if (explicit_retry) |policy| {
            resolved.retry_policy = policy;
            resolved.hedging_policy = null;
        }
        if (explicit_hedging) |policy| {
            resolved.hedging_policy = policy;
            resolved.retry_policy = null;
        }
        // Service configuration is immutable after construction and remains
        // owned by this retained State. Resolve it before lock admission so a
        // configured timeout bounds that first wait as well.
        const deadline: ?std.Io.Clock.Timestamp = if (resolved.options.timeout) |timeout| .{ .raw = entered.addDuration(timeout.duration()), .clock = .awake } else null;
        try self.lockBefore(deadline);
        const closed = self.closed;
        self.unlock();
        if (closed) return error.SharedChannelClosed;
        if (resolved.options.message.len > resolved.options.requestMessageLimit()) return error.GrpcMessageTooLarge;
        resolved.options.wait_for_ready = resolved.wait_for_ready;
        if (resolved.hedging_policy) |policy| {
            return @import("hedging.zig").run(
                self,
                resolved.options,
                policy,
                deadline,
            );
        }
        return retry.runWithDeadline(self, self.allocator, resolved.options, resolved.retry_policy, deadline, attempt);
    }
};
