const std = @import("std");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const channel = @import("../../channel.zig");
const call = @import("../../call.zig");
const health = @import("../../health.zig");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const retry = @import("../../call/retry.zig");
const Job = @import("job.zig").Job;
pub const Options = @import("options.zig").Options;
pub const Error = health.WatchError || channel.Error || service_config.Error || error{ SharedChannelClosed, SharedQueueFull, InvalidSharedOptions, StreamReceiveBufferExceeded };

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

    pub const Worker = @import("worker.zig").Worker(State);
    pub const Source = @import("source.zig").Source(Worker);
    pub const Membership = @import("membership.zig").Membership(State);
    pub const Resolution = @import("resolution.zig").Resolution(State);
    pub const Failure = @import("state.zig").Error;
    pub const StreamCall = @import("stream/call.zig").Call(State);

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.head == null);
        std.debug.assert(self.workers.items.len == 0);
        self.workers.deinit(self.allocator);
        for (self.sources) |*source| source.deinit(self.allocator);
        self.allocator.free(self.sources);
        if (self.config) |*config| config.deinit();
        if (self.health_service) |name| self.allocator.free(name);
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
        const changed = worker.published != state or worker.capacity != capacity;
        worker.published = state;
        worker.capacity = capacity;
        worker.tracker.setState(if (self.closed or worker.retired) .shutdown else state);
        Membership.promoteLocked(self, worker.source_index);
        self.recomputeLocked();
        if (changed) self.wakeAllLocked();
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
    fn pickLocked(self: *State) ?*Worker {
        if (self.policy == .pick_first) {
            if (self.selected) |worker| if (worker.eligible and worker.published == .ready) {
                return if (worker.capacity != 0) worker else null;
            };
        }
        var count: usize = 0;
        for (self.sources) |source| count += source.current.len;
        for (0..count) |offset| {
            var ordinal = if (self.policy == .round_robin) (self.next_pick + offset) % count else offset;
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
    pub fn claim(self: *State, worker: *Worker) ?*Job {
        self.lock();
        defer self.unlock();
        if (self.closed or self.head == null) return null;
        const picked = self.pickLocked() orelse return null;
        if (picked != worker) return null;
        const job = self.head.?;
        self.removeQueuedLocked(job);
        job.setOwnerWake(worker.wake);
        worker.capacity -= 1;
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
    pub fn attempt(self: *State, _: std.mem.Allocator, options: call.UnaryCallOptions, deadline: ?std.Io.Clock.Timestamp, _: ?@import("../../wire.zig").Timeout, previous: ?u8) Error!call.UnaryResponse {
        const job = try Job.create(self, options, deadline, previous);
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
    pub fn unary(self: *State, options: call.UnaryCallOptions, explicit_retry: ?call.RetryPolicy, entered: std.Io.Timestamp) Error!call.UnaryResponse {
        var resolved: service_config.ResolvedUnary = .{ .options = options, .retry_policy = null, .wait_for_ready = options.wait_for_ready orelse false };
        if (self.config) |*config| resolved = try config.resolveUnary(options);
        if (explicit_retry) |policy| resolved.retry_policy = policy;
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
        return retry.runWithDeadline(self, self.allocator, resolved.options, resolved.retry_policy, deadline, attempt);
    }
};
