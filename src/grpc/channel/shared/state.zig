const std = @import("std");
const channel = @import("../../channel.zig");
const call = @import("../../call.zig");
const health = @import("../../health.zig");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const retry = @import("../../call/retry.zig");
const Job = @import("job.zig").Job;
pub const Options = @import("options.zig").Options;
pub const Error = health.WatchError || channel.Error || service_config.Error || error{ SharedChannelClosed, SharedQueueFull, InvalidSharedOptions };

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    refs: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    group: std.Io.Group = .init,
    workers: []Worker,
    config: ?service_config.ServiceConfig = null,
    health_service: ?[]u8 = null,
    tracker: *connectivity.Tracker,
    policy: channel.SelectionPolicy,
    head: ?*Job = null,
    tail: ?*Job = null,
    queued: usize = 0,
    demand: bool = false,
    closed: bool = false,
    selected: ?usize = null,
    next_pick: usize = 0,

    pub const Worker = @import("worker.zig").Worker(State);

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.head == null);
        for (self.workers) |*worker| {
            worker.owner.deinit();
            worker.tracker.release();
        }
        self.allocator.free(self.workers);
        if (self.config) |*config| config.deinit();
        if (self.health_service) |name| self.allocator.free(name);
        self.tracker.release();
        self.allocator.destroy(self);
    }

    pub fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
    }
    pub fn unlock(self: *State) void {
        self.mutex.unlock(self.io);
    }
    pub fn wakeAllLocked(self: *State) void {
        for (self.workers) |*worker| worker.wake.set(self.io);
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
        for (self.workers) |*worker| worker.tracker.setState(.shutdown);
        self.wakeAllLocked();
    }
    fn finishLocked(self: *State, job: *Job, result: ?call.UnaryResponse, err: ?anyerror) void {
        job.result = result;
        job.err = if (self.closed and err != null) error.SharedChannelClosed else err;
        job.phase = .completed;
        job.done.set(self.io);
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
        for (self.workers) |worker| {
            if (worker.published == .ready) return .ready;
            if (worker.published == .connecting or worker.published == .idle) connecting = true;
        }
        return if (connecting) .connecting else .transient_failure;
    }
    pub fn publish(self: *State, worker: *Worker, state: connectivity.State, capacity: usize) void {
        self.lock();
        defer self.unlock();
        const changed = worker.published != state or worker.capacity != capacity;
        worker.published = state;
        worker.capacity = capacity;
        worker.tracker.setState(state);
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
        if (changed) self.wakeAllLocked();
    }
    pub fn needsConnection(self: *State, worker: *Worker) bool {
        self.lock();
        defer self.unlock();
        worker.wake.reset();
        return self.demand;
    }
    pub fn canceled(self: *State, job: *Job) bool {
        self.lock();
        defer self.unlock();
        return job.cancel_requested or self.closed;
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
    fn pickLocked(self: *State) ?usize {
        if (self.policy == .pick_first) {
            if (self.selected) |id| if (self.workers[id].published == .ready) {
                return if (self.workers[id].capacity != 0) id else null;
            };
        }
        for (0..self.workers.len) |offset| {
            const id = if (self.policy == .round_robin) (self.next_pick + offset) % self.workers.len else offset;
            if (self.workers[id].published == .ready and self.workers[id].capacity != 0) return id;
        }
        return null;
    }
    pub fn claim(self: *State, worker: *Worker) ?*Job {
        self.lock();
        defer self.unlock();
        if (self.closed or self.head == null) return null;
        const picked = self.pickLocked() orelse return null;
        if (picked != worker.id) return null;
        const job = self.head.?;
        self.removeQueuedLocked(job);
        job.phase = .assigned;
        worker.capacity -= 1;
        self.selected = picked;
        self.next_pick = (picked + 1) % self.workers.len;
        self.wakeAllLocked();
        return job;
    }
    pub fn attempt(self: *State, _: std.mem.Allocator, options: call.UnaryCallOptions, deadline: ?std.Io.Clock.Timestamp, _: ?@import("../../wire.zig").Timeout, previous: ?u8) Error!call.UnaryResponse {
        var job: Job = .{ .options = options, .deadline = deadline, .wait_for_ready = options.wait_for_ready orelse false, .previous_attempts = previous };
        self.lock();
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
        if (self.tail) |tail| tail.next = &job else self.head = &job;
        self.tail = &job;
        self.queued += 1;
        self.demand = true;
        self.tracker.setState(self.aggregateLocked());
        self.wakeAllLocked();
        self.unlock();
        const waited = self.waitForJob(&job, deadline);
        waited catch |err| {
            self.lock();
            if (job.phase == .queued) {
                self.removeQueuedLocked(&job);
                self.unlock();
                return err;
            }
            if (job.phase != .completed) {
                job.cancel_requested = true;
                self.wakeAllLocked();
            }
            self.unlock();
            job.done.waitUncancelable(self.io);
            if (job.result) |*result| result.deinit();
            return err;
        };
        if (job.err) |err| return @errorCast(err);
        return job.result.?;
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
        self.lock();
        const closed = self.closed;
        self.unlock();
        if (closed) return error.SharedChannelClosed;
        var resolved: service_config.ResolvedUnary = .{ .options = options, .retry_policy = null, .wait_for_ready = options.wait_for_ready orelse false };
        if (self.config) |*config| resolved = try config.resolveUnary(options);
        if (explicit_retry) |policy| resolved.retry_policy = policy;
        if (resolved.options.message.len > resolved.options.requestMessageLimit()) return error.GrpcMessageTooLarge;
        resolved.options.wait_for_ready = resolved.wait_for_ready;
        const deadline: ?std.Io.Clock.Timestamp = if (resolved.options.timeout) |timeout| .{ .raw = entered.addDuration(timeout.duration()), .clock = .awake } else null;
        return retry.runWithDeadline(self, self.allocator, resolved.options, resolved.retry_policy, deadline, attempt);
    }
};
