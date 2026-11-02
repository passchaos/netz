//! Connection generations, connector backoff, and terminal retirement.
const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const endpoint = @import("../../endpoint_client.zig");
const timed_mutex = @import("../../../../internal/timed_mutex.zig");
const admission = @import("admission.zig");
const completion = @import("completion.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

pub const Error = endpoint.Error || error{
    ClientClosed,
    StaleConnection,
    InvalidReconnectOptions,
};

pub const CustomConnector = @import("target.zig").CustomConnector;
pub const Target = @import("target.zig").Target;

pub const Backoff = struct {
    initial: std.Io.Duration = .fromSeconds(1),
    maximum: std.Io.Duration = .fromSeconds(120),
    multiplier: f64 = 1.6,
    jitter: f64 = 0.2,
    min_connect_timeout: std.Io.Duration = .fromSeconds(20),

    fn validate(self: Backoff) Error!void {
        if (self.initial.nanoseconds <= 0 or
            self.maximum.nanoseconds < self.initial.nanoseconds or
            self.min_connect_timeout.nanoseconds <= 0 or
            !std.math.isFinite(self.multiplier) or
            self.multiplier < 1 or
            !std.math.isFinite(self.jitter) or
            self.jitter < 0 or self.jitter >= 1)
        {
            return error.InvalidReconnectOptions;
        }
    }
};

pub const Options = struct {
    endpoint: endpoint.Options = .{},
    backoff: Backoff = .{},

    pub fn validate(self: Options) Error!void {
        try self.endpoint.validate();
        try self.backoff.validate();
    }
};

pub const Generation = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    id: u64,
    client: endpoint.EndpointClient,
    retire_requested: std.atomic.Value(bool) = .init(false),

    fn create(
        allocator: std.mem.Allocator,
        id: u64,
        connection_value: http2.runtime.Connection,
        options: endpoint.Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Generation {
        var connection = connection_value;
        var owned = true;
        errdefer if (owned) connection.closeWithoutCloseNotify();
        _ = try deadline_policy.usableAwake(connection.io, deadline);
        try connection.io.checkCancel();
        const self = try allocator.create(Generation);
        errdefer allocator.destroy(self);
        owned = false;
        const client = try endpoint.EndpointClient.initWithDeadline(allocator, connection, options, deadline);
        self.* = .{ .allocator = allocator, .id = id, .client = client };
        return self;
    }

    fn discardUnpublished(self: *Generation) void {
        std.debug.assert(self.refs.load(.acquire) == 1);
        self.client.deinitAbortive();
        self.allocator.destroy(self);
    }

    pub fn retain(self: *Generation) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Generation) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.retire_requested.load(.acquire)) self.client.deinitAbortive() else self.client.deinit();
        self.allocator.destroy(self);
    }
};

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    target: Target,
    options: Options,
    mutex: std.Io.Mutex = .init,
    wake: std.Io.Event = .unset,
    idle: std.Io.Event = .unset,
    current: ?*Generation = null,
    next_generation: u64 = 1,
    failures: usize = 0,
    next_attempt_ns: ?i96 = null,
    connecting: bool = false,
    pending_failure: completion.Failure = .{},
    active: std.atomic.Value(usize) = .init(0),
    closed: bool = false,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
    ) Error!*State {
        try target.validate();
        try options.validate();
        const self = try allocator.create(State);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .target = target,
            .options = options,
        };
        return self;
    }

    fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
    }

    fn unlock(self: *State) void {
        self.mutex.unlock(self.io);
    }

    pub fn enter(self: *State, deadline: std.Io.Clock.Timestamp) Error!void {
        return admission.enter(self, deadline);
    }

    pub fn leave(self: *State) void {
        admission.leave(self);
    }

    pub fn acquireCurrent(
        self: *State,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Generation {
        if (deadline.clock != .awake) return error.Timeout;
        while (true) {
            try timed_mutex.lock(&self.mutex, self.io, deadline);
            if (self.closed) {
                self.unlock();
                return error.ClientClosed;
            }
            self.applyPendingFailureLocked();
            if (self.current) |generation| {
                if (generation.retire_requested.load(.acquire)) {
                    self.current = null;
                    self.failures +|= 1;
                    self.scheduleBackoffLocked();
                    self.unlock();
                    generation.client.requestShutdownAbortive();
                    generation.release();
                    continue;
                }
                generation.retain();
                self.unlock();
                if (generation.client.terminalFailure()) |failure| {
                    _ = self.retireAfterError(generation, failure);
                    generation.release();
                    continue;
                }
                return generation;
            }
            if (self.connecting) {
                self.wake.reset();
                // A producer does not need the State mutex to publish a
                // failed attempt. Do not lose its wake across this reset.
                if (self.pending_failure.ready.load(.acquire)) {
                    self.unlock();
                    continue;
                }
                self.unlock();
                try waitEventUntil(&self.wake, self.io, deadline);
                continue;
            }
            const now = std.Io.Clock.awake.now(self.io).nanoseconds;
            if (self.next_attempt_ns) |next| if (next > now) {
                self.wake.reset();
                self.unlock();
                const wait_deadline = earlier(
                    deadline,
                    .{ .raw = .{ .nanoseconds = next }, .clock = .awake },
                );
                waitEventUntil(&self.wake, self.io, wait_deadline) catch |err| {
                    if (err != error.Timeout) return err;
                };
                if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
                continue;
            };
            self.connecting = true;
            const generation_id = self.takeGenerationLocked();
            self.unlock();

            const attempt_deadline = earlier(
                deadline,
                .fromNow(self.io, .{
                    .raw = self.options.backoff.min_connect_timeout,
                    .clock = .awake,
                }),
            );
            const connection = self.target.connect(
                self.allocator,
                self.io,
                attempt_deadline,
            ) catch |err| {
                const retry = self.target.retryable(err);
                self.finishConnectFailure();
                if (!retry) return @errorCast(err);
                if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
                continue;
            };
            const generation = Generation.create(
                self.allocator,
                generation_id,
                connection,
                self.options.endpoint,
                deadline,
            ) catch |err| {
                self.finishConnectFailure();
                return err;
            };
            timed_mutex.lock(&self.mutex, self.io, deadline) catch |err| {
                generation.discardUnpublished();
                self.finishConnectFailure();
                return err;
            };
            self.io.checkCancel() catch |err| {
                self.unlock();
                generation.discardUnpublished();
                self.finishConnectFailure();
                return err;
            };
            self.connecting = false;
            self.wake.set(self.io);
            if (self.closed) {
                self.unlock();
                generation.discardUnpublished();
                return error.ClientClosed;
            }
            self.failures = 0;
            self.next_attempt_ns = null;
            self.current = generation;
            generation.retain();
            self.unlock();
            return generation;
        }
    }

    pub fn acquireHandle(self: *State, generation_id: u64, deadline: std.Io.Clock.Timestamp) Error!*Generation {
        try timed_mutex.lock(&self.mutex, self.io, deadline);
        defer self.unlock();
        if (self.closed) return error.ClientClosed;
        const generation = self.current orelse return error.StaleConnection;
        if (generation.id != generation_id) return error.StaleConnection;
        if (generation.retire_requested.load(.acquire)) return error.StaleConnection;
        generation.retain();
        return generation;
    }

    pub fn retireAfterError(
        self: *State,
        generation: *Generation,
        err: anyerror,
    ) bool {
        if (generation.client.terminalFailure() == null and
            !connectionLost(err)) return false;
        return self.retire(generation);
    }

    pub fn retireAfterConnectError(
        self: *State,
        generation: *Generation,
        err: anyerror,
    ) bool {
        if (err != error.SessionClosed and
            err != error.ConnectionGoAway)
        {
            return self.retireAfterError(generation, err);
        }
        return self.retire(generation);
    }

    fn retire(self: *State, generation: *Generation) bool {
        var removed = false;
        if (!self.mutex.tryLock()) {
            // The operation already owns this generation and State activity.
            // Record retirement without waiting past its deadline. Handle
            // lookup refuses it and the next CONNECT completes removal.
            generation.retire_requested.store(true, .release);
            self.wake.set(self.io);
            return true;
        }
        if (self.current == generation) {
            generation.retire_requested.store(true, .release);
            self.current = null;
            self.failures +|= 1;
            self.scheduleBackoffLocked();
            self.wake.set(self.io);
            removed = true;
        }
        self.unlock();
        if (removed) {
            generation.client.requestShutdownAbortive();
            generation.release();
        }
        return removed;
    }

    fn takeGenerationLocked(self: *State) u64 {
        const result = self.next_generation;
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;
        return result;
    }

    fn finishConnectFailure(self: *State) void {
        self.pending_failure.publish(self.io);
        if (self.mutex.tryLock()) {
            self.applyPendingFailureLocked();
            self.unlock();
        }
        self.wake.set(self.io);
    }

    fn applyPendingFailureLocked(self: *State) void {
        const at_ns = self.pending_failure.take() orelse return;
        self.connecting = false;
        if (self.closed) return;
        self.failures +|= 1;
        self.scheduleBackoffFromLocked(at_ns);
    }

    fn scheduleBackoffLocked(self: *State) void {
        self.scheduleBackoffFromLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
    }

    fn scheduleBackoffFromLocked(self: *State, at_ns: i96) void {
        var delay: f64 = @floatFromInt(self.options.backoff.initial.nanoseconds);
        const maximum: f64 = @floatFromInt(self.options.backoff.maximum.nanoseconds);
        var remaining = self.failures -| 1;
        while (remaining != 0 and delay < maximum) : (remaining -= 1) {
            delay = @min(maximum, delay * self.options.backoff.multiplier);
        }
        if (self.options.backoff.jitter != 0) {
            var bytes: [8]u8 = undefined;
            self.io.random(&bytes);
            const unit = @as(f64, @floatFromInt(std.mem.readInt(u64, &bytes, .little))) /
                @as(f64, @floatFromInt(std.math.maxInt(u64)));
            delay *= 1 - self.options.backoff.jitter +
                2 * self.options.backoff.jitter * unit;
        }
        const bounded = @min(
            delay,
            @as(f64, @floatFromInt(std.math.maxInt(i96))),
        );
        self.next_attempt_ns = (std.Io.Timestamp{ .nanoseconds = at_ns })
            .addDuration(.fromNanoseconds(@intFromFloat(@ceil(bounded))))
            .nanoseconds;
    }

    pub fn closeAndDestroy(self: *State) void {
        self.lock();
        if (self.closed) {
            self.unlock();
            return;
        }
        self.closed = true;
        const generation = self.current;
        self.current = null;
        self.wake.set(self.io);
        self.unlock();
        if (generation) |value| {
            if (value.retire_requested.load(.acquire)) value.client.requestShutdownAbortive() else value.client.requestShutdown();
            value.release();
        }
        admission.waitForIdle(self);
        self.allocator.destroy(self);
    }
};

fn earlier(
    a: std.Io.Clock.Timestamp,
    b: std.Io.Clock.Timestamp,
) std.Io.Clock.Timestamp {
    return if (std.Io.Clock.Timestamp.compare(a, .lt, b)) a else b;
}

fn waitEventUntil(
    event: *std.Io.Event,
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and
                deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}

fn connectionLost(err: anyerror) bool {
    return switch (err) {
        error.BrokenPipe,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.NetworkDown,
        error.ReadFailed,
        error.SocketUnconnected,
        error.TruncatedRecord,
        error.UnexpectedEof,
        error.WriteFailed,
        => true,
        else => false,
    };
}
