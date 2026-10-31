//! Connection generations, connector backoff, and terminal retirement.
const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const endpoint = @import("../../endpoint_client.zig");

pub const Error = endpoint.Error || error{
    ClientClosed,
    StaleConnection,
    InvalidReconnectOptions,
};

pub const CustomConnector = struct {
    context: ?*anyopaque,
    connect_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection,
    retryable_fn: ?*const fn (context: ?*anyopaque, err: anyerror) bool = null,
};

/// Borrowed for the ReconnectingEndpointClient lifetime. Established
/// connections and Sessions own their transport state independently.
pub const Target = union(enum) {
    cleartext_address: struct {
        address: std.Io.net.IpAddress,
        limits: http2.runtime.Limits = .{},
    },
    cleartext_host: struct {
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
    },
    tls_address: struct {
        address: std.Io.net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    tls_host: struct {
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    custom: CustomConnector,

    fn validate(self: Target) Error!void {
        switch (self) {
            .cleartext_host => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            .tls_host => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            else => {},
        }
    }

    fn connect(
        self: Target,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection {
        return switch (self) {
            .cleartext_address => |value| http2.runtime.Client.connectWithDeadline(
                allocator,
                io,
                value.address,
                value.limits,
                deadline,
            ),
            .cleartext_host => |value| http2.runtime.Client.connectHostWithDeadline(
                allocator,
                io,
                value.host,
                value.port,
                value.limits,
                deadline,
            ),
            .tls_address => |value| http2.runtime.Client.connectTlsAddressWithDeadline(
                allocator,
                io,
                value.address,
                value.tls_host,
                value.authority,
                value.limits,
                value.tls,
                deadline,
            ),
            .tls_host => |value| http2.runtime.Client.connectTlsHostWithDeadline(
                allocator,
                io,
                value.host,
                value.port,
                value.limits,
                value.tls,
                deadline,
            ),
            .custom => |value| value.connect_fn(
                value.context,
                allocator,
                io,
                deadline,
            ),
        };
    }

    fn retryable(self: Target, err: anyerror) bool {
        return switch (self) {
            .custom => |value| if (value.retryable_fn) |classify|
                classify(value.context, err)
            else
                retryableConnectError(err),
            else => retryableConnectError(err),
        };
    }
};

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

    fn create(
        allocator: std.mem.Allocator,
        id: u64,
        client: endpoint.EndpointClient,
    ) std.mem.Allocator.Error!*Generation {
        const self = try allocator.create(Generation);
        self.* = .{ .allocator = allocator, .id = id, .client = client };
        return self;
    }

    pub fn retain(self: *Generation) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Generation) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.client.deinit();
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
    active: usize = 0,
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

    pub fn enter(self: *State) Error!void {
        self.lock();
        defer self.unlock();
        if (self.closed) return error.ClientClosed;
        self.active += 1;
    }

    pub fn leave(self: *State) void {
        self.lock();
        defer self.unlock();
        self.active -= 1;
        if (self.active == 0) self.idle.set(self.io);
    }

    pub fn acquireCurrent(
        self: *State,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Generation {
        if (deadline.clock != .awake) return error.Timeout;
        while (true) {
            self.lock();
            if (self.closed) {
                self.unlock();
                return error.ClientClosed;
            }
            if (self.current) |generation| {
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
            var client = endpoint.EndpointClient.init(
                self.allocator,
                connection,
                self.options.endpoint,
            ) catch |err| {
                self.finishConnectFailure();
                return err;
            };
            const generation = Generation.create(
                self.allocator,
                self.takeGeneration(),
                client,
            ) catch |err| {
                client.deinit();
                self.finishConnectFailure();
                return err;
            };
            self.lock();
            self.connecting = false;
            self.wake.set(self.io);
            if (self.closed) {
                self.unlock();
                generation.release();
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

    pub fn acquireHandle(self: *State, generation_id: u64) Error!*Generation {
        self.lock();
        defer self.unlock();
        if (self.closed) return error.ClientClosed;
        const generation = self.current orelse return error.StaleConnection;
        if (generation.id != generation_id) return error.StaleConnection;
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
        self.lock();
        if (self.current == generation) {
            self.current = null;
            self.failures +|= 1;
            self.scheduleBackoffLocked();
            self.wake.set(self.io);
            removed = true;
        }
        self.unlock();
        if (removed) {
            generation.client.requestShutdown();
            generation.release();
        }
        return removed;
    }

    fn takeGeneration(self: *State) u64 {
        self.lock();
        defer self.unlock();
        const result = self.next_generation;
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;
        return result;
    }

    fn finishConnectFailure(self: *State) void {
        self.lock();
        defer self.unlock();
        self.connecting = false;
        self.failures +|= 1;
        self.scheduleBackoffLocked();
        self.wake.set(self.io);
    }

    fn scheduleBackoffLocked(self: *State) void {
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
        self.next_attempt_ns = std.Io.Clock.awake.now(self.io)
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
        if (self.active == 0) self.idle.set(self.io);
        self.unlock();
        if (generation) |value| {
            value.client.requestShutdown();
            value.release();
        }
        while (true) {
            self.lock();
            const done = self.active == 0;
            if (!done) self.idle.reset();
            self.unlock();
            if (done) break;
            self.idle.wait(self.io) catch {};
        }
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

fn retryableConnectError(err: anyerror) bool {
    return switch (err) {
        error.AddressUnavailable,
        error.ConnectionPending,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.DetectingNetworkConfigurationFailed,
        error.HostUnreachable,
        error.NameServerFailure,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.NoAddressReturned,
        error.ProcessFdQuotaExceeded,
        error.SocketUnconnected,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.Timeout,
        error.UnknownHostName,
        => true,
        else => false,
    };
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
