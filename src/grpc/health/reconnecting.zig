//! Reconnecting, consumption-driven Health Watch with gRPC Core retry policy.
//! One owner drives next; the private heap Channel keeps stream pointers
//! stable when this handle moves. Target and metadata slices remain borrowed.
const std = @import("std");
const health = @import("../health.zig");
const channel = @import("../channel.zig");
const call = @import("../call.zig");
const http2 = @import("../../http2/mod.zig");
const wire = @import("../wire.zig");
const service_config = @import("../service_config.zig");

pub const Error = health.WatchError || channel.Error || error{
    HealthWatchStopped,
    HealthWatchDisabled,
};

pub const Options = struct {
    watch: health.WatchOptions = .{},
    channel_options: channel.Options = .{},
    backoff: channel.BackoffPolicy = .{},
    /// Explicit service override for configured construction. Empty selects
    /// overall server health; null permits the config or watch.service name.
    service_override: ?[]const u8 = null,
};

pub const Failure = union(enum) {
    rpc: struct {
        status: wire.Status,
        reset: ?http2.ErrorCode,
    },
    transport: anyerror,
};

pub const Retry = struct {
    failure: Failure,
    deadline: std.Io.Clock.Timestamp,
    consecutive_failures: usize,
};

pub const Event = union(enum) {
    status: health.Response,
    retrying: Retry,
    /// UNIMPLEMENTED disables checking and treats the backend as healthy.
    disabled,
};

pub const ReconnectingWatch = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    owner: *channel.Channel,
    options: Options,
    service: []u8,
    watch: ?health.ClientWatch = null,
    retry_at: ?std.Io.Clock.Timestamp = null,
    failures: usize = 0,
    received_status: bool = false,
    last_status: ?health.ServingStatus = null,
    disabled: bool = false,
    stopped: bool = false,

    /// Lazy: validation and allocation only. A dedicated connection is used
    /// so Health Watch never competes with an application's RPC frame reader.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: channel.Target,
        options: Options,
    ) Error!ReconnectingWatch {
        var resolved = options;
        if (options.service_override) |name| resolved.watch.service = name;
        return initResolved(allocator, io, target, resolved, null);
    }

    /// Return null without allocating or connecting when checking is disabled.
    /// service_override wins, then a non-empty explicit watch.service, then
    /// healthCheckConfig.serviceName. Explicit channel options override the
    /// service config's load-balancing policy. The selected name is copied.
    pub fn initWithServiceConfig(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: channel.Target,
        options: Options,
        config: *const service_config.ServiceConfig,
    ) Error!?ReconnectingWatch {
        const name = options.service_override orelse
            (if (options.watch.service.len != 0) options.watch.service else config.healthCheckServiceName()) orelse
            return null;
        var resolved = options;
        resolved.watch.service = name;
        return try initResolved(allocator, io, target, resolved, config);
    }

    fn initResolved(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: channel.Target,
        options: Options,
        config: ?*const service_config.ServiceConfig,
    ) Error!ReconnectingWatch {
        try options.backoff.validate();
        try call.validateCustomMetadata(options.watch.metadata);
        try call.validateCustomBinaryMetadata(options.watch.binary_metadata);
        const encoded = try health.encodeRequestAlloc(allocator, .{
            .service = options.watch.service,
        });
        defer allocator.free(encoded);
        const service = try allocator.dupe(u8, options.watch.service);
        errdefer allocator.free(service);
        const owner = try allocator.create(channel.Channel);
        errdefer allocator.destroy(owner);
        owner.* = if (config) |configured|
            try channel.Channel.initWithServiceConfig(allocator, io, target, options.channel_options, configured)
        else
            try channel.Channel.init(allocator, io, target, options.channel_options);
        var retained = options;
        retained.watch.service = service;
        if (retained.service_override != null) retained.service_override = service;
        return .{
            .allocator = allocator,
            .io = io,
            .owner = owner,
            .options = retained,
            .service = service,
        };
    }

    pub fn deinit(self: *ReconnectingWatch) void {
        self.dropWatch();
        self.owner.deinit();
        self.allocator.destroy(self.owner);
        self.allocator.free(self.service);
        self.* = undefined;
    }

    /// Single-owner terminal cancellation. To interrupt a concurrently
    /// running next operation, cancel and join its std.Io task first.
    pub fn cancel(self: *ReconnectingWatch) Error!void {
        if (self.stopped) return;
        self.stopped = true;
        self.last_status = null;
        self.retry_at = null;
        self.owner.cancelWaits();
        defer self.dropWatch();
        if (self.watch) |*watch| {
            if (!watch.terminal_seen) try watch.cancel();
        }
    }

    pub fn isServing(self: *const ReconnectingWatch) bool {
        return !self.stopped and (self.disabled or self.last_status == .serving);
    }

    pub fn nextWithTimeout(
        self: *ReconnectingWatch,
        timeout: std.Io.Duration,
    ) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.nextWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    /// One absolute budget covers retry sleep, DNS, connect/TLS/bootstrap,
    /// request output and the next response. A read timeout retains an active
    /// Watch; an interrupted request write is retired before the next attempt.
    pub fn nextWithDeadline(
        self: *ReconnectingWatch,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Event {
        if (self.stopped) return error.HealthWatchStopped;
        if (self.disabled) return error.HealthWatchDisabled;
        if (expired(self.io, deadline)) return error.Timeout;
        if (self.retry_at) |retry_at| {
            const wake_at = if (std.Io.Clock.Timestamp.compare(retry_at, .lt, deadline))
                retry_at
            else
                deadline;
            try (std.Io.Timeout{ .deadline = wake_at }).sleep(self.io);
            if (expired(self.io, deadline)) return error.Timeout;
            self.retry_at = null;
        }
        if (self.watch == null) {
            const connection = self.owner.connectWithDeadline(deadline) catch |err| {
                return self.operationFailed(err, deadline);
            };
            self.watch = health.startWatchWithDeadline(
                connection,
                self.allocator,
                self.options.watch,
                deadline,
            ) catch |err| {
                return self.operationFailed(err, deadline);
            };
            self.received_status = false;
        }
        var event = self.watch.?.nextWithDeadline(deadline) catch |err| {
            if (err == error.Timeout and !self.watch.?.terminal_seen) return err;
            self.dropWatch();
            return self.operationFailed(err, deadline);
        };
        defer event.deinit();
        switch (event) {
            .status => |response| {
                self.received_status = true;
                self.last_status = response.status;
                return .{ .status = response };
            },
            .terminal => |terminal| {
                const failure: Failure = .{ .rpc = .{
                    .status = terminal.status,
                    .reset = if (terminal.reset) |reset| reset.error_code else null,
                } };
                self.dropWatch();
                self.last_status = null;
                if (terminal.status == .unimplemented) {
                    self.disabled = true;
                    return .disabled;
                }
                return self.scheduleRetry(failure);
            },
        }
    }

    /// Drive reconnects and non-SERVING updates until the backend is ready.
    pub fn waitForServingWithDeadline(
        self: *ReconnectingWatch,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        while (!self.isServing()) {
            _ = try self.nextWithDeadline(deadline);
        }
    }

    pub fn waitForServingWithTimeout(
        self: *ReconnectingWatch,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForServingWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    fn operationFailed(
        self: *ReconnectingWatch,
        err: anyerror,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Event {
        self.last_status = null;
        switch (err) {
            error.Canceled, error.ConcurrencyUnavailable, error.OutOfMemory => return @errorCast(err),
            error.Timeout => if (expired(self.io, deadline)) return error.Timeout,
            else => {},
        }
        return self.scheduleRetry(.{ .transport = err });
    }

    fn scheduleRetry(self: *ReconnectingWatch, failure: Failure) Event {
        self.last_status = null;
        const delay: std.Io.Duration = if (self.received_status) blk: {
            self.failures = 0;
            break :blk .zero;
        } else blk: {
            self.failures +|= 1;
            var sample: u64 = undefined;
            self.io.random(std.mem.asBytes(&sample));
            break :blk self.options.backoff.delay(self.failures, sample);
        };
        self.received_status = false;
        const retry_at = std.Io.Clock.Timestamp.fromNow(self.io, .{
            .raw = delay,
            .clock = .awake,
        });
        self.retry_at = retry_at;
        return .{ .retrying = .{
            .failure = failure,
            .deadline = retry_at,
            .consecutive_failures = self.failures,
        } };
    }

    fn dropWatch(self: *ReconnectingWatch) void {
        if (self.watch) |*watch| watch.deinit();
        self.watch = null;
    }
};

fn expired(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    return deadline.clock != .awake or deadline.durationFromNow(io).raw.nanoseconds <= 0;
}

test {
    _ = @import("reconnecting_tests.zig");
    _ = @import("configured_tests.zig");
}
