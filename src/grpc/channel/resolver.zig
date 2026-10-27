//! Background polling resolver state for gRPC host targets.

const std = @import("std");
const address_resolver = @import("../../internal/address_resolver.zig");
const backoff = @import("backoff.zig");

const net = std.Io.net;

pub const AddressResolver = address_resolver.Resolver;
pub const Error = address_resolver.Error;

pub const Result = union(enum) {
    addresses: []net.IpAddress,
    failure: Error,

    fn deinit(self: Result, allocator: std.mem.Allocator) void {
        switch (self) {
            .addresses => |addresses| allocator.free(addresses),
            .failure => {},
        }
    }
};

pub const Published = struct {
    generation: u64,
    result: Result,
};

/// Stable heap state lets the resolver task outlive moves of the public
/// Channel value. Host and custom resolver context remain borrowed for the
/// Channel lifetime; every published address slice is allocator-owned.
pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    resolver: ?AddressResolver,
    minimum_refresh_interval: std.Io.Duration,
    backoff_policy: backoff.Policy,

    mutex: std.Io.Mutex = .init,
    wake: std.Io.Event = .unset,
    result_ready: std.Io.Event = .unset,
    pending: ?Published = null,
    acknowledgement: ?bool = null,
    generation: u64 = 0,
    requested: bool = true,
    reset_backoff: bool = false,
    closed: bool = false,
    started: bool = false,
    future: std.Io.Future(void) = undefined,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        resolver: ?AddressResolver,
        minimum_refresh_interval: std.Io.Duration,
        backoff_policy: backoff.Policy,
    ) (std.mem.Allocator.Error || net.HostName.ValidateError)!*State {
        _ = try net.HostName.init(host);
        const state = try allocator.create(State);
        state.* = .{
            .allocator = allocator,
            .io = io,
            .host = host,
            .port = port,
            .resolver = resolver,
            .minimum_refresh_interval = minimum_refresh_interval,
            .backoff_policy = backoff_policy,
        };
        return state;
    }

    pub fn deinit(self: *State) void {
        const allocator = self.allocator;
        self.mutex.lockUncancelable(self.io);
        self.closed = true;
        self.mutex.unlock(self.io);
        self.wake.set(self.io);
        self.result_ready.set(self.io);
        if (self.started) self.future.cancel(self.io);

        self.mutex.lockUncancelable(self.io);
        const pending = self.pending;
        self.pending = null;
        self.mutex.unlock(self.io);
        if (pending) |published| published.result.deinit(allocator);
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn start(self: *State) bool {
        self.mutex.lockUncancelable(self.io);
        if (self.started or self.closed) {
            self.mutex.unlock(self.io);
            return false;
        }
        self.started = true;
        self.mutex.unlock(self.io);
        self.future = self.io.async(run, .{self});
        return true;
    }

    pub fn requestRefresh(self: *State) void {
        if (self.start()) return;
        self.mutex.lockUncancelable(self.io);
        if (!self.closed) self.requested = true;
        self.mutex.unlock(self.io);
        self.wake.set(self.io);
    }

    pub fn resetBackoff(self: *State) void {
        if (self.start()) return;
        self.mutex.lockUncancelable(self.io);
        if (!self.closed) {
            self.requested = true;
            self.reset_backoff = true;
        }
        self.mutex.unlock(self.io);
        self.wake.set(self.io);
    }

    pub fn currentGeneration(self: *State) u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.generation;
    }

    pub fn takePublished(self: *State) ?Published {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const published = self.pending orelse return null;
        self.pending = null;
        self.result_ready.reset();
        return published;
    }

    pub fn acknowledge(self: *State, accepted: bool) void {
        self.mutex.lockUncancelable(self.io);
        if (!self.closed) self.acknowledgement = accepted;
        self.mutex.unlock(self.io);
        self.wake.set(self.io);
    }

    pub fn resultEvent(self: *State) *std.Io.Event {
        return &self.result_ready;
    }

    fn run(self: *State) void {
        var consecutive_failures: usize = 0;
        var last_attempt_at_ns: ?i96 = null;
        var retrying = false;
        while (true) {
            if (!retrying) {
                if (!self.waitForRequest()) return;
                if (last_attempt_at_ns) |last| {
                    const earliest = last +
                        self.minimum_refresh_interval.nanoseconds;
                    if (!self.waitUntil(earliest, true)) return;
                } else self.clearResetBackoff();
            }
            if (self.isClosed()) return;
            last_attempt_at_ns = std.Io.Clock.awake.now(self.io).nanoseconds;

            const addresses = self.resolve() catch |err| {
                if (self.isClosed()) return;
                self.publish(.{ .failure = err });
                _ = self.waitForAcknowledgement() orelse return;
                consecutive_failures +|= 1;
                const retry_at = std.Io.Clock.awake.now(self.io)
                    .addDuration(self.backoff_policy.delay(
                        consecutive_failures,
                        self.randomSample(),
                    )).nanoseconds;
                if (!self.waitUntil(retry_at, true)) return;
                self.clearRequested();
                retrying = true;
                continue;
            };
            if (self.isClosed()) {
                self.allocator.free(addresses);
                return;
            }
            self.publish(.{ .addresses = addresses });
            if (!(self.waitForAcknowledgement() orelse return)) {
                consecutive_failures +|= 1;
                const retry_at = std.Io.Clock.awake.now(self.io)
                    .addDuration(self.backoff_policy.delay(
                        consecutive_failures,
                        self.randomSample(),
                    )).nanoseconds;
                if (!self.waitUntil(retry_at, true)) return;
                self.clearRequested();
                retrying = true;
                continue;
            }
            consecutive_failures = 0;
            retrying = false;
        }
    }

    fn resolve(self: *State) Error![]net.IpAddress {
        if (self.resolver) |configured| {
            return configured.resolve(
                configured.context,
                self.allocator,
                self.io,
                self.host,
                self.port,
                null,
            );
        }
        return address_resolver.resolveSystem(
            self.allocator,
            self.io,
            self.host,
            self.port,
            null,
        );
    }

    fn publish(self: *State, result: Result) void {
        self.mutex.lockUncancelable(self.io);
        if (self.closed) {
            self.mutex.unlock(self.io);
            result.deinit(self.allocator);
            return;
        }
        const previous = self.pending;
        self.generation +%= 1;
        self.acknowledgement = null;
        self.pending = .{ .generation = self.generation, .result = result };
        self.mutex.unlock(self.io);
        if (previous) |published| published.result.deinit(self.allocator);
        self.result_ready.set(self.io);
    }

    fn waitForRequest(self: *State) bool {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.mutex.unlock(self.io);
                return false;
            }
            if (self.requested) {
                self.requested = false;
                self.mutex.unlock(self.io);
                return true;
            }
            self.wake.reset();
            self.mutex.unlock(self.io);
            self.wake.wait(self.io) catch return false;
        }
    }

    fn waitForAcknowledgement(self: *State) ?bool {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.mutex.unlock(self.io);
                return null;
            }
            if (self.acknowledgement) |accepted| {
                self.acknowledgement = null;
                self.mutex.unlock(self.io);
                return accepted;
            }
            self.wake.reset();
            self.mutex.unlock(self.io);
            self.wake.wait(self.io) catch return null;
        }
    }

    fn waitUntil(
        self: *State,
        target_ns: i96,
        reset_may_bypass: bool,
    ) bool {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.mutex.unlock(self.io);
                return false;
            }
            const reset = self.reset_backoff;
            self.reset_backoff = false;
            self.wake.reset();
            self.mutex.unlock(self.io);
            if (reset_may_bypass and reset) return true;

            const remaining_ns = target_ns -
                std.Io.Clock.awake.now(self.io).nanoseconds;
            if (remaining_ns <= 0) return true;
            self.wake.waitTimeout(self.io, .{ .duration = .{
                .raw = .fromNanoseconds(remaining_ns),
                .clock = .awake,
            } }) catch |err| switch (err) {
                error.Timeout => continue,
                error.Canceled => return false,
            };
        }
    }

    fn clearRequested(self: *State) void {
        self.mutex.lockUncancelable(self.io);
        self.requested = false;
        self.mutex.unlock(self.io);
    }

    fn clearResetBackoff(self: *State) void {
        self.mutex.lockUncancelable(self.io);
        self.reset_backoff = false;
        self.mutex.unlock(self.io);
    }

    fn isClosed(self: *State) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.closed;
    }

    fn randomSample(self: *State) u64 {
        if (self.backoff_policy.jitter == 0) return 0;
        var bytes: [8]u8 = undefined;
        self.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }
};
