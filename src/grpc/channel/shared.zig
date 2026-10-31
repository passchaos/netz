//! Reference-counted send handles and concurrent background endpoint owners.
const std = @import("std");
const channel = @import("../channel.zig");
const call = @import("../call.zig");
const connectivity = @import("connectivity.zig");
const state_module = @import("shared/state.zig");
const State = state_module.State;
const streaming = @import("../stream/runtime.zig");
pub const Duplex = @import("shared/stream.zig").Duplex;
pub const StreamWriter = @import("shared/stream.zig").Writer;
pub const StreamOwnedWriteMessage = @import("shared/stream.zig").OwnedWriteMessage;
pub const StreamReader = @import("shared/stream.zig").Reader;
pub const StreamEvent = @import("shared/stream.zig").Event;
pub const Error = state_module.Error;
pub const Options = state_module.Options;
pub const KeepAliveOptions = @import("shared/keepalive.zig").Options;
pub const KeepAliveStats = @import("shared/keepalive.zig").Stats;
pub const HedgingStats = state_module.State.HedgingStats;
pub const OrcaOobOptions = @import("shared/orca/config.zig").Options;
pub const OrcaOobWatch = state_module.orca_tracker.Watch;
pub const OrcaOobUpdate = state_module.orca_tracker.Update;
pub const OrcaOobStatus = state_module.orca_tracker.Status;
pub const Update = @import("shared/update.zig").Update;

pub const Sender = struct {
    state: *State,
    pub fn clone(self: Sender) Sender {
        self.state.retain();
        return self;
    }
    pub fn deinit(self: *Sender) void {
        self.state.release();
        self.* = undefined;
    }
    pub fn unary(self: Sender, options: call.UnaryCallOptions) Error!call.UnaryResponse {
        return self.unaryResolved(options, null, null);
    }
    pub fn unaryWithRetry(self: Sender, options: call.UnaryCallOptions, policy: call.RetryPolicy) Error!call.UnaryResponse {
        return self.unaryResolved(options, policy, null);
    }
    pub fn unaryWithHedging(self: Sender, options: call.UnaryCallOptions, policy: call.HedgingPolicy) Error!call.UnaryResponse {
        return self.unaryResolved(options, null, policy);
    }
    pub fn startDuplex(self: Sender, options: streaming.RequestOptions) Error!Duplex {
        const entered = std.Io.Clock.awake.now(self.state.io);
        return .{ .call = try @import("shared/stream/open.zig").open(self.state, options, entered) };
    }
    fn unaryResolved(self: Sender, options: call.UnaryCallOptions, retry_policy: ?call.RetryPolicy, hedging_policy: ?call.HedgingPolicy) Error!call.UnaryResponse {
        const entered = std.Io.Clock.awake.now(self.state.io);
        if (options.message.len > options.requestMessageLimit()) return error.GrpcMessageTooLarge;
        _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
        try call.validateCustomMetadata(options.metadata);
        try call.validateCustomBinaryMetadata(options.binary_metadata);
        return self.state.unary(
            options,
            retry_policy,
            hedging_policy,
            entered,
        );
    }
};

pub const SharedChannel = struct {
    state: *State,
    pub fn init(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: Options) Error!SharedChannel {
        return .{ .state = try @import("shared/init.zig").create(allocator, io, target, options) };
    }
    pub fn sender(self: SharedChannel) Sender {
        self.state.retain();
        return .{ .state = self.state };
    }
    pub fn connect(self: SharedChannel) void {
        self.connectUntil(null) catch unreachable;
    }
    pub fn connectWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.connectUntil(deadline);
    }
    pub fn connectWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    fn connectUntil(self: SharedChannel, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (deadline) |until| {
            try self.state.lockBefore(until);
        } else self.state.lock();
        defer self.state.unlock();
        if (self.state.closed) return;
        if (deadline) |until| {
            try self.state.tracker.exitIdleWithDeadline(until);
        } else self.state.tracker.exitIdle();
        self.state.demand = true;
        self.state.wakeAllLocked();
    }
    pub fn watchConnectivity(self: SharedChannel) connectivity.Watch {
        return .init(self.state.tracker);
    }
    pub fn watchConnectivityWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!connectivity.Watch {
        return try .initWithDeadline(self.state.tracker, deadline);
    }
    pub fn watchConnectivityWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!connectivity.Watch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.watchConnectivityWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn connectivityState(self: SharedChannel) connectivity.State {
        return self.state.tracker.snapshot().state;
    }
    /// Lock-free aggregate probe telemetry across current and retired endpoint
    /// connections owned by this SharedChannel.
    pub fn keepAliveStats(self: SharedChannel) KeepAliveStats {
        return self.state.keepalive_counters.snapshot();
    }
    pub fn hedgingStats(self: SharedChannel) HedgingStats {
        return self.state.hedging_counters.snapshot();
    }
    pub fn keepAliveInterval(self: SharedChannel) ?std.Io.Duration {
        return self.state.keepAliveInterval();
    }
    pub fn connectivityStateWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!connectivity.State {
        return (try self.state.tracker.snapshotWithDeadline(deadline)).state;
    }
    pub fn connectivityStateWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!connectivity.State {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectivityStateWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Latest resolver membership; retained cursors still identify their
    /// original endpoint when a later update changes this ordinal.
    pub fn watchEndpointConnectivity(self: SharedChannel, index: usize) ?connectivity.Watch {
        return self.state.watchEndpoint(index);
    }
    pub fn watchEndpointConnectivityWithDeadline(self: SharedChannel, index: usize, deadline: std.Io.Clock.Timestamp) Error!?connectivity.Watch {
        return self.state.watchEndpointWithDeadline(index, deadline);
    }
    pub fn watchEndpointConnectivityWithTimeout(self: SharedChannel, index: usize, timeout: std.Io.Duration) Error!?connectivity.Watch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.watchEndpointConnectivityWithDeadline(index, .fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn watchEndpointOrca(self: SharedChannel, index: usize) ?OrcaOobWatch {
        return self.state.watchEndpointOrca(index);
    }
    pub fn watchEndpointOrcaWithDeadline(
        self: SharedChannel,
        index: usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?OrcaOobWatch {
        return self.state.watchEndpointOrcaWithDeadline(index, deadline);
    }
    pub fn watchEndpointOrcaWithTimeout(
        self: SharedChannel,
        index: usize,
        timeout: std.Io.Duration,
    ) Error!?OrcaOobWatch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.watchEndpointOrcaWithDeadline(index, .fromNow(
            self.state.io,
            .{ .clock = .awake, .raw = timeout },
        ));
    }
    pub fn endpointCount(self: SharedChannel) usize {
        return self.state.endpointCount();
    }
    /// Full configured resolver inventory before the active policy derives
    /// logical/deduplicated endpoint owners.
    pub fn configuredEndpointCount(self: SharedChannel) usize {
        return self.state.configuredEndpointCount();
    }
    pub fn selectionPolicy(self: SharedChannel) channel.SelectionPolicy {
        return self.state.selectionPolicy();
    }
    /// Atomically publish service config and/or resolver endpoints. Endpoint
    /// values are copied; their internal slices retain Channel's target lifetime.
    /// Retained Sender handles adopt new method policy on their next RPC.
    pub fn update(self: SharedChannel, change: Update) Error!u64 {
        return @import("shared/update.zig").apply(self.state, change, null);
    }
    pub fn updateWithDeadline(self: SharedChannel, change: Update, deadline: std.Io.Clock.Timestamp) Error!u64 {
        return @import("shared/update.zig").apply(self.state, change, deadline);
    }
    pub fn updateWithTimeout(self: SharedChannel, change: Update, timeout: std.Io.Duration) Error!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.updateWithDeadline(change, .fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn configurationRevision(self: SharedChannel) u64 {
        self.state.lock();
        defer self.state.unlock();
        return self.state.config_revision;
    }
    pub fn retainedChildCount(self: SharedChannel) usize {
        self.state.lock();
        defer self.state.unlock();
        return self.state.retention.count;
    }
    pub fn endpointCountWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!usize {
        return self.state.endpointCountWithDeadline(deadline);
    }
    pub fn endpointCountWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.endpointCountWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn requestNameResolution(self: SharedChannel) Error!void {
        return self.state.requestNameResolution();
    }
    /// Retry failed endpoint connections and name resolution immediately.
    /// Healthy connections and in-progress attempt deadlines are preserved;
    /// resetting an idle channel does not create connection demand.
    pub fn resetConnectionBackoff(self: SharedChannel) Error!void {
        return @import("shared/backoff_control.zig").reset(self.state, null);
    }
    pub fn resetConnectionBackoffWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!void {
        return @import("shared/backoff_control.zig").reset(self.state, deadline);
    }
    pub fn resetConnectionBackoffWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetConnectionBackoffWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn refreshNameResolutionWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!usize {
        return self.state.refreshNameResolution(deadline);
    }
    pub fn refreshNameResolutionWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.refreshNameResolutionWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn deinit(self: *SharedChannel) void {
        self.state.close();
        self.state.group.cancel(self.state.io);
        self.state.stopResolution();
        self.state.release();
        self.* = undefined;
    }
};

test {
    _ = @import("shared/tests.zig");
    _ = @import("shared/admission_tests.zig");
    _ = @import("shared/retirement_tests.zig");
    _ = @import("shared/job_tests.zig");
    _ = @import("shared/control_deadline_tests.zig");
    _ = @import("shared/backoff_tests.zig");
    _ = @import("shared/update/tests.zig");
    _ = @import("shared/retention/tests.zig");
    _ = @import("shared/keepalive_tests.zig");
    _ = @import("shared/keepalive_throttle_tests.zig");
    _ = @import("shared/resolution/tests.zig");
    _ = @import("shared/stream/tests.zig");
    _ = @import("shared/orca/tracker_tests.zig");
    _ = @import("shared/orca/tests.zig");
    _ = @import("shared/outlier_detection_tests.zig");
    _ = @import("shared/weighted_round_robin_tests.zig");
    _ = @import("shared/hedging_tests.zig");
}
