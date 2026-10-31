//! Lazy, reconnecting gRPC channel with fail-fast and wait-for-ready calls.
const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");
const retry = @import("call/retry.zig");
const orca = @import("orca.zig");
const service_config = @import("service_config.zig");
const streaming = @import("stream/runtime.zig");
const duplex = @import("stream/duplex.zig");
const completion = @import("stream/completion.zig");
const wire = @import("wire.zig");
const backoff = @import("channel/backoff.zig");
const connectivity = @import("channel/connectivity.zig");
const resolver = @import("channel/resolver.zig");
const endpoint_host = @import("../internal/endpoint_host.zig");
const connect_race = @import("channel/connect_race.zig");
const weighted_round_robin = @import("channel/weighted_round_robin.zig");
const outlier_detection = @import("channel/outlier_detection.zig");
const ConnectAllocator = @import("channel/connect_race/allocator.zig").Guard;

const net = std.Io.net;

pub const BackoffPolicy = backoff.Policy;
pub const AddressResolver = resolver.AddressResolver;

pub const Error = streaming.Error || resolver.Error || error{
    InvalidChannelOptions,
    ChannelBusy,
    ConnectionUnavailable,
    Canceled,
};

pub const CustomConnector = struct {
    context: ?*anyopaque,
    connect_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection,
    retryable_fn: ?*const fn (
        context: ?*anyopaque,
        err: anyerror,
    ) bool = null,
};

pub const SelectionPolicy = enum {
    pick_first,
    round_robin,
    weighted_round_robin,
};

pub const ConnectivityState = connectivity.State;
pub const ConnectivitySnapshot = connectivity.Snapshot;
pub const ConnectivityWatch = connectivity.Watch;

/// One pre-resolved backend. Every slice and custom context is borrowed for
/// the Channel lifetime; the Channel owns only established HTTP/2 state.
pub const Endpoint = union(enum) {
    cleartext_ip: struct {
        address: net.IpAddress,
        /// Optional logical authority retained across address resolution.
        authority: ?[]const u8 = null,
        limits: http2.runtime.Limits = .{},
    },
    cleartext_host: struct {
        /// DNS name or IP literal. IPv6 accepts bare or bracketed text;
        /// `port` remains a separate argument.
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
    },
    tls_host: struct {
        /// DNS/IP certificate identity, independent of a custom resolver's
        /// selected socket address. IPv6 brackets are removed for TLS.
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    tls_address: struct {
        address: net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    custom: CustomConnector,

    fn connect(
        self: Endpoint,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection {
        return switch (self) {
            .cleartext_ip => |target| blk: {
                var connection = try http2.runtime.Client.connectWithDeadline(
                    allocator,
                    io,
                    target.address,
                    target.limits,
                    deadline,
                );
                errdefer connection.close();
                if (target.authority) |authority| {
                    try connection.replaceDefaultAuthority(authority);
                }
                break :blk connection;
            },
            .cleartext_host => |target| http2.runtime.Client.connectHostWithDeadline(
                allocator,
                io,
                target.host,
                target.port,
                target.limits,
                deadline,
            ),
            .tls_host => |target| http2.runtime.Client.connectTlsHostWithDeadline(
                allocator,
                io,
                target.host,
                target.port,
                target.limits,
                target.tls,
                deadline,
            ),
            .tls_address => |target| http2.runtime.Client.connectTlsAddressWithDeadline(
                allocator,
                io,
                target.address,
                target.tls_host,
                target.authority,
                target.limits,
                target.tls,
                deadline,
            ),
            .custom => |target| target.connect_fn(
                target.context,
                allocator,
                io,
                deadline,
            ),
        };
    }

    fn retryable(self: Endpoint, err: anyerror) bool {
        return switch (self) {
            .custom => |target| if (target.retryable_fn) |classify|
                classify(target.context, err)
            else
                retryableConnectError(err),
            else => retryableConnectError(err),
        };
    }

    fn validate(self: Endpoint) error{InvalidChannelOptions}!void {
        const enables_push = switch (self) {
            .cleartext_ip => |target| target.limits.enable_push,
            .cleartext_host => |target| target.limits.enable_push,
            .tls_host => |target| target.limits.enable_push,
            .tls_address => |target| target.limits.enable_push,
            .custom => false,
        };
        if (enables_push) return error.InvalidChannelOptions;
    }
};

/// Target configuration is borrowed for the Channel lifetime. Existing
/// single-target forms remain source-compatible; `resolved` adds a non-empty
/// endpoint list and a picker policy.
pub const Target = union(enum) {
    cleartext_ip: @FieldType(Endpoint, "cleartext_ip"),
    cleartext_host: @FieldType(Endpoint, "cleartext_host"),
    tls_host: @FieldType(Endpoint, "tls_host"),
    tls_address: @FieldType(Endpoint, "tls_address"),
    custom: CustomConnector,
    resolved: struct {
        endpoints: []const Endpoint,
        policy: SelectionPolicy = .pick_first,
    },

    fn count(self: Target) usize {
        return switch (self) {
            .resolved => |set| set.endpoints.len,
            else => 1,
        };
    }

    fn endpoint(self: Target, index: usize) Endpoint {
        return switch (self) {
            .cleartext_ip => |value| .{ .cleartext_ip = value },
            .cleartext_host => |value| .{ .cleartext_host = value },
            .tls_host => |value| .{ .tls_host = value },
            .tls_address => |value| .{ .tls_address = value },
            .custom => |value| .{ .custom = value },
            .resolved => |set| set.endpoints[index],
        };
    }

    fn policy(self: Target) SelectionPolicy {
        return switch (self) {
            .resolved => |set| set.policy,
            else => .pick_first,
        };
    }

    fn validate(self: Target) error{InvalidChannelOptions}!void {
        if (self.count() == 0) return error.InvalidChannelOptions;
        for (0..self.count()) |index| try self.endpoint(index).validate();
    }
};

pub const Options = struct {
    backoff: BackoffPolicy = .{},
    /// Null uses the resolved target policy (pick_first for single targets).
    selection_policy: ?SelectionPolicy = null,
    /// Null keeps resolver order; a service config may request shuffling.
    shuffle_address_list: ?bool = null,
    /// Optional asynchronous resolver for hostname targets. Its returned
    /// address slice is owned by the allocator passed to the callback.
    address_resolver: ?AddressResolver = null,
    /// gRPC DNS re-resolution cooldown; failures independently use backoff.
    resolver_min_refresh_interval: std.Io.Duration = .fromSeconds(30),
    /// Start another endpoint after this delay while earlier handshakes are
    /// pending. Null selects serial connection attempts. The default follows
    /// grpc-core pick_first's 250 ms Happy Eyeballs pass.
    connection_attempt_delay: ?std.Io.Duration = .fromMilliseconds(250),

    pub fn validate(self: Options) error{InvalidChannelOptions}!void {
        try self.backoff.validate();
        if (self.resolver_min_refresh_interval.nanoseconds < 0) return error.InvalidChannelOptions;
        if (self.connection_attempt_delay) |delay| if (delay.nanoseconds <= 0) return error.InvalidChannelOptions;
    }
};

const Slot = struct {
    endpoint: Endpoint,
    connection: ?http2.runtime.Connection = null,
    consecutive_failures: usize = 0,
    next_attempt_at_ns: ?i96 = null,
    disabled: bool = false,
    wrr_weight: weighted_round_robin.Weight = .{},
    outlier: outlier_detection.Endpoint = .{},

    fn closeConnection(self: *Slot) void {
        if (self.connection) |*connection| connection.close();
        self.connection = null;
        self.wrr_weight.disconnected();
    }

    fn resetBackoff(self: *Slot) void {
        self.consecutive_failures = 0;
        self.next_attempt_at_ns = null;
        self.disabled = false;
    }
};

const ReadyConnection = struct {
    index: usize,
    connection: *http2.runtime.Connection,
};

const HostResolution = struct {
    state: *resolver.State,
    authority: []u8,
    transport: union(enum) {
        cleartext: struct {
            limits: http2.runtime.Limits,
        },
        tls: struct {
            host: []const u8,
            limits: http2.runtime.Limits,
            options: http2.runtime.TlsConnectOptions,
        },
    },

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
    ) Error!?HostResolution {
        const host: []const u8, const port: u16, var transport = switch (target) {
            .cleartext_host => |value| .{
                value.host,
                value.port,
                @FieldType(HostResolution, "transport"){
                    .cleartext = .{ .limits = value.limits },
                },
            },
            .tls_host => |value| .{
                value.host,
                value.port,
                @FieldType(HostResolution, "transport"){ .tls = .{
                    .host = value.host,
                    .limits = value.limits,
                    .options = value.tls,
                } },
            },
            else => return null,
        };
        if (port == 0) return error.InvalidChannelOptions;
        const parsed = try endpoint_host.parse(host, port);
        if (transport == .tls) transport.tls.host = parsed.host;
        const authority = try parsed.authorityAlloc(allocator, port);
        errdefer allocator.free(authority);
        const state = try resolver.State.create(
            allocator,
            io,
            host,
            port,
            options.address_resolver,
            options.resolver_min_refresh_interval,
            options.backoff,
        );
        return .{
            .state = state,
            .authority = authority,
            .transport = transport,
        };
    }

    fn deinit(self: *HostResolution, allocator: std.mem.Allocator) void {
        self.state.deinit();
        allocator.free(self.authority);
        self.* = undefined;
    }

    fn endpoint(self: *const HostResolution, address: net.IpAddress) Endpoint {
        return switch (self.transport) {
            .cleartext => |value| .{ .cleartext_ip = .{
                .address = address,
                .authority = self.authority,
                .limits = value.limits,
            } },
            .tls => |value| .{ .tls_address = .{
                .address = address,
                .tls_host = value.host,
                .authority = self.authority,
                .limits = value.limits,
                .tls = value.options,
            } },
        };
    }

    fn endpointAddress(
        self: *const HostResolution,
        candidate: Endpoint,
    ) ?net.IpAddress {
        return switch (self.transport) {
            .cleartext => switch (candidate) {
                .cleartext_ip => |value| value.address,
                else => null,
            },
            .tls => switch (candidate) {
                .tls_address => |value| value.address,
                else => null,
            },
        };
    }
};

/// A single-owner gRPC channel. It reconnects before a call begins but never
/// replays an RPC merely because `wait_for_ready` was set. Explicit gRPC retry
/// policy and transparent REFUSED_STREAM recovery remain separate call logic.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    slots: []Slot,
    selection_policy: SelectionPolicy,
    backoff_policy: BackoffPolicy,
    shuffle_address_list: bool,
    connection_attempt_delay: ?std.Io.Duration,
    connect_allocator: ?*ConnectAllocator = null,
    host_resolution: ?HostResolution = null,
    connectivity_tracker: *connectivity.Tracker,
    selected_index: ?usize = null,
    next_pick_index: usize = 0,
    wrr_config: ?service_config.WeightedRoundRobinConfig = null,
    wrr_metric_names: ?[][]u8 = null,
    wrr_sequence: u32 = 0,
    wrr_scheduler: weighted_round_robin.Scheduler = .{},
    outlier_config: ?service_config.OutlierDetectionConfig = null,
    outlier_next_evaluation_ns: ?i96 = null,
    canceled: std.Io.Event = .unset,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
    ) Error!Channel {
        try options.validate();
        try target.validate();
        var host_resolution = try HostResolution.init(
            allocator,
            io,
            target,
            options,
        );
        errdefer if (host_resolution) |*value| value.deinit(allocator);
        if (options.address_resolver != null and host_resolution == null) {
            return error.InvalidChannelOptions;
        }
        const slots = try allocator.alloc(
            Slot,
            if (host_resolution == null) target.count() else 0,
        );
        errdefer allocator.free(slots);
        const connectivity_tracker = try connectivity.Tracker.create(
            allocator,
            io,
        );
        errdefer connectivity_tracker.release();
        if (host_resolution == null) {
            for (slots, 0..) |*slot, index| {
                slot.* = .{ .endpoint = target.endpoint(index) };
            }
        }
        var result = Channel{
            .allocator = allocator,
            .io = io,
            .slots = slots,
            .selection_policy = options.selection_policy orelse
                target.policy(),
            .backoff_policy = options.backoff,
            .shuffle_address_list = options.shuffle_address_list orelse false,
            .connection_attempt_delay = options.connection_attempt_delay,
            .host_resolution = host_resolution,
            .connectivity_tracker = connectivity_tracker,
        };
        if (result.shuffle_address_list) result.shuffleSlots();
        return result;
    }

    pub fn initWithServiceConfig(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
        config: *const service_config.ServiceConfig,
    ) Error!Channel {
        return initWithServiceConfigMode(
            allocator,
            io,
            target,
            options,
            config,
            false,
        );
    }

    /// SharedChannel owns composite endpoint policy outside each child
    /// transport Channel. Keep method/retry configuration on the child while
    /// allowing the outer owner to apply outlier detection exactly once.
    pub fn initWithServiceConfigChild(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
        config: *const service_config.ServiceConfig,
    ) Error!Channel {
        return initWithServiceConfigMode(
            allocator,
            io,
            target,
            options,
            config,
            true,
        );
    }

    fn initWithServiceConfigMode(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
        config: *const service_config.ServiceConfig,
        composite_owned: bool,
    ) Error!Channel {
        const balancing = config.loadBalancingConfig();
        var resolved = options;
        if (resolved.selection_policy == null and balancing.configured) {
            resolved.selection_policy = switch (balancing.policy) {
                .pick_first => .pick_first,
                .round_robin => .round_robin,
                .weighted_round_robin => .weighted_round_robin,
            };
        }
        if (resolved.shuffle_address_list == null and balancing.configured) {
            resolved.shuffle_address_list = balancing.shuffle_address_list;
        }
        var result = try init(allocator, io, target, resolved);
        errdefer result.deinit();
        if (result.selection_policy == .weighted_round_robin and
            balancing.policy == .weighted_round_robin)
        {
            try result.setWeightedRoundRobinConfig(
                balancing.weighted_round_robin,
            );
        }
        if (!composite_owned) if (balancing.outlier_detection) |outlier| {
            result.outlier_config = outlier;
            if (outlier.countingEnabled()) {
                result.outlier_next_evaluation_ns =
                    std.Io.Clock.awake.now(io).addDuration(
                        .fromNanoseconds(@max(outlier.interval.nanoseconds, 1)),
                    ).nanoseconds;
            }
        };
        return result;
    }

    pub fn deinit(self: *Channel) void {
        self.connectivity_tracker.setState(.shutdown);
        if (self.host_resolution) |*resolution| {
            resolution.deinit(self.allocator);
        }
        for (self.slots) |*slot| slot.closeConnection();
        self.allocator.free(self.slots);
        self.wrr_scheduler.deinit(self.allocator);
        if (self.wrr_metric_names) |names| {
            for (names) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        if (self.connect_allocator) |guard| self.allocator.destroy(guard);
        self.connectivity_tracker.release();
        self.* = undefined;
    }

    /// Interrupt current or future wait-for-ready backoff. In-progress socket
    /// connection attempts retain their bounded attempt deadline.
    pub fn cancelWaits(self: *Channel) void {
        self.canceled.set(self.io);
    }

    /// Re-enable waits after the caller has joined every canceled operation.
    pub fn resetCancellation(self: *Channel) void {
        self.canceled.reset();
    }

    pub fn resetConnectionBackoff(self: *Channel) void {
        for (self.slots) |*slot| slot.resetBackoff();
        if (self.host_resolution) |*resolution| {
            resolution.state.resetBackoff();
        }
        if (self.connectivityState() == .transient_failure) {
            self.setConnectivityState(.connecting);
        }
    }

    pub fn connectivityState(self: *const Channel) ConnectivityState {
        return self.connectivity_tracker.snapshot().state;
    }

    pub fn connectivitySnapshot(self: *const Channel) ConnectivitySnapshot {
        return self.connectivity_tracker.snapshot();
    }

    /// Return an independent cursor that may wait concurrently and remains
    /// valid through Channel deinitialization until the watch is released.
    pub fn watchConnectivity(self: *const Channel) ConnectivityWatch {
        return .init(self.connectivity_tracker);
    }

    /// Leave lazy IDLE state. Host targets begin resolution; connection
    /// establishment remains owned by the next warm or RPC operation.
    pub fn exitIdle(self: *Channel) void {
        if (self.connectivityState() == .idle) {
            self.setConnectivityState(.connecting);
        }
        if (self.host_resolution) |*resolution| {
            _ = resolution.state.start();
        }
    }

    /// Ask a polling hostname resolver for a fresh result. Requests coalesce
    /// and honor the configured minimum interval.
    pub fn requestNameResolution(self: *Channel) Error!void {
        const resolution = if (self.host_resolution) |*value|
            value
        else
            return error.InvalidChannelOptions;
        const was_idle = self.connectivityState() == .idle;
        self.exitIdle();
        if (!was_idle) resolution.state.requestRefresh();
    }

    pub fn refreshNameResolutionWithDeadline(
        self: *Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (self.canceled.isSet()) return error.Canceled;
        if (deadlineExpired(self.io, deadline)) return error.Timeout;
        try self.prepareSlots();
        const resolution = if (self.host_resolution) |*value|
            value
        else
            return error.InvalidChannelOptions;
        const was_idle = self.connectivityState() == .idle;
        var previous = resolution.state.currentGeneration();
        self.exitIdle();
        if (!was_idle) {
            if (resolution.state.resultEvent().isSet()) {
                _ = try self.applyPendingResolution(true);
                return self.slots.len;
            }
            previous = resolution.state.currentGeneration();
            resolution.state.requestRefresh();
        }
        while (resolution.state.currentGeneration() == previous) {
            try self.waitForProgress(deadline);
            if (self.canceled.isSet()) return error.Canceled;
        }
        _ = try self.applyPendingResolution(true);
        return self.slots.len;
    }

    pub fn refreshNameResolutionWithTimeout(
        self: *Channel,
        timeout: std.Io.Duration,
    ) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.refreshNameResolutionWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn connected(self: *Channel) ?*http2.runtime.Connection {
        const index = self.selected_index orelse return null;
        if (self.slots[index].connection) |*connection| return connection;
        return null;
    }

    /// Close established transports after all borrowed stream handles retire.
    /// A background owner uses this seam before reconnecting its subchannel.
    pub fn disconnect(self: *Channel) Error!void {
        for (self.slots) |*slot| {
            if (slot.connection) |*connection| {
                if (connection.activeLocalStreamCount() != 0 or connection.activeClientDuplexCount() != 0 or connection.activePeerStreamCount() != 0) return error.ChannelBusy;
            }
        }
        for (self.slots) |*slot| slot.closeConnection();
        self.selected_index = null;
        self.setConnectivityState(.transient_failure);
    }

    /// Establish/select a quiescent connection without starting an RPC.
    /// The caller borrows it until stream teardown; other Channel operations
    /// must wait for that stream to release ownership. Connection failures
    /// retain their original cause rather than becoming a warm-count result.
    pub fn connectWithDeadline(
        self: *Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*http2.runtime.Connection {
        if (deadline.clock != .awake) return error.Timeout;
        return (try self.ready(false, deadline)).connection;
    }

    pub fn negotiatedAlpn(self: *Channel) ?[]const u8 {
        const connection = self.connected() orelse return null;
        return connection.negotiatedAlpn();
    }

    pub fn peerCertificates(self: *Channel) ?[]const []const u8 {
        const connection = self.connected() orelse return null;
        return connection.peerCertificates();
    }

    pub fn selectionPolicy(self: *const Channel) SelectionPolicy {
        return self.selection_policy;
    }

    /// Establish as many endpoint connections as possible within one absolute
    /// deadline. Round-robin calls select only among these READY connections;
    /// a slow unconnected sibling never delays a call while another is ready.
    pub fn warmWithDeadline(
        self: *Channel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        if (self.canceled.isSet()) return error.Canceled;
        self.exitIdle();
        try self.prepareSlots();
        try self.ensureHostResolution(false, deadline);
        var ready_count: usize = 0;
        for (self.slots, 0..) |*slot, index| {
            if (slot.connection != null) {
                self.noteWarmedConnection(index);
                ready_count += 1;
                continue;
            }
            if (slot.disabled or !slotMayAttempt(slot, self.io)) continue;
            const attempt_deadline = self.connectDeadline(deadline) catch |err| {
                if (ready_count != 0 and err == error.Timeout) {
                    self.setConnectivityState(.ready);
                    return ready_count;
                }
                return err;
            };
            slot.connection = slot.endpoint.connect(
                self.allocator,
                self.io,
                attempt_deadline,
            ) catch |err| {
                if (slot.endpoint.retryable(err)) {
                    slot.consecutive_failures +|= 1;
                    self.scheduleBackoff(slot);
                } else {
                    slot.disabled = true;
                }
                if (deadlineExpired(self.io, deadline)) {
                    if (ready_count != 0) {
                        self.setConnectivityState(.ready);
                        return ready_count;
                    }
                    return error.Timeout;
                }
                continue;
            };
            slot.resetBackoff();
            self.noteWarmedConnection(index);
            ready_count += 1;
        }
        if (ready_count == 0) {
            self.setConnectivityState(.transient_failure);
            if (self.host_resolution) |*resolution| {
                resolution.state.requestRefresh();
            }
            return error.ConnectionUnavailable;
        }
        self.setConnectivityState(.ready);
        return ready_count;
    }

    pub fn warmWithTimeout(
        self: *Channel,
        timeout: std.Io.Duration,
    ) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.warmWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn unary(
        self: *Channel,
        options: call.UnaryCallOptions,
    ) Error!call.UnaryResponse {
        return self.unaryResolved(.{
            .options = options,
            .retry_policy = null,
            .wait_for_ready = options.wait_for_ready orelse false,
        });
    }

    pub fn unaryWithRetry(
        self: *Channel,
        options: call.UnaryCallOptions,
        retry_policy: call.RetryPolicy,
    ) Error!call.UnaryResponse {
        return self.unaryResolved(.{
            .options = options,
            .retry_policy = retry_policy,
            .wait_for_ready = options.wait_for_ready orelse false,
        });
    }

    pub fn unaryWithServiceConfig(
        self: *Channel,
        options: call.UnaryCallOptions,
        config: *service_config.ServiceConfig,
    ) Error!call.UnaryResponse {
        return self.unaryResolved(try config.resolveUnary(options));
    }

    fn unaryResolved(
        self: *Channel,
        resolved: service_config.ResolvedUnary,
    ) Error!call.UnaryResponse {
        const deadline = callDeadline(self.io, resolved.options.timeout);
        var options = resolved.options;
        options.wait_for_ready = resolved.wait_for_ready;
        return retry.runWithDeadline(
            self,
            self.allocator,
            options,
            resolved.retry_policy,
            deadline,
            unaryAttempt,
        );
    }

    fn unaryAttempt(
        self: *Channel,
        allocator: std.mem.Allocator,
        options: call.UnaryCallOptions,
        attempt_deadline: ?std.Io.Clock.Timestamp,
        rpc_deadline: ?std.Io.Clock.Timestamp,
        _: ?wire.Timeout,
        previous_attempts: ?u8,
    ) Error!call.UnaryResponse {
        const ready_connection = try self.ready(
            options.wait_for_ready orelse false,
            attempt_deadline,
        );
        const timeout_header: ?wire.Timeout = if (rpc_deadline) |absolute| blk: {
            const remaining = absolute.durationFromNow(self.io).raw;
            if (remaining.nanoseconds <= 0) return error.Timeout;
            break :blk try wire.Timeout.fromDuration(remaining);
        } else null;
        var response = call.unaryCallAttempt(
            ready_connection.connection,
            allocator,
            options,
            attempt_deadline,
            timeout_header,
            previous_attempts,
        ) catch |err| {
            self.recordOutlier(ready_connection.index, false);
            if (err == error.Timeout) {
                self.slots[ready_connection.index].closeConnection();
            }
            self.retireAfterOperationError(ready_connection.index, err);
            return err;
        };
        self.recordOutlier(ready_connection.index, response.status == .ok);
        self.observeWrr(ready_connection.index, &response);
        return response;
    }

    pub fn startStreaming(
        self: *Channel,
        options: streaming.RequestOptions,
    ) Error!streaming.ClientWriter {
        return self.startStreamingResolved(.{
            .options = options,
            .wait_for_ready = options.wait_for_ready orelse false,
        });
    }

    pub fn startStreamingWithServiceConfig(
        self: *Channel,
        options: streaming.RequestOptions,
        config: *service_config.ServiceConfig,
    ) Error!streaming.ClientWriter {
        return self.startStreamingResolved(
            try config.resolveStreaming(options),
        );
    }

    fn startStreamingResolved(
        self: *Channel,
        resolved: service_config.ResolvedStreaming,
    ) Error!streaming.ClientWriter {
        const deadline = callDeadline(self.io, resolved.options.timeout);
        const ready_connection = try self.ready(
            resolved.wait_for_ready,
            deadline,
        );
        var writer = streaming.startClientUnderDeadline(
            ready_connection.connection,
            self.allocator,
            resolved.options,
            deadline,
        ) catch |err| {
            self.recordOutlier(ready_connection.index, false);
            self.retireAfterOperationError(ready_connection.index, err);
            return err;
        };
        errdefer {
            self.recordOutlier(ready_connection.index, false);
            writer.deinit();
        }
        if (try self.outlierCompletionObserver(ready_connection.index)) |observer| {
            writer.setCompletionObserver(observer);
        }
        return writer;
    }

    pub fn startDuplex(
        self: *Channel,
        options: streaming.RequestOptions,
    ) Error!duplex.ClientDuplex {
        return self.startDuplexResolved(.{
            .options = options,
            .wait_for_ready = options.wait_for_ready orelse false,
        });
    }

    pub fn startDuplexWithServiceConfig(
        self: *Channel,
        options: streaming.RequestOptions,
        config: *service_config.ServiceConfig,
    ) Error!duplex.ClientDuplex {
        return self.startDuplexResolved(try config.resolveStreaming(options));
    }

    fn startDuplexResolved(
        self: *Channel,
        resolved: service_config.ResolvedStreaming,
    ) Error!duplex.ClientDuplex {
        const deadline = callDeadline(self.io, resolved.options.timeout);
        const ready_connection = try self.ready(
            resolved.wait_for_ready,
            deadline,
        );
        var stream = duplex.startDuplexUnderDeadline(
            ready_connection.connection,
            self.allocator,
            resolved.options,
            deadline,
        ) catch |err| {
            self.recordOutlier(ready_connection.index, false);
            self.retireAfterOperationError(ready_connection.index, err);
            return err;
        };
        errdefer {
            self.recordOutlier(ready_connection.index, false);
            stream.deinit();
        }
        if (try self.outlierCompletionObserver(ready_connection.index)) |observer| {
            stream.setCompletionObserver(observer);
        }
        return stream;
    }

    fn ready(
        self: *Channel,
        wait_for_ready: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ReadyConnection {
        if (self.canceled.isSet()) return error.Canceled;
        self.exitIdle();
        errdefer if (!self.hasReadyConnection()) self.setConnectivityState(.transient_failure);
        try self.prepareSlots();
        self.evaluateOutliers();
        try self.ensureHostResolution(wait_for_ready, deadline);
        if (self.selection_policy == .weighted_round_robin and
            self.wrr_config != null)
        {
            if (self.pickReadyWeighted()) |ready_connection| {
                return ready_connection;
            }
        }
        if (self.selection_policy != .pick_first) {
            if (self.pickReadyRoundRobin()) |ready_connection| {
                return ready_connection;
            }
        }

        while (true) {
            if (self.canceled.isSet()) return error.Canceled;
            _ = try self.applyPendingResolution(false);
            self.evaluateOutliers();
            if (self.selection_policy == .weighted_round_robin and
                self.wrr_config != null)
            {
                if (self.pickReadyWeighted()) |ready_connection| {
                    return ready_connection;
                }
            }
            if (self.selection_policy != .pick_first) {
                if (self.pickReadyRoundRobin()) |ready_connection| {
                    return ready_connection;
                }
            }
            var retryable_failure = self.hasEjectedSlots();
            const start = self.pickStart();
            if (self.connection_attempt_delay) |delay| {
                if (self.slots.len > 1) {
                    for (0..self.slots.len) |offset| {
                        const index = (start + offset) % self.slots.len;
                        if (self.slots[index].outlier.isEjected()) continue;
                        if (self.slots[index].connection) |*connection| return self.select(index, connection);
                    }
                    var retryable: std.atomic.Value(bool) = .init(false);
                    if (self.connect_allocator == null) {
                        const guard = try self.allocator.create(ConnectAllocator);
                        guard.* = .{ .child = self.allocator, .io = self.io };
                        self.connect_allocator = guard;
                    }
                    const context = ConnectRaceContext{ .channel = self, .deadline = deadline, .retryable = &retryable };
                    const winner = connect_race.connect(Error, self.allocator, self.io, context, start, delay, deadline, &self.canceled) catch |err| switch (err) {
                        error.Canceled, error.Timeout, error.OutOfMemory, error.ConcurrencyUnavailable => return err,
                        else => null,
                    };
                    if (winner) |index| {
                        if (self.canceled.isSet() or deadlineExpired(self.io, deadline)) {
                            self.slots[index].closeConnection();
                            return if (self.canceled.isSet()) error.Canceled else error.Timeout;
                        }
                        return self.select(index, &self.slots[index].connection.?);
                    }
                    retryable_failure = retryable_failure or
                        retryable.load(.acquire);
                    if (self.host_resolution) |*resolution| {
                        resolution.state.requestRefresh();
                        retryable_failure = true;
                    }
                    self.setConnectivityState(.transient_failure);
                    if (!wait_for_ready or !retryable_failure) return error.ConnectionUnavailable;
                    try self.waitForProgress(deadline);
                    continue;
                }
            }
            const pass_deadline = try self.connectDeadline(deadline);
            for (0..self.slots.len) |offset| {
                const index = (start + offset) % self.slots.len;
                const slot = &self.slots[index];
                if (slot.disabled) continue;
                if (slot.outlier.isEjected()) {
                    retryable_failure = true;
                    continue;
                }
                if (slot.connection) |*connection| {
                    return self.select(index, connection);
                }
                if (!slotMayAttempt(slot, self.io)) {
                    retryable_failure = true;
                    continue;
                }
                self.setConnectivityState(.connecting);
                slot.connection = slot.endpoint.connect(
                    self.allocator,
                    self.io,
                    pass_deadline,
                ) catch |err| {
                    if (!slot.endpoint.retryable(err)) {
                        if (self.slots.len == 1) return err;
                        slot.disabled = true;
                        continue;
                    }
                    if (deadlineExpired(self.io, deadline)) {
                        return error.Timeout;
                    }
                    if (!wait_for_ready and self.slots.len == 1 and
                        self.host_resolution == null)
                    {
                        self.setConnectivityState(.transient_failure);
                        return err;
                    }
                    retryable_failure = true;
                    slot.consecutive_failures +|= 1;
                    self.scheduleBackoff(slot);
                    if (self.host_resolution) |*resolution| {
                        resolution.state.requestRefresh();
                    }
                    if (!wait_for_ready and self.slots.len == 1) {
                        self.setConnectivityState(.transient_failure);
                        return err;
                    }
                    continue;
                };
                slot.resetBackoff();
                return self.select(index, &slot.connection.?);
            }
            if (self.host_resolution) |*resolution| {
                resolution.state.requestRefresh();
                retryable_failure = true;
            }
            if (!wait_for_ready or !retryable_failure) {
                self.setConnectivityState(.transient_failure);
                return error.ConnectionUnavailable;
            }
            self.setConnectivityState(.transient_failure);
            try self.waitForProgress(deadline);
        }
    }

    fn prepareSlots(self: *Channel) Error!void {
        for (self.slots) |*slot| {
            if (slot.connection) |*connection| {
                if (connection.activeLocalStreamCount() != 0 or
                    connection.activePeerStreamCount() != 0)
                {
                    return error.ChannelBusy;
                }
            }
        }
        for (self.slots) |*slot| {
            if (slot.connection) |*connection| {
                if (!connection.isReusable()) slot.closeConnection();
            }
        }
        if (!self.hasReadyConnection() and self.connectivityState() == .ready) {
            self.setConnectivityState(.transient_failure);
        }
    }

    const ConnectRaceContext = @import("channel/connect_race/context.zig").Context(Channel, Error, .{
        .may_attempt = slotMayAttempt,
        .publish = setConnectivityState,
        .connect_deadline = connectDeadline,
        .connect_endpoint = Endpoint.connect,
        .expired = deadlineExpired,
        .retryable_endpoint = Endpoint.retryable,
        .schedule_backoff = scheduleBackoff,
        .reset_backoff = Slot.resetBackoff,
        .close = Slot.closeConnection,
    });

    fn pickStart(self: *const Channel) usize {
        return switch (self.selection_policy) {
            .pick_first => self.selected_index orelse 0,
            .round_robin, .weighted_round_robin => self.next_pick_index,
        };
    }

    fn pickReadyRoundRobin(self: *Channel) ?ReadyConnection {
        for (0..self.slots.len) |offset| {
            const index = (self.next_pick_index + offset) % self.slots.len;
            if (self.slots[index].outlier.isEjected()) continue;
            if (self.slots[index].connection) |*connection| {
                return self.select(index, connection);
            }
        }
        return null;
    }

    fn pickReadyWeighted(self: *Channel) ?ReadyConnection {
        const config = self.wrr_config orelse return null;
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (now >= self.wrr_scheduler.next_update_ns) {
            self.wrr_scheduler.rebuild(
                self.allocator,
                self.slots,
                now,
                config,
                wrrSlotReady,
            ) catch {};
        }
        const slot = self.wrr_scheduler.pick(
            Slot,
            &self.wrr_sequence,
            wrrSlotReady,
        ) orelse return null;
        for (self.slots, 0..) |*candidate, index| {
            if (candidate != slot) continue;
            return self.selectWeighted(index, &slot.connection.?);
        }
        unreachable;
    }

    fn select(
        self: *Channel,
        index: usize,
        connection: *http2.runtime.Connection,
    ) ReadyConnection {
        std.debug.assert(!self.slots[index].outlier.isEjected());
        self.selected_index = index;
        self.setConnectivityState(.ready);
        if (self.selection_policy != .pick_first) {
            self.next_pick_index = (index + 1) % self.slots.len;
        }
        return .{ .index = index, .connection = connection };
    }

    fn selectWeighted(
        self: *Channel,
        index: usize,
        connection: *http2.runtime.Connection,
    ) ReadyConnection {
        std.debug.assert(!self.slots[index].outlier.isEjected());
        self.selected_index = index;
        self.setConnectivityState(.ready);
        return .{ .index = index, .connection = connection };
    }

    fn observeWrr(
        self: *Channel,
        index: usize,
        response: *const call.UnaryResponse,
    ) void {
        const config = self.wrr_config orelse return;
        if (config.enable_oob_load_report) return;
        const transport = response.transport orelse return;
        if (orca.fromMetadataAlloc(
            self.allocator,
            transport.headers,
            transport.trailers,
        )) |owned_optional| {
            if (owned_optional) |owned_value| {
                var owned = owned_value;
                defer owned.deinit();
                self.slots[index].wrr_weight.update(
                    owned.report,
                    std.Io.Clock.awake.now(self.io).nanoseconds,
                    config,
                );
            }
        } else |_| {}
    }

    fn setWeightedRoundRobinConfig(
        self: *Channel,
        config: service_config.WeightedRoundRobinConfig,
    ) std.mem.Allocator.Error!void {
        if (config.metric_names.len == 0) {
            self.wrr_config = config;
            return;
        }
        const names = try self.allocator.alloc([]u8, config.metric_names.len);
        var initialized: usize = 0;
        errdefer {
            for (names[0..initialized]) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        for (config.metric_names, names) |name, *owned| {
            owned.* = try self.allocator.dupe(u8, name);
            initialized += 1;
        }
        var retained = config;
        retained.metric_names = names;
        self.wrr_metric_names = names;
        self.wrr_config = retained;
    }

    fn noteWarmedConnection(self: *Channel, index: usize) void {
        const selected = self.selected_index orelse {
            self.selected_index = index;
            return;
        };
        if (self.slots[selected].connection == null) {
            self.selected_index = index;
        }
    }

    fn connectDeadline(
        self: *Channel,
        call_deadline: ?std.Io.Clock.Timestamp,
    ) Error!std.Io.Clock.Timestamp {
        if (deadlineExpired(self.io, call_deadline)) return error.Timeout;
        const attempt = std.Io.Clock.Timestamp.fromNow(self.io, .{
            .raw = self.backoff_policy.min_connect_timeout,
            .clock = .awake,
        });
        const outer = call_deadline orelse return attempt;
        return if (std.Io.Clock.Timestamp.compare(outer, .lt, attempt))
            outer
        else
            attempt;
    }

    fn scheduleBackoff(
        self: *Channel,
        slot: *Slot,
    ) void {
        const delay = self.backoff_policy.delay(
            slot.consecutive_failures,
            self.randomSample(),
        );
        slot.next_attempt_at_ns = std.Io.Clock.awake.now(self.io)
            .addDuration(delay).nanoseconds;
    }

    fn ensureHostResolution(
        self: *Channel,
        wait_for_ready: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const resolution = if (self.host_resolution) |*value|
            value
        else
            return;
        _ = resolution.state.start();
        while (self.slots.len == 0) {
            if (self.canceled.isSet()) return error.Canceled;
            const applied = self.applyPendingResolution(
                !wait_for_ready,
            ) catch |err| {
                self.setConnectivityState(.transient_failure);
                return err;
            };
            if (applied and self.slots.len != 0) return;
            if (!wait_for_ready and
                self.connectivityState() == .transient_failure)
            {
                return error.ConnectionUnavailable;
            }
            self.setConnectivityState(.connecting);
            try self.waitForProgress(deadline);
        }
    }

    fn applyPendingResolution(
        self: *Channel,
        propagate_failure: bool,
    ) Error!bool {
        const resolution = if (self.host_resolution) |*value|
            value
        else
            return false;
        const published = resolution.state.takePublished() orelse return false;
        var accepted = false;
        defer resolution.state.acknowledge(accepted);
        switch (published.result) {
            .addresses => |addresses| {
                defer self.allocator.free(addresses);
                if (addresses.len == 0) {
                    self.setConnectivityState(if (self.hasReadyConnection())
                        .ready
                    else
                        .transient_failure);
                    if (propagate_failure) return error.NoAddressReturned;
                    return false;
                }
                try self.reconcileResolvedAddresses(addresses);
                accepted = true;
                self.setConnectivityState(if (self.hasReadyConnection())
                    .ready
                else
                    .connecting);
                return true;
            },
            .failure => |err| {
                accepted = true;
                self.setConnectivityState(if (self.hasReadyConnection())
                    .ready
                else
                    .transient_failure);
                if (propagate_failure) return err;
                return false;
            },
        }
    }

    fn reconcileResolvedAddresses(
        self: *Channel,
        addresses: []net.IpAddress,
    ) Error!void {
        const resolution = if (self.host_resolution) |*value|
            value
        else
            unreachable;
        var unique_count: usize = 0;
        for (addresses) |address| {
            for (addresses[0..unique_count]) |*existing| {
                if (existing.eql(&address)) break;
            } else {
                addresses[unique_count] = address;
                unique_count += 1;
            }
        }
        if (unique_count == 0) return error.NoAddressReturned;
        const unique = addresses[0..unique_count];
        if (self.shuffle_address_list) self.shuffleAddresses(unique);

        const replacement = try self.allocator.alloc(Slot, unique.len);
        errdefer self.allocator.free(replacement);
        const old_slots = self.slots;
        const old_selected = self.selected_index;
        var selected: ?usize = null;
        for (unique, 0..) |address, new_index| {
            var matched: ?usize = null;
            for (old_slots, 0..) |*slot, old_index| {
                const existing = resolution.endpointAddress(slot.endpoint) orelse
                    continue;
                if (existing.eql(&address)) {
                    matched = old_index;
                    break;
                }
            }
            if (matched) |old_index| {
                replacement[new_index] = old_slots[old_index];
                old_slots[old_index].connection = null;
                if (old_selected == old_index) selected = new_index;
            } else {
                replacement[new_index] = .{
                    .endpoint = resolution.endpoint(address),
                };
            }
        }
        for (old_slots) |*slot| slot.closeConnection();
        self.wrr_scheduler.invalidate();
        self.allocator.free(old_slots);
        self.slots = replacement;
        self.selected_index = selected;
        if (self.selected_index == null) {
            for (self.slots, 0..) |slot, index| {
                if (slot.connection != null) {
                    self.selected_index = index;
                    break;
                }
            }
        }
        self.next_pick_index = if (self.selected_index) |index|
            (index + 1) % self.slots.len
        else
            0;
    }

    fn waitForProgress(
        self: *Channel,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.canceled.isSet()) return error.Canceled;
        const now_ns = std.Io.Clock.awake.now(self.io).nanoseconds;
        var timer_ns = self.earliestAttempt();
        if (deadline) |absolute| {
            if (absolute.clock != .awake or
                absolute.durationFromNow(self.io).raw.nanoseconds <= 0)
            {
                return error.Timeout;
            }
            timer_ns = if (timer_ns) |current|
                @min(current, absolute.raw.nanoseconds)
            else
                absolute.raw.nanoseconds;
        }
        if (timer_ns) |target| {
            if (target <= now_ns) {
                if (deadlineExpired(self.io, deadline)) return error.Timeout;
                return;
            }
        } else if (self.host_resolution == null) {
            return error.ConnectionUnavailable;
        }

        const Wake = union(enum) {
            canceled: std.Io.Cancelable!void,
            resolved: std.Io.Cancelable!void,
            timer: std.Io.Cancelable!void,
        };
        var storage: [3]Wake = undefined;
        var wait_set: std.Io.Select(Wake) = .init(self.io, &storage);
        defer while (wait_set.cancel()) |wake| discardProgressWake(wake);
        wait_set.async(.canceled, std.Io.Event.wait, .{
            &self.canceled,
            self.io,
        });
        if (self.host_resolution) |*resolution| {
            wait_set.async(.resolved, std.Io.Event.wait, .{
                resolution.state.resultEvent(),
                self.io,
            });
        }
        if (timer_ns) |target| {
            wait_set.async(.timer, waitUntil, .{
                self.io,
                std.Io.Clock.Timestamp{
                    .raw = .{ .nanoseconds = target },
                    .clock = .awake,
                },
            });
        }
        const wake = wait_set.await() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
        switch (wake) {
            .canceled => |result| {
                result catch return error.Canceled;
                return error.Canceled;
            },
            .resolved => |result| result catch return error.Canceled,
            .timer => |result| {
                result catch return error.Canceled;
                if (deadlineExpired(self.io, deadline)) return error.Timeout;
            },
        }
    }

    fn earliestAttempt(self: *const Channel) ?i96 {
        var earliest = self.outlier_next_evaluation_ns;
        for (self.slots) |slot| {
            const candidate = slot.next_attempt_at_ns orelse continue;
            earliest = if (earliest) |current|
                @min(current, candidate)
            else
                candidate;
        }
        return earliest;
    }

    fn randomSample(self: *Channel) u64 {
        if (self.backoff_policy.jitter == 0) return 0;
        var bytes: [8]u8 = undefined;
        self.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    fn shuffleAddresses(
        self: *Channel,
        addresses: []net.IpAddress,
    ) void {
        var remaining = addresses.len;
        while (remaining > 1) {
            var bytes: [8]u8 = undefined;
            self.io.random(&bytes);
            const sample = std.mem.readInt(u64, &bytes, .little);
            const index: usize = @intCast(
                (@as(u128, sample) * @as(u128, remaining)) >> 64,
            );
            remaining -= 1;
            std.mem.swap(
                net.IpAddress,
                &addresses[index],
                &addresses[remaining],
            );
        }
    }

    fn shuffleSlots(self: *Channel) void {
        var remaining = self.slots.len;
        while (remaining > 1) {
            var bytes: [8]u8 = undefined;
            self.io.random(&bytes);
            const sample = std.mem.readInt(u64, &bytes, .little);
            const index: usize = @intCast(
                (@as(u128, sample) * @as(u128, remaining)) >> 64,
            );
            remaining -= 1;
            std.mem.swap(Slot, &self.slots[index], &self.slots[remaining]);
        }
    }

    fn retireAfterOperationError(
        self: *Channel,
        index: usize,
        err: anyerror,
    ) void {
        const slot = &self.slots[index];
        if (slot.connection) |*connection| {
            if (connectionLost(err) or !connection.isReusable()) {
                slot.closeConnection();
            }
        }
        if (!self.hasReadyConnection()) {
            self.setConnectivityState(.transient_failure);
            if (self.host_resolution) |*resolution| {
                resolution.state.requestRefresh();
            }
        }
    }

    fn hasReadyConnection(self: *const Channel) bool {
        for (self.slots) |*slot| {
            if (slot.outlier.isEjected()) continue;
            if (slot.connection) |*connection| {
                if (connection.isReusable()) return true;
            }
        }
        return false;
    }

    fn hasEjectedSlots(self: *const Channel) bool {
        for (self.slots) |slot| if (slot.outlier.isEjected()) return true;
        return false;
    }

    fn outlierSlot(
        slots: []Slot,
        index: usize,
    ) *outlier_detection.Endpoint {
        return &slots[index].outlier;
    }

    fn outlierSlotEligible(_: []Slot, _: usize) bool {
        return true;
    }

    fn evaluateOutliers(self: *Channel) void {
        const config = self.outlier_config orelse return;
        const next = self.outlier_next_evaluation_ns orelse return;
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (now < next) return;
        const changed = outlier_detection.evaluate(
            self.io,
            config,
            self.slots,
            self.slots.len,
            now,
            outlierSlot,
            outlierSlotEligible,
        );
        self.outlier_next_evaluation_ns = now +| @max(
            config.interval.nanoseconds,
            1,
        );
        if (!changed) return;
        if (self.selected_index) |index| {
            if (self.slots[index].outlier.isEjected()) {
                self.selected_index = null;
            }
        }
        self.wrr_scheduler.invalidate();
        self.setConnectivityState(if (self.hasReadyConnection())
            .ready
        else
            .transient_failure);
    }

    fn outlierCompletionObserver(
        self: *Channel,
        index: usize,
    ) std.mem.Allocator.Error!?*completion.Observer {
        if (self.outlier_config == null) return null;
        return try completion.Observer.create(
            self.allocator,
            &self.slots[index].outlier,
            finishOutlierCompletion,
        );
    }

    fn recordOutlier(self: *Channel, index: usize, success: bool) void {
        if (self.outlier_config == null) return;
        self.slots[index].outlier.record(success);
    }

    fn finishOutlierCompletion(context: *anyopaque, success: bool) void {
        const endpoint: *outlier_detection.Endpoint = @ptrCast(
            @alignCast(context),
        );
        endpoint.record(success);
    }

    fn setConnectivityState(
        self: *Channel,
        state: ConnectivityState,
    ) void {
        self.connectivity_tracker.setState(state);
    }
};

fn discardProgressWake(wake: anytype) void {
    switch (wake) {
        inline else => |result| result catch {},
    }
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

fn slotMayAttempt(slot: *Slot, io: std.Io) bool {
    if (slot.outlier.isEjected()) return false;
    const target = slot.next_attempt_at_ns orelse return true;
    if (target > std.Io.Clock.awake.now(io).nanoseconds) return false;
    slot.next_attempt_at_ns = null;
    return true;
}

fn wrrSlotReady(slot: *Slot) bool {
    if (slot.outlier.isEjected()) return false;
    const connection = if (slot.connection) |*value| value else return false;
    return connection.isReusable();
}

fn callDeadline(
    io: std.Io,
    timeout: ?wire.Timeout,
) ?std.Io.Clock.Timestamp {
    const value = timeout orelse return null;
    return .fromNow(io, .{ .raw = value.duration(), .clock = .awake });
}

fn deadlineExpired(
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp,
) bool {
    const absolute = deadline orelse return false;
    return absolute.durationFromNow(io).raw.nanoseconds <= 0;
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

test {
    _ = backoff;
}
