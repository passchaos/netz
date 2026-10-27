//! Lazy, reconnecting gRPC channel with fail-fast and wait-for-ready calls.
const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");
const service_config = @import("service_config.zig");
const streaming = @import("stream/runtime.zig");
const duplex = @import("stream/duplex.zig");
const wire = @import("wire.zig");
const backoff = @import("channel/backoff.zig");

const net = std.Io.net;

pub const BackoffPolicy = backoff.Policy;

pub const Error = streaming.Error || error{
    InvalidChannelOptions,
    ChannelBusy,
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

/// Target configuration is borrowed for the Channel lifetime. Host names,
/// authorities, trust bundles, identities, and custom connector contexts must
/// therefore outlive the Channel. Established HTTP/2 state remains owned.
pub const Target = union(enum) {
    cleartext_ip: struct {
        address: net.IpAddress,
        limits: http2.runtime.Limits = .{},
    },
    cleartext_host: struct {
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
    },
    tls_host: struct {
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
        self: Target,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection {
        return switch (self) {
            .cleartext_ip => |target| http2.runtime.Client.connectWithDeadline(
                allocator,
                io,
                target.address,
                target.limits,
                deadline,
            ),
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

    fn retryable(self: Target, err: anyerror) bool {
        return switch (self) {
            .custom => |target| if (target.retryable_fn) |classify|
                classify(target.context, err)
            else
                retryableConnectError(err),
            else => retryableConnectError(err),
        };
    }

    fn validate(self: Target) error{InvalidChannelOptions}!void {
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

pub const Options = struct {
    backoff: BackoffPolicy = .{},
};

/// A single-owner gRPC channel. It reconnects before a call begins but never
/// replays an RPC merely because `wait_for_ready` was set. Explicit gRPC retry
/// policy and transparent REFUSED_STREAM recovery remain separate call logic.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    target: Target,
    backoff_policy: BackoffPolicy,
    connection: ?http2.runtime.Connection = null,
    consecutive_failures: usize = 0,
    next_attempt_at_ns: ?i96 = null,
    canceled: std.Io.Event = .unset,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
    ) Error!Channel {
        try options.backoff.validate();
        try target.validate();
        return .{
            .allocator = allocator,
            .io = io,
            .target = target,
            .backoff_policy = options.backoff,
        };
    }

    pub fn deinit(self: *Channel) void {
        self.closeConnection();
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
        self.consecutive_failures = 0;
        self.next_attempt_at_ns = null;
    }

    pub fn connected(self: *Channel) ?*http2.runtime.Connection {
        if (self.connection) |*connection| return connection;
        return null;
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
        const connection = try self.ready(resolved.wait_for_ready, deadline);
        const response = if (resolved.retry_policy) |policy|
            call.unaryCallWithRetryUnderDeadline(
                connection,
                self.allocator,
                resolved.options,
                policy,
                deadline,
            )
        else
            call.unaryCallUnderDeadline(
                connection,
                self.allocator,
                resolved.options,
                deadline,
            );
        return response catch |err| {
            self.retireAfterOperationError(err);
            return err;
        };
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
        const connection = try self.ready(resolved.wait_for_ready, deadline);
        return streaming.startClientUnderDeadline(
            connection,
            self.allocator,
            resolved.options,
            deadline,
        ) catch |err| {
            self.retireAfterOperationError(err);
            return err;
        };
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
        const connection = try self.ready(resolved.wait_for_ready, deadline);
        return duplex.startDuplexUnderDeadline(
            connection,
            self.allocator,
            resolved.options,
            deadline,
        ) catch |err| {
            self.retireAfterOperationError(err);
            return err;
        };
    }

    fn ready(
        self: *Channel,
        wait_for_ready: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!*http2.runtime.Connection {
        if (self.canceled.isSet()) return error.Canceled;
        if (self.connection) |*connection| {
            if (connection.activeLocalStreamCount() != 0 or
                connection.activePeerStreamCount() != 0)
            {
                return error.ChannelBusy;
            }
            if (connection.isReusable()) return connection;
            self.closeConnection();
        }

        while (true) {
            if (self.canceled.isSet()) return error.Canceled;
            if (wait_for_ready) try self.waitScheduledAttempt(deadline);
            const attempt_deadline = try self.connectDeadline(deadline);
            self.connection = self.target.connect(
                self.allocator,
                self.io,
                attempt_deadline,
            ) catch |err| {
                if (!wait_for_ready or !self.target.retryable(err)) return err;
                if (deadlineExpired(self.io, deadline)) return error.Timeout;
                self.consecutive_failures +|= 1;
                self.scheduleBackoff(
                    self.backoff_policy.delay(
                        self.consecutive_failures,
                        self.randomSample(),
                    ),
                );
                continue;
            };
            self.consecutive_failures = 0;
            self.next_attempt_at_ns = null;
            return &self.connection.?;
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
        delay: std.Io.Duration,
    ) void {
        self.next_attempt_at_ns = std.Io.Clock.awake.now(self.io)
            .addDuration(delay).nanoseconds;
    }

    fn waitScheduledAttempt(
        self: *Channel,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const target_ns = self.next_attempt_at_ns orelse return;
        while (true) {
            if (self.canceled.isSet()) return error.Canceled;
            const remaining_ns = target_ns -
                std.Io.Clock.awake.now(self.io).nanoseconds;
            if (remaining_ns <= 0) {
                self.next_attempt_at_ns = null;
                return;
            }
            const remaining_delay = std.Io.Duration.fromNanoseconds(
                remaining_ns,
            );
            const remaining = if (deadline) |absolute| blk: {
                const rpc = absolute.durationFromNow(self.io).raw;
                if (rpc.nanoseconds <= 0) return error.Timeout;
                break :blk std.Io.Duration.fromNanoseconds(@min(
                    remaining_delay.nanoseconds,
                    rpc.nanoseconds,
                ));
            } else remaining_delay;
            self.canceled.waitTimeout(self.io, .{
                .duration = .{ .raw = remaining, .clock = .awake },
            }) catch |err| switch (err) {
                error.Timeout => {
                    if (deadlineExpired(self.io, deadline)) {
                        return error.Timeout;
                    }
                    continue;
                },
                error.Canceled => return error.Canceled,
            };
            return error.Canceled;
        }
    }

    fn randomSample(self: *Channel) u64 {
        if (self.backoff_policy.jitter == 0) return 0;
        var bytes: [8]u8 = undefined;
        self.io.random(&bytes);
        return std.mem.readInt(u64, &bytes, .little);
    }

    fn retireAfterOperationError(self: *Channel, err: anyerror) void {
        if (self.connection) |*connection| {
            if (connectionLost(err) or !connection.isReusable()) {
                self.closeConnection();
            }
        }
    }

    fn closeConnection(self: *Channel) void {
        if (self.connection) |*connection| connection.close();
        self.connection = null;
    }
};

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
