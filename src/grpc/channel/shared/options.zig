const std = @import("std");
const channel = @import("../../channel.zig");
const health = @import("../../health.zig");
const keepalive = @import("keepalive.zig");
const orca_config = @import("orca/config.zig");

pub const Options = struct {
    channel: channel.Options = .{},
    max_queued_calls: usize = 256,
    max_active_calls_per_endpoint: usize = 32,
    /// Opt-in per-cluster unary counters for xDS LRS reporting.
    enable_lrs_stats: bool = false,
    max_write_bytes_per_turn: usize = 64 * 1024,
    operation_timeout: std.Io.Duration = .fromSeconds(20),
    max_buffered_stream_bytes: usize = 16 * 1024 * 1024,
    health_service: ?[]const u8 = null,
    disable_health_check: bool = false,
    health_metadata: health.WatchOptions = .{},
    service_config_json: ?[]const u8 = null,
    /// Initial immutable per-RPC configuration; the channel retains its owner.
    call_selector: ?@import("../call_selector.zig").Selector = null,
    /// Opt into grpc-core's experimental retryPolicy.perAttemptRecvTimeout.
    /// Attempts remain sequential; this does not enable concurrent hedging.
    enable_per_attempt_recv_timeout: bool = false,
    /// grpc-core-compatible HTTP/2 liveness probes. Null disables keepalive;
    /// the default probes active transports after two hours of peer silence.
    keepalive: ?keepalive.Options = .{},
    /// Optional per-endpoint ORCA OOB stream. Enabling it creates background
    /// connection demand and publishes latest-value reports to endpoint
    /// watches across reconnects.
    orca_oob: ?orca_config.Options = null,
    /// Keep deactivated weighted-target children for grpc-core's 15 minutes.
    /// Zero disables retention. The capacity rejects updates instead of
    /// silently evicting a child before its configured lifetime expires.
    removed_child_retention: std.Io.Duration = .fromSeconds(15 * 60),
    max_retained_children: usize = 256,
    /// grpc-core priority child failover timeout. Null uses 10 seconds; zero
    /// makes lower priorities eligible immediately.
    priority_failover_timeout: ?std.Io.Duration = null,
};
