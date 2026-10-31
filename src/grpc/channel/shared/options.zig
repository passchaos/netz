const std = @import("std");
const channel = @import("../../channel.zig");
const health = @import("../../health.zig");
const keepalive = @import("keepalive.zig");
const orca_config = @import("orca/config.zig");

pub const Options = struct {
    channel: channel.Options = .{},
    max_queued_calls: usize = 256,
    max_active_calls_per_endpoint: usize = 32,
    max_write_bytes_per_turn: usize = 64 * 1024,
    operation_timeout: std.Io.Duration = .fromSeconds(20),
    max_buffered_stream_bytes: usize = 16 * 1024 * 1024,
    health_service: ?[]const u8 = null,
    disable_health_check: bool = false,
    health_metadata: health.WatchOptions = .{},
    service_config_json: ?[]const u8 = null,
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
};
