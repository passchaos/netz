//! Validate and own shared configuration before admitting background tasks.
const std = @import("std");
const channel = @import("../../channel.zig");
const health = @import("../../health.zig");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const State = @import("state.zig").State;
const Error = @import("state.zig").Error;
const Options = @import("options.zig").Options;
const orca_config = @import("orca/config.zig");
const ConfigGeneration = @import("config_generation.zig").Generation;

pub fn create(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: Options) Error!*State {
    if (options.max_queued_calls == 0 or options.max_active_calls_per_endpoint == 0 or options.max_write_bytes_per_turn == 0 or options.max_buffered_stream_bytes == 0 or options.operation_timeout.nanoseconds <= 0) return error.InvalidSharedOptions;
    if (options.keepalive) |keepalive| try keepalive.validate();
    try options.channel.validate();
    if (options.removed_child_retention.nanoseconds < 0 or options.max_retained_children == 0) return error.InvalidSharedOptions;
    if (target == .resolved and target.resolved.endpoints.len == 0) {
        return error.InvalidSharedOptions;
    }
    try target.validate();
    var config: ?service_config.ServiceConfig = if (options.service_config_json) |json| try service_config.ServiceConfig.parseWithOptions(
        allocator,
        json,
        .{ .enable_per_attempt_recv_timeout = options.enable_per_attempt_recv_timeout },
    ) else null;
    var transferred = false;
    errdefer if (!transferred) if (config) |*value| value.deinit();
    const name: ?[]const u8 = if (options.disable_health_check) null else options.health_service orelse (if (options.health_metadata.service.len != 0) options.health_metadata.service else if (config) |*value| value.healthCheckServiceName() else null);
    if (name) |service| {
        const encoded = try health.encodeRequestAlloc(allocator, .{ .service = service });
        allocator.free(encoded);
    }
    const owned_name = if (name) |service| try allocator.dupe(u8, service) else null;
    errdefer if (!transferred) if (owned_name) |value| allocator.free(value);
    const balancing = @import("balancing.zig").resolve(if (config) |*value| value.loadBalancingConfig() else service_config.LoadBalancingConfig{}, options.channel.selection_policy);
    const policy = @import("balancing.zig").select(balancing, options.channel.selection_policy, if (target == .resolved) target.resolved.policy else .pick_first);
    if (policy == .weighted_target and balancing.policy != .weighted_target) {
        return error.InvalidSharedOptions;
    }
    if (policy == .priority and balancing.policy != .priority) {
        return error.InvalidSharedOptions;
    }
    var weighted_target = if (policy == .weighted_target or policy == .priority)
        State.WeightedTarget.initWithPriorityFailoverTimeout(
            allocator,
            balancing.root orelse return error.InvalidSharedOptions,
            (options.priority_failover_timeout orelse
                std.Io.Duration.fromSeconds(10)).nanoseconds,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidSharedOptions,
        }
    else
        null;
    var weighted_target_transferred = false;
    errdefer if (!weighted_target_transferred) if (weighted_target) |*runtime| {
        runtime.deinit();
    };
    const requested_orca = options.orca_oob orelse if (policy == .weighted_round_robin and
        balancing.weighted_round_robin.enable_oob_load_report) @import("../../orca/oob.zig").ClientOptions{
        .report_interval = balancing.weighted_round_robin.oob_reporting_period,
    } else null;
    var owned_orca = if (requested_orca) |orca|
        try orca_config.Config.init(allocator, orca)
    else
        null;
    errdefer if (!transferred) if (owned_orca) |*config_value| config_value.deinit();
    const tracker = try connectivity.Tracker.create(allocator, io);
    errdefer if (!transferred) tracker.release();
    const config_generation = if (config) |value|
        try ConfigGeneration.createWithJson(allocator, value, options.service_config_json.?)
    else
        null;
    config = null;
    errdefer if (!transferred) if (config_generation) |value| value.release();
    const canonical_count = switch (target) {
        .resolved => |resolved| resolved.endpoints.len,
        else => 1,
    };
    const canonical_endpoints = try allocator.alloc(
        channel.Endpoint,
        canonical_count,
    );
    errdefer if (!transferred) allocator.free(canonical_endpoints);
    for (canonical_endpoints, 0..) |*endpoint, index| {
        endpoint.* = switch (target) {
            .resolved => |resolved| resolved.endpoints[index],
            .cleartext_ip => |value| .{ .cleartext_ip = value },
            .cleartext_host => |value| .{ .cleartext_host = value },
            .tls_host => |value| .{ .tls_host = value },
            .tls_address => |value| .{ .tls_address = value },
            .custom => |value| .{ .custom = value },
        };
    }
    const state = try allocator.create(State);
    var state_initialized = false;
    errdefer if (!state_initialized) allocator.destroy(state);
    var retained = options;
    retained.service_config_json = null;
    retained.health_service = owned_name;
    retained.health_metadata.service = owned_name orelse "";
    retained.orca_oob = null;
    state.* = .{
        .allocator = allocator,
        .io = io,
        .options = retained,
        .config = .init(config_generation),
        .health_explicit = options.health_service != null or options.health_metadata.service.len != 0,
        .orca_explicit = options.orca_oob != null,
        .resolver_policy = if (target == .resolved) target.resolved.policy else .pick_first,
        .canonical_endpoints = canonical_endpoints,
        .health_service = owned_name,
        .orca_oob = owned_orca,
        .tracker = tracker,
        .policy = policy,
        .shuffle_addresses = options.channel.shuffle_address_list orelse (balancing.configured and balancing.shuffle_address_list),
        .keepalive_interval_ns = .init(if (options.keepalive) |keepalive|
            @intCast(keepalive.interval.nanoseconds)
        else
            0),
        .demand = owned_orca != null,
        .wrr_config = if (policy == .weighted_round_robin)
            balancing.weighted_round_robin
        else
            null,
        .weighted_target = weighted_target,
        .least_request_config = balancing.least_request,
        .ring_hash_config = balancing.ring_hash,
        .outlier_config = if (balancing.policy == .weighted_target or
            balancing.policy == .priority)
            null
        else
            balancing.outlier_detection,
        .outlier_next_evaluation_ns = if (balancing.policy == .weighted_target or
            balancing.policy == .priority)
            null
        else if (balancing.outlier_detection) |outlier|
            if (outlier.countingEnabled()) std.Io.Clock.awake.now(io)
                .addDuration(.fromNanoseconds(@max(
                    outlier.interval.nanoseconds,
                    1,
                ))).nanoseconds else null
        else
            null,
    };
    weighted_target_transferred = true;
    state_initialized = true;
    transferred = true;
    errdefer {
        state.close();
        state.group.cancel(io);
        state.stopResolution();
        state.release();
    }
    const sources = try @import("layout.zig").create(allocator, io, target, options, state.policy, if (state.weighted_target) |*runtime| runtime else null, state.shuffle_addresses, true);
    state.sources = sources;
    for (sources, 0..) |source, index| {
        if (source.resolver) |resolver| {
            resolver.notifyPublication(&source.wake);
            source.retain();
            state.group.concurrent(io, State.Resolution.run, .{ state, source }) catch |err| {
                source.release();
                return err;
            };
            source.activation.set(io);
        } else {
            source.current = try allocator.alloc(*State.Worker, 1);
            state.lock();
            const worker = State.Membership.createLocked(state, index, null) catch |err| {
                state.unlock();
                return err;
            };
            worker.eligible = true;
            source.current[0] = worker;
            state.unlock();
        }
    }
    return state;
}
