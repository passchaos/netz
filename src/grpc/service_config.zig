//! Owned gRPC service-config subset for unary retry policy selection.

const std = @import("std");
const call = @import("call.zig");
const streaming = @import("stream/runtime.zig");
const wire = @import("wire.zig");
const health_config = @import("service_config/health.zig");

pub const Error = std.mem.Allocator.Error || error{InvalidServiceConfig};

const JsonThrottle = struct {
    maxTokens: ?u32 = null,
    tokenRatio: ?f64 = null,
};

const JsonName = struct {
    service: ?[]const u8 = null,
    method: ?[]const u8 = null,
};

const JsonRetryPolicy = struct {
    maxAttempts: ?u32 = null,
    initialBackoff: ?[]const u8 = null,
    maxBackoff: ?[]const u8 = null,
    backoffMultiplier: ?f64 = null,
    retryableStatusCodes: ?[]const []const u8 = null,
    perAttemptRecvTimeout: ?[]const u8 = null,
};

const JsonHedgingPolicy = struct {
    maxAttempts: ?u32 = null,
    hedgingDelay: ?[]const u8 = null,
    nonFatalStatusCodes: ?[]const []const u8 = null,
};

const JsonMethodConfig = struct {
    name: []const JsonName = &.{},
    timeout: ?[]const u8 = null,
    waitForReady: ?bool = null,
    maxRequestMessageBytes: ?std.json.Value = null,
    maxResponseMessageBytes: ?std.json.Value = null,
    retryPolicy: ?JsonRetryPolicy = null,
    hedgingPolicy: ?JsonHedgingPolicy = null,
};

const JsonServiceConfig = struct {
    retryThrottling: ?JsonThrottle = null,
    methodConfig: []const JsonMethodConfig = &.{},
    loadBalancingConfig: ?[]const std.json.Value = null,
    loadBalancingPolicy: ?[]const u8 = null,
    healthCheckConfig: ?health_config.JsonConfig = null,
};

pub const LoadBalancingPolicy = enum {
    pick_first,
    round_robin,
    least_request,
    ring_hash,
    weighted_round_robin,
    weighted_target,
    priority,
};

pub const max_load_balancing_depth: usize = 32;

pub const LeastRequestConfig = @import("channel/least_request.zig").Config;
pub const RingHashConfig = @import("channel/ring_hash.zig").Config;

pub const WeightedRoundRobinConfig = struct {
    enable_oob_load_report: bool = false,
    oob_reporting_period: std.Io.Duration = .fromSeconds(10),
    blackout_period: std.Io.Duration = .fromSeconds(10),
    weight_update_period: std.Io.Duration = .fromSeconds(1),
    weight_expiration_period: std.Io.Duration = .fromSeconds(180),
    error_utilization_penalty: f64 = 1,
    metric_names: []const []const u8 = &.{},
};

pub const PickFirstConfig = struct {
    shuffle_address_list: bool = false,
};

pub const SuccessRateEjection = struct {
    stdev_factor: u32 = 1900,
    enforcement_percentage: u32 = 100,
    minimum_hosts: u32 = 5,
    request_volume: u32 = 100,
};

pub const FailurePercentageEjection = struct {
    threshold: u32 = 85,
    enforcement_percentage: u32 = 100,
    minimum_hosts: u32 = 5,
    request_volume: u32 = 50,
};

pub const OutlierDetectionConfig = struct {
    interval: std.Io.Duration = .fromSeconds(10),
    base_ejection_time: std.Io.Duration = .fromSeconds(30),
    max_ejection_time: std.Io.Duration = .fromSeconds(300),
    max_ejection_percent: u32 = 10,
    success_rate_ejection: ?SuccessRateEjection = null,
    failure_percentage_ejection: ?FailurePercentageEjection = null,

    pub fn countingEnabled(self: OutlierDetectionConfig) bool {
        return self.success_rate_ejection != null or
            self.failure_percentage_ejection != null;
    }
};

pub const WeightedTargetConfig = struct {
    targets: []const Target = &.{},

    pub const Target = struct {
        name: []const u8,
        weight: u32,
        child: *const LoadBalancingNode,
    };
};

pub const PriorityConfig = struct {
    children: []const Child = &.{},
    priorities: []const []const u8 = &.{},

    pub const Child = struct {
        name: []const u8,
        ignore_reresolution_requests: bool = false,
        child: *const LoadBalancingNode,
    };
};

/// Arena-owned recursive representation of the selected service-config LB
/// policy. Leaf policies retain their complete parsed configuration; composite
/// policies point at child nodes in the same ServiceConfig arena. This is the
/// ownership foundation for grpc-core-style recursive policy composition.
pub const LoadBalancingNode = union(enum) {
    pick_first: PickFirstConfig,
    round_robin,
    least_request: LeastRequestConfig,
    ring_hash: RingHashConfig,
    weighted_round_robin: WeightedRoundRobinConfig,
    weighted_target: WeightedTargetConfig,
    xds_wrr_locality: *const LoadBalancingNode,
    priority: PriorityConfig,
    outlier_detection: struct {
        config: OutlierDetectionConfig,
        child: *const LoadBalancingNode,
    },

    pub fn leafPolicy(self: *const LoadBalancingNode) LoadBalancingPolicy {
        return switch (self.*) {
            .pick_first => .pick_first,
            .round_robin => .round_robin,
            .least_request => .least_request,
            .ring_hash => .ring_hash,
            .weighted_round_robin => .weighted_round_robin,
            .weighted_target, .xds_wrr_locality => .weighted_target,
            .priority => .priority,
            .outlier_detection => |wrapper| wrapper.child.leafPolicy(),
        };
    }
};

pub const LoadBalancingConfig = struct {
    policy: LoadBalancingPolicy = .pick_first,
    shuffle_address_list: bool = false,
    configured: bool = false,
    least_request: LeastRequestConfig = .{},
    ring_hash: RingHashConfig = .{},
    weighted_round_robin: WeightedRoundRobinConfig = .{},
    weighted_target: WeightedTargetConfig = .{},
    priority: PriorityConfig = .{},
    outlier_detection: ?OutlierDetectionConfig = null,
    /// Null means no LB policy was configured. The pointed tree is owned by
    /// the ServiceConfig arena and remains valid until `ServiceConfig.deinit`.
    root: ?*const LoadBalancingNode = null,
};

pub const ParseOptions = struct {
    /// Match grpc-core's GRPC_ARG_EXPERIMENTAL_ENABLE_HEDGING gate. This
    /// enables sequential retry perAttemptRecvTimeout only; Netz does not
    /// claim concurrent hedging support.
    enable_per_attempt_recv_timeout: bool = false,
};

const OwnedRetryPolicy = struct {
    max_attempts: u8,
    initial_backoff: std.Io.Duration,
    max_backoff: std.Io.Duration,
    backoff_multiplier: f64,
    retryable_status_codes: []const wire.Status,
    per_attempt_recv_timeout: ?std.Io.Duration,

    fn view(
        self: OwnedRetryPolicy,
        throttler: ?*call.RetryThrottler,
    ) call.RetryPolicy {
        return .{
            .max_attempts = self.max_attempts,
            .initial_backoff = self.initial_backoff,
            .max_backoff = self.max_backoff,
            .backoff_multiplier = self.backoff_multiplier,
            .retryable_status_codes = self.retryable_status_codes,
            .per_attempt_recv_timeout = self.per_attempt_recv_timeout,
            .throttler = throttler,
        };
    }
};

const OwnedMethodPolicy = struct {
    timeout: ?std.Io.Duration = null,
    wait_for_ready: ?bool = null,
    max_request_message_bytes: ?u32 = null,
    max_response_message_bytes: ?u32 = null,
    retry_policy: ?OwnedRetryPolicy = null,
    hedging_policy: ?OwnedHedgingPolicy = null,
};

const OwnedHedgingPolicy = struct {
    max_attempts: u8,
    hedging_delay: std.Io.Duration,
    non_fatal_status_codes: []const wire.Status,

    fn view(
        self: OwnedHedgingPolicy,
        throttler: ?*call.RetryThrottler,
    ) call.HedgingPolicy {
        return .{
            .max_attempts = self.max_attempts,
            .hedging_delay = self.hedging_delay,
            .non_fatal_status_codes = self.non_fatal_status_codes,
            .throttler = throttler,
        };
    }
};

pub const MethodPolicy = struct {
    timeout: ?std.Io.Duration,
    wait_for_ready: ?bool,
    max_request_message_bytes: ?u32,
    max_response_message_bytes: ?u32,
    retry_policy: ?call.RetryPolicy,
    hedging_policy: ?call.HedgingPolicy,
};

const MethodConfig = struct {
    service: ?[]const u8,
    method: ?[]const u8,
    policy: OwnedMethodPolicy,
};

pub const ServiceConfig = struct {
    arena: std.heap.ArenaAllocator,
    methods: []const MethodConfig,
    retry_throttler: ?*call.RetryThrottler,
    load_balancing: LoadBalancingConfig,
    health_check_service_name: ?[]const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        json: []const u8,
    ) Error!ServiceConfig {
        return parseWithOptions(allocator, json, .{});
    }

    pub fn parseWithOptions(
        allocator: std.mem.Allocator,
        json: []const u8,
        options: ParseOptions,
    ) Error!ServiceConfig {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const parsed = std.json.parseFromSliceLeaky(
            JsonServiceConfig,
            owned,
            json,
            .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidServiceConfig,
        };

        var method_count: usize = 0;
        for (parsed.methodConfig) |config| {
            method_count = std.math.add(
                usize,
                method_count,
                config.name.len,
            ) catch return error.InvalidServiceConfig;
        }
        const methods = try owned.alloc(MethodConfig, method_count);
        var method_index: usize = 0;
        for (parsed.methodConfig) |config| {
            if (config.retryPolicy != null and config.hedgingPolicy != null) {
                return error.InvalidServiceConfig;
            }
            const policy = OwnedMethodPolicy{
                .timeout = if (config.timeout) |timeout|
                    try parseDuration(timeout, true)
                else
                    null,
                .wait_for_ready = config.waitForReady,
                .max_request_message_bytes = try parseOptionalSize(
                    config.maxRequestMessageBytes,
                ),
                .max_response_message_bytes = try parseOptionalSize(
                    config.maxResponseMessageBytes,
                ),
                .retry_policy = if (config.retryPolicy) |retry|
                    try parseRetryPolicy(
                        owned,
                        retry,
                        options.enable_per_attempt_recv_timeout,
                    )
                else
                    null,
                .hedging_policy = if (config.hedgingPolicy) |hedging|
                    try parseHedgingPolicy(owned, hedging)
                else
                    null,
            };
            for (config.name) |name| {
                if (name.method != null and
                    (name.service == null or name.service.?.len == 0))
                {
                    return error.InvalidServiceConfig;
                }
                const service = if (name.service) |value|
                    if (value.len == 0) null else value
                else
                    null;
                const method = if (name.method) |value|
                    if (value.len == 0) null else value
                else
                    null;
                if (service) |value| {
                    if (std.mem.indexOfScalar(u8, value, '/') != null) {
                        return error.InvalidServiceConfig;
                    }
                }
                if (method) |value| {
                    if (std.mem.indexOfScalar(u8, value, '/') != null) {
                        return error.InvalidServiceConfig;
                    }
                }
                const entry = MethodConfig{
                    .service = service,
                    .method = method,
                    .policy = policy,
                };
                if (selectorExists(methods[0..method_index], entry)) {
                    return error.InvalidServiceConfig;
                }
                methods[method_index] = entry;
                method_index += 1;
            }
        }

        const throttler = if (parsed.retryThrottling) |throttle| blk: {
            const value = call.RetryThrottler.init(
                throttle.maxTokens orelse
                    return error.InvalidServiceConfig,
                throttle.tokenRatio orelse
                    return error.InvalidServiceConfig,
            ) catch return error.InvalidServiceConfig;
            const result = try owned.create(call.RetryThrottler);
            result.* = value;
            break :blk result;
        } else null;
        const load_balancing = try parseLoadBalancing(owned, parsed);
        return .{
            .arena = arena,
            .methods = methods,
            .retry_throttler = throttler,
            .load_balancing = load_balancing,
            .health_check_service_name = try health_config.serviceName(parsed.healthCheckConfig),
        };
    }

    pub fn deinit(self: *ServiceConfig) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Resolve retry policy by exact method, then service, then default.
    pub fn retryPolicy(
        self: *ServiceConfig,
        path: []const u8,
    ) ?call.RetryPolicy {
        const policy = self.methodPolicy(path) orelse return null;
        return policy.retry_policy;
    }

    pub fn hedgingPolicy(
        self: *ServiceConfig,
        path: []const u8,
    ) ?call.HedgingPolicy {
        const policy = self.methodPolicy(path) orelse return null;
        return policy.hedging_policy;
    }

    pub fn loadBalancingConfig(self: *const ServiceConfig) LoadBalancingConfig {
        return self.load_balancing;
    }

    /// Null disables client health checking. An explicitly empty name enables
    /// the server's overall health service, as in gRPC Core's global config.
    pub fn healthCheckServiceName(self: *const ServiceConfig) ?[]const u8 {
        return self.health_check_service_name;
    }

    test {
        _ = @import("service_config/health_tests.zig");
    }

    pub fn methodPolicy(
        self: *ServiceConfig,
        path: []const u8,
    ) ?MethodPolicy {
        const name = splitPath(path) orelse return null;
        if (self.find(name.service, name.method)) |entry| {
            return resolvedPolicy(self, entry.policy);
        }
        if (self.find(name.service, null)) |entry| {
            return resolvedPolicy(self, entry.policy);
        }
        if (self.find(null, null)) |entry| {
            return resolvedPolicy(self, entry.policy);
        }
        return null;
    }

    pub fn resolveUnary(
        self: *ServiceConfig,
        options: call.UnaryCallOptions,
    ) ResolveError!ResolvedUnary {
        const policy = self.methodPolicy(options.path);
        var resolved = options;
        if (policy) |selected| {
            if (selected.timeout) |configured| {
                if (configured.nanoseconds <= 0) return error.Timeout;
                const duration = if (options.timeout) |explicit|
                    minDuration(explicit.duration(), configured)
                else
                    configured;
                resolved.timeout = try wire.Timeout.fromDuration(duration);
            }
            if (selected.max_request_message_bytes) |configured| {
                resolved.max_request_message_size = @min(
                    resolved.requestMessageLimit(),
                    @as(usize, configured),
                );
            }
            if (selected.max_response_message_bytes) |configured| {
                resolved.max_response_message_size = @min(
                    resolved.responseMessageLimit(),
                    @as(usize, configured),
                );
            }
        }
        return .{
            .options = resolved,
            .retry_policy = if (policy) |selected|
                selected.retry_policy
            else
                null,
            .hedging_policy = if (policy) |selected|
                selected.hedging_policy
            else
                null,
            .wait_for_ready = options.wait_for_ready orelse
                (if (policy) |selected|
                    selected.wait_for_ready orelse false
                else
                    false),
        };
    }

    pub fn resolveStreaming(
        self: *ServiceConfig,
        options: streaming.RequestOptions,
    ) ResolveError!ResolvedStreaming {
        const policy = self.methodPolicy(options.path);
        var resolved = options;
        if (policy) |selected| {
            if (selected.timeout) |configured| {
                if (configured.nanoseconds <= 0) return error.Timeout;
                const duration = if (options.timeout) |explicit|
                    minDuration(explicit.duration(), configured)
                else
                    configured;
                resolved.timeout = try wire.Timeout.fromDuration(duration);
            }
            if (selected.max_request_message_bytes) |configured| {
                resolved.max_request_message_size = @min(
                    resolved.requestMessageLimit(),
                    @as(usize, configured),
                );
            }
            if (selected.max_response_message_bytes) |configured| {
                resolved.max_response_message_size = @min(
                    resolved.responseMessageLimit(),
                    @as(usize, configured),
                );
            }
        }
        return .{
            .options = resolved,
            .hedging_policy = if (policy) |selected|
                selected.hedging_policy
            else
                null,
            .wait_for_ready = options.wait_for_ready orelse
                (if (policy) |selected|
                    selected.wait_for_ready orelse false
                else
                    false),
        };
    }

    fn find(
        self: *ServiceConfig,
        service: ?[]const u8,
        method: ?[]const u8,
    ) ?MethodConfig {
        for (self.methods) |entry| {
            if (optionalEql(entry.service, service) and
                optionalEql(entry.method, method)) return entry;
        }
        return null;
    }
};

pub const ResolveError = wire.Error || error{Timeout};

pub const ResolvedUnary = struct {
    options: call.UnaryCallOptions,
    retry_policy: ?call.RetryPolicy,
    hedging_policy: ?call.HedgingPolicy,
    wait_for_ready: bool,
};

pub const ResolvedStreaming = struct {
    options: streaming.RequestOptions,
    hedging_policy: ?call.HedgingPolicy,
    wait_for_ready: bool,
};

fn minDuration(a: std.Io.Duration, b: std.Io.Duration) std.Io.Duration {
    return if (a.nanoseconds < b.nanoseconds) a else b;
}

fn resolvedPolicy(
    config: *ServiceConfig,
    owned: OwnedMethodPolicy,
) MethodPolicy {
    return .{
        .timeout = owned.timeout,
        .wait_for_ready = owned.wait_for_ready,
        .max_request_message_bytes = owned.max_request_message_bytes,
        .max_response_message_bytes = owned.max_response_message_bytes,
        .retry_policy = if (owned.retry_policy) |retry|
            retry.view(throttlerPointer(config))
        else
            null,
        .hedging_policy = if (owned.hedging_policy) |hedging|
            hedging.view(throttlerPointer(config))
        else
            null,
    };
}

fn throttlerPointer(config: *ServiceConfig) ?*call.RetryThrottler {
    return config.retry_throttler;
}

fn parseLoadBalancing(
    allocator: std.mem.Allocator,
    config: JsonServiceConfig,
) Error!LoadBalancingConfig {
    return parseLoadBalancingAt(allocator, config, 0);
}

fn parseLoadBalancingAt(
    allocator: std.mem.Allocator,
    config: JsonServiceConfig,
    depth: usize,
) Error!LoadBalancingConfig {
    if (depth > max_load_balancing_depth) {
        return error.InvalidServiceConfig;
    }
    if (config.loadBalancingConfig) |entries| {
        if (entries.len == 0) return error.InvalidServiceConfig;
        for (entries) |entry| {
            const object = switch (entry) {
                .object => |value| value,
                else => return error.InvalidServiceConfig,
            };
            if (object.count() != 1) return error.InvalidServiceConfig;
            var iterator = object.iterator();
            const item = iterator.next().?;
            if (std.mem.eql(
                u8,
                item.key_ptr.*,
                "outlier_detection_experimental",
            )) {
                const parsed = try parseOutlierDetection(item.value_ptr.*);
                var child = try parseLoadBalancingAt(allocator, .{
                    .loadBalancingConfig = parsed.child_policy,
                }, depth + 1);
                if (child.outlier_detection != null) {
                    return error.InvalidServiceConfig;
                }
                child.outlier_detection = parsed.config;
                child.root = try allocateLoadBalancingNode(
                    allocator,
                    .{ .outlier_detection = .{
                        .config = parsed.config,
                        .child = child.root orelse
                            return error.InvalidServiceConfig,
                    } },
                );
                return child;
            }
            if (std.mem.eql(u8, item.key_ptr.*, "xds_wrr_locality_experimental")) {
                const child_entries = try @import("service_config/locality.zig").childPolicies(item.value_ptr.*);
                const child = try parseLoadBalancingAt(allocator, .{ .loadBalancingConfig = child_entries }, depth + 1);
                return configuredLoadBalancing(allocator, .{ .policy = .weighted_target, .configured = true }, .{ .xds_wrr_locality = child.root orelse return error.InvalidServiceConfig });
            }
            if (std.mem.eql(
                u8,
                item.key_ptr.*,
                "weighted_target_experimental",
            )) {
                const weighted_target = try parseWeightedTarget(
                    allocator,
                    item.value_ptr.*,
                    depth,
                );
                return configuredLoadBalancing(allocator, .{
                    .policy = .weighted_target,
                    .configured = true,
                    .weighted_target = weighted_target,
                }, .{ .weighted_target = weighted_target });
            }
            if (std.mem.eql(
                u8,
                item.key_ptr.*,
                "priority_experimental",
            )) {
                const priority = try parsePriority(
                    allocator,
                    item.value_ptr.*,
                    depth,
                );
                return configuredLoadBalancing(allocator, .{
                    .policy = .priority,
                    .configured = true,
                    .priority = priority,
                }, .{ .priority = priority });
            }
            if (std.mem.eql(u8, item.key_ptr.*, "round_robin")) {
                const options = switch (item.value_ptr.*) {
                    .object => |value| value,
                    else => return error.InvalidServiceConfig,
                };
                if (options.count() != 0) return error.InvalidServiceConfig;
                return configuredLoadBalancing(
                    allocator,
                    .{ .policy = .round_robin, .configured = true },
                    .round_robin,
                );
            }
            if (std.mem.eql(
                u8,
                item.key_ptr.*,
                "least_request_experimental",
            )) {
                const options = switch (item.value_ptr.*) {
                    .object => |value| value,
                    else => return error.InvalidServiceConfig,
                };
                var least_request: LeastRequestConfig = .{};
                var fields = options.iterator();
                while (fields.next()) |field| {
                    if (!std.mem.eql(
                        u8,
                        field.key_ptr.*,
                        "choiceCount",
                    )) return error.InvalidServiceConfig;
                    const raw = switch (field.value_ptr.*) {
                        .integer => |value| value,
                        else => return error.InvalidServiceConfig,
                    };
                    if (raw < 2 or raw > std.math.maxInt(u32)) {
                        return error.InvalidServiceConfig;
                    }
                    least_request.choice_count = @intCast(@min(
                        raw,
                        LeastRequestConfig.max_choice_count,
                    ));
                }
                return configuredLoadBalancing(allocator, .{
                    .policy = .least_request,
                    .configured = true,
                    .least_request = least_request,
                }, .{ .least_request = least_request });
            }
            if (std.mem.eql(
                u8,
                item.key_ptr.*,
                "ring_hash_experimental",
            )) {
                const options = switch (item.value_ptr.*) {
                    .object => |value| value,
                    else => return error.InvalidServiceConfig,
                };
                var ring: RingHashConfig = .{};
                var fields = options.iterator();
                while (fields.next()) |field| {
                    const key = field.key_ptr.*;
                    const value = field.value_ptr.*;
                    if (std.mem.eql(u8, key, "minRingSize")) {
                        ring.min_ring_size = try parseRingSize(value);
                    } else if (std.mem.eql(u8, key, "maxRingSize")) {
                        ring.max_ring_size = try parseRingSize(value);
                    } else if (std.mem.eql(u8, key, "requestHashHeader")) {
                        const header = switch (value) {
                            .string => |text| text,
                            else => return error.InvalidServiceConfig,
                        };
                        if (!validRequestHashHeader(header)) {
                            return error.InvalidServiceConfig;
                        }
                        ring.request_hash_header = header;
                    } else return error.InvalidServiceConfig;
                }
                if (ring.min_ring_size > ring.max_ring_size) {
                    return error.InvalidServiceConfig;
                }
                return configuredLoadBalancing(allocator, .{
                    .policy = .ring_hash,
                    .configured = true,
                    .ring_hash = ring,
                }, .{ .ring_hash = ring });
            }
            if (std.mem.eql(u8, item.key_ptr.*, "pick_first")) {
                const options = switch (item.value_ptr.*) {
                    .object => |value| value,
                    else => return error.InvalidServiceConfig,
                };
                var shuffle = false;
                var fields = options.iterator();
                while (fields.next()) |field| {
                    if (!std.mem.eql(
                        u8,
                        field.key_ptr.*,
                        "shuffleAddressList",
                    )) return error.InvalidServiceConfig;
                    shuffle = switch (field.value_ptr.*) {
                        .bool => |value| value,
                        else => return error.InvalidServiceConfig,
                    };
                }
                return configuredLoadBalancing(allocator, .{
                    .policy = .pick_first,
                    .shuffle_address_list = shuffle,
                    .configured = true,
                }, .{ .pick_first = .{
                    .shuffle_address_list = shuffle,
                } });
            }
            if (std.mem.eql(u8, item.key_ptr.*, "weighted_round_robin")) {
                const options = switch (item.value_ptr.*) {
                    .object => |value| value,
                    else => return error.InvalidServiceConfig,
                };
                var weighted: WeightedRoundRobinConfig = .{};
                var metric_names_value: ?std.json.Value = null;
                var fields = options.iterator();
                while (fields.next()) |field| {
                    const key = field.key_ptr.*;
                    const value = field.value_ptr.*;
                    if (std.mem.eql(u8, key, "enableOobLoadReport")) {
                        weighted.enable_oob_load_report = switch (value) {
                            .bool => |v| v,
                            else => return error.InvalidServiceConfig,
                        };
                    } else if (std.mem.eql(u8, key, "oobReportingPeriod")) {
                        weighted.oob_reporting_period = try parseDurationValue(value);
                    } else if (std.mem.eql(u8, key, "blackoutPeriod")) {
                        weighted.blackout_period = try parseDurationValue(value);
                    } else if (std.mem.eql(u8, key, "weightUpdatePeriod")) {
                        weighted.weight_update_period = try parseDurationValue(value);
                    } else if (std.mem.eql(u8, key, "weightExpirationPeriod")) {
                        weighted.weight_expiration_period = try parseDurationValue(value);
                    } else if (std.mem.eql(u8, key, "errorUtilizationPenalty")) {
                        weighted.error_utilization_penalty = switch (value) {
                            .float => |v| v,
                            .integer => |v| @floatFromInt(v),
                            .number_string => |v| std.fmt.parseFloat(f64, v) catch return error.InvalidServiceConfig,
                            else => return error.InvalidServiceConfig,
                        };
                    } else if (std.mem.eql(u8, key, "metricNamesForComputingUtilization")) {
                        metric_names_value = value;
                    } else return error.InvalidServiceConfig;
                }
                if (!std.math.isFinite(weighted.error_utilization_penalty) or
                    weighted.error_utilization_penalty < 0)
                {
                    return error.InvalidServiceConfig;
                }
                if (weighted.weight_update_period.nanoseconds <
                    100 * std.time.ns_per_ms)
                {
                    weighted.weight_update_period = .fromMilliseconds(100);
                }
                if (metric_names_value) |raw| {
                    const array = switch (raw) {
                        .array => |v| v,
                        else => return error.InvalidServiceConfig,
                    };
                    const names = try allocator.alloc([]const u8, array.items.len);
                    for (array.items, names) |value, *name| {
                        name.* = switch (value) {
                            .string => |v| v,
                            else => return error.InvalidServiceConfig,
                        };
                        if (!validWrrMetricName(name.*)) return error.InvalidServiceConfig;
                    }
                    weighted.metric_names = names;
                }
                return configuredLoadBalancing(allocator, .{
                    .policy = .weighted_round_robin,
                    .configured = true,
                    .weighted_round_robin = weighted,
                }, .{ .weighted_round_robin = weighted });
            }
            // gRPC selects the first policy implemented by the client.
        }
        return error.InvalidServiceConfig;
    }
    if (config.loadBalancingPolicy) |name| {
        if (std.ascii.eqlIgnoreCase(name, "pick_first")) {
            return configuredLoadBalancing(
                allocator,
                .{ .configured = true },
                .{ .pick_first = .{} },
            );
        }
        if (std.ascii.eqlIgnoreCase(name, "round_robin")) {
            return configuredLoadBalancing(
                allocator,
                .{ .policy = .round_robin, .configured = true },
                .round_robin,
            );
        }
        return error.InvalidServiceConfig;
    }
    return .{};
}

fn parseWeightedTarget(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    depth: usize,
) Error!WeightedTargetConfig {
    const options = switch (value) {
        .object => |object| object,
        else => return error.InvalidServiceConfig,
    };
    if (options.count() != 1) return error.InvalidServiceConfig;
    const targets_value = options.get("targets") orelse
        return error.InvalidServiceConfig;
    const targets_object = switch (targets_value) {
        .object => |object| object,
        else => return error.InvalidServiceConfig,
    };
    const targets = try allocator.alloc(
        WeightedTargetConfig.Target,
        targets_object.count(),
    );
    var index: usize = 0;
    var iterator = targets_object.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        const name = entry.key_ptr.*;
        if (name.len == 0) return error.InvalidServiceConfig;
        const child_object = switch (entry.value_ptr.*) {
            .object => |object| object,
            else => return error.InvalidServiceConfig,
        };
        if (child_object.count() != 2) return error.InvalidServiceConfig;
        const weight_value = child_object.get("weight") orelse
            return error.InvalidServiceConfig;
        const raw_weight = switch (weight_value) {
            .integer => |number| number,
            else => return error.InvalidServiceConfig,
        };
        if (raw_weight <= 0 or raw_weight > std.math.maxInt(u32)) {
            return error.InvalidServiceConfig;
        }
        const child_policy = child_object.get("childPolicy") orelse
            return error.InvalidServiceConfig;
        const child_entries = switch (child_policy) {
            .array => |array| array.items,
            else => return error.InvalidServiceConfig,
        };
        const child = try parseLoadBalancingAt(allocator, .{
            .loadBalancingConfig = child_entries,
        }, depth + 1);
        targets[index] = .{
            .name = name,
            .weight = @intCast(raw_weight),
            .child = child.root orelse return error.InvalidServiceConfig,
        };
    }
    std.mem.sort(
        WeightedTargetConfig.Target,
        targets,
        {},
        lessWeightedTarget,
    );
    return .{ .targets = targets };
}

fn lessWeightedTarget(
    _: void,
    left: WeightedTargetConfig.Target,
    right: WeightedTargetConfig.Target,
) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn parsePriority(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    depth: usize,
) Error!PriorityConfig {
    const options = switch (value) {
        .object => |object| object,
        else => return error.InvalidServiceConfig,
    };
    if (options.count() != 2) return error.InvalidServiceConfig;
    const children_value = options.get("children") orelse
        return error.InvalidServiceConfig;
    const priorities_value = options.get("priorities") orelse
        return error.InvalidServiceConfig;
    const children_object = switch (children_value) {
        .object => |object| object,
        else => return error.InvalidServiceConfig,
    };
    const priorities_array = switch (priorities_value) {
        .array => |array| array.items,
        else => return error.InvalidServiceConfig,
    };

    const children = try allocator.alloc(
        PriorityConfig.Child,
        children_object.count(),
    );
    var index: usize = 0;
    var iterator = children_object.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        const name = entry.key_ptr.*;
        if (name.len == 0) return error.InvalidServiceConfig;
        const child_object = switch (entry.value_ptr.*) {
            .object => |object| object,
            else => return error.InvalidServiceConfig,
        };
        const config_value = child_object.get("config") orelse
            return error.InvalidServiceConfig;
        var ignore_reresolution_requests = false;
        if (child_object.get("ignoreReresolutionRequests")) |ignore_value| {
            ignore_reresolution_requests = switch (ignore_value) {
                .bool => |flag| flag,
                else => return error.InvalidServiceConfig,
            };
        }
        var child_iterator = child_object.iterator();
        while (child_iterator.next()) |child_entry| {
            if (!std.mem.eql(u8, child_entry.key_ptr.*, "config") and
                !std.mem.eql(
                    u8,
                    child_entry.key_ptr.*,
                    "ignoreReresolutionRequests",
                ))
            {
                return error.InvalidServiceConfig;
            }
        }
        const child_entries = switch (config_value) {
            .array => |array| array.items,
            else => return error.InvalidServiceConfig,
        };
        const child = try parseLoadBalancingAt(allocator, .{
            .loadBalancingConfig = child_entries,
        }, depth + 1);
        children[index] = .{
            .name = name,
            .ignore_reresolution_requests = ignore_reresolution_requests,
            .child = child.root orelse return error.InvalidServiceConfig,
        };
    }
    std.mem.sort(PriorityConfig.Child, children, {}, lessPriorityChild);

    const priorities = try allocator.alloc([]const u8, priorities_array.len);
    for (priorities_array, 0..) |priority_value, priority_index| {
        const name = switch (priority_value) {
            .string => |text| text,
            else => return error.InvalidServiceConfig,
        };
        if (name.len == 0) return error.InvalidServiceConfig;
        var found = false;
        for (children) |child| {
            if (std.mem.eql(u8, child.name, name)) {
                found = true;
                break;
            }
        }
        if (!found) return error.InvalidServiceConfig;
        priorities[priority_index] = name;
    }
    return .{ .children = children, .priorities = priorities };
}

fn lessPriorityChild(
    _: void,
    left: PriorityConfig.Child,
    right: PriorityConfig.Child,
) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn configuredLoadBalancing(
    allocator: std.mem.Allocator,
    config: LoadBalancingConfig,
    node: LoadBalancingNode,
) std.mem.Allocator.Error!LoadBalancingConfig {
    var result = config;
    result.root = try allocateLoadBalancingNode(allocator, node);
    return result;
}

fn allocateLoadBalancingNode(
    allocator: std.mem.Allocator,
    node: LoadBalancingNode,
) std.mem.Allocator.Error!*const LoadBalancingNode {
    const owned = try allocator.create(LoadBalancingNode);
    owned.* = node;
    return owned;
}

fn parseRingSize(value: std.json.Value) Error!usize {
    const raw: u64 = switch (value) {
        .integer => |number| if (number >= 0)
            @intCast(number)
        else
            return error.InvalidServiceConfig,
        .number_string, .string => |text| std.fmt.parseInt(
            u64,
            text,
            10,
        ) catch return error.InvalidServiceConfig,
        else => return error.InvalidServiceConfig,
    };
    if (raw == 0 or
        raw > @import("channel/ring_hash.zig").max_configured_ring_size)
    {
        return error.InvalidServiceConfig;
    }
    return @intCast(raw);
}

fn validRequestHashHeader(name: []const u8) bool {
    if (name.len == 0 or std.mem.endsWith(u8, name, "-bin") or
        std.mem.startsWith(u8, name, "grpc-") or
        std.mem.eql(u8, name, "content-type") or
        std.mem.eql(u8, name, "te"))
    {
        return false;
    }
    for (name) |byte| {
        if ((byte >= '0' and byte <= '9') or
            (byte >= 'a' and byte <= 'z') or
            byte == '_' or byte == '-' or byte == '.')
        {
            continue;
        }
        return false;
    }
    return true;
}

const ParsedOutlierDetection = struct {
    config: OutlierDetectionConfig,
    child_policy: []const std.json.Value,
};

fn parseOutlierDetection(
    value: std.json.Value,
) Error!ParsedOutlierDetection {
    const options = switch (value) {
        .object => |object| object,
        else => return error.InvalidServiceConfig,
    };
    var config: OutlierDetectionConfig = .{};
    var child_policy: ?[]const std.json.Value = null;
    var max_ejection_time_present = false;
    var fields = options.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        const raw = field.value_ptr.*;
        if (std.mem.eql(u8, key, "interval")) {
            config.interval = try parseDurationValue(raw);
        } else if (std.mem.eql(u8, key, "baseEjectionTime")) {
            config.base_ejection_time = try parseDurationValue(raw);
        } else if (std.mem.eql(u8, key, "maxEjectionTime")) {
            config.max_ejection_time = try parseDurationValue(raw);
            max_ejection_time_present = true;
        } else if (std.mem.eql(u8, key, "maxEjectionPercent")) {
            config.max_ejection_percent = try parseJsonU32(raw);
        } else if (std.mem.eql(u8, key, "successRateEjection")) {
            config.success_rate_ejection = try parseSuccessRateEjection(raw);
        } else if (std.mem.eql(u8, key, "failurePercentageEjection")) {
            config.failure_percentage_ejection =
                try parseFailurePercentageEjection(raw);
        } else if (std.mem.eql(u8, key, "childPolicy")) {
            child_policy = switch (raw) {
                .array => |array| array.items,
                else => return error.InvalidServiceConfig,
            };
        } else return error.InvalidServiceConfig;
    }
    if (!max_ejection_time_present) {
        config.max_ejection_time = .fromNanoseconds(@max(
            config.base_ejection_time.nanoseconds,
            300 * std.time.ns_per_s,
        ));
    }
    if (config.max_ejection_percent > 100) {
        return error.InvalidServiceConfig;
    }
    return .{
        .config = config,
        .child_policy = child_policy orelse
            return error.InvalidServiceConfig,
    };
}

fn parseSuccessRateEjection(
    value: std.json.Value,
) Error!SuccessRateEjection {
    const object = switch (value) {
        .object => |entry| entry,
        else => return error.InvalidServiceConfig,
    };
    var result: SuccessRateEjection = .{};
    var fields = object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        if (std.mem.eql(u8, key, "stdevFactor")) {
            result.stdev_factor = try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "enforcementPercentage")) {
            result.enforcement_percentage =
                try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "minimumHosts")) {
            result.minimum_hosts = try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "requestVolume")) {
            result.request_volume = try parseJsonU32(field.value_ptr.*);
        } else return error.InvalidServiceConfig;
    }
    if (result.enforcement_percentage > 100) {
        return error.InvalidServiceConfig;
    }
    return result;
}

fn parseFailurePercentageEjection(
    value: std.json.Value,
) Error!FailurePercentageEjection {
    const object = switch (value) {
        .object => |entry| entry,
        else => return error.InvalidServiceConfig,
    };
    var result: FailurePercentageEjection = .{};
    var fields = object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        if (std.mem.eql(u8, key, "threshold")) {
            result.threshold = try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "enforcementPercentage")) {
            result.enforcement_percentage =
                try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "minimumHosts")) {
            result.minimum_hosts = try parseJsonU32(field.value_ptr.*);
        } else if (std.mem.eql(u8, key, "requestVolume")) {
            result.request_volume = try parseJsonU32(field.value_ptr.*);
        } else return error.InvalidServiceConfig;
    }
    if (result.threshold > 100 or result.enforcement_percentage > 100) {
        return error.InvalidServiceConfig;
    }
    return result;
}

fn parseJsonU32(value: std.json.Value) Error!u32 {
    return switch (value) {
        .integer => |integer| std.math.cast(u32, integer) orelse
            error.InvalidServiceConfig,
        .number_string => |text| std.fmt.parseInt(u32, text, 10) catch
            error.InvalidServiceConfig,
        else => error.InvalidServiceConfig,
    };
}

fn parseDurationValue(value: std.json.Value) Error!std.Io.Duration {
    const text = switch (value) {
        .string => |v| v,
        else => return error.InvalidServiceConfig,
    };
    return parseDuration(text, true);
}

fn validWrrMetricName(name: []const u8) bool {
    return std.mem.eql(u8, name, "cpu_utilization") or
        std.mem.eql(u8, name, "mem_utilization") or
        std.mem.eql(u8, name, "application_utilization") or
        std.mem.startsWith(u8, name, "named_metrics.") or
        std.mem.startsWith(u8, name, "utilization.");
}

fn parseOptionalSize(value: ?std.json.Value) Error!?u32 {
    const raw = value orelse return null;
    return switch (raw) {
        .integer => |number| std.math.cast(u32, number) orelse
            error.InvalidServiceConfig,
        .string, .number_string => |text| std.fmt.parseInt(
            u32,
            text,
            10,
        ) catch error.InvalidServiceConfig,
        else => error.InvalidServiceConfig,
    };
}

fn parseRetryPolicy(
    allocator: std.mem.Allocator,
    json: JsonRetryPolicy,
    enable_per_attempt_recv_timeout: bool,
) Error!OwnedRetryPolicy {
    const raw_attempts = json.maxAttempts orelse
        return error.InvalidServiceConfig;
    if (raw_attempts < 2) return error.InvalidServiceConfig;
    const per_attempt_recv_timeout = if (enable_per_attempt_recv_timeout)
        if (json.perAttemptRecvTimeout) |value|
            try parseDuration(value, false)
        else
            null
    else
        null;
    const statuses_raw = json.retryableStatusCodes orelse &.{};
    if (statuses_raw.len == 0 and per_attempt_recv_timeout == null) {
        return error.InvalidServiceConfig;
    }
    const statuses = try allocator.alloc(wire.Status, statuses_raw.len);
    for (statuses_raw, statuses) |raw, *status| {
        status.* = parseStatusName(raw) orelse
            return error.InvalidServiceConfig;
        if (status.* == .ok) return error.InvalidServiceConfig;
    }
    const policy = OwnedRetryPolicy{
        .max_attempts = @intCast(@min(raw_attempts, 5)),
        .initial_backoff = try parseDuration(
            json.initialBackoff orelse
                return error.InvalidServiceConfig,
            false,
        ),
        .max_backoff = try parseDuration(
            json.maxBackoff orelse
                return error.InvalidServiceConfig,
            false,
        ),
        .backoff_multiplier = json.backoffMultiplier orelse
            return error.InvalidServiceConfig,
        .retryable_status_codes = statuses,
        .per_attempt_recv_timeout = per_attempt_recv_timeout,
    };
    policy.view(null).validate() catch return error.InvalidServiceConfig;
    return policy;
}

fn parseHedgingPolicy(
    allocator: std.mem.Allocator,
    json: JsonHedgingPolicy,
) Error!OwnedHedgingPolicy {
    const raw_attempts = json.maxAttempts orelse
        return error.InvalidServiceConfig;
    if (raw_attempts < 2) return error.InvalidServiceConfig;
    const statuses_raw = json.nonFatalStatusCodes orelse &.{};
    const statuses = try allocator.alloc(wire.Status, statuses_raw.len);
    for (statuses_raw, statuses, 0..) |raw, *status, index| {
        status.* = parseStatusName(raw) orelse
            return error.InvalidServiceConfig;
        if (status.* == .ok) return error.InvalidServiceConfig;
        for (statuses[0..index]) |prior| {
            if (prior == status.*) return error.InvalidServiceConfig;
        }
    }
    const policy = OwnedHedgingPolicy{
        .max_attempts = @intCast(@min(raw_attempts, 5)),
        .hedging_delay = if (json.hedgingDelay) |delay|
            try parseDuration(delay, true)
        else
            .zero,
        .non_fatal_status_codes = statuses,
    };
    policy.view(null).validate() catch return error.InvalidServiceConfig;
    return policy;
}

fn parseDuration(
    raw: []const u8,
    allow_zero: bool,
) Error!std.Io.Duration {
    if (raw.len < 2 or raw[raw.len - 1] != 's') {
        return error.InvalidServiceConfig;
    }
    const number = raw[0 .. raw.len - 1];
    const decimal = std.mem.indexOfScalar(u8, number, '.');
    const whole_text = if (decimal) |index| number[0..index] else number;
    if (whole_text.len == 0) return error.InvalidServiceConfig;
    const whole = std.fmt.parseInt(u96, whole_text, 10) catch
        return error.InvalidServiceConfig;
    // google.protobuf.Duration bounds its seconds component to 10,000 years.
    if (whole > 315_576_000_000) return error.InvalidServiceConfig;
    var fractional_ns: u96 = 0;
    if (decimal) |index| {
        const fraction = number[index + 1 ..];
        if (fraction.len == 0 or fraction.len > 9) {
            return error.InvalidServiceConfig;
        }
        fractional_ns = std.fmt.parseInt(u96, fraction, 10) catch
            return error.InvalidServiceConfig;
        for (fraction.len..9) |_| fractional_ns *= 10;
    }
    const total = std.math.add(
        u96,
        std.math.mul(u96, whole, std.time.ns_per_s) catch
            return error.InvalidServiceConfig,
        fractional_ns,
    ) catch return error.InvalidServiceConfig;
    if ((!allow_zero and total == 0) or total > std.math.maxInt(i96)) {
        return error.InvalidServiceConfig;
    }
    return .fromNanoseconds(@intCast(total));
}

fn parseStatusName(raw: []const u8) ?wire.Status {
    inline for (std.enums.values(wire.Status)) |status| {
        var buffer: [32]u8 = undefined;
        const canonical = std.ascii.upperString(
            buffer[0..@tagName(status).len],
            @tagName(status),
        );
        if (std.mem.eql(u8, raw, canonical)) return status;
    }
    return null;
}

fn selectorExists(
    entries: []const MethodConfig,
    candidate: MethodConfig,
) bool {
    for (entries) |entry| {
        if (optionalEql(entry.service, candidate.service) and
            optionalEql(entry.method, candidate.method)) return true;
    }
    return false;
}

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn splitPath(path: []const u8) ?struct {
    service: []const u8,
    method: []const u8,
} {
    if (path.len < 4 or path[0] != '/') return null;
    const slash = std.mem.indexOfScalar(u8, path[1..], '/') orelse
        return null;
    const absolute = slash + 1;
    if (absolute == 1 or absolute + 1 >= path.len or
        std.mem.indexOfScalar(u8, path[absolute + 1 ..], '/') != null)
    {
        return null;
    }
    return .{
        .service = path[1..absolute],
        .method = path[absolute + 1 ..],
    };
}

test "gRPC service config selects exact service and default retry policies" {
    const json =
        \\{
        \\  "retryThrottling": {"maxTokens": 4, "tokenRatio": 1.5},
        \\  "methodConfig": [
        \\    {"name": [{}], "retryPolicy": {
        \\      "maxAttempts": 2, "initialBackoff": "1s",
        \\      "maxBackoff": "2s", "backoffMultiplier": 2,
        \\      "retryableStatusCodes": ["UNAVAILABLE"]}},
        \\    {"name": [{"service": "demo.Echo"}],
        \\      "timeout": "9s",
        \\      "waitForReady": true,
        \\      "maxRequestMessageBytes": "1024",
        \\      "maxResponseMessageBytes": 2048, "retryPolicy": {
        \\      "maxAttempts": 3, "initialBackoff": "0.125s",
        \\      "maxBackoff": "1.500000001s", "backoffMultiplier": 1.6,
        \\      "retryableStatusCodes": ["ABORTED"]}},
        \\    {"name": [{"service": "demo.Echo", "method": "Exact"}],
        \\     "retryPolicy": {"maxAttempts": 9, "initialBackoff": "2s",
        \\      "maxBackoff": "3s", "backoffMultiplier": 1,
        \\      "retryableStatusCodes": ["RESOURCE_EXHAUSTED"]}},
        \\    {"name": [{"service": "demo.Echo", "method": "Disabled"}]}
        \\  ]
        \\}
    ;
    var config = try ServiceConfig.parse(std.testing.allocator, json);
    defer config.deinit();
    const exact = config.retryPolicy("/demo.Echo/Exact").?;
    try std.testing.expectEqual(@as(u8, 5), exact.max_attempts);
    try std.testing.expectEqual(
        @as(i96, 2 * std.time.ns_per_s),
        exact.initial_backoff.nanoseconds,
    );
    try std.testing.expectEqual(wire.Status.resource_exhausted, exact.retryable_status_codes[0]);
    try std.testing.expect(exact.throttler != null);

    const service = config.retryPolicy("/demo.Echo/Other").?;
    try std.testing.expectEqual(@as(u8, 3), service.max_attempts);
    try std.testing.expectEqual(
        @as(i96, 125 * std.time.ns_per_ms),
        service.initial_backoff.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 1_500_000_001),
        service.max_backoff.nanoseconds,
    );
    try std.testing.expectEqual(wire.Status.aborted, service.retryable_status_codes[0]);
    const service_policy = config.methodPolicy("/demo.Echo/Other").?;
    try std.testing.expectEqual(
        @as(i96, 9 * std.time.ns_per_s),
        service_policy.timeout.?.nanoseconds,
    );
    try std.testing.expectEqual(@as(?u32, 1024), service_policy.max_request_message_bytes);
    try std.testing.expectEqual(@as(?u32, 2048), service_policy.max_response_message_bytes);
    try std.testing.expectEqual(@as(?bool, true), service_policy.wait_for_ready);

    const inherited = try config.resolveUnary(.{
        .path = "/demo.Echo/Other",
        .message = "request",
    });
    try std.testing.expect(inherited.wait_for_ready);
    const explicit = try config.resolveUnary(.{
        .path = "/demo.Echo/Other",
        .message = "request",
        .wait_for_ready = false,
    });
    try std.testing.expect(!explicit.wait_for_ready);

    const default = config.retryPolicy("/other.Service/Method").?;
    try std.testing.expectEqual(@as(u8, 2), default.max_attempts);
    try std.testing.expectEqual(wire.Status.unavailable, default.retryable_status_codes[0]);
    try std.testing.expect(config.retryPolicy("/demo.Echo/Disabled") == null);
}

test "gRPC service config rejects malformed retry settings" {
    const invalid = [_][]const u8{
        "[]",
        \\{"retryThrottling": {"maxTokens": 0, "tokenRatio": 1}}
        ,
        \\{"methodConfig": [{"name": [{"method": "M"}]}]}
        ,
        \\{"methodConfig": [{"name": [{}], "retryPolicy": {
        \\  "maxAttempts": 2, "initialBackoff": "0s",
        \\  "maxBackoff": "1s", "backoffMultiplier": 1,
        \\  "retryableStatusCodes": ["UNAVAILABLE"]}}]}
        ,
        \\{"methodConfig": [{"name": [{}], "retryPolicy": {
        \\  "maxAttempts": 2, "initialBackoff": "1s",
        \\  "maxBackoff": "1s", "backoffMultiplier": 1,
        \\  "retryableStatusCodes": ["OK"]}}]}
        ,
        \\{"methodConfig": [{"name": [{}]}, {"name": [{"service": ""}]}]}
        ,
        \\{"methodConfig": [{"name": [{}], "maxRequestMessageBytes": -1}]}
        ,
        \\{"methodConfig": [{"name": [{}], "maxResponseMessageBytes": "4294967296"}]}
        ,
    };
    for (invalid) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

test "gRPC service config accepts an immediate method timeout" {
    var config = try ServiceConfig.parse(std.testing.allocator,
        \\{"methodConfig": [{"name": [{}], "timeout": "0s"}]}
    );
    defer config.deinit();
    try std.testing.expectEqual(
        @as(i96, 0),
        config.methodPolicy("/demo.Service/Call").?.timeout.?.nanoseconds,
    );
}

test "gRPC service config gates per-attempt receive timeout" {
    const without_statuses =
        \\{"methodConfig":[{"name":[{}],"retryPolicy":{
        \\ "maxAttempts":2,"initialBackoff":"1s","maxBackoff":"2s",
        \\ "backoffMultiplier":1.5,"perAttemptRecvTimeout":"0.25s"}}]}
    ;
    try std.testing.expectError(
        error.InvalidServiceConfig,
        ServiceConfig.parse(std.testing.allocator, without_statuses),
    );
    var enabled = try ServiceConfig.parseWithOptions(
        std.testing.allocator,
        without_statuses,
        .{ .enable_per_attempt_recv_timeout = true },
    );
    defer enabled.deinit();
    const policy = enabled.retryPolicy("/demo.Service/Unary").?;
    try std.testing.expectEqual(@as(usize, 0), policy.retryable_status_codes.len);
    try std.testing.expectEqual(
        @as(i96, 250 * std.time.ns_per_ms),
        policy.per_attempt_recv_timeout.?.nanoseconds,
    );

    var ignored = try ServiceConfig.parse(std.testing.allocator,
        \\{"methodConfig":[{"name":[{}],"retryPolicy":{
        \\ "maxAttempts":2,"initialBackoff":"1s","maxBackoff":"2s",
        \\ "backoffMultiplier":1.5,"perAttemptRecvTimeout":"invalid",
        \\ "retryableStatusCodes":["ABORTED"]}}]}
    );
    defer ignored.deinit();
    try std.testing.expect(
        ignored.retryPolicy("/demo.Service/Unary").?.per_attempt_recv_timeout == null,
    );

    try std.testing.expectError(
        error.InvalidServiceConfig,
        ServiceConfig.parseWithOptions(
            std.testing.allocator,
            \\{"methodConfig":[{"name":[{}],"retryPolicy":{
            \\ "maxAttempts":2,"initialBackoff":"1s","maxBackoff":"2s",
            \\ "backoffMultiplier":1.5,"perAttemptRecvTimeout":"0s"}}]}
        ,
            .{ .enable_per_attempt_recv_timeout = true },
        ),
    );
}

test "gRPC service config parses weighted round robin defaults and bounds" {
    var defaults = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{}}]}
    );
    defer defaults.deinit();
    const default_lb = defaults.loadBalancingConfig();
    try std.testing.expectEqual(LoadBalancingPolicy.weighted_round_robin, default_lb.policy);
    try std.testing.expect(!default_lb.weighted_round_robin.enable_oob_load_report);
    try std.testing.expectEqual(@as(i96, 10 * std.time.ns_per_s), default_lb.weighted_round_robin.oob_reporting_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, 10 * std.time.ns_per_s), default_lb.weighted_round_robin.blackout_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, std.time.ns_per_s), default_lb.weighted_round_robin.weight_update_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, 180 * std.time.ns_per_s), default_lb.weighted_round_robin.weight_expiration_period.nanoseconds);
    try std.testing.expectEqual(@as(f64, 1), default_lb.weighted_round_robin.error_utilization_penalty);

    var configured = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{
        \\ "enableOobLoadReport":true,"oobReportingPeriod":"2s",
        \\ "blackoutPeriod":"0s","weightUpdatePeriod":"0.001s",
        \\ "weightExpirationPeriod":"9s","errorUtilizationPenalty":2.5,
        \\ "metricNamesForComputingUtilization":["cpu_utilization","utilization.disk"]}}]}
    );
    defer configured.deinit();
    const wrr = configured.loadBalancingConfig().weighted_round_robin;
    try std.testing.expect(wrr.enable_oob_load_report);
    try std.testing.expectEqual(@as(i96, 2 * std.time.ns_per_s), wrr.oob_reporting_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, 0), wrr.blackout_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, 100 * std.time.ns_per_ms), wrr.weight_update_period.nanoseconds);
    try std.testing.expectEqual(@as(i96, 9 * std.time.ns_per_s), wrr.weight_expiration_period.nanoseconds);
    try std.testing.expectEqual(@as(usize, 2), wrr.metric_names.len);
    try std.testing.expectEqual(@as(f64, 2.5), wrr.error_utilization_penalty);

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"weighted_round_robin":{"errorUtilizationPenalty":-1}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{"metricNamesForComputingUtilization":["unsupported"]}}]}
        ,
    }) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

test "gRPC service config parses outlier detection and child policy" {
    var parsed = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "interval":"1.2s","baseEjectionTime":"2.3s",
        \\ "maxEjectionTime":"3.4s","maxEjectionPercent":3,
        \\ "successRateEjection":{"stdevFactor":1,
        \\  "enforcementPercentage":2,"minimumHosts":3,"requestVolume":4},
        \\ "failurePercentageEjection":{"threshold":5,
        \\  "enforcementPercentage":6,"minimumHosts":7,"requestVolume":8},
        \\ "childPolicy":[{"unknown":{}},{"round_robin":{}}]}}]}
    );
    defer parsed.deinit();
    const balancing = parsed.loadBalancingConfig();
    try std.testing.expectEqual(
        LoadBalancingPolicy.round_robin,
        balancing.policy,
    );
    const outlier = balancing.outlier_detection.?;
    try std.testing.expectEqual(
        @as(i96, 1200 * std.time.ns_per_ms),
        outlier.interval.nanoseconds,
    );
    try std.testing.expectEqual(@as(u32, 3), outlier.max_ejection_percent);
    try std.testing.expectEqual(
        @as(u32, 1),
        outlier.success_rate_ejection.?.stdev_factor,
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        outlier.failure_percentage_ejection.?.threshold,
    );
    const root = balancing.root.?;
    try std.testing.expectEqual(
        LoadBalancingPolicy.round_robin,
        root.leafPolicy(),
    );
    switch (root.*) {
        .outlier_detection => |wrapper| {
            try std.testing.expectEqual(
                @as(u32, 3),
                wrapper.config.max_ejection_percent,
            );
            try std.testing.expect(wrapper.child.* == .round_robin);
        },
        else => return error.TestUnexpectedResult,
    }

    var defaults = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "baseEjectionTime":"400s",
        \\ "childPolicy":[{"pick_first":{}}]}}]}
    );
    defer defaults.deinit();
    const default_outlier = defaults.loadBalancingConfig()
        .outlier_detection.?;
    try std.testing.expectEqual(
        @as(i96, 400 * std.time.ns_per_s),
        default_outlier.max_ejection_time.nanoseconds,
    );
    try std.testing.expect(!default_outlier.countingEnabled());

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{}}]}
        ,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "maxEjectionPercent":101,"childPolicy":[{"round_robin":{}}]}}]}
        ,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "failurePercentageEjection":{"threshold":101},
        \\ "childPolicy":[{"round_robin":{}}]}}]}
        ,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "successRateEjection":{"enforcementPercentage":101},
        \\ "childPolicy":[{"round_robin":{}}]}}]}
        ,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "childPolicy":[{"unknown":{}}]}}]}
        ,
    }) |json| try std.testing.expectError(
        error.InvalidServiceConfig,
        ServiceConfig.parse(std.testing.allocator, json),
    );
}

test "gRPC service config parses priority children and order" {
    var parsed = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{
        \\  "high":{"config":[{"round_robin":{}}],
        \\   "ignoreReresolutionRequests":true},
        \\  "low":{"config":[{"pick_first":{}}]}},
        \\ "priorities":["high","low"]}}]}
    );
    defer parsed.deinit();
    const balancing = parsed.loadBalancingConfig();
    try std.testing.expectEqual(LoadBalancingPolicy.priority, balancing.policy);
    const root = balancing.root.?;
    try std.testing.expectEqual(LoadBalancingPolicy.priority, root.leafPolicy());
    switch (root.*) {
        .priority => |priority| {
            try std.testing.expectEqual(@as(usize, 2), priority.children.len);
            try std.testing.expectEqualStrings("high", priority.children[0].name);
            try std.testing.expect(priority.children[0].ignore_reresolution_requests);
            try std.testing.expect(priority.children[0].child.* == .round_robin);
            try std.testing.expectEqualStrings("low", priority.children[1].name);
            try std.testing.expect(!priority.children[1].ignore_reresolution_requests);
            try std.testing.expect(priority.children[1].child.* == .pick_first);
            try std.testing.expectEqual(@as(usize, 2), priority.priorities.len);
            try std.testing.expectEqualStrings("high", priority.priorities[0]);
            try std.testing.expectEqualStrings("low", priority.priorities[1]);
        },
        else => return error.TestUnexpectedResult,
    }

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}]}}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{},"priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}]}},
        \\ "priorities":["missing"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{}},"priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}],
        \\  "unknown":true}},"priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}],
        \\  "ignoreReresolutionRequests":"yes"}},"priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"round_robin":{}}]}},
        \\ "priorities":[""]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"":{"config":[{"round_robin":{}}]}},
        \\ "priorities":[""]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[]}},"priorities":["high"]}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{},"priorities":[],"extra":true}}]}
        ,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"high":{"config":[{"unknown":{}}]}},
        \\ "priorities":["high"]}}]}
        ,
    }) |json| try std.testing.expectError(
        error.InvalidServiceConfig,
        ServiceConfig.parse(std.testing.allocator, json),
    );
}

test "gRPC service config selects the first supported balancing policy" {
    var defaults = try ServiceConfig.parse(std.testing.allocator, "{}");
    defer defaults.deinit();
    try std.testing.expect(!defaults.loadBalancingConfig().configured);
    try std.testing.expect(defaults.loadBalancingConfig().root == null);

    var round_robin = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[
        \\  {"unknown_policy":{}},{"round_robin":{}}]}
    );
    defer round_robin.deinit();
    try std.testing.expectEqual(
        LoadBalancingPolicy.round_robin,
        round_robin.loadBalancingConfig().policy,
    );
    try std.testing.expect(round_robin.loadBalancingConfig().configured);
    try std.testing.expect(
        round_robin.loadBalancingConfig().root.?.* == .round_robin,
    );

    var pick_first = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[
        \\  {"pick_first":{"shuffleAddressList":true}}],
        \\ "loadBalancingPolicy":"round_robin"}
    );
    defer pick_first.deinit();
    try std.testing.expectEqual(
        LoadBalancingPolicy.pick_first,
        pick_first.loadBalancingConfig().policy,
    );
    try std.testing.expect(
        pick_first.loadBalancingConfig().shuffle_address_list,
    );

    var deprecated = try ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingPolicy":"ROUND_ROBIN"}
    );
    defer deprecated.deinit();
    try std.testing.expectEqual(
        LoadBalancingPolicy.round_robin,
        deprecated.loadBalancingConfig().policy,
    );

    for ([_][]const u8{
        \\{"loadBalancingConfig":[]}
        ,
        \\{"loadBalancingConfig":[{"unknown":{}}]}
        ,
        \\{"loadBalancingConfig":[{"pick_first":{"unknown":true}}]}
        ,
        \\{"loadBalancingPolicy":"unknown"}
        ,
    }) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

test "gRPC service config owns parsed selectors" {
    const json = try std.testing.allocator.dupe(u8,
        \\{"methodConfig": [{"name": [{"service": "demo.Owned"}],
        \\  "retryPolicy": {"maxAttempts": 2, "initialBackoff": "1s",
        \\    "maxBackoff": "2s", "backoffMultiplier": 2,
        \\    "retryableStatusCodes": ["UNAVAILABLE"]}}],
        \\ "loadBalancingConfig":[{"outlier_detection_experimental":{
        \\  "childPolicy":[{"least_request_experimental":{
        \\   "choiceCount":4}}]}}]}
    );
    var config = try ServiceConfig.parse(std.testing.allocator, json);
    defer config.deinit();
    @memset(json, 'x');
    std.testing.allocator.free(json);
    try std.testing.expect(config.retryPolicy("/demo.Owned/Call") != null);
    const root = config.loadBalancingConfig().root.?;
    try std.testing.expectEqual(LoadBalancingPolicy.least_request, root.leafPolicy());
    switch (root.*) {
        .outlier_detection => |wrapper| switch (wrapper.child.*) {
            .least_request => |least| try std.testing.expectEqual(
                @as(u8, 4),
                least.choice_count,
            ),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "gRPC service config parsing is transactional on allocation failure" {
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var config = try ServiceConfig.parse(allocator,
                \\{"retryThrottling": {"maxTokens": 8, "tokenRatio": 0.25},
                \\ "methodConfig": [{"name": [{"service": "demo.A"},
                \\ {"service": "demo.B", "method": "Call"}],
                \\ "retryPolicy": {"maxAttempts": 4,
                \\ "initialBackoff": "0.010s", "maxBackoff": "1s",
                \\ "backoffMultiplier": 1.5,
                \\ "retryableStatusCodes": ["UNAVAILABLE", "ABORTED"]}}],
                \\ "loadBalancingConfig":[{"outlier_detection_experimental":{
                \\  "childPolicy":[{"round_robin":{}}]}}]}
            );
            defer config.deinit();
            try std.testing.expect(config.retryPolicy("/demo.A/Call") != null);
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{},
    );
}
