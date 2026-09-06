//! Owned gRPC service-config subset for unary retry policy selection.

const std = @import("std");
const call = @import("call.zig");
const wire = @import("wire.zig");

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
};

const JsonMethodConfig = struct {
    name: []const JsonName = &.{},
    timeout: ?[]const u8 = null,
    waitForReady: ?bool = null,
    maxRequestMessageBytes: ?std.json.Value = null,
    maxResponseMessageBytes: ?std.json.Value = null,
    retryPolicy: ?JsonRetryPolicy = null,
};

const JsonServiceConfig = struct {
    retryThrottling: ?JsonThrottle = null,
    methodConfig: []const JsonMethodConfig = &.{},
};

const OwnedRetryPolicy = struct {
    max_attempts: u8,
    initial_backoff: std.Io.Duration,
    max_backoff: std.Io.Duration,
    backoff_multiplier: f64,
    retryable_status_codes: []const wire.Status,

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
            .throttler = throttler,
        };
    }
};

const OwnedMethodPolicy = struct {
    timeout: ?std.Io.Duration = null,
    max_request_message_bytes: ?u32 = null,
    max_response_message_bytes: ?u32 = null,
    retry_policy: ?OwnedRetryPolicy = null,
};

pub const MethodPolicy = struct {
    timeout: ?std.Io.Duration,
    max_request_message_bytes: ?u32,
    max_response_message_bytes: ?u32,
    retry_policy: ?call.RetryPolicy,
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

    pub fn parse(
        allocator: std.mem.Allocator,
        json: []const u8,
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
            if (config.waitForReady != null) {
                return error.InvalidServiceConfig;
            }
            const policy = OwnedMethodPolicy{
                .timeout = if (config.timeout) |timeout|
                    try parseDuration(timeout, true)
                else
                    null,
                .max_request_message_bytes = try parseOptionalSize(
                    config.maxRequestMessageBytes,
                ),
                .max_response_message_bytes = try parseOptionalSize(
                    config.maxResponseMessageBytes,
                ),
                .retry_policy = if (config.retryPolicy) |retry|
                    try parseRetryPolicy(owned, retry)
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
        return .{
            .arena = arena,
            .methods = methods,
            .retry_throttler = throttler,
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

fn resolvedPolicy(
    config: *ServiceConfig,
    owned: OwnedMethodPolicy,
) MethodPolicy {
    return .{
        .timeout = owned.timeout,
        .max_request_message_bytes = owned.max_request_message_bytes,
        .max_response_message_bytes = owned.max_response_message_bytes,
        .retry_policy = if (owned.retry_policy) |retry|
            retry.view(throttlerPointer(config))
        else
            null,
    };
}

fn throttlerPointer(config: *ServiceConfig) ?*call.RetryThrottler {
    return config.retry_throttler;
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
) Error!OwnedRetryPolicy {
    const raw_attempts = json.maxAttempts orelse
        return error.InvalidServiceConfig;
    if (raw_attempts < 2) return error.InvalidServiceConfig;
    const statuses_raw = json.retryableStatusCodes orelse
        return error.InvalidServiceConfig;
    if (statuses_raw.len == 0) return error.InvalidServiceConfig;
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
        \\  ],
        \\  "loadBalancingConfig": []
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
        \\{"methodConfig": [{"name": [{}], "waitForReady": true}]}
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

test "gRPC service config owns parsed selectors" {
    const json = try std.testing.allocator.dupe(u8,
        \\{"methodConfig": [{"name": [{"service": "demo.Owned"}],
        \\  "retryPolicy": {"maxAttempts": 2, "initialBackoff": "1s",
        \\    "maxBackoff": "2s", "backoffMultiplier": 2,
        \\    "retryableStatusCodes": ["UNAVAILABLE"]}}]}
    );
    var config = try ServiceConfig.parse(std.testing.allocator, json);
    defer config.deinit();
    @memset(json, 'x');
    std.testing.allocator.free(json);
    try std.testing.expect(config.retryPolicy("/demo.Owned/Call") != null);
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
                \\ "retryableStatusCodes": ["UNAVAILABLE", "ABORTED"]}}]}
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
