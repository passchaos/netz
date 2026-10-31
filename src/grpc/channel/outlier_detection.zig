//! grpc-core-compatible interval buckets and endpoint ejection policy.
const std = @import("std");
const service_config = @import("../service_config.zig");

pub const Config = service_config.OutlierDetectionConfig;

pub const Endpoint = struct {
    successes: std.atomic.Value(u64) = .init(0),
    failures: std.atomic.Value(u64) = .init(0),
    backup_successes: u64 = 0,
    backup_failures: u64 = 0,
    multiplier: u32 = 0,
    ejected_at_ns: ?i96 = null,

    pub fn record(self: *Endpoint, success: bool) void {
        const counter = if (success) &self.successes else &self.failures;
        _ = counter.fetchAdd(1, .monotonic);
    }

    pub fn isEjected(self: *const Endpoint) bool {
        return self.ejected_at_ns != null;
    }

    fn rotate(self: *Endpoint) void {
        self.backup_successes = self.successes.swap(0, .acq_rel);
        self.backup_failures = self.failures.swap(0, .acq_rel);
    }

    fn volume(self: Endpoint) u64 {
        return self.backup_successes +| self.backup_failures;
    }

    fn successRate(self: Endpoint) ?f64 {
        const request_volume = self.volume();
        if (request_volume == 0) return null;
        return 100 * @as(f64, @floatFromInt(self.backup_successes)) /
            @as(f64, @floatFromInt(request_volume));
    }

    fn eject(self: *Endpoint, now_ns: i96) bool {
        if (self.ejected_at_ns != null) return false;
        self.multiplier +|= 1;
        self.ejected_at_ns = now_ns;
        return true;
    }

    fn maybeUneject(self: *Endpoint, config: Config, now_ns: i96) bool {
        const ejected = self.ejected_at_ns orelse {
            self.multiplier -|= 1;
            return false;
        };
        const base = @max(config.base_ejection_time.nanoseconds, 0);
        const maximum = @max(
            base,
            @max(config.max_ejection_time.nanoseconds, 0),
        );
        const scaled = std.math.mul(
            i96,
            base,
            self.multiplier,
        ) catch std.math.maxInt(i96);
        const duration = @min(scaled, maximum);
        const expires = std.math.add(i96, ejected, duration) catch
            std.math.maxInt(i96);
        if (now_ns <= expires) return false;
        self.ejected_at_ns = null;
        return true;
    }
};

/// Evaluate every currently eligible endpoint without allocating. `endpoint`
/// returns its persistent counter state; `eligible` excludes retired resolver
/// generations from both statistics and max-ejection-percent accounting.
pub fn evaluate(
    io: std.Io,
    config: Config,
    context: anytype,
    count: usize,
    now_ns: i96,
    comptime endpoint: anytype,
    comptime eligible: anytype,
) bool {
    if (!config.countingEnabled()) return false;
    var total_hosts: usize = 0;
    var ejected_hosts: usize = 0;
    var success_candidates: usize = 0;
    var success_sum: f64 = 0;
    var failure_candidates: usize = 0;
    for (0..count) |index| {
        if (!eligible(context, index)) continue;
        total_hosts += 1;
        const state = endpoint(context, index);
        state.rotate();
        ejected_hosts += @intFromBool(state.isEjected());
        const rate = state.successRate() orelse continue;
        const volume = state.volume();
        if (config.success_rate_ejection) |policy| {
            if (volume >= policy.request_volume) {
                success_candidates += 1;
                success_sum += rate;
            }
        }
        if (config.failure_percentage_ejection) |policy| {
            if (volume >= policy.request_volume) {
                failure_candidates += 1;
            }
        }
    }
    if (total_hosts == 0) return false;

    var changed = false;
    if (config.success_rate_ejection) |policy| {
        if (success_candidates != 0 and
            success_candidates >= policy.minimum_hosts)
        {
            const mean = success_sum /
                @as(f64, @floatFromInt(success_candidates));
            var variance: f64 = 0;
            for (0..count) |index| {
                if (!eligible(context, index)) continue;
                const state = endpoint(context, index);
                if (state.volume() < policy.request_volume) continue;
                const rate = state.successRate() orelse continue;
                variance += std.math.pow(f64, rate - mean, 2);
            }
            variance /= @as(f64, @floatFromInt(success_candidates));
            const threshold = mean - std.math.sqrt(variance) *
                @as(f64, @floatFromInt(policy.stdev_factor)) / 1000;
            for (0..count) |index| {
                if (!eligible(context, index)) continue;
                const state = endpoint(context, index);
                if (state.volume() < policy.request_volume) continue;
                const rate = state.successRate() orelse continue;
                if (rate < threshold and
                    enforced(io, policy.enforcement_percentage) and
                    canEject(ejected_hosts, total_hosts, config.max_ejection_percent))
                {
                    if (state.eject(now_ns)) {
                        ejected_hosts += 1;
                        changed = true;
                    }
                }
            }
        }
    }
    if (config.failure_percentage_ejection) |policy| {
        if (failure_candidates != 0 and
            failure_candidates >= policy.minimum_hosts)
        {
            for (0..count) |index| {
                if (!eligible(context, index)) continue;
                const state = endpoint(context, index);
                if (state.isEjected() or
                    state.volume() < policy.request_volume) continue;
                const rate = state.successRate() orelse continue;
                if (100 - rate > @as(f64, @floatFromInt(policy.threshold)) and
                    enforced(io, policy.enforcement_percentage) and
                    canEject(ejected_hosts, total_hosts, config.max_ejection_percent))
                {
                    if (state.eject(now_ns)) {
                        ejected_hosts += 1;
                        changed = true;
                    }
                }
            }
        }
    }
    for (0..count) |index| {
        if (!eligible(context, index)) continue;
        changed = endpoint(context, index).maybeUneject(config, now_ns) or changed;
    }
    return changed;
}

fn canEject(ejected: usize, total: usize, maximum_percent: u32) bool {
    if (ejected == 0) return true;
    const current = 100 * @as(f64, @floatFromInt(ejected)) /
        @as(f64, @floatFromInt(total));
    return current < @as(f64, @floatFromInt(maximum_percent));
}

fn enforced(io: std.Io, percentage: u32) bool {
    if (percentage == 0) return false;
    if (percentage >= 100) return true;
    var sample: u32 = undefined;
    io.random(std.mem.asBytes(&sample));
    return sample % 100 < percentage;
}

test "gRPC outlier detection rotates success rate and failure buckets" {
    const Item = struct { endpoint: Endpoint = .{}, eligible: bool = true };
    const Access = struct {
        fn endpoint(items: []const *Item, index: usize) *Endpoint {
            return &items[index].endpoint;
        }
        fn eligible(items: []const *Item, index: usize) bool {
            return items[index].eligible;
        }
    };
    var items = [_]Item{ .{}, .{}, .{} };
    for (0..4) |_| {
        items[0].endpoint.record(true);
        items[1].endpoint.record(true);
        items[2].endpoint.record(false);
    }
    const pointers = [_]*Item{ &items[0], &items[1], &items[2] };
    const success = Config{
        .interval = .fromSeconds(1),
        .base_ejection_time = .fromSeconds(2),
        .max_ejection_time = .fromSeconds(4),
        .max_ejection_percent = 10,
        .success_rate_ejection = .{
            .stdev_factor = 1000,
            .minimum_hosts = 3,
            .request_volume = 4,
        },
    };
    try std.testing.expect(evaluate(
        undefined,
        success,
        &pointers,
        pointers.len,
        10,
        Access.endpoint,
        Access.eligible,
    ));
    try std.testing.expect(items[2].endpoint.isEjected());
    try std.testing.expect(!items[0].endpoint.isEjected());
    try std.testing.expect(evaluate(
        undefined,
        success,
        &pointers,
        pointers.len,
        2 * std.time.ns_per_s + 11,
        Access.endpoint,
        Access.eligible,
    ));
    try std.testing.expect(!items[2].endpoint.isEjected());

    items[1].eligible = false;
    items[2].endpoint.record(false);
    const failure = Config{
        .max_ejection_percent = 100,
        .failure_percentage_ejection = .{
            .threshold = 50,
            .minimum_hosts = 1,
            .request_volume = 1,
        },
    };
    try std.testing.expect(evaluate(
        undefined,
        failure,
        &pointers,
        pointers.len,
        100,
        Access.endpoint,
        Access.eligible,
    ));
    try std.testing.expect(items[2].endpoint.isEjected());
}
