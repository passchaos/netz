const std = @import("std");
const orca = @import("../../orca.zig");
const service_config = @import("../../service_config.zig");

const max_scaled: u64 = std.math.maxInt(u16);

pub const Scheduler = struct {
    const Entry = struct { worker: *anyopaque, weight: u16 };
    entries: std.ArrayList(Entry) = .empty,
    next_update_ns: i96 = 0,

    pub fn deinit(self: *Scheduler, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.* = .{};
    }

    pub fn remove(self: *Scheduler, worker: *anyopaque) void {
        for (self.entries.items, 0..) |entry, index| if (entry.worker == worker) {
            _ = self.entries.swapRemove(index);
            break;
        };
        self.next_update_ns = 0;
    }

    pub fn rebuild(self: *Scheduler, allocator: std.mem.Allocator, workers: anytype, now_ns: i96, config: service_config.WeightedRoundRobinConfig) std.mem.Allocator.Error!void {
        var ready: usize = 0;
        var nonzero: usize = 0;
        var sum: f64 = 0;
        var maximum: f64 = 0;
        for (workers) |worker| {
            if (!worker.eligible or worker.published != .ready) continue;
            ready += 1;
            const value = worker.wrr_weight.usable(now_ns, config);
            if (value > 0) {
                nonzero += 1;
                sum += value;
                maximum = @max(maximum, value);
            }
        }
        if (nonzero == 0) {
            self.entries.clearRetainingCapacity();
            self.next_update_ns = now_ns + config.weight_update_period.nanoseconds;
            return;
        }
        // Reserve before replacing the prior snapshot, so an allocation
        // failure never leaves a partially rebuilt scheduler visible.
        try self.entries.ensureTotalCapacity(allocator, ready);
        self.entries.clearRetainingCapacity();
        const mean = sum / @as(f64, @floatFromInt(nonzero));
        maximum = @min(maximum, mean * 10);
        const scale = @as(f64, @floatFromInt(max_scaled)) / maximum;
        const scaled_mean: u16 = @intFromFloat(@round(scale * mean));
        const lower: u16 = @max(1, @as(u16, @intFromFloat(@round(@as(f64, @floatFromInt(scaled_mean)) * 0.01))));
        for (workers) |worker| {
            if (!worker.eligible or worker.published != .ready) continue;
            const raw = worker.wrr_weight.usable(now_ns, config);
            const scaled: u16 = if (raw == 0) scaled_mean else @max(lower, @as(u16, @intFromFloat(@round(@min(raw, maximum) * scale))));
            self.entries.appendAssumeCapacity(.{ .worker = worker, .weight = scaled });
        }
        self.next_update_ns = now_ns + config.weight_update_period.nanoseconds;
    }

    pub fn pick(self: *Scheduler, comptime Worker: type, sequence: *u32) ?*Worker {
        var available: usize = 0;
        for (self.entries.items) |entry| {
            const worker: *Worker = @ptrCast(@alignCast(entry.worker));
            if (worker.eligible and worker.published == .ready and worker.capacity != 0) {
                available += 1;
                if (available > 1) break;
            }
        }
        if (available <= 1) return null;
        while (true) {
            const current = sequence.*;
            sequence.* +%= 1;
            const index = current % @as(u32, @intCast(self.entries.items.len));
            const generation = current / @as(u32, @intCast(self.entries.items.len));
            const entry = self.entries.items[index];
            const worker: *Worker = @ptrCast(@alignCast(entry.worker));
            if (!worker.eligible or worker.published != .ready or worker.capacity == 0) continue;
            const mod = (@as(u64, entry.weight) * generation + @as(u64, index) * (max_scaled / 2)) % max_scaled;
            if (mod >= max_scaled - entry.weight) return worker;
        }
    }
};

pub const Weight = struct {
    value: f64 = 0,
    non_empty_since_ns: ?i96 = null,
    last_update_ns: ?i96 = null,

    pub fn update(self: *Weight, report: orca.LoadReport, now_ns: i96, config: service_config.WeightedRoundRobinConfig) void {
        const utilization = reportUtilization(report, config.metric_names);
        if (report.rps_fractional <= 0 or utilization <= 0) return;
        const penalty = if (report.eps > 0 and config.error_utilization_penalty > 0)
            report.eps / report.rps_fractional * config.error_utilization_penalty
        else
            0;
        const value = report.rps_fractional / (utilization + penalty);
        if (!std.math.isFinite(value) or value <= 0) return;
        if (self.non_empty_since_ns == null) self.non_empty_since_ns = now_ns;
        self.value = value;
        self.last_update_ns = now_ns;
    }

    pub fn usable(self: *Weight, now_ns: i96, config: service_config.WeightedRoundRobinConfig) f64 {
        const updated = self.last_update_ns orelse return 0;
        if (now_ns - updated >= config.weight_expiration_period.nanoseconds) {
            self.non_empty_since_ns = null;
            return 0;
        }
        const since = self.non_empty_since_ns orelse return 0;
        if (now_ns - since < config.blackout_period.nanoseconds) return 0;
        return self.value;
    }

    pub fn disconnected(self: *Weight) void {
        self.non_empty_since_ns = null;
    }
};

fn reportUtilization(report: orca.LoadReport, names: []const []const u8) f64 {
    var result: f64 = 0;
    for (names) |name| {
        const value = if (std.mem.eql(u8, name, "cpu_utilization"))
            report.cpu_utilization
        else if (std.mem.eql(u8, name, "mem_utilization"))
            report.memory_utilization
        else if (std.mem.eql(u8, name, "application_utilization"))
            report.application_utilization
        else if (std.mem.startsWith(u8, name, "named_metrics."))
            metric(report.named_metrics, name["named_metrics.".len..])
        else
            metric(report.utilization, name["utilization.".len..]);
        if (value > 0) result = @max(result, value);
    }
    if (result <= 0) result = report.application_utilization;
    if (result <= 0) result = report.cpu_utilization;
    return result;
}

fn metric(metrics: []const orca.Metric, name: []const u8) f64 {
    for (metrics) |entry| if (std.mem.eql(u8, entry.name, name)) return entry.value;
    return 0;
}

test "gRPC weighted round robin follows ORCA weights and lifecycle" {
    const Fake = struct {
        eligible: bool = true,
        published: @import("../connectivity.zig").State = .ready,
        capacity: usize = 1,
        wrr_weight: Weight = .{},
    };
    var a: Fake = .{};
    var b: Fake = .{};
    const config = service_config.WeightedRoundRobinConfig{
        .blackout_period = .zero,
        .weight_expiration_period = .fromSeconds(10),
    };
    a.wrr_weight.update(.{ .rps_fractional = 1, .cpu_utilization = 1 }, 0, config);
    b.wrr_weight.update(.{ .rps_fractional = 3, .cpu_utilization = 1 }, 0, config);
    const workers = [_]*Fake{ &a, &b };
    var scheduler: Scheduler = .{};
    defer scheduler.deinit(std.testing.allocator);
    try scheduler.rebuild(std.testing.allocator, &workers, 1, config);
    var sequence: u32 = 0;
    var counts = [_]usize{ 0, 0 };
    for (0..4000) |_| {
        const selected = scheduler.pick(Fake, &sequence).?;
        counts[@intFromBool(selected == &b)] += 1;
    }
    try std.testing.expect(counts[1] > counts[0] * 2);
    try std.testing.expect(counts[1] < counts[0] * 4);
    b.capacity = 0;
    const before_fallback = sequence;
    try std.testing.expect(scheduler.pick(Fake, &sequence) == null);
    try std.testing.expectEqual(before_fallback, sequence);
    b.capacity = 1;
    try scheduler.rebuild(
        std.testing.allocator,
        &workers,
        10 * std.time.ns_per_s,
        config,
    );
    try std.testing.expect(scheduler.pick(Fake, &sequence) == null);

    a.wrr_weight.disconnected();
    try std.testing.expectEqual(@as(f64, 0), a.wrr_weight.usable(20, config));
    const blackout = service_config.WeightedRoundRobinConfig{
        .blackout_period = .fromSeconds(1),
    };
    a.wrr_weight.update(.{ .rps_fractional = 1, .cpu_utilization = 1 }, 20, blackout);
    try std.testing.expectEqual(@as(f64, 0), a.wrr_weight.usable(20, blackout));
}
