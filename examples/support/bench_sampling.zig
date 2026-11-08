//! Shared harnessz-backed sampling helpers for native netz benchmarks.
//!
//! Benchmarks keep their existing command-line interface and record output,
//! but obtain warmup, repeated samples, and distribution statistics from
//! `harnessz.bench` instead of hand-written timing loops.

const std = @import("std");
const builtin = @import("builtin");
const harnessz = @import("harnessz");

pub const Stats = harnessz.bench.Stats;

pub const Options = struct {
    /// Operations performed by one timed callback.
    iterations: usize,
    /// Number of timed callback invocations.
    samples: usize = 10,
    /// Untimed callback invocations before sampling.
    warmup: usize = 1,
};

/// Run `work` with harnessz warmup and sampling. The callback signature is
/// `fn (context, allocator, io) anyerror!u64` and should return a checksum.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    context: anytype,
    comptime work: anytype,
) !Stats {
    return harnessz.bench.run(
        allocator,
        io,
        .{
            .warmup_iterations = options.warmup,
            .iterations = options.samples,
        },
        context,
        work,
    );
}

/// Median sample duration divided by the operations in one callback.
pub fn nsPerOp(stats: Stats, iterations: usize) u64 {
    if (iterations == 0) return 0;
    const median = stats.distribution.median;
    if (median <= 0) return 0;
    return @intFromFloat(median / @as(f64, @floatFromInt(iterations)));
}

pub fn printDistribution(label: []const u8, stats: Stats) void {
    const distribution = stats.distribution;
    std.debug.print(
        "    {s} sample ns: min={d:.0} p50={d:.0} p90={d:.0} p99={d:.0} mean={d:.0} stddev={d:.0}\n",
        .{
            label,
            distribution.min,
            distribution.median,
            distribution.p90,
            distribution.p99,
            distribution.mean,
            distribution.stddev,
        },
    );
}

pub fn ratioTimes100(numerator: f64, denominator: f64) u64 {
    if (denominator <= 0 or numerator <= 0) return 0;
    return @intFromFloat(numerator * 100.0 / denominator);
}

pub const BaselineOptions = struct {
    /// Relative path to the JSON baseline store.
    path: []const u8,
    /// A regression is reported when
    /// `current_median > baseline_median * max_regression_ratio`.
    max_regression_ratio: f64 = 1.05,
    /// Replace or add entries instead of comparing.
    update: bool = false,
    /// Report regressions without returning `error.PerformanceRegression`.
    warn_only: bool = false,
};

pub const BaselineEntry = struct {
    name: []const u8,
    stats: Stats,
};

/// Compare (or update) the named scenario samples against a harnessz
/// baseline store. Comparison enforces the environment fingerprint so a
/// baseline recorded with another build mode or CPU count fails loudly.
pub fn checkBaselines(
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: []const BaselineEntry,
    options: BaselineOptions,
) !void {
    if (entries.len == 0) return;

    const dir = std.Io.Dir.cwd();
    var store = harnessz.baseline.Store.init(allocator);
    defer store.deinit();
    store.load(io, dir, options.path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const fingerprint = try harnessz.baseline.environmentFingerprint(
        allocator,
        io,
        @tagName(builtin.mode),
    );
    defer allocator.free(fingerprint);

    if (options.update) {
        var updated: std.ArrayList(harnessz.baseline.Entry) = .empty;
        defer updated.deinit(allocator);
        try updated.appendSlice(allocator, store.entries);
        for (entries) |item| {
            const entry: harnessz.baseline.Entry = .{
                .name = item.name,
                .environment_fingerprint = fingerprint,
                .samples_ns = item.stats.samples_ns,
                .summary = item.stats.distribution,
            };
            var replaced = false;
            for (updated.items) |*existing| {
                if (std.mem.eql(u8, existing.name, item.name)) {
                    existing.* = entry;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) try updated.append(allocator, entry);
        }
        store.entries = updated.items;
        try store.save(io, dir, options.path);
        std.debug.print(
            "baseline updated: {s} ({d} entries)\n",
            .{ options.path, updated.items.len },
        );
        return;
    }

    var regressed = false;
    for (entries) |item| {
        const regression = store.compare(item.name, item.stats.samples_ns, .{
            .max_regression_ratio = options.max_regression_ratio,
            .require_fingerprint = true,
            .expected_fingerprint = fingerprint,
        }) catch |err| switch (err) {
            error.MissingBaseline => {
                std.debug.print(
                    "baseline entry missing: {s} (rerun with --update-baseline)\n",
                    .{item.name},
                );
                return err;
            },
            error.EnvironmentMismatch => {
                std.debug.print(
                    "baseline environment mismatch: {s} (recorded fingerprint differs from {s})\n",
                    .{ item.name, fingerprint },
                );
                return err;
            },
            else => return err,
        };
        const entry = store.get(item.name) orelse return error.MissingBaseline;
        const comparison = harnessz.bench.Comparison.fromSamples(
            entry.samples_ns,
            item.stats.samples_ns,
        );
        const robust_available =
            entry.samples_ns.len >= 2 and item.stats.samples_ns.len >= 2;
        const failed = regression.regressed and
            (!robust_available or comparison.robust_significant);
        std.debug.print(
            "baseline {s}: {d:.0} ns -> {d:.0} ns, speedup {d:.3}x, robust p={d:.4}{s}\n",
            .{
                item.name,
                regression.baseline_median,
                regression.current_median,
                regression.speedup,
                comparison.robust_p_value,
                if (failed)
                    " REGRESSED"
                else if (regression.regressed)
                    " ratio-regression (not significant)"
                else
                    "",
            },
        );
        regressed = regressed or failed;
    }
    if (regressed) {
        if (options.warn_only) {
            std.debug.print(
                "baseline regression reported for {s} (warn-only mode)\n",
                .{options.path},
            );
            return;
        }
        return error.PerformanceRegression;
    }
}
