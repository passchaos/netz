const std = @import("std");
const sampling = @import("support").bench_sampling;
const netz = @import("netz");

const device_count: usize = 4096;
const default_samples: usize = 10;
const default_warmup: usize = 1;

/// One topic per device in the broad store, four in the mixed store. The
/// mixed store exercises selective wildcard filters where a full-table scan
/// visits four times more entries than the filter matches.
const mixed_kinds = [_][]const u8{ "state", "temp", "config", "meta" };

const Scenario = enum { all, exact, wildcard, hash, selective, subtree };

const Options = struct {
    scenario: Scenario = .all,
    samples: usize = default_samples,
    warmup: usize = default_warmup,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const WorkContext = struct {
    store: *netz.mqtt.retained.Store,
    filter: []const u8,
    out: []netz.mqtt.retained.Match,
    iterations: usize,
    now: std.Io.Timestamp,
};

const Run = struct {
    stats: sampling.Stats,
    iterations: usize,

    fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        self.stats.deinit(allocator);
    }

    fn medianNsPerOp(self: Run) u64 {
        return sampling.nsPerOp(self.stats, self.iterations);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const now = std.Io.Timestamp.zero;

    var state_store = netz.mqtt.retained.Store.init(allocator, .{
        .max_messages = device_count,
    });
    defer state_store.deinit();
    var mixed_store = netz.mqtt.retained.Store.init(allocator, .{
        .max_messages = device_count * mixed_kinds.len,
    });
    defer mixed_store.deinit();

    var topic_buffer: [64]u8 = undefined;
    var payload: [64]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 19);
    for (0..device_count) |index| {
        const state_topic = try std.fmt.bufPrint(
            &topic_buffer,
            "devices/{d}/state",
            .{index},
        );
        _ = try state_store.applyPublish(state_topic, &payload, .{
            .retain = true,
            .qos = .at_least_once,
            .now = now,
        });
        for (mixed_kinds) |kind| {
            const topic = try std.fmt.bufPrint(
                &topic_buffer,
                "devices/{d}/{s}",
                .{ index, kind },
            );
            _ = try mixed_store.applyPublish(topic, &payload, .{
                .retain = true,
                .qos = .at_least_once,
                .now = now,
            });
        }
    }

    var storage: [device_count]netz.mqtt.retained.Match = undefined;
    var exact: ?Run = null;
    defer if (exact) |*run| run.deinit(allocator);
    var wildcard: ?Run = null;
    defer if (wildcard) |*run| run.deinit(allocator);
    var hash: ?Run = null;
    defer if (hash) |*run| run.deinit(allocator);
    var selective: ?Run = null;
    defer if (selective) |*run| run.deinit(allocator);
    var subtree: ?Run = null;
    defer if (subtree) |*run| run.deinit(allocator);

    if (options.scenario == .all or options.scenario == .exact) {
        exact = try runScenario(
            allocator,
            io,
            options,
            .{
                .store = &state_store,
                .filter = "devices/2048/state",
                .out = storage[0..1],
                .iterations = 100_000,
                .now = now,
            },
        );
    }
    if (options.scenario == .all or options.scenario == .wildcard) {
        wildcard = try runScenario(
            allocator,
            io,
            options,
            .{
                .store = &state_store,
                .filter = "devices/+/state",
                .out = &storage,
                .iterations = 1_000,
                .now = now,
            },
        );
    }
    if (options.scenario == .all or options.scenario == .hash) {
        hash = try runScenario(
            allocator,
            io,
            options,
            .{
                .store = &state_store,
                .filter = "devices/#",
                .out = &storage,
                .iterations = 1_000,
                .now = now,
            },
        );
    }
    if (options.scenario == .all or options.scenario == .selective) {
        selective = try runScenario(
            allocator,
            io,
            options,
            .{
                .store = &mixed_store,
                .filter = "devices/+/state",
                .out = &storage,
                .iterations = 500,
                .now = now,
            },
        );
    }
    if (options.scenario == .all or options.scenario == .subtree) {
        subtree = try runScenario(
            allocator,
            io,
            options,
            .{
                .store = &mixed_store,
                .filter = "devices/1234/#",
                .out = storage[0..4],
                .iterations = 100_000,
                .now = now,
            },
        );
    }

    std.debug.print(
        "MQTT retained store benchmark\n" ++
            "  io backend: zio-std-io\n" ++
            "  retained messages: {d} state-only, {d} mixed\n" ++
            "  samples: {d}, warmup: {d}\n",
        .{
            device_count,
            device_count * mixed_kinds.len,
            options.samples,
            options.warmup,
        },
    );
    if (exact) |run| printRun("exact", run);
    if (wildcard) |run| printRun("wildcard devices/+/state", run);
    if (hash) |run| printRun("wildcard devices/#", run);
    if (selective) |run| printRun("selective devices/+/state", run);
    if (subtree) |run| printRun("selective devices/1234/#", run);

    if (options.baseline_path) |path| {
        var entries: [5]sampling.BaselineEntry = undefined;
        var count: usize = 0;
        if (exact) |run| {
            entries[count] = .{
                .name = "bench-mqtt-retained/exact",
                .stats = run.stats,
            };
            count += 1;
        }
        if (wildcard) |run| {
            entries[count] = .{
                .name = "bench-mqtt-retained/wildcard",
                .stats = run.stats,
            };
            count += 1;
        }
        if (hash) |run| {
            entries[count] = .{
                .name = "bench-mqtt-retained/hash",
                .stats = run.stats,
            };
            count += 1;
        }
        if (selective) |run| {
            entries[count] = .{
                .name = "bench-mqtt-retained/selective",
                .stats = run.stats,
            };
            count += 1;
        }
        if (subtree) |run| {
            entries[count] = .{
                .name = "bench-mqtt-retained/subtree",
                .stats = run.stats,
            };
            count += 1;
        }
        try sampling.checkBaselines(allocator, io, entries[0..count], .{
            .path = path,
            .max_regression_ratio = options.max_regression_ratio,
            .update = options.update_baseline,
            .warn_only = options.warn_only,
        });
    }
}

fn runScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    context: WorkContext,
) !Run {
    const stats = try sampling.run(
        allocator,
        io,
        .{
            .iterations = context.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        context,
        lookupWork,
    );
    return .{ .stats = stats, .iterations = context.iterations };
}

fn lookupWork(
    context: WorkContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const matches = try context.store.matchInto(
            context.filter,
            context.now,
            context.out,
        );
        total +%= @intCast(matches.len);
        if (matches.len != 0) {
            total +%= matches[matches.len - 1].payload[0];
        }
    }
    return total;
}

fn printRun(label: []const u8, run: Run) void {
    std.debug.print(
        "  {s}: {d} ns/op\n",
        .{ label, run.medianNsPerOp() },
    );
    sampling.printDistribution(label, run.stats);
}

fn parseOptions(
    init: std.process.Init,
    allocator: std.mem.Allocator,
) !Options {
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--scenario=")) {
            options.scenario = std.meta.stringToEnum(
                Scenario,
                arg["--scenario=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--samples=")) {
            options.samples = try std.fmt.parseInt(
                usize,
                arg["--samples=".len..],
                10,
            );
            if (options.samples == 0) return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--baseline=")) {
            options.baseline_path = arg["--baseline=".len..];
            if (options.baseline_path.?.len == 0) return error.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--update-baseline")) {
            options.update_baseline = true;
        } else if (std.mem.eql(u8, arg, "--warn-only")) {
            options.warn_only = true;
        } else if (std.mem.startsWith(u8, arg, "--max-regression-ratio=")) {
            options.max_regression_ratio = try std.fmt.parseFloat(
                f64,
                arg["--max-regression-ratio=".len..],
            );
            if (!std.math.isFinite(options.max_regression_ratio) or
                options.max_regression_ratio <= 0)
            {
                return error.InvalidArgument;
            }
        } else {
            return error.InvalidArgument;
        }
    }
    return options;
}
