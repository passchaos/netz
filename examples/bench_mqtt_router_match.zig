const std = @import("std");
const sampling = @import("support/bench_sampling.zig");
const netz = @import("netz");

const filter_count: usize = 4096;
const default_samples: usize = 10;
const default_warmup: usize = 1;
const match_iterations: usize = 20_000;
const linear_iterations: usize = 100;
const shared_member_count: usize = 64;
const shared_iterations: usize = 100_000;

const Options = struct {
    samples: usize = default_samples,
    warmup: usize = default_warmup,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const MatchContext = struct {
    router: *netz.mqtt.router.Router,
    topic: []const u8,
    out: []netz.mqtt.router.Match,
    iterations: usize,
};

const LinearContext = struct {
    filters: []const []u8,
    topic: []const u8,
    iterations: usize,
};

const SharedContext = struct {
    router: *netz.mqtt.router.Router,
    vary_topic: bool,
    iterations: usize,
};

const Run = struct {
    stats: sampling.Stats,
    iterations: usize,

    fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        self.stats.deinit(allocator);
    }

    fn nsPerOp(self: Run) u64 {
        return sampling.nsPerOp(self.stats, self.iterations);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var router = try netz.mqtt.router.Router.init(allocator);
    defer router.deinit();

    var filters: std.ArrayList([]u8) = .empty;
    defer {
        for (filters.items) |filter| allocator.free(filter);
        filters.deinit(allocator);
    }
    try filters.ensureTotalCapacity(allocator, filter_count + 2);

    var filter_buf: [64]u8 = undefined;
    for (0..filter_count) |index| {
        const filter = try std.fmt.bufPrint(
            &filter_buf,
            "devices/{d}/state",
            .{index},
        );
        const owned = try allocator.dupe(u8, filter);
        try filters.append(allocator, owned);
        try router.subscribe(@intCast(index), .{ .topic_filter = owned });
    }
    const wildcard_one = try allocator.dupe(u8, "devices/+/state");
    try filters.append(allocator, wildcard_one);
    try router.subscribe(100_000, .{ .topic_filter = wildcard_one });
    const wildcard_many = try allocator.dupe(u8, "devices/#");
    try filters.append(allocator, wildcard_many);
    try router.subscribe(100_001, .{ .topic_filter = wildcard_many });

    const topic = "devices/2047/state";
    var match_storage: [8]netz.mqtt.router.Match = undefined;
    var match_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, match_iterations),
        MatchContext{
            .router = &router,
            .topic = topic,
            .out = &match_storage,
            .iterations = match_iterations,
        },
        matchWork,
    );
    defer match_run.deinit(allocator);

    var linear_run = try sampling.run(
        allocator,
        io,
        samplingOptions(options, linear_iterations),
        LinearContext{
            .filters = filters.items,
            .topic = topic,
            .iterations = linear_iterations,
        },
        linearWork,
    );
    defer linear_run.deinit(allocator);

    var round_robin = try initSharedRouter(allocator, .round_robin);
    defer round_robin.deinit();
    var round_robin_run = try runShared(
        allocator,
        io,
        options,
        &round_robin,
        false,
    );
    defer round_robin_run.deinit(allocator);

    var sticky = try initSharedRouter(allocator, .sticky);
    defer sticky.deinit();
    var sticky_run = try runShared(allocator, io, options, &sticky, false);
    defer sticky_run.deinit(allocator);

    var random = try initSharedRouter(allocator, .random);
    defer random.deinit();
    var random_run = try runShared(allocator, io, options, &random, false);
    defer random_run.deinit(allocator);

    var rendezvous = try initSharedRouter(allocator, .rendezvous_hash);
    defer rendezvous.deinit();
    var rendezvous_run = try runShared(
        allocator,
        io,
        options,
        &rendezvous,
        true,
    );
    defer rendezvous_run.deinit(allocator);

    std.debug.print(
        "MQTT router match benchmark\n" ++
            "  io backend: zio-std-io\n" ++
            "  filters: {d}\n" ++
            "  samples: {d}, warmup: {d}\n",
        .{ filters.items.len, options.samples, options.warmup },
    );
    printRun("router-match", match_run, match_iterations);
    printRun("linear-match", linear_run, linear_iterations);
    printRun("shared-round-robin", round_robin_run.stats, round_robin_run.iterations);
    printRun("shared-sticky", sticky_run.stats, sticky_run.iterations);
    printRun("shared-random", random_run.stats, random_run.iterations);
    printRun("shared-rendezvous", rendezvous_run.stats, rendezvous_run.iterations);

    if (options.baseline_path) |path| {
        const entries = [_]sampling.BaselineEntry{
            .{ .name = "bench-mqtt-router/match", .stats = match_run },
            .{ .name = "bench-mqtt-router/linear", .stats = linear_run },
            .{ .name = "bench-mqtt-router/shared-round-robin", .stats = round_robin_run.stats },
            .{ .name = "bench-mqtt-router/shared-sticky", .stats = sticky_run.stats },
            .{ .name = "bench-mqtt-router/shared-random", .stats = random_run.stats },
            .{ .name = "bench-mqtt-router/shared-rendezvous", .stats = rendezvous_run.stats },
        };
        try sampling.checkBaselines(allocator, io, &entries, .{
            .path = path,
            .max_regression_ratio = options.max_regression_ratio,
            .update = options.update_baseline,
            .warn_only = options.warn_only,
        });
    }
}

fn runShared(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    router: *netz.mqtt.router.Router,
    vary_topic: bool,
) !Run {
    const stats = try sampling.run(
        allocator,
        io,
        samplingOptions(options, shared_iterations),
        SharedContext{
            .router = router,
            .vary_topic = vary_topic,
            .iterations = shared_iterations,
        },
        sharedWork,
    );
    return .{ .stats = stats, .iterations = shared_iterations };
}

fn samplingOptions(options: Options, iterations: usize) sampling.Options {
    return .{
        .iterations = iterations,
        .samples = options.samples,
        .warmup = options.warmup,
    };
}

fn matchWork(
    context: MatchContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const matches = try context.router.matchInto(context.topic, context.out);
        total +%= @intCast(matches.len);
        if (matches.len != 0) total +%= matches[0].subscriber_id;
    }
    return total;
}

fn linearWork(
    context: LinearContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        for (context.filters) |filter| {
            total +%= @intFromBool(netz.mqtt.topicMatchesFilter(
                context.topic,
                filter,
            ));
        }
    }
    return total;
}

fn sharedWork(
    context: SharedContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var storage: [1]netz.mqtt.router.Match = undefined;
    var topic_buffer: [64]u8 = undefined;
    var total: u64 = 0;
    for (0..context.iterations) |iteration| {
        const topic = if (context.vary_topic)
            try std.fmt.bufPrint(
                &topic_buffer,
                "devices/{d}/state",
                .{iteration & 1023},
            )
        else
            "devices/2047/state";
        const matches = try context.router.matchInto(topic, &storage);
        total +%= matches[0].subscriber_id;
    }
    return total;
}

fn initSharedRouter(
    allocator: std.mem.Allocator,
    strategy: netz.mqtt.router.SharedSubscriptionStrategy,
) !netz.mqtt.router.Router {
    var router = try netz.mqtt.router.Router.initWithOptions(
        allocator,
        .{
            .shared_subscription_strategy = strategy,
            .random_seed = 0x1234_5678,
        },
    );
    errdefer router.deinit();
    for (0..shared_member_count) |member| {
        try router.subscribe(
            @intCast(200_000 + member),
            .{ .topic_filter = "$share/workers/devices/+/state" },
        );
    }
    return router;
}

fn printRun(
    label: []const u8,
    stats: sampling.Stats,
    iterations: usize,
) void {
    std.debug.print(
        "  {s}: {d} ns/op\n",
        .{ label, sampling.nsPerOp(stats, iterations) },
    );
    sampling.printDistribution(label, stats);
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
        if (std.mem.startsWith(u8, arg, "--samples=")) {
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
