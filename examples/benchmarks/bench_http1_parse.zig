const std = @import("std");
const sampling = @import("support").bench_sampling;
const netz = @import("netz");

const default_iterations: usize = 100_000;
const default_samples: usize = 10;
const default_warmup: usize = 1;
const raw_request =
    "POST /bench?mode=parse HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "User-Agent: netz-bench/1\r\n" ++
    "Accept: */*\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Content-Length: 11\r\n" ++
    "Connection: keep-alive\r\n" ++
    "\r\n" ++
    "hello world" ++
    "GET /next HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "\r\n";
const raw_absolute_request =
    "POST http://example.com/bench?mode=parse HTTP/1.1\r\n" ++
    raw_request["POST /bench?mode=parse HTTP/1.1\r\n".len..];

const Scenario = enum { all, borrowed, owned, owned_checked };
const TargetForm = enum { origin, absolute };

const Options = struct {
    scenario: Scenario = .all,
    target_form: TargetForm = .origin,
    iterations: usize = default_iterations,
    samples: usize = default_samples,
    warmup: usize = default_warmup,
    baseline_path: ?[]const u8 = null,
    update_baseline: bool = false,
    max_regression_ratio: f64 = 1.05,
    warn_only: bool = false,
};

const ParseContext = struct {
    request_bytes: []const u8,
    iterations: usize,
};

const Run = struct {
    stats: sampling.Stats,

    fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        self.stats.deinit(allocator);
    }

    fn total(self: Run) u64 {
        return self.stats.last_result;
    }

    fn medianNsPerOp(self: Run, iterations: usize) u64 {
        return sampling.nsPerOp(self.stats, iterations);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const options = try parseOptions(init, allocator);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const request_bytes = switch (options.target_form) {
        .origin => raw_request,
        .absolute => raw_absolute_request,
    };

    var borrowed: ?Run = null;
    defer if (borrowed) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .borrowed) {
        borrowed = try runScenario(
            allocator,
            io,
            options,
            request_bytes,
            borrowedWork,
        );
    }

    var owned: ?Run = null;
    defer if (owned) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .owned) {
        owned = try runScenario(
            allocator,
            io,
            options,
            request_bytes,
            ownedWork,
        );
    }

    var owned_checked: ?Run = null;
    defer if (owned_checked) |*run| run.deinit(allocator);
    if (options.scenario == .all or options.scenario == .owned_checked) {
        owned_checked = try runScenario(
            allocator,
            io,
            options,
            request_bytes,
            ownedCheckedWork,
        );
    }

    std.debug.print(
        "HTTP/1 parse benchmark\n  io backend: zio-std-io\n" ++
            "  target form: {s}\n" ++
            "  iterations: {d}\n" ++
            "  samples: {d}, warmup: {d}\n",
        .{
            @tagName(options.target_form),
            options.iterations,
            options.samples,
            options.warmup,
        },
    );
    if (borrowed) |run| printRun("borrowed", run, options.iterations);
    if (owned) |run| printRun("owned", run, options.iterations);
    if (owned_checked) |run| printRun("owned+host", run, options.iterations);
    if (options.scenario == .all) {
        const speedup_x100 = sampling.ratioTimes100(
            owned_checked.?.stats.distribution.median,
            borrowed.?.stats.distribution.median,
        );
        std.debug.print(
            "  strict borrowed speedup: {d}.{d:0>2}x\n",
            .{ speedup_x100 / 100, speedup_x100 % 100 },
        );
    }
    if (options.baseline_path) |path| {
        var entries: [3]sampling.BaselineEntry = undefined;
        var count: usize = 0;
        if (borrowed) |run| {
            entries[count] = .{
                .name = "bench-http1-parse/borrowed",
                .stats = run.stats,
            };
            count += 1;
        }
        if (owned) |run| {
            entries[count] = .{
                .name = "bench-http1-parse/owned",
                .stats = run.stats,
            };
            count += 1;
        }
        if (owned_checked) |run| {
            entries[count] = .{
                .name = "bench-http1-parse/owned-host",
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
    request_bytes: []const u8,
    comptime work: anytype,
) !Run {
    const stats = try sampling.run(
        allocator,
        io,
        .{
            .iterations = options.iterations,
            .samples = options.samples,
            .warmup = options.warmup,
        },
        ParseContext{
            .request_bytes = request_bytes,
            .iterations = options.iterations,
        },
        work,
    );
    return .{ .stats = stats };
}

fn borrowedWork(
    context: ParseContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = allocator;
    _ = io;
    var headers: [32]netz.http1.Header = undefined;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        const head = try netz.http1.parseRequestHead(
            context.request_bytes,
            &headers,
            .{},
        );
        total += @intCast((try head.messageLength()).?);
    }
    return total;
}

fn ownedWork(
    context: ParseContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        var request = try netz.http1.parseRequest(
            allocator,
            context.request_bytes,
            .{},
        );
        total += @intCast(request.consumed);
        request.deinit(allocator);
    }
    return total;
}

fn ownedCheckedWork(
    context: ParseContext,
    allocator: std.mem.Allocator,
    io: std.Io,
) anyerror!u64 {
    _ = io;
    var total: u64 = 0;
    for (0..context.iterations) |_| {
        var request = try netz.http1.parseRequest(
            allocator,
            context.request_bytes,
            .{},
        );
        try netz.http1.validateRequestHost(request);
        total += @intCast(request.consumed);
        request.deinit(allocator);
    }
    return total;
}

fn printRun(label: []const u8, run: Run, iterations: usize) void {
    std.debug.print(
        "  {s} total: {d}, ns/op: {d}\n",
        .{ label, run.total(), run.medianNsPerOp(iterations) },
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
        } else if (std.mem.startsWith(u8, arg, "--target-form=")) {
            options.target_form = std.meta.stringToEnum(
                TargetForm,
                arg["--target-form=".len..],
            ) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
            if (options.iterations == 0) return error.InvalidArgument;
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
    if (options.update_baseline and options.baseline_path == null) {
        return error.InvalidArgument;
    }
    return options;
}
